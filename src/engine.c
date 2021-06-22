
#if 0
openssl s_client -quiet -connect 127.1:443 </dev/uradnom  >/dev/null

SETUP
======
echo 4096 >/proc/sys/net/core/rmem_default
echo 8196 >/proc/sys/net/core/wmem_default

DEFAUTLS
========
echo 212992 >/proc/sys/net/core/rmem_default
echo 212992 >/proc/sys/net/core/wmem_default

#endif

#include "common.h"
#include "utils.h"
#include "net.h"
#include "packet.h"
#include "peer.h"
#include "gsrnd.h"
#include "protocol.h"
#include "engine.h"
#include "gopt.h"

static void cb_bev_relay_read(struct bufferevent *bev, void *arg);
static void buddy_up(struct _peer *server, struct _peer *client);

void
cb_gsrn_protocol_error(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	GSRN_send_status_fatal(p, GS_STATUS_CODE_PROTOERROR, "Protocol error");
	PEER_goodbye(p);
}

static int
gsrn_listen(struct _peer *p)
{
	// Adjust timeout
	bufferevent_set_timeouts(p->bev, TVSEC(GSRN_MSG_TIMEOUT), NULL);
	GSRN_change_state(p, GS_PKT_TYPE_LISTEN);

	// Check if addr is already listening
	// The binary tree contains a double-linked list of peers.
	// Most of the time there will be just 1 (listening) peer per address
	// unless the caller specified GS_LISTEN(n>1).
	int ret;
	ret = PEER_add(p, PEER_L_LISTENING);
	if (ret != 0)
		goto err;

	struct _peer *buddy = PEER_get(p->addr, PEER_L_WAITING, NULL);
	if (buddy != NULL)
	{
		// There was a client waiting (-w). Connect immediately.
		buddy_up(p /*server*/   , buddy /*client*/);
	}

	return 0;
err:
	GSRN_send_status_fatal(p, GS_STATUS_CODE_BAD_AUTH, NULL);

	return -1;
}

void
cb_gsrn_listen(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _gs_listen gs_listen;

	evbuffer_remove(eb, &gs_listen, sizeof gs_listen);
	uint128_t addr;
	memcpy(&addr, gs_listen.addr, sizeof addr);
	addr = be128toh(addr);

	p->addr = addr;
	memcpy(&p->token, gs_listen.token, sizeof p->token);
	char valstr[64]; DEBUGF_G("LISTEN received (addr=0x%s)\n", strx128(addr, valstr, sizeof valstr));

	if (gsrn_listen(p) != 0)
		goto err;

	return;
err:
	PEER_goodbye(p); 
	return;
}

static void
buddy_up(struct _peer *server, struct _peer *client)
{
	server->buddy = client;
	client->buddy = server;

	server->flags |= FL_PEER_IS_SERVER;
	client->flags |= FL_PEER_IS_CLIENT;

	PEER_L_mv(server, PEER_L_WAIT_ACCEPT);
	PEER_L_mv(client, PEER_L_WAIT_ACCEPT);

	GSRN_send_start(server, GS_FL_PROTO_START_SERVER);
	GSRN_send_start(client, GS_FL_PROTO_START_CLIENT);

	GSRN_change_state(server, GSRN_STATE_BUDDY_UP);
	GSRN_change_state(client, GSRN_STATE_BUDDY_UP);

	// Adjust timeout
	bufferevent_set_timeouts(server->bev, TVSEC(GSRN_ACCEPT_TIMEOUT), NULL);
	bufferevent_set_timeouts(client->bev, TVSEC(GSRN_ACCEPT_TIMEOUT), NULL);
}

void
cb_gsrn_connect(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _gs_connect gs_connect;

	evbuffer_remove(eb, &gs_connect, sizeof gs_connect);
	uint128_t addr;
	memcpy(&addr, gs_connect.addr, sizeof addr);
	addr = be128toh(addr);

	p->addr = addr;
	char valstr[64]; DEBUGF_G("CONNECT received (addr=0x%s)\n", strx128(addr, valstr, sizeof valstr));

	// IGNORE any further LISTEN/CONNECT messages
	GSRN_change_state(p, GSRN_STATE_CONNECT);

	struct _peer_l_mgr *bmgr;
	struct _peer *buddy = PEER_get(p->addr, PEER_L_LISTENING, &bmgr);
	if (buddy == NULL)
	{
		// HERE: No server listening.
		if (gs_connect.flags & GS_FL_PROTO_CLIENT_OR_SERVER)
		{
			// HERE: peer is allowed to become a server
			// -A flag. When no server listening. 
			DEBUGF_G("CONNECT but becoming a listening server instead (-A is set)\n");
			if (gsrn_listen(p) != 0)
				goto err;

			return;
		}

		// HERE: Client not allowed to become a server.
		if (!(gs_connect.flags & GS_FL_PROTO_WAIT)) // FALSE
		{
			// Check if a listening server was recently available and
			// let this client wait for a big with the hope of server to
			// open another listening connection.
			if ((bmgr != NULL) && (evtimer_pending(bmgr->evt_shortwait, NULL)))
			{
				p->flags |= FL_PEER_IS_SHORTWAIT;
			} else {
				GSRN_send_status_fatal(p, GS_STATUS_CODE_CONNREFUSED, NULL);
				goto err;
			}
		}

		int ret;
		ret = PEER_add(p, PEER_L_WAITING);
		if (ret != 0)
		{
			GSRN_send_status_fatal(p, GS_STATUS_CODE_CONNDENIED, "Not allowed to connect.");
			goto err;
		}

		// Waiting clients will send PINGs.
		bufferevent_set_timeouts(p->bev, TVSEC(GSRN_MSG_TIMEOUT), NULL);
		return;
	}

	// HERE: Buddy found. Connect them.
	buddy_up(buddy /*server*/, p /*client*/);

	DEBUGF_Y("%c connect received\n", IS_CS(p));


	return;
err:
	PEER_goodbye(p);
}

static void
flush_relay(struct _peer *p)
{
	struct evbuffer *in = bufferevent_get_input(p->bev);

	if (in == NULL)
		return;

	if (evbuffer_get_length(in) > 0)
		bufferevent_write_buffer(p->buddy->bev, in);
}

void
cb_gsrn_accept(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _gs_accept msg;

	DEBUGF_Y("%c GSRN_ACCEPT\n", IS_CS(p));
	evbuffer_remove(eb, &msg, sizeof msg);
	p->flags |= FL_PEER_IS_ACCEPT_RECV;

	// Adjust timeout
	bufferevent_set_timeouts(p->bev, TVSEC(GSRN_IDLE_TIMEOUT), NULL);
	// IGNORE any further ACCEPT messages
	GSRN_change_state(p, GSRN_STATE_ACCEPT);

	struct _peer *buddy = p->buddy;
	if (buddy == NULL)
	{
		DEBUGF_R("ACCEPT but buddy is NULL\n");
		return; // CAN NOT HAPPEN
	}

	bufferevent_setcb(p->bev, cb_bev_relay_read, cb_bev_write, cb_bev_status, p);
	PKT_free(&p->pkt); // stop processing packets. Might still be more data in input buffer...
	PEER_L_mv(p, PEER_L_CONNECTED);
	// Libevent does not trigger EV_READ for data that is left inside the input buffer (doh!).
	flush_relay(p);

	if (!PEER_IS_ACCEPT_RECEIVED(buddy)) // FALSE
	{
		PEER_L_mv(buddy, PEER_L_ACCEPTED);
		DEBUGF_G("Waiting for ACCEPT from buddy.\n");
		return;
	}

	DEBUGF_Y("%c CONNECTED\n", IS_CS(p));
}

void
cb_gsrn_ping(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _gs_ping msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	DEBUGF_G("%c PING received\n", IS_CS(p));
	GSRN_send_pong(p, &msg.payload[0]);
}


#define BEV_ERR_ADD(dst, end, rem, what, check)  do{ \
	if (!(what & check)) { break; } \
	rem &= ~check; \
	int rv; \
	rv = snprintf(dst, end - dst, "|%s", #check); \
	if (rv <= 0) { break; } \
	dst += rv; \
} while (0)

// Return BEV_EVENT_ errors as string
const char *
BEV_strerror(short what)
{
	static char err[128];
	char *d = &err[0];
	char *e = d + sizeof err;
	short rem = what; // remaining flags

	*d = 0;

	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_READING);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_WRITING);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_EOF);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_ERROR);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_TIMEOUT);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_CONNECTED);

	if (rem != 0)
		snprintf(d, e - d, "|UNKNOWN-%x", rem);

	return err;
}

void
cb_bev_status(struct bufferevent *bev, short what, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	DEBUGF_Y("%c status event=%d (%s)\n", IS_CS(p), what, BEV_strerror(what));
	if (what & BEV_EVENT_CONNECTED)
	{
		DEBUGF_Y("Connected\n");
		bufferevent_enable(bev, EV_READ);
		return;
	}

	if (what & BEV_EVENT_TIMEOUT)
	{
		DEBUGF_C("***TIMEOUT*** (is_goodbye=%d)\n", PEER_IS_GOODBYE(p));
	}

	if (what & BEV_EVENT_EOF)
	{
		DEBUGF("p=%p, buddy=%p\n", p, p->buddy);
		if (p->buddy == NULL)
			goto err; // no buddy connected.

		if (PEER_IS_EOF_RECEIVED(p))
			goto err; // 2nd EOF. Treat as ERROR.

		if (PEER_IS_EOF_RECEIVED(p->buddy))
			goto err; // Both sides decided to stop. Free both.

		p->flags |= FL_PEER_IS_EOF_RECEIVED;

		// soft close(). Inform buddy that no more data is coming
		// his way. Buddy may still send data to us (the socket is not
		// closed for reading yet).
		shutdown(p->buddy->fd, SHUT_WR);
		// Stop reading
		bufferevent_disable(p->bev, EV_READ);

		return;
	}

	// Any other error-event is bad (disconnect)
err:
	PEER_free(p);
}

void
cb_bev_write(struct bufferevent *bev, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	// DEBUGF("EV_WRITE (all data written)\n");
	// All data written. Enable reading again.
	if (PEER_IS_GOODBYE(p))
	{
		PEER_free(p);
		return;
	}
	if (PEER_IS_EOF_RECEIVED(p))
		return; // Do not enable reading if we received EOF already

	bufferevent_enable(bev, EV_READ);
}

static void
cb_bev_relay_read(struct bufferevent *bev, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct evbuffer *in = bufferevent_get_input(bev);

	struct _peer *buddy = p->buddy;
	struct evbuffer *out = bufferevent_get_input(buddy->bev);
	size_t out_sz = evbuffer_get_length(out);

	// DEBUGF_W("%c read=%zd (out-buf=%zd)\n", IS_CS(p), evbuffer_get_length(in), out_sz);
	if (out_sz > 0)
	{
		DEBUGF_R("%c Still data in output buffer (%zu). Stop reading..\n", IS_CS(p), out_sz);
		bufferevent_disable(bev, EV_READ);
	}

	bufferevent_write_buffer(buddy->bev, in);
}

void
cb_bev_read(struct bufferevent *bev, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	struct evbuffer *in = bufferevent_get_input(bev);
	struct evbuffer *out = bufferevent_get_output(bev);
	size_t in_sz = evbuffer_get_length(in);
	size_t out_sz = evbuffer_get_length(out);

	if (out_sz > 0)
	{
		DEBUGF_R("%c Still data in output buffer (%zu). Stop reading..\n", IS_CS(p), out_sz);
		bufferevent_disable(bev, EV_READ);
	}

	// Dispatch protocol message
	DEBUGF("in-buf length=%zu\n", in_sz);
	PKT_dispatch(&p->pkt, in);
	DEBUGF("Input buffer size=%zu after PKT_dispatch()\n", evbuffer_get_length(in));

	DEBUGF("Output Buffer size=%zu after PKT_dispatch()\n", evbuffer_get_length(out));
}

// Assign fd to bio and create peer and events for this peer.
static int
accept_ssl(int ls, SSL *ssl)
{
	int sox = -1;

	sox = fd_net_accept(ls);
	if (sox < 0)
	{
		// FIXME: Log this failure.
		goto err;
	}

	// Create peer
	struct _peer *p;
	p = PEER_new(sox, ssl);
	if (p == NULL)
		goto err;

	return 0;
err:
	DEBUGF_R("error\n");
	XCLOSE(sox);
	return -1;
}

void
cb_accept(int ls, short ev, void *arg)
{
	// BIO *bio = BIO_new(BIO_s_socket());

	if (accept_ssl(ls, NULL) != 0)
		goto err;

	return;
err:
	return;
}

void
cb_accept_ssl(int ls, short ev, void *arg)
{
	// BIO *bio = BIO_new(BIO_f_ssl()); // alternative
	// SSL *ssl = SSL_new(gopt.ssl_ctx); // alternative
	// BIO_set_ssl(bio, ssl, BIO_NOCLOSE); // alternative
	// BIO_set_ssl_mode(bio, 0 /*server*/); // alternative
	// BIO *bio = BIO_new_ssl(gopt.ssl_ctx, 0 /*server*/);

	SSL *ssl = SSL_new(gopt.ssl_ctx);
	if (accept_ssl(ls, ssl) != 0)
		goto err;

	return;
err:
	SSL_free(ssl);
	// XBIO_FREE(bio);
}

// Accept TCP for CNC
void
cb_accept_con(int fd, short ev, void *arg)
{
	accept_ssl(fd, NULL);
// FIXME: pass which msg dispatcher function should be called for message types.

	// FIXME: add event for reading and writing.
}
