
#if 0
openssl s_client -quiet -connect 127.1:443 </dev/urandom  >/dev/null

SETUP
======
echo 4096 >/proc/sys/net/core/rmem_default
echo 8196 >/proc/sys/net/core/wmem_default

DEFAULTS
========
echo 212992 >/proc/sys/net/core/rmem_default
echo 212992 >/proc/sys/net/core/wmem_default

#endif

#include "common.h"
#include "utils.h"
#include "net.h"
#include "packet.h"
#include "peer.h"
#include "cli.h"
#include "gsrnd.h"
#include "protocol.h"
#include "engine.h"
#include "gopt.h"

static void cb_bev_relay_read(struct bufferevent *bev, void *arg);
static void buddy_up(struct _peer *server, struct _peer *client);

extern struct _cli *logstream_cli;

static void
logstream_msg(struct _cli_logstream *ls, uint8_t opcode, struct _peer *p) {
	ls->hdr.type = GSRN_CLI_TYPE_LOGSTREAM;
	ls->opcode = opcode;
	if (p != NULL)
		memcpy(&ls->addr, &p->addr, sizeof ls->addr);
	CLI_msg(logstream_cli, ls, sizeof *ls);
}

// Send log file to cli (if logstream is enabled)
static void
logstream_listen(struct _peer *p, struct _gs_listen *msg) {
	if (logstream_cli == NULL)
		return;

	// Log only the _first_ LISTEN: The client immediately establishes another
	// LISTEN() connection after the first connection. Dont log in.
	// Get total number of all PEERS of this ADDRESS
	// Subtract all that are in a BAD state
	int n;
	n = p->plr->pl_mgr->n_entries - p->plr->pl_mgr->plr[PEER_L_BAD_AUTH].n_entries;;
	if (n != 1)
		return;

	// First ENTRY. Nobody else in ACCEPT or CONNECT state.
	struct _cli_logstream ls;
	memcpy(&ls.ipa, &p->addr_in, sizeof ls.ipa);
	if (msg != NULL)
		memcpy(&ls.msg, msg, sizeof ls.msg);
	else
		memset(&ls.msg, 0, sizeof ls.msg);

	logstream_msg(&ls, GSRN_CLI_OP_LS_LISTEN, p);
}


// #if sizeof (struct _gs_connect) != sizeof (struct _gs_listen)
// # error "Sizeof _gs_connect and _gs_listen not the same"
// #endif
static void
logstream_connect(struct _peer *p, struct _gs_connect *msg)
{
	if (logstream_cli == NULL)
		return;

	struct _cli_logstream ls;
	if (p->flags & FL_PEER_IS_SERVER) {
		memcpy(&ls.ipa, &p->addr_in, sizeof ls.ipa);
		memcpy(&ls.ipb, &p->buddy->addr_in, sizeof ls.ipb);
	} else {
		memcpy(&ls.ipa, &p->buddy->addr_in, sizeof ls.ipa);
		memcpy(&ls.ipb, &p->addr_in, sizeof ls.ipb);
	}

	if (msg != NULL)
		memcpy(&ls.msg, msg, sizeof ls.msg);
	else
		memset(&ls.msg, 0, sizeof ls.msg);

	logstream_msg(&ls, GSRN_CLI_OP_LS_CONNECT, p);
}


void
cb_gsrn_protocol_error(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	GSRN_send_status_fatal(p, GS_STATUS_CODE_PROTOERROR, "Protocol error");
	PEER_goodbye(p);
}

static void
cb_evt_bad_auth_delay(int fd_notusec, short event, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	DEBUGF_W("[%6u] {fd=%d} Sending delayed BAD_AUTH\n", p->id, p->fd);
	GSRN_send_status_fatal(p, GS_STATUS_CODE_BAD_AUTH, NULL);
	PEER_goodbye(p);
}

// Check if DISCONNECT/ERROR should be delayed (return 0) or immediately.
// return -1 (immediately / error)
// Called from gsrn_listen()
static int
gsrn_bad_auth_delay(struct _peer *p)
{
	struct _peer_l_mgr *pl_mgr = NULL;
	pl_mgr = PEER_get_mgr(p->addr);
	if (pl_mgr == NULL)
		return -1;

	uint64_t last_bad_auth_usec = pl_mgr->last_bad_auth_usec;
	pl_mgr->last_bad_auth_usec = gopt.usec_now;
	if (last_bad_auth_usec <= 0)
		return -1; // First time we see BAD_AUTH. Disconnect immediately.
	if (last_bad_auth_usec + GS_SEC_TO_USEC(GSRN_BAD_AUTH_WINDOW) < gopt.usec_now)
		return -1; // No BAD_AUTH for a while. Disconnect immediately.

	DEBUGF_W("Delaying BAD_AUTH (last: %0.03fsec ago)\n", (float)(gopt.usec_now - last_bad_auth_usec) / 1000 / 1000);
	// HERE: Rapid LISTEN requests with BAD-AUTH.
	// Delay the error and disconnect.
	p->evt_bad_auth_delay = evtimer_new(gopt.evb, cb_evt_bad_auth_delay, p);
	uint64_t msec = (GSRN_BAD_AUTH_DELAY + random() % GSRN_BAD_AUTH_JITTER) * 1000 + random() % 1000;
	DEBUGF("DELAY=%.03f sec\n", (float)msec/1000);
	evtimer_add(p->evt_bad_auth_delay, TVMSEC(msec));

	return 0;
}

// NOTE: msg might be NULL if called from cb_connect() and the client request to
// go into "listen()" if no server is connected.
static int
gsrn_listen(struct _peer *p, uint8_t *token, struct _gs_listen *msg /* MIGHT BE NULL */)
{
	// Adjust timeout
	bufferevent_set_timeouts(p->bev, TVSEC(GSRN_MSG_TIMEOUT), NULL);
	GSRN_change_state(p, GSRN_STATE_LISTEN);

	// Check if addr is already listening
	// The binary tree contains a double-linked list of peers.
	// Most of the time there will be just 1 (listening) peer per address
	// unless the caller specified GS_LISTEN(n>1).
	int ret;
	ret = PEER_add(p, PEER_L_LISTENING, token);
	if (ret != 0)
	{
		// BAD AUTH TOKEN (another peer of same addr is already listening)
		gstats.n_bad_auth += 1;
		GSRN_change_state(p, GSRN_STATE_FINISHED);
		if (gsrn_bad_auth_delay(p) == 0)
		{
			PEER_L_mv(p, PEER_L_BAD_AUTH);
			return 0; // Trigger cb_evt_bad_auth_delay()
		}

		GSRN_send_status_fatal(p, GS_STATUS_CODE_BAD_AUTH, NULL);
		return -1;
	}

	if (msg != NULL) {
		memcpy(p->gs_id, msg->id, sizeof p->gs_id);
		logstream_listen(p, msg);
	}

	struct _peer *buddy = PEER_get(p->addr, PEER_L_WAITING, NULL);
	if (buddy != NULL) {
		// There was a client waiting (-w). Connect immediately.
		buddy_up(p /*server*/   , buddy /*client*/);
	} else {
		if ((msg != NULL) && (msg->flags & GS_FL_PROTO_BUDDY_CHECK)) {
			GSRN_send_status_warn(p, GS_STATUS_CODE_BUDDY_NOK, NULL);
			// Client wants GSRN to close the connection.
			if (msg->flags & GS_FL_PROTO_CONN_CLOSE)
				return -1; // Trigger PEER_goodbye()
		}
	}

	gstats.n_gs_listen += 1;
	return 0;
}

// Set PEER information from _gs_listen/_gs_connect message
static void
peer_set_gs_info(struct _peer *p, struct _gs_hdr_lc *msg)
{
	uint128_t addr;
	memcpy(&addr, msg->addr, sizeof addr);
	addr = be128toh(addr);

	p->addr = addr;
	p->version_major = msg->version_major;
	p->version_minor = msg->version_minor;
	p->gs_proto_flags = msg->flags;
	if (p->gs_proto_flags & GS_FL_PROTO_WAIT)
		DEBUGF_C("WAITING\n");
}



#define GS_STR_OBSOLETE_CLIENT      "Obsolete client detected."
void
cb_gsrn_listen(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _gs_listen msg;

	evbuffer_remove(eb, &msg, sizeof msg);
	peer_set_gs_info(p, &msg.hdr);
	// memcpy(&p->token, msg.token, sizeof p->token);
	DEBUGF_G("{fd=%d} LISTEN received (addr=0x%s)\n", p->fd, GS_addr128hex(NULL, p->addr));

	if ((msg.version_major < gd.min_version_major) || ((msg.version_major == gd.min_version_major) && (msg.version_minor < gd.min_version_minor)))
	{
		GS_LOG_V("[%6u] %32s OBSOLETE CLIENT (listen) %s v%u.%u", p->id, GS_addr128hex(NULL, p->addr), gs_log_in_addr2str(&p->addr_in), p->version_major, p->version_minor);
		GSRN_send_status_fatal(p, GS_STATUS_CODE_NEEDUPDATE, GS_STR_OBSOLETE_CLIENT);
		goto err;
	}
	char hex[GS_ID_SIZE * 2 + 1];
	GS_LOG_V("[%6u] %32s LISTEN %s %s v%u.%u", p->id, GS_addr128hex(NULL, p->addr), GS_bin2hex(hex, sizeof hex, msg.id, sizeof msg.id), gs_log_in_addr2str(&p->addr_in), p->version_major, p->version_minor);

	if (gsrn_listen(p, msg.token, &msg) != 0)
		goto err;

	// HERE: Can be SUCCESS or delayed BAD-AUTH.
	return;
err:
	PEER_goodbye(p); 
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

	char s_ipport[32];
	snprintf(s_ipport, sizeof s_ipport, "%s", gs_log_in_addr2str(&server->addr_in));
	
	GS_LOG_V("[%6u] %32s CONNECT v%u.%u %s->%s", client->id, GS_addr128hex(NULL, client->addr), client->version_major, client->version_minor, gs_log_in_addr2str(&client->addr_in), s_ipport);

	DEBUGF_G("%c Server-%d fd=%d bev=%p\n", IS_CS(server), server->id, bufferevent_getfd(server->bev), server->bev);
	DEBUGF_G("%c Client-%d fd=%d bev=%p\n", IS_CS(client), client->id, bufferevent_getfd(client->bev), client->bev);
	client->bps_last_usec = client->state_usec;
	server->bps_last_usec = server->state_usec;

	gstats.n_gs_connect += 1;
}

void
cb_gsrn_connect(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _gs_connect msg;

	evbuffer_remove(eb, &msg, sizeof msg);
	peer_set_gs_info(p, &msg.hdr);

	if ((msg.version_major < gd.min_version_major) || ((msg.version_major == gd.min_version_major) && (msg.version_minor < gd.min_version_minor)))
	{
		GS_LOG_V("[%6u] %32s OBSOLETE CLIENT (connect) %s v%u.%u", p->id, GS_addr128hex(NULL, p->addr), gs_log_in_addr2str(&p->addr_in), p->version_major, p->version_minor);
		GSRN_send_status_fatal(p, GS_STATUS_CODE_NEEDUPDATE, GS_STR_OBSOLETE_CLIENT);
		goto err;
	}

	DEBUGF_Y("msg.flags=%x\n", msg.flags);
	// IGNORE any further LISTEN/CONNECT messages
	GSRN_change_state(p, GSRN_STATE_CONNECT);

	struct _peer_l_mgr *bmgr;
	struct _peer *buddy = PEER_get(p->addr, PEER_L_LISTENING, &bmgr);
	if (buddy == NULL)
	{
		// HERE: No server listening.
		if (msg.flags & GS_FL_PROTO_CLIENT_OR_SERVER)
		{
			// HERE: peer is allowed to become a server
			// -A flag. When no server listening. 
			DEBUGF_G("CONNECT but becoming a listening server instead (-A is set)\n");
			if (gsrn_listen(p, NULL, NULL /*&msg*/) != 0)
				goto err;

			// HERE: Can be SUCCESS or delayed BAD-AUTH.
			return;
		}

		// HERE: Client not allowed to become a server.
		if (!(msg.flags & GS_FL_PROTO_WAIT)) // FALSE
		{
			// Check if a listening server was recently available and
			// let this client wait for a bit with the hope of server to
			// open another listening connection.
			if ((bmgr != NULL) && (evtimer_pending(bmgr->evt_shortwait, NULL)))
			{
				p->flags |= FL_PEER_IS_SHORTWAIT;
			} else {
				PEER_conn_refused(p);
				return;
			}
		}

		int ret;
		ret = PEER_add(p, PEER_L_WAITING, NULL);
		if (ret != 0)
		{
			GS_LOG_V("[%6u] %32s CON-DENIED %s v%u.%u", p->id, GS_addr128hex(NULL, p->addr), gs_log_in_addr2str(&p->addr_in), p->version_major, p->version_minor);

			GSRN_send_status_fatal(p, GS_STATUS_CODE_CONNDENIED, "Not allowed to connect.");
			goto err;
		}

		// Waiting clients will send PINGs.
		bufferevent_set_timeouts(p->bev, TVSEC(GSRN_MSG_TIMEOUT), NULL);
		return;
	}

	if (msg.flags & GS_FL_PROTO_BUDDY_CHECK)
	{
		// HERE: Server is listening but we only want to check.
		DEBUGF_Y("FL_PROTO_BUDDY_CHECK is set. Server is ok\n");
		GSRN_send_status_fatal(p, GS_STATUS_CODE_SERVER_OK, NULL);
		goto err;
	}
		
	// HERE: Buddy found. Connect them.
	buddy_up(buddy /*server*/, p /*client*/);

	DEBUGF_Y("%c connect received\n", IS_CS(p));
	logstream_connect(p, &msg);


	return;
err:
	PEER_goodbye(p);
}

static void
flush_relay(struct _peer *p)
{
	struct evbuffer *evb = bufferevent_get_input(p->bev);

	if (evb == NULL)
		return;

	size_t sz = evbuffer_get_length(evb);
	DEBUGF("Flushing %zu to %c\n", sz, IS_CS(p->buddy));
	if (sz > 0)
	{
		PEER_stats_update(p, evb);
		bufferevent_write_buffer(p->buddy->bev, evb);
	}
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

	// PKT_dispatch may have received a GS-ACCEPT (and called this function) but there
	// is more data in this peer's in-buffer. Copy it to the buddy's output buffer
	flush_relay(p);
	// And start reading again (all data will be appended to buddy's out-buffer
	// and if that gets to large then it will stop...)
	bufferevent_enable(p->bev, EV_READ);

	if (!PEER_IS_ACCEPT_RECEIVED(buddy)) // FALSE
	{
		PEER_L_mv(buddy, PEER_L_ACCEPTED);
		DEBUGF_G("Waiting for ACCEPT from %c.\n", IS_CS(buddy));
		return;
	}

	// Enable EV_READ in case it was disabled by cb_bev_read(). This may have happened
	// before the GS-ACCEPT was received and while there was still data that needed to
	// be send to this peer.
	bufferevent_enable(p->buddy->bev, EV_READ);

	DEBUGF_Y("%c CONNECTED fd=%d\n", IS_CS(p), bufferevent_getfd(p->bev));
}

void
cb_gsrn_ping(struct evbuffer *eb, size_t len, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _gs_ping msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	// DEBUGF_G("%c PING received fd=%d\n", IS_CS(p), p->fd);
	GSRN_send_pong(p, &msg.payload[0]);
}


void
cb_shutdown_complete(void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _peer *buddy = p->buddy;

	DEBUGF("[%6u] {fd=%d} %c SHUTDOWN-COMPLETE (IS_SHUT_WR_SENT(buddy)=%s)\n", p->id, p->fd, IS_CS(p), buddy==NULL?"NULL":PEER_IS_SHUT_WR_SENT(buddy)?"true":"false");

	if (buddy == NULL)
	{
		PEER_free(p);
		return;
	}

	if (PEER_IS_SHUT_WR_SENT(buddy))
	{
		PEER_free(p);
		PEER_free(buddy);
		return;
	}

	// HERE: buddy has not called sys_shutdown() yet.
	// 1. Buddy sent EOF. Peer can still write to buddy
	// 2. Write to peer causes SIGPIPE
#ifdef DEBUG
	int ret;
	int value;
	socklen_t len = sizeof (value);
	ret = getsockopt(buddy->fd, SOL_SOCKET, SO_ERROR, &value, &len);
#endif

	DEBUGF("[%6u] {fd=%d} %c Waiting for buddy...(half-close).[%6u] {fd=%d} has %zd bytes in output buffer, sockopt=%d, so_error=%d])\n", p->id, p->fd, IS_CS(p), buddy->id, buddy->fd, evbuffer_get_length(bufferevent_get_output(buddy->bev)), ret, value);
}

void
cb_bev_status(struct bufferevent *bev, short what, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _peer *buddy = p->buddy;

	DEBUGF_Y("[%6u] {fd=%d} %c peer=%p bev=%p status event=%d (%s)\n", p->id, p->fd, IS_CS(p), p, bev, what, BEV_strerror(what));
	if (what & BEV_EVENT_CONNECTED)
	{
		DEBUGF_Y("Connected\n");
		bufferevent_enable(bev, EV_READ);
		return;
	}

	if (what & BEV_EVENT_TIMEOUT)
	{
		DEBUGF_C("[%6u] %c ***TIMEOUT***\n", p->id, IS_CS(p));
		// We sent SHUT_WR to this peer but are not receiving any data from this peer.
		PEER_free(p);
		if (buddy)
			PEER_free(buddy);
		return;
	}

	// This can happen: BEV_EVENT_READING|BEV_EVENT_WRITING|BEV_EVENT_EOF|BEV_EVENT_ERROR
	// Can not WRITE anymore.
	// if ((what & (BEV_EVENT_WRITING | BEV_EVENT_ERROR)) == (BEV_EVENT_WRITING | BEV_EVENT_ERROR)) {
	// Cant recover. This peer is dead.
	if (what & BEV_EVENT_ERROR) {
		PEER_free(p);
		if (buddy)
			PEER_shutdown(buddy, cb_shutdown_complete); // calls PEER_free() when done.
		return;
	}

	// Waiting/Listening peer disconnects (before GS-CONNECT)
	if (buddy == NULL)
	{
		DEBUGF_R("NO BUDDY\n");
		PEER_shutdown(p, cb_shutdown_complete);
		return;
	}

	if (what & BEV_EVENT_EOF)
	{
		if (PEER_IS_EOF_RECEIVED(p)) {
			DEBUGF_R("EVENT_EOF received 2nd time!\n");
			// FIXME: Odd, EV_READ gets disabled (see below) but libevent invokes this
			// twice every once in a while...
			// PEER_free(p); // pointer may have gotten freed already. 
			return;
		}
		p->flags |= FL_PEER_IS_EOF_RECEIVED;

		// EOF received. Stop reading
		DEBUGF_W("%c Stopping EV_READ\n", IS_CS(p));
		bufferevent_disable(p->bev, EV_READ);

		if (!PEER_IS_EOF_RECEIVED(buddy))
		{
			DEBUGF_W("[%6u] %c fd=%d Setting write shutdown-idle-timeout\n", p->id, IS_CS(p), p->fd);
			// This connection is half-dead. Free if buddy is not sending data...(READ-timeout)
			bufferevent_set_timeouts(buddy->bev, TVSEC(GSRN_SHUTDOWN_IDLE_TIMEOUT), NULL);
		}

		// Forward SHUT_WR to buddy (We wont send any more data)
		// MIGHT FREE BUDDY and PEER.
		PEER_shutdown(buddy, cb_shutdown_complete);

		return;
	}

	// Any other error-event is bad (disconnect hard)
	// Broken Pipe, Connection reset by peer
	// GS_LOG("ODD-ERROR: [%6u] %c fd=%d, event=%d", p->id, IS_CS(p), p->fd, what);
	PEER_free(p);
	if (buddy)
		PEER_free(buddy);
}

void
cb_bev_write(struct bufferevent *bev, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct _peer *buddy = (struct _peer *)p->buddy;

	// DEBUGF("%c write done peer=%p buddy=%p\n", IS_CS(p), p, buddy);
	// All data written. Enable reading again.

	if (PEER_IS_WANT_SEND_SHUT_WR(p))
	{
		PEER_shutdown(p, NULL /* already set*/);
		return;
	}

	if ((buddy != NULL) && PEER_IS_ACCEPT_RECEIVED(p))
	{
		bufferevent_enable(buddy->bev, EV_READ);
		return;
	}

	// Or if GS-ACCEPT has not been received yet then write
	// completed and reading from this peer's input should continue
	// (until GS-ACCEPT is received).
	bufferevent_enable(p->bev, EV_READ);
}


static void
cb_bev_relay_read(struct bufferevent *bev, void *arg)
{
	struct _peer *p = (struct _peer *)arg;
	struct evbuffer *in = bufferevent_get_input(bev);
	struct _peer *buddy = p->buddy;
	size_t in_sz = evbuffer_get_length(in);

	PEER_stats_update(p, in);

	// DEBUGF("%c in_sz=%zd\n", IS_CS(p), in_sz);

	bufferevent_write_buffer(buddy->bev, in);

	size_t bsz = evbuffer_get_length(bufferevent_get_output(buddy->bev));

	if (bsz >= MAX(in_sz, 4096) * 4)
	{
		DEBUGF_R("[%6u] %c Still data in %c's output buffer (%zu). Stop reading..\n", p->id, IS_CS(p), IS_CS(buddy), bsz);
		bufferevent_disable(bev, EV_READ);
	}
}

// Read data from peer. May add data to p->bev=>out and may stop reading
// if there is still data to send to itself (e.g. replies).
// Special care needs to be taken when moving to CONNECT state and when
// this peer's bev=>in is written to buddy's bev=>out: Data left here in the out-buffer
// need to be flushed to the buddy.
void
cb_bev_read(struct bufferevent *bev, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	struct evbuffer *in = bufferevent_get_input(bev);
	struct evbuffer *out = bufferevent_get_output(bev);
	size_t out_sz = evbuffer_get_length(out);

	if (out_sz > 0)
	{
		// HERE: Only happens when PKT_dispatch() adds a message to the out-buffer
		// and it hasnt been send yet to _this_ peer (not the buddy).
		DEBUGF_R("%c Still data in output buffer (%zu). Stop reading..\n", IS_CS(p), out_sz);
		bufferevent_disable(bev, EV_READ);
	}

	gopt.usec_now = GS_usec();
	// Dispatch protocol message
	PKT_dispatch(&p->pkt, in);
	// May have enabled EV_READ (if a gs-accept was received).
	// HERE: PKT_dispatch() may have added data to _this_ peer's out-buffer
	// and may have enable EV_READ (for example when buddy got connected and all
	// further in-data should be send to the peer's buddy out-buffer).

	// DEBUGF("Input buffer size=%zu after PKT_dispatch()\n", evbuffer_get_length(in));
	// DEBUGF("Output Buffer size=%zu after PKT_dispatch()\n", evbuffer_get_length(out));
}

// Assign fd to bio and create peer and events for this peer.
static int
accept_ssl(int ls, SSL *ssl)
{
	int sox;

	sox = fd_net_accept(ls);
	if (sox < 0)
	{
		GS_LOG_V("[%6u] ERROR: accept(%d)=%s", ls, strerror(errno));
		// Likely ran out of FD's. We should not exit
		// but instead increase FD limit, accept fd, disconnect FD
		// and the set FD limit again.
		fd_limit_unlimited();
		sox = fd_net_accept(ls);
		fd_limit_limited();

		// Catch-all total fuckup: wait...
		if (sox < 0)
			usleep(100 * 1000);
		goto err; // Will close() the accepted socket.
	}

	// Create peer
	struct _peer *p;
	p = PEER_new(sox, ssl);
	if (p == NULL)
		goto err;

	return 0;
err:
	DEBUGF_R("ERROR %s ls=%d, sox=%d\n", strerror(errno), ls, sox);
	XCLOSE(sox);
	return -1;
}

void
cb_accept(int ls, short ev, void *arg)
{
	// struct event *ev = (struct event *)arg;
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
cb_accept_cnc(int fd, short ev, void *arg)
{
	accept_ssl(fd, NULL);
// FIXME: pass which msg dispatcher function should be called for message types.

	// FIXME: add event for reading and writing.
}

