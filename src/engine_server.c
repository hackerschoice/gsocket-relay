// Only linked against gsrnd
#include "common.h"
#include "utils.h"
#include "cli.h"
#include "net.h"
#include "engine.h"
#include "engine_cli.h"
#include "gopt.h"


void
cb_bev_status_cli(struct bufferevent *bev, short what, void *arg)
{
	struct _cli *c = (struct _cli *)arg;

	DEBUGF("status=%d (%s)\n", what, BEV_strerror(what));

	if (what & BEV_EVENT_CONNECTED)
	{
		c->flags |= FL_CLI_IS_CONNECTED;
		bufferevent_enable(bev, EV_READ);
		return;
	}

	if (what & BEV_EVENT_ERROR)
	{
		// if (!(c->flags & FL_CLI_IS_CONNECTED))
		// else
	}

	CLI_free(c);
}


static void
cb_peers_list(struct _peer *p, struct _peer_l_root *plr, void *arg)
{
	int *first_call_ptr = (int *)arg;
	if (p == NULL)
	{
		if (plr == NULL)
			return;

		DEBUGF("List-#%ld(%s) (%d entries):\n", PLR_L_get_id(plr), PEER_L_name(PLR_L_get_id(plr)), plr->n_entries);
		return;
	}

	DEBUGF("  [%u] %c addr=%s\n", p->id, IS_CS(p), strx128x(p->addr));

	peer_l_id_t pl_id = PLR_L_get_id(plr);
	// Do not show connected client (as we alrady show the server connected)
	if (!PEER_IS_SERVER(p) && (pl_id == PEER_L_CONNECTED))
		return;

	DEBUGF_W("Sending peer-id %d\n", p->id);
	struct _cli_list_r msg;
	memset(&msg, 0, sizeof msg);
	msg.type = GSRN_CLI_TYPE_LIST_RESPONSE;
	msg.addr = htobe128(p->addr);
	msg.pl_id = pl_id;
	msg.peer_id = htonl(p->id);
	msg.ip = p->addr_in.sin_addr.s_addr;
	msg.port =  p->addr_in.sin_port;

	msg.in_n = htonll(p->in_n);
	msg.out_n = htonll(p->out_n);

	if (p->state_usec != 0)
		msg.age_sec = htonl(GS_USEC_TO_SEC(gopt.usec_now - p->state_usec));

	if (pl_id == PEER_L_CONNECTED)
	{
		GS_format_bps(msg.bps, sizeof msg.bps, PEER_get_bps(p), NULL);
	}	

	if (*first_call_ptr == 1)
	{
		*first_call_ptr = 0;
		msg.flags |= GSRN_FL_CLI_LIST_START;
	}


	memset(&msg.flagstr, '-', sizeof msg.flagstr);
	if (p->flags & FL_PEER_IS_SAW_SSL_CLIENTHELO)
		msg.fl.ssl = 'S';
	uint8_t gpflags = p->gs_proto_flags;
	msg.fl.major = p->version_major;
	msg.fl.minor = p->version_minor;
	if (p->buddy != NULL)
	{
		if (p->buddy->flags & FL_PEER_IS_SAW_SSL_CLIENTHELO)
			msg.fl.ssl = 'S';
		gpflags |= p->buddy->gs_proto_flags;
		// Report the lowest of both version numbers to CLI.
		if (msg.fl.major > p->buddy->version_major)
		{
			msg.fl.major = p->buddy->version_major;
			msg.fl.minor = p->buddy->version_minor;
		} else if (msg.fl.major == p->buddy->version_major) {
			msg.fl.minor = MIN(msg.fl.minor, p->buddy->version_minor);
		}
	}
	msg.fl.major += '0';
	msg.fl.minor += '0';

	if (gpflags & GS_FL_PROTO_WAIT)
		msg.fl.wait = 'W';
	if (gpflags & GS_FL_PROTO_CLIENT_OR_SERVER)
		msg.fl.x_client_or_server = 'X';
	if (gpflags & GS_FL_PROTO_FAST_CONNECT)
		msg.fl.low_latency = 'F';
	if (gpflags & GS_FL_PROTO_LOW_LATENCY)
		msg.fl.low_latency = 'L';

	uint32_t idle = 0;
	if (p->in_last_usec != 0)
		idle = MAX(0, GS_USEC_TO_SEC(gopt.usec_now - MAX(p->in_last_usec, p->out_last_usec)));
	msg.idle_sec = htonl(idle);

	if (p->buddy != NULL)
	{
		msg.buddy_ip = p->buddy->addr_in.sin_addr.s_addr;
		msg.buddy_port = p->buddy->addr_in.sin_port;
	}

	evbuffer_add(gopt.cli_out_evb, &msg, sizeof msg);
}


static void
cb_cli_list(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;

	DEBUGF_B("CLI requested LIST\n");
	if (gopt.cli_out_evb == NULL)
	{
		gopt.cli_out_evb = evbuffer_new();
		if (gopt.cli_out_evb == NULL)
			return;
	}

	size_t sz = evbuffer_get_length(gopt.cli_out_evb);
	if (sz > 0)
		DEBUGF_R("Ohh, already %zu bytes in cli_out_evb\n", sz); // CAN NOT HAPPEN

	gopt.usec_now = GS_usec();
	// Gather data (to gopt.evb_cli_out)
	int first_call = 1;
	PEERS_walk(cb_peers_list, &first_call);

	CLI_write(c, gopt.cli_out_evb);
}

static void
cb_free(struct _peer *p, void *arg)
{
	PEER_free(p, 0);
	*(int *)arg += 1;
}

static void
cb_cli_kill(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;
	struct _cli_kill msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	msg.addr = be128toh(msg.addr);
	msg.peer_id = ntohl(msg.peer_id);

	DEBUGF_B("CLI request KILL (len=%zu, id=%u addr=%s)\n", len, msg.peer_id, strx128x(msg.addr));

	int killed = 0;
	if (msg.peer_id == 0)
	{
		PEER_by_addr(msg.addr, cb_free, &killed);
		if (killed == 0)
			CLI_printf(c, "%s - No such address.", strx128x(msg.addr));
		else
			CLI_printf(c, "%d connections terminated.", killed);
	} else {
		CLI_printf(c, "ERR: killing by ID not yet supported!");

	}
}

#define CLI_BADOPCODE(_xc, _xop)       CLI_printf(_xc, "ERR: Unknown opcode (%u)", _xop)
static void
cb_cli_stop(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;
	struct _cli_stop msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	if (msg.opcode == GSRN_CLI_OP_STOP_LISTEN_TCP)
	{
		close_del_ev(&gopt.ev_listen);
		close_del_ev(&gopt.ev_listen_ssl);

		CLI_printf(c, "Stopped TCP port.");
		return;
	}

	CLI_BADOPCODE(c, msg.opcode);
}

static void
cb_cli_set(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;
	struct _cli_set msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	if (msg.opcode == GSRN_CLI_OP_SET_PROTO)
	{
		gd.min_version_major = msg.version_major;
		gd.min_version_minor = msg.version_minor;

		CLI_printf(c, "Minimum Protocol set to %u.%u", gd.min_version_major, gd.min_version_minor);
		return;
	}

	if (msg.opcode == GSRN_CLI_OP_SET_LOG_IP)
	{
		const char *str;
		gd.is_log_ip = msg.opvalue1;
		str = "enabled";
		if (msg.opvalue1 == 0)
			str = "disabled";

		CLI_printf(c, "IP Address logging %s", str);
		return;
	}

	CLI_BADOPCODE(c, msg.opcode);
}

// Called by server
static void
cb_accept_cli(int ls, short ev, void *arg)
{
	int sox;

	sox = fd_net_accept(ls);
	if (sox < 0)
		goto err;

	struct _cli *c;
	c = CLI_new(sox, NULL, 1 /*is_server*/);
	if (c == NULL)
		goto err;

	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_LIST, 0, cb_cli_list, c); // variable length message
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_KILL, sizeof (struct _cli_kill), cb_cli_kill, c); // Fixed length message
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_STOP, sizeof (struct _cli_stop), cb_cli_stop, c); // Fixed length message
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_SET, sizeof (struct _cli_set), cb_cli_set, c); // Fixed length message
	bufferevent_enable(c->bev, EV_READ);

	return;
err:
	XCLOSE(sox);
}


void
init_engine(void)
{
	// Start listening
	add_listen_sock(INADDR_ANY, gopt.port, &gopt.ev_listen, cb_accept);
	add_listen_sock(INADDR_ANY, gopt.port_ssl, &gopt.ev_listen_ssl, cb_accept_ssl);
	add_listen_sock(gopt.ip_cli, gopt.port_cli, &gd.ev_listen_cli, cb_accept_cli);
}