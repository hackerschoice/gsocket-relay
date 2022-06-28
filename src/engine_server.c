// Only linked against gsrnd
#include "common.h"
#include "gsrnd.h"
#include "utils.h"
#include "cli.h"
#include "net.h"
#include "engine.h"
#include "engine_cli.h"
#include "gopt.h"

struct _gstats gstats;

struct _cli_list_param
{
	int n;
	uint8_t opcode;
};

struct _cli_shutdown_param
{
	uint32_t timer_sec;
	uint32_t n_shutdown;
	uint32_t n_notlistening;
};

static void cb_accept_cli(int ls, short ev, void *arg);
static void gsrn_stats_init(void);
static void gsrn_stats_reset(void);

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
cb_peers_shutdown(struct _peer *p, struct _peer_l_root *plr, void *arg)
{
	struct _cli_shutdown_param *param = (struct _cli_shutdown_param *)arg;
	if ((p == NULL) || (plr == NULL))
		return;

	peer_l_id_t pl_id = PLR_L_get_id(plr);
	if (pl_id != PEER_L_LISTENING)
	{
		param->n_notlistening += 1;
		return;
	}

	// HERE: peer is LISTENING
	GS_LOG_VV("[%6u] %32s Shutdown", p->id, GS_addr128hex(NULL, p->addr));
	param->n_shutdown += 1;
	PEER_goodbye(p);	
}

static void
cb_peers_list(struct _peer *p, struct _peer_l_root *plr, void *arg)
{
	struct _cli_list_param *param = (struct _cli_list_param *)arg;
	if (p == NULL)
	{
		if (plr == NULL)
			return;

		DEBUGF("List-#%ld(%s) (%d entries):\n", PLR_L_get_id(plr), PEER_L_name(PLR_L_get_id(plr)), plr->n_entries);
		return;
	}

	DEBUGF("  [%u] %c addr=%s\n", p->id, IS_CS(p), strx128x(p->addr));

	peer_l_id_t pl_id = PLR_L_get_id(plr);
	if (param->opcode == GSRN_CLI_OP_LIST_BAD)
	{
		if (pl_id != PEER_L_BAD_AUTH)
			return;
	} else if (param->opcode == GSRN_CLI_OP_LIST_ESTAB) {
		if (pl_id != PEER_L_CONNECTED)
			return;
		if (!PEER_IS_SERVER(p))
			return;
	} else if (param->opcode == GSRN_CLI_OP_LIST_LISTEN) {
		if (pl_id != PEER_L_LISTENING)
			return;
	} else if (param->opcode == 0) {
		// ALL
		if (pl_id == PEER_L_CONNECTED)
		{
			// Do not show connected client (as we already show the connected buddy)
			if (!PEER_IS_SERVER(p))
				return;
		}
	} else {
		DEBUGF("SHOULD NOT HAPPEN\n");
		return;
	}

	DEBUGF_W("Sending peer-id %d\n", p->id);
	struct _cli_list_r msg;
	memset(&msg, 0, sizeof msg);
	msg.hdr.type = GSRN_CLI_TYPE_LIST_RESPONSE;
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

	if (param->n == 0)
	{
		msg.flags |= GSRN_FL_CLI_LIST_START;
	}
	param->n += 1;

	memset(&msg.flagstr, '-', sizeof msg.flagstr);
	if (p->flags & FL_PEER_IS_SAW_SSL_HELO)
		msg.fl.ssl = 'S';
	uint8_t gpflags = p->gs_proto_flags;
	msg.fl.major = p->version_major;
	msg.fl.minor = p->version_minor;
	if (p->buddy != NULL)
	{
		if (p->buddy->flags & FL_PEER_IS_SAW_SSL_HELO)
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
		msg.fl.fast_connect = 'F';
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
cb_cli_shutdown(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;
	struct _cli_shutdown msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	DEBUGF_B("CLI Shutdown received (timer=%usec)\n", msg.timer_sec);

	// Disconnect all listening peers.
	struct _cli_shutdown_param p;
	memset(&p, 0, sizeof p);
	p.timer_sec = msg.timer_sec;
	PEERS_walk(cb_peers_shutdown, &p);

	// Mark to terminate when last ESTABLISHED GS connction finishes?
	// NO: Do not self-terminate. Instead let GSRND linger
	// around doing nothing. If we would self-terminate here then systemd would
	// try to restart us - which is not what we want. Wait for GSRND to be shut down
	// by systemctl instead.

	CLI_printf(c, "%u peers shut down (LISTENING).", p.n_shutdown);
	if (p.n_notlistening > 0)
		CLI_printf(c, "WARNING: %u peers still connected (not LISTENING)",p.n_notlistening);
}

static void
cb_cli_list(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;
	struct _cli_list msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	DEBUGF_B("CLI requested LIST (opcode=%2.2x)\n", msg.opcode);
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
	struct _cli_list_param p;
	memset(&p, 0, sizeof p);
	p.opcode = msg.opcode;
	// Gather data (to gopt.evb_cli_out)
	PEERS_walk(cb_peers_list, &p);

	CLI_write(c, gopt.cli_out_evb);
	// CLI_printf() will also trigger a new prompt on cli side.
	CLI_printf(c, "Total %d", p.n);
}

static void
cb_free(struct _peer *p, void *arg)
{
	PEER_free(p);
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
		// HERE: By GS-ADDRESS
		PEER_by_addr(msg.addr, cb_free, &killed);
		if (killed == 0)
			CLI_printf(c, "%s - No such address.", strx128x(msg.addr));
		else
			CLI_printf(c, "%d connections terminated.", killed);
	} else {
		// HERE: By PEER-ID
		CLI_printf(c, "ERR: killing by ID not yet supported!");

	}
}

static void
cb_cli_stats(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;
	struct _cli_stats msg;
	uint64_t usec_now = GS_usec();

	DEBUGF("stats request\n");
	evbuffer_remove(eb, &msg, sizeof msg);

	struct _cli_stats_r r;
	memset(&r, 0, sizeof r);

	r.hdr.type = GSRN_CLI_TYPE_STATS_RESPONSE;
	r.uptime_usec = usec_now - gstats.start_usec;
	r.since_reset_usec = usec_now - gstats.reset_usec;
	r.n_gs_connect = gstats.n_gs_connect;
	r.n_gs_listen = gstats.n_gs_listen;
	r.n_bad_auth = gstats.n_bad_auth;
	r.n_gs_refused = gstats.n_gs_refused;

	int i;
	for (i = 0; i < MAX_LISTS_BY_ADDR; i++)
	{
		if (i == PEER_L_CONNECTED)
			r.n_peers_total += gopt.t_peers.n_entries[i] / 2;
		else
			r.n_peers_total += gopt.t_peers.n_entries[i];
	}

	// CONNECTED holds 1 server and 1 client but for the purpose of counting
	// we treat this as '1 connection'.
	r.n_peers_connected = gopt.t_peers.n_entries[PEER_L_CONNECTED] / 2;
	r.n_peers_listening = gopt.t_peers.n_entries[PEER_L_LISTENING];

	if (msg.opcode == GSRN_CLI_OP_STATS_RESET)
	{
		gsrn_stats_reset();
		gstats.reset_usec = usec_now;
	}

	DEBUGF("senidng %zd\n", sizeof r);
	CLI_msg(c, &r, sizeof r);
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

	if (msg.opcode == GSRN_CLI_OP_SET_LOG_VERBOSITY)
	{
		CLI_printf(c, "Log verbosity set from %d to %d", gopt.verbosity, msg.opvalue1);
		gopt.verbosity = msg.opvalue1;
		return;
	}

	if (msg.opcode == GSRN_CLI_OP_SET_PORT_CLI)
	{
		DEBUGF("Changing CLI port to %u\n", msg.port);
		close_del_ev(&gd.ev_listen_cli);
		gopt.port_cli = msg.port;
		add_listen_sock(gopt.ip_cli, gopt.port_cli, &gd.ev_listen_cli, cb_accept_cli);
		CLI_printf(c, "CLI listening on port %u", gopt.port_cli);
		return;
	}

	CLI_BADOPCODE(c, msg.opcode);
}

// Called by server
static void
cb_accept_cli(int ls, short ev, void *arg)
{
	int sox;

	fd_limit_unlimited();
	sox = fd_net_accept(ls);
	fd_limit_limited();

	if (sox < 0)
		goto err;

	struct _cli *c;
	c = CLI_new(sox, NULL, 1 /*is_server*/);
	if (c == NULL)
		goto err;

	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_LIST, sizeof (struct _cli_list), cb_cli_list, c);
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_KILL, sizeof (struct _cli_kill), cb_cli_kill, c);
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_STOP, sizeof (struct _cli_stop), cb_cli_stop, c);
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_SET, sizeof (struct _cli_set), cb_cli_set, c);
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_SHUTDOWN, sizeof (struct _cli_shutdown), cb_cli_shutdown, c);
	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_STATS, sizeof (struct _cli_stats), cb_cli_stats, c);
	bufferevent_enable(c->bev, EV_READ);

	return;
err:
	XCLOSE(sox);
}

static void
gsrn_stats_init(void)
{
	memset(&gstats, 0, sizeof gstats);
	gstats.start_usec = GS_usec();
	gstats.reset_usec = gstats.start_usec;
}

static void
gsrn_stats_reset(void)
{
	uint64_t usec;

	usec = gstats.start_usec;
	memset(&gstats, 0, sizeof gstats);
	gstats.start_usec = usec;
	gstats.reset_usec = GS_usec();
}

void
init_engine(void)
{
	gsrn_stats_init();

	// Raise FD Limit but keep it just below Hard-Limit (ulimit -Hn) and keep
	// those few reserved for CLI port connections:
	struct rlimit *r = (struct rlimit *)&gopt.rlim_fd;
	if (fd_limit_init() != 0)
		ERREXIT("getrlimit()=%s\n", strerror(errno));
	if (r->rlim_max <= 1024)
		GS_LOG("WARNING: Max fd limit is %lu", r->rlim_max);
	GS_LOG("File descriptor limit set to %lu+%d (was %lu)", r->rlim_max - GSRN_FD_RESERVE, GSRN_FD_RESERVE, r->rlim_cur);
	if (fd_limit_limited() != 0)
		ERREXIT("setrlimit()=%s\n", strerror(errno));;

	// Start listening
	add_listen_sock(INADDR_ANY, gopt.port, &gopt.ev_listen, cb_accept);
	add_listen_sock(INADDR_ANY, gopt.port_ssl, &gopt.ev_listen_ssl, cb_accept_ssl);
	add_listen_sock(gopt.ip_cli, gopt.port_cli, &gd.ev_listen_cli, cb_accept_cli);
}