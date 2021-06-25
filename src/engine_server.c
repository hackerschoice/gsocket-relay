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

		peer_l_id_t pl_id;
		pl_id = PLR_L_get_id(plr);
		DEBUGF("List-#%d(%s) (%d entries):\n", pl_id, PEER_L_name(pl_id), plr->n_entries);
		return;
	}

	char valstr[64]; DEBUGF("  [%u] %c addr=%s\n", p->id, IS_CS(p), strx128(p->addr, valstr, sizeof valstr));

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
		msg.flags |= GSRN_FL_CLI_LIST_FIRSTCALL;
	}
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

	PKT_setcb(&c->pkt, GSRN_CLI_TYPE_LIST, 0, cb_cli_list, c);
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