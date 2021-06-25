// Command Line Interface to configure gsrnd, retrieve status and log
// information.
// Linked against gsrnd and gsrn_cli

#include "common.h"
#include "utils.h"
#include "net.h"
#include "cli.h"
#include "packet.h"
#include "engine_cli.h"
#include "gopt.h"

void
cb_bev_read_cli(struct bufferevent *bev, void *arg)
{
	struct _cli *c = (struct _cli *)arg;
	DEBUGF("read\n");
	PKT_dispatch(&c->pkt, bufferevent_get_input(bev));
}

void
cb_bev_write_cli(struct bufferevent *bev, void *arg)
{
	struct _cli *c = (struct _cli *)arg;

	DEBUGF("write\n");
}

