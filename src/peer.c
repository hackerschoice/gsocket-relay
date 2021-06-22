#include "common.h"
#include "gsrnd.h"
#include "engine.h"
#include "packet.h"
#include "utils.h"
#include "protocol.h"
#include "peer.h"
#include "gopt.h"

static char *peer_l_names[MAX_LISTS_BY_ADDR] = {
	"LISTENING  ",
	"WAITING    ",
	"WAIT-ACCEPT",
	"ACCEPTED   ",
	"CONNECTED  "
};

static void
tree_stats(void)
{
	int i;

	DEBUGF("Tree Stats (%d nodes)\n", gopt.t_peers.n_nodes);
	for (i = 0; i < MAX_LISTS_BY_ADDR; i++)
	{
		DEBUGF("LIST-ID=#%d(%s)  Entries=%d  Unique=%d\n", i, peer_l_names[i], gopt.t_peers.n_entries[i], gopt.t_peers.n_uniq[i]);
	}
}

static void
cb_t_peer_printall(const void *nodep, const VISIT which, const int depth)
{
	struct _peer *p;

	switch (which)
	{
		case postorder:
		case leaf:
			break;
		case preorder:
		case endorder:
			return;
	}

	if ((nodep == NULL) || (*(struct _peer_l_mgr **)nodep == NULL))
		return;

	struct _peer_l_mgr *pl_mgr;
	pl_mgr = *(struct _peer_l_mgr **)nodep;

	char valstr[64];
	int i;
	for (i = 0; i < MAX_LISTS_BY_ADDR; i++)
	{
		struct _peer_l_root *plr;
		plr = &pl_mgr->plr[i];
		DEBUGF("List-#%d(%s) (%d entries):\n", i, peer_l_names[i], plr->n_entries);
		LIST_FOREACH(p, &plr->head, ll)
			DEBUGF("  [%"PRIu64"] %c addr=%s\n", p->id, IS_CS(p), strx128(p->addr, valstr, sizeof valstr));
	}
}

// Each leaf is a double linked list of peer entries.
int
cb_t_peer_by_addr(const void *a, const void *b)
{
	struct _peer_l_mgr *pla = (struct _peer_l_mgr *)a;
	struct _peer_l_mgr *plb = (struct _peer_l_mgr *)b;

	if (pla->addr < plb->addr)
		return -1;

	if (pla->addr > plb->addr)
		return 1; // tree right

	return 0; // (found/exists)
}

// A little hack to make insertion faster when list
// does not exists.
int
cb_t_peer_find(const void *needle_a, const void *stack_b)
{
	struct _peer_l_mgr *pl_mgr_b = (struct _peer_l_mgr *)stack_b;
	uint128_t *addr_a = (uint128_t *)needle_a;

	// char val[64]; DEBUGF_C("looking for %s @ %p\n", strx128(*addr_a, val, sizeof val), stack_b);

	if (*addr_a < pl_mgr_b->addr)
		return -1;

	if (*addr_a > pl_mgr_b->addr)
		return 1; // tree right

	return 0; // (found/exists)

}

static int
pl_link(struct _peer_l_mgr *pl_mgr, struct _peer *p, peer_l_id_t pl_id)
{
	struct _peer_l_root *plr = &pl_mgr->plr[pl_id];
	struct _peer *fp;
	fp = LIST_FIRST(&plr->head);
	if (pl_id == PEER_L_LISTENING)
	{
		if (fp != NULL)
		{
			if (memcmp(fp->token, p->token, sizeof fp->token) != 0)
			{
				DEBUGF_R("BAD TOKEN\n");
				return -1; // Bad Token
			}
		}
	}

	// First time we add something to this list...
	if (fp == NULL)
		gopt.t_peers.n_uniq[pl_id] += 1;

	LIST_INSERT_HEAD(&plr->head, p, ll);
	plr->n_entries += 1;
	pl_mgr->n_entries += 1;
	gopt.t_peers.n_entries[pl_id] += 1;

	p->plr = plr;

	return 0;
}


static struct _peer_l_mgr *
peer_find_mgr(uint128_t *addr)
{
	void *vptr;

	vptr = tfind(addr, &gopt.t_peers.tree, cb_t_peer_find);
	if (vptr == NULL)
		return NULL;

	return *(struct _peer_l_mgr **)vptr;
}

static struct _peer_l_root *
peer_find_root(uint128_t *addr, peer_l_id_t pl_id)
{
	struct _peer_l_mgr *pl_mgr;

	pl_mgr = peer_find_mgr(addr);
	if (pl_mgr == NULL)
		return NULL;

	struct _peer_l_root *plr;
	plr = &pl_mgr->plr[pl_id];
	if (LIST_EMPTY(&plr->head))
		return NULL;

	return plr;
}

// Add a Peer by peer->addr to a double-linked list which is
// linked to a binary tree
int
PEER_add(struct _peer *p, peer_l_id_t pl_id)
{
	struct _peer_l_mgr *pl_mgr = NULL;

	XASSERT(p->plr == NULL, "Oops. Peer already in a linked list\n");
	pl_mgr = peer_find_mgr(&p->addr);

	if (pl_mgr == NULL)
	{
		// HERE: New leaf in binary tree
		DEBUGF("Creating a new linked list. (list-mgr=%p, list=%d) tree=%p\n", pl_mgr, pl_id, gopt.t_peers.tree);

		pl_mgr = calloc(1, sizeof (struct _peer_l_mgr));
		pl_mgr->addr = p->addr;
		int i;
		for (i = 0; i < MAX_LISTS_BY_ADDR; i++)
		{
			LIST_INIT(&pl_mgr->plr[i].head);
			pl_mgr->plr[i].pl_mgr = pl_mgr;
		}

		tsearch(pl_mgr, &gopt.t_peers.tree, cb_t_peer_by_addr);  // Add to binary tree
		gopt.t_peers.n_nodes += 1;
	} else {
		// HERE: Existing linked list (peer with same addr already exists)
		DEBUGF_W("Using existing list-mgr=%p. Already has %d entries\n", pl_mgr, pl_mgr->n_entries);
	}
	int ret;
	ret = pl_link(pl_mgr, p, pl_id);
	if (ret != 0)
		return ret; // Bad Token;

	return 0;
}

// Unlink from list (but do not remove binary tree entry
static void
pl_unlink(struct _peer *p)
{
	peer_l_id_t pl_id = PEER_L_get_id(p);
	struct _peer_l_mgr *pl_mgr = PEER_L_get_mgr(p);
	p->plr->n_entries -= 1;
	LIST_REMOVE(p, ll);

	if (LIST_EMPTY(&p->plr->head))
		gopt.t_peers.n_uniq[pl_id] -= 1;

	pl_mgr->n_entries -= 1;

	gopt.t_peers.n_entries[pl_id] -= 1;
}

// Move from 1 list to another or add if currently in no list.
void
PEER_L_mv(struct _peer *p, peer_l_id_t pl_id)
{
	if (p->plr == NULL)
	{
		DEBUGF_R("WARN: Peer is not in any list yet. Adding to %d...\n", pl_id);
		PEER_add(p, pl_id);
		return;
	}

	// Check if already in correct list.
	if (PEER_L_get_id(p) == pl_id)
		return;

	// Remove from current list.
	pl_unlink(p);

	// Add to new list
	pl_link(p->plr->pl_mgr, p, pl_id);
}

// Return oldest listening peer.
struct _peer *
PEER_get(uint128_t addr, peer_l_id_t pl_id)
{
	struct _peer_l_root *plr;

	plr = peer_find_root(&addr, pl_id);
	if (plr == NULL)
		return NULL;

	return (struct _peer *)LIST_FIRST(&plr->head); // FIXME> use TAILQ instead
}


// Remove peer from double linked list and if this is the last peer then also
// remove the list-root from the binary tree.
static void
peer_t_del(struct _peer *p)
{
	if ((p == NULL) || (p->plr == NULL))
		return; // Not in any list

	pl_unlink(p);
	struct _peer_l_mgr *pl_mgr = PEER_L_get_mgr(p);

	if (pl_mgr->n_entries <= 0)
	{
		char val[64];
		DEBUGF_C("This was the last peer with addr=%s\n", strx128(p->addr, val, sizeof val));
		tdelete(pl_mgr, &gopt.t_peers.tree, cb_t_peer_by_addr);
		gopt.t_peers.n_nodes -= 1;
		XFREE(pl_mgr);
	}

	p->plr = NULL;
}


// When there are no pending data in the 'out' buffer then free the peer now.
// Otherwise give I/O time to send the data to the peer and free peer when
// a. all data has been written (in cb_bev_write)
// b. the write timeout has expired (in cb_bev_status)
void
PEER_goodbye(struct _peer *p)
{
	struct evbuffer *out = bufferevent_get_output(p->bev);
	size_t sz;

	// Remove myself from lists. No longer available to any GS-messages
	peer_t_del(p);

	sz = evbuffer_get_length(out);

	if (sz <= 0)
	{
		PEER_free(p);
		return;
	}

	DEBUGF("%zu bytes left to write\n", sz);
	p->flags |= FL_PEER_IS_GOODBYE;
	bufferevent_set_timeouts(p->bev, NULL, GSRN_FLUSH_TV_TIMEOUT);
	bufferevent_enable(p->bev, EV_WRITE);
	PKT_set_void(&p->pkt);
}

void
PEER_free(struct _peer *p)
{
	DEBUGF_G("%s peer=%p\n", __func__, p);
	tree_stats();

#ifdef DEBUG
	twalk(gopt.t_peers.tree, cb_t_peer_printall);
#endif

	// Remove myself from lists
	peer_t_del(p);

	size_t sz = evbuffer_get_length(bufferevent_get_output(p->bev));
	if (sz > 0)
		DEBUGF_R("WARN: Free'ing peer with %zu left in output buffer\n", sz);
	XBEV_FREE(p->bev);

	// Unlink myself from my buddy
	if (p->buddy)
	{
		p->buddy->buddy = NULL;
		PEER_free(p->buddy); // Disconnect my buddy.
	}

	XCLOSE(p->fd);
	XFREE(p);
}

struct _peer *
PEER_new(int fd, SSL *ssl)
{
	struct _peer *p;

	p = calloc(1, sizeof *p);
	if (p == NULL)
	{
		// FIXME: Log this failure
		return NULL;
	}

	PKT_init(&p->pkt);

	// Assign a uniq PEER id to each instance (start with 1)
	gopt.peer_id += 1;
	p->id = gopt.peer_id;

	p->fd = fd;

	int ev_opt = BEV_OPT_DEFER_CALLBACKS;
	DEBUGF_W("fd=%d\n", fd);
	if (ssl != NULL)
	{
		p->ssl = ssl;
		SSL_set_fd(p->ssl, fd);
		p->bev = bufferevent_openssl_socket_new(gopt.evb, -1, p->ssl, BUFFEREVENT_SSL_ACCEPTING, ev_opt);
	} else {
		p->bev = bufferevent_socket_new(gopt.evb, fd, ev_opt);
	}

	bufferevent_setcb(p->bev, cb_bev_read, cb_bev_write /*NULL*/, cb_bev_status, p);
	struct timeval to = {GSRN_1STMSG_TIMEOUT, 0};
	bufferevent_set_timeouts(p->bev, &to /*read*/, NULL /*write*/);

	if (ssl == NULL)
		cb_bev_status(p->bev, BEV_EVENT_CONNECTED, p); // Immediately go into 'connected' state

	GSRN_change_state(p, GSRN_STATE_INIT);

	if (ssl != NULL)
	{
		// When using SSL then also allow auth
		// PKT_setcb(&p->pkt, GS_PKT_TYPE_AUTH, 0 /*variable length*/, p);
	}

	return p;
}


