
#ifndef __GSRN_PEER_H__
#define __GSRN_PEER_H__ 1

#include "packet.h"

// A binary tree contains a Peer-List-Manager (peer_l_mgr) at every node. Each pl-mgr contains
// multiple lists (for listening peers, waiting peers, ...). Each list is rooted at
// peer_l_root. The peer can only be in 1 of the lists at the same time (the same
// TAILQ_ENTRY(_peer, ll) is used for all lists).
//
// Use PEER_L_mv() to move peer to a list (e.g. from 'listening' to connected etc)

typedef enum
{
	PEER_L_LISTENING      = 0,   // Waiting for client
	PEER_L_WAITING        = 1,   // Client waiting for listening server
	PEER_L_WAIT_ACCEPT    = 2,   // Waiting for peer to send 'ACCEPT'
	PEER_L_ACCEPTED       = 3,   // ACCEPT received.
	PEER_L_CONNECTED      = 4
} peer_l_id_t;
#define MAX_LISTS_BY_ADDR     (5)

struct _peer_l_root
{
	int n_entries;
	struct _peer_l_mgr *pl_mgr;
	TAILQ_HEAD(_listhead, _peer) head;
};

struct _peer_l_mgr
{
	int n_entries;
	uint128_t addr;
	struct event *evt_linger;    // Timeout to free gsocket-listen block (matching token)
	struct event *evt_shortwait; // Delete waiting peers who are FL_PEER_IS_SHOTWAIT
	uint8_t token[GS_TOKEN_SIZE];
	int flags;
	struct _peer_l_root plr[MAX_LISTS_BY_ADDR];	
};

#define FL_PL_IS_TOKEN_SET   (0x01)

struct _peer
{
	SSL *ssl;
	int fd;
	uint64_t id;
	uint128_t addr;
	struct bufferevent *bev;
	PKT pkt;
	uint8_t token[GS_TOKEN_SIZE]; // might not need this here..
	int flags;

	struct _peer_l_root *plr;
	TAILQ_ENTRY(_peer) ll;        // linked entries.

	struct _peer *buddy;
};

#define FL_PEER_IS_SERVER         (0x01)
#define FL_PEER_IS_CLIENT         (0x02)
#define FL_PEER_IS_ACCEPT_RECV    (0x04)  // Peer sent ACCEPTT after _gs_start msg
#define FL_PEER_IS_GOODBYE        (0x08)  // PEER_goodbye was called.
#define FL_PEER_IS_EOF_RECEIVED   (0x10)
#define FL_PEER_IS_SHORTWAIT      (0x20)

#define PEER_IS_SERVER(p)           ((p)->flags & FL_PEER_IS_SERVER)
#define PEER_IS_CLIENT(p)           ((p)->flags & FL_PEER_IS_CLIENT)
#define PEER_IS_ACCEPT_RECEIVED(p)  ((p)->flags & FL_PEER_IS_ACCEPT_RECV)
#define PEER_IS_GOODBYE(p)          ((p)->flags & FL_PEER_IS_GOODBYE)
#define PEER_IS_EOF_RECEIVED(p)     ((p)->flags & FL_PEER_IS_EOF_RECEIVED)
#define PEER_IS_SHORTWAIT(p)        ((p)->flags & FL_PEER_IS_SHORTWAIT)

// Return S, C or - for Server, Client or Unknown (used by DEBUGF)
#define IS_CS(p)   (p)->flags & FL_PEER_IS_SERVER?'S':(p)->flags & FL_PEER_IS_CLIENT?'C':'-'

void PEER_goodbye(struct _peer *p);
int PEER_add(struct _peer *p, peer_l_id_t pl_id);
void PEER_free(struct _peer *p);
struct _peer *PEER_new(int fd, SSL *ssl);

#define PEER_L_get_id(p)    ((p)->plr - &(p)->plr->pl_mgr->plr[0])
#define PEER_L_get_mgr(p)   (p)->plr->pl_mgr

void PEER_L_mv(struct _peer *p, peer_l_id_t pl_id);

struct _peer *PEER_get(uint128_t addr, peer_l_id_t pl_id, struct _peer_l_mgr **pl_mgr_ptr);
#define PEER_get_listening(addr)   PEER_get(addr, PEER_L_LISTENING, NULL)
#define PEER_get_waiting(addr)     PEER_get(addr, PEER_L_WAITING, NULL)

#endif // !__GSRN_PEER_H__