#ifndef __GSRN_PROTO_CLI_H__
#define __GSRN_PROTO_CLI_H__ 1

#include "peer.h"

struct _cli_req
{
	uint8_t type;
	uint16_t len;
	char opt[0];
} __attribute__((__packed__));

struct _cli_log
{
	uint8_t type;
	uint16_t len;
	char msg[0];
} __attribute__((__packed__));

///////////// CLI responses

// 'list' response
struct _cli_list_r
{
	uint8_t type;
	uint8_t con_type;  // TCP, SSL or CNC
	uint16_t port;

	uint32_t ip;

	uint64_t xfer_bytes;
	uint128_t addr;
	uint32_t peer_id;
	uint32_t buddy_ip;
	uint16_t buddy_port;
	uint64_t in_n;           // bytes FROM peer
	uint64_t out_n;          // bytes TO peer
	uint32_t idle_sec;       // Idle in seconds
	peer_l_id_t pl_id;       // Current state: LISTENING, WAITING, ...
	uint32_t age_sec;        // Age in sec in current state (LISTEN, WAITING, CONNECTED etc) 
	char bps[GS_BPS_MAXSIZE];
	uint8_t flags;
} __attribute__((__packed__));

#define GSRN_FL_CLI_LIST_FIRSTCALL    (0x01)

#define GSRN_CLI_TYPE_LIST            (0x01)
#define GSRN_CLI_TYPE_LIST_RESPONSE   (0x01)
#define GSRN_CLI_TYPE_LOG             (0x02)

#endif // !__GSRN_PROTO_CLI_H__
