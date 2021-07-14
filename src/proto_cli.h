#ifndef __GSRN_PROTO_CLI_H__
#define __GSRN_PROTO_CLI_H__ 1

#include "peer.h"

struct _cli_hdr
{
	uint8_t type;
	uint16_t len;
	char payload[0];
} __attribute__((__packed__));

struct _cli_req
{
	struct _cli_hdr hdr;
	char opt[0];
} __attribute__((__packed__));

struct _cli_msg
{
	struct _cli_hdr hdr;
	char msg[0];
} __attribute__((__packed__));

struct _cli_log
{
	struct _cli_hdr hdr;
	char msg[0];
} __attribute__((__packed__));

struct _cli_kill
{
	struct _cli_hdr hdr;
	uint32_t peer_id;
	uint128_t addr;
} __attribute__((__packed__));

struct _cli_stop
{
	struct _cli_hdr hdr;
	uint32_t peer_id;
	uint128_t addr;
	uint8_t opcode;
} __attribute__((__packed__));
#define GSRN_CLI_OP_STOP_LISTEN_TCP      (0x01)

struct _cli_set
{
	struct _cli_hdr hdr;
	uint32_t peer_id;
	uint128_t addr;
	uint8_t opcode;
	uint8_t opvalue1;
	uint8_t opvalue2;
	uint8_t version_major;
	uint8_t version_minor;
} __attribute__((__packed__));

#define GSRN_CLI_OP_SET_PROTO          (0x01)
#define GSRN_CLI_OP_SET_LOG_IP         (0x02)

///////////// CLI responses

struct _flagstr
{
	uint8_t ssl;
	uint8_t x_client_or_server;
	uint8_t fast_connect;
	uint8_t low_latency;
	uint8_t wait;
	uint8_t major;
	uint8_t minor;
};

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
	uint8_t flags;           // GSRN_FL_CLI_LIST_START
	union {
		uint8_t flagstr[7];
		struct _flagstr fl;
	};
} __attribute__((__packed__));

#define GSRN_CLI_HDR_SIZE             (sizeof (struct _cli_hdr))
#define GSRN_CLI_PAYLOAD_SIZE(xmsg)   (sizeof xmsg - GSRN_CLI_HDR_SIZE)

#define GSRN_FL_CLI_LIST_START        (0x01)

#define GSRN_CLI_TYPE_LIST_RESPONSE   (0x01)  // s2c - response (to list request)
#define GSRN_CLI_TYPE_LOG             (0x02)  // s2c - log message
#define GSRN_CLI_TYPE_MSG             (0x04)  // s2c - message (to display)

#define GSRN_CLI_TYPE_LIST            (0x01)  // c2s - list all connected clients
#define GSRN_CLI_TYPE_KILL            (0x03)  // c2s - Kill a session (by ID or ADDR)
#define GSRN_CLI_TYPE_STOP            (0x05)  // c2s - stop listening tcp/gsocket
#define GSRN_CLI_TYPE_SET             (0x06)  // c2s - set a variable (config)

#endif // !__GSRN_PROTO_CLI_H__
