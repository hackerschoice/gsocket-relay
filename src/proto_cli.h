#ifndef __GSRN_PROTO_CLI_H__
#define __GSRN_PROTO_CLI_H__ 1

#include "peer.h"

struct _cli_hdr_tlv
{
	// As per packet.h
	uint8_t type;      // GSRN_CLI_TYPE_*
	uint16_t len;      // Only used for variable length
	char payload[0];
} __attribute__((__packed__));

struct _cli_hdr_fixed
{
	uint8_t type;      // GSRN_CLI_TYPE_*
	char payload[0];
} __attribute__((__packed__));

struct _cli_msg
{
	struct _cli_hdr_tlv hdr;
	char msg[0];
} __attribute__((__packed__));

struct _cli_log
{
	struct _cli_hdr_tlv hdr;
	char msg[0];
} __attribute__((__packed__));

struct _cli_shutdown
{
	struct _cli_hdr_fixed hdr;
	uint8_t opcode;
	uint8_t reserved[3];
	uint32_t timer_sec;
} __attribute__((__packed__));

struct _cli_kill
{
	struct _cli_hdr_fixed hdr;
	uint32_t peer_id;
	uint128_t addr;
} __attribute__((__packed__));

struct _cli_list
{
	struct _cli_hdr_fixed hdr;
	uint32_t peer_id;
	uint128_t addr;
	uint8_t opcode;
} __attribute__((__packed__));
#define GSRN_CLI_OP_LIST_ESTAB           (0x01)
#define GSRN_CLI_OP_LIST_LISTEN          (0x02)

struct _cli_stop
{
	struct _cli_hdr_fixed hdr;
	uint32_t peer_id;
	uint128_t addr;
	uint8_t opcode;
} __attribute__((__packed__));
#define GSRN_CLI_OP_STOP_LISTEN_TCP      (0x01)

struct _cli_set
{
	struct _cli_hdr_fixed hdr;
	uint32_t peer_id;
	uint128_t addr;
	uint8_t opcode;
	uint8_t opvalue1;
	uint8_t opvalue2; // NOT USED
	uint8_t version_major;
	uint8_t version_minor;
	uint16_t port;
} __attribute__((__packed__));
#define GSRN_CLI_OP_SET_PROTO          (0x01)
#define GSRN_CLI_OP_SET_LOG_IP         (0x02)
#define GSRN_CLI_OP_SET_PORT_CLI       (0x03)
#define GSRN_CLI_OP_SET_LOG_VERBOSITY  (0x04)

struct _cli_stats
{
	struct _cli_hdr_fixed hdr;
	uint8_t opcode;
	uint8_t flags;
} __attribute__((__packed__));
#define GSRN_CLI_OP_STATS_RESET        (0x01)

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
	struct _cli_hdr_fixed hdr;
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

// 'stats' response
struct _cli_stats_r
{
	struct _cli_hdr_fixed hdr;
	uint64_t uptime_usec;            // GSRND uptime
	uint64_t since_reset_usec;       // Since last stats reset
	uint64_t n_gs_connect;
	uint64_t n_gs_listen;
	uint64_t n_bad_auth;
	uint64_t n_gs_refused;

	uint32_t n_peers_total;
	uint32_t n_peers_listening;
	uint32_t n_peers_connected;
} __attribute__((__packed__));

#define GSRN_CLI_HDR_TLV_SIZE         (sizeof (struct _cli_hdr_tlv))
#define GSRN_CLI_PAYLOAD_SIZE(xmsg)   (sizeof xmsg - GSRN_CLI_HDR_TLV_SIZE)

#define GSRN_FL_CLI_LIST_START        (0x01)

///////////// CLI TYPE definitions
#define GSRN_CLI_TYPE_LIST_RESPONSE   (0x01)  // s2c - response (to list request)
#define GSRN_CLI_TYPE_LOG             (0x02)  // s2c - log message
#define GSRN_CLI_TYPE_MSG             (0x04)  // s2c - message (to display)
#define GSRN_CLI_TYPE_STATS_RESPONSE  (0x09)  // s2c - stats response

#define GSRN_CLI_TYPE_LIST            (0x01)  // c2s - list all connected clients
#define GSRN_CLI_TYPE_KILL            (0x03)  // c2s - Kill a session (by ID or ADDR)
#define GSRN_CLI_TYPE_STOP            (0x05)  // c2s - stop listening tcp/gsocket
#define GSRN_CLI_TYPE_SET             (0x06)  // c2s - set a variable (config)
#define GSRN_CLI_TYPE_SHUTDOWN        (0x07)  // c2s - Shut all GS-Listeners 
#define GSRN_CLI_TYPE_STATS           (0x08)  // c2s - Request stats

#endif // !__GSRN_PROTO_CLI_H__
