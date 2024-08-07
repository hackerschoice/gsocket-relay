
#ifndef __GSRN_GOPT_H__
#define __GSRN_GOPT_H__ 1

#include "peer.h"
#include "utils.h"


struct _tree_mgr
{
	int n_nodes;
	// e.g. A single list can have >1 peers listening
	int n_entries[MAX_LISTS_BY_ADDR]; // Total Listening/Waiting/Connected
	// e.g. Record how many (different) addr are listening
	int n_uniq[MAX_LISTS_BY_ADDR];    // Uniq
	void *tree;
	// peers_walk() will call *func for each peer in the binary-tree.
	walk_peers_func_t walk_peers_func;
	void *walk_peers_func_arg;
};

struct _gopt
{
	prg_t prg;               // GSRND or CLI
	FILE *err_fp;
	FILE *log_fp;
	SSL_CTX *ssl_ctx;
	uint32_t ip_cli;         // 127.0.0.1
	uint16_t port_cli;       // Only used by gsrn_cli.c
	uint16_t port_cnc;       // Concentrator port (no SSL)
	uint32_t ip_cnc;         // IP of concentrator

	struct _port_listhead ports_head;
	struct _port_listhead ports_cli_head;

	int verbosity;
	uint32_t flags;
	struct event_base *evb;      // libevent base
	// struct event *ev_listen;      // Listening socket event
	// struct event *ev_listen_ssl;  // Listening socket event
	struct event *ev_listen_con;  // Listening socket event
	int is_concentrator;
	struct rlimit rlim_fd;

	uint64_t usec_now;
	// binary trees for listening and waiting peers.
	struct _tree_mgr t_peers;

	// CLI output buffer
	struct evbuffer *cli_out_evb;
};
#define GSR_FL_LOGSTREAM     (0x01)

// Server (daemon) globals
struct _gd
{
	struct event *ev_listen_cli;
	// Unique ID (like PID) for linked-list entries
	uint32_t peer_id;
	int is_log_ip;
	// Minimum accepted protocol version
	uint8_t min_version_major;
	uint8_t min_version_minor;
};

#endif // !__GSRN_GOPT_H__
