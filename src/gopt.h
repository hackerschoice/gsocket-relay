
#ifndef __GSRN_GOPT_H__
#define __GSRN_GOPT_H__ 1

struct _tree_mgr
{
	int n_nodes;
	// e.g. A single list can have >1 peers listening
	int n_entries[MAX_LISTS_BY_ADDR]; // Total Listening/Waiting/Connected
	// e.g. Record how many (different) addr are listening
	int n_uniq[MAX_LISTS_BY_ADDR];    // Uniq
	void *tree;
};

struct _gopt
{
	FILE *err_fp;
	SSL_CTX *ssl_ctx;
	uint16_t port;           // Edge port
	uint16_t port_ssl;       // Edge SSL port
	uint16_t port_con;       // Concentrator port (no SSL)
	uint32_t ip_con;         // IP of concentrator
	int verbosity;
	struct event_base *evb;      // libevent base
	struct event ev_listen;      // Listening socket event
	struct event ev_listen_ssl;  // Listening socket event
	struct event ev_listen_con;  // Listening socket event
	int is_concentrator;

	// binary trees for listening and waiting peers.
	struct _tree_mgr t_peers;

	// Linked Lists
	uint64_t peer_id;           // peer uniq id counter (PEER_new). Likd pid_t
};

#endif // !__GSRN_GOPT_H__