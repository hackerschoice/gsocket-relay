
#include "common.h"
#include "net.h"
#include "engine.h"
#include "gopt.h"

struct _gopt gopt;
struct _g_debug_ctx g_dbg_ctx;

const char *
strx128(uint128_t x, char *val, size_t sz)
{
	if (x >> 64 > 0)
		snprintf(val, sz, "%"PRIx64"%"PRIx64, INT128_HIGH(x), INT128_LOW(x));
	else
		snprintf(val, sz, "%"PRIx64, (uint64_t)x);

	return val;
}

void
init_defaults(void)
{
	gopt.err_fp = stderr;

	// Must ignore SIGPIPE. Epoll may signal that socket is ready for wiriting
	// but gets closed by remote before calling write().
	signal(SIGPIPE, SIG_IGN);

	gopt.port = GSRN_DEFAULT_PORT;
	gopt.port_ssl = GSRN_DEFAULT_PORT_SSL;
}


static void
add_listen_sock(int port, struct event *ev, event_callback_fn cb_func)
{
	if (port <= 0)
		return;

	int ls;
	int ret;
	ls = fd_new_socket(SOCK_STREAM);
	ret = fd_net_listen(ls, port);
	if (ret < 0)
	{
		// FIXME: Log this event
		DEBUGF("listen(%d): %s\n", port, strerror(errno));
		return;
	}

	event_assign(ev, gopt.evb, ls, EV_READ|EV_PERSIST, cb_func, NULL);
	event_add(ev, NULL);
}

void
init_vars(void)
{
	SSL_load_error_strings();
	SSL_library_init();
	gopt.ssl_ctx = SSL_CTX_new(TLS_server_method() /*SSLv23_client_method()*/);
	XASSERT(gopt.ssl_ctx != NULL, "Failed creating SSL context\n");
	
	if (gopt.port_ssl > 0)
	{
		// Dont explode when realloc buffers
		SSL_CTX_set_mode(gopt.ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	#ifdef DEBUG
		// For testing WANT_READ/WRITE we disable auto-retry. This will trigger
		// SSL to return if it wants to write (during SSL_read) even if
		// the underlying socket is available for writing. 
		SSL_CTX_set_mode(gopt.ssl_ctx, SSL_CTX_get_mode(gopt.ssl_ctx) & ~SSL_MODE_AUTO_RETRY);
	#endif

		// FIXME: Use certificate in memory if no file specified.
		if (!SSL_CTX_use_certificate_file(gopt.ssl_ctx, "server.pem", SSL_FILETYPE_PEM)
	         || !SSL_CTX_use_PrivateKey_file(gopt.ssl_ctx, "server.pem", SSL_FILETYPE_PEM)
	         || !SSL_CTX_check_private_key(gopt.ssl_ctx))
		{
			fprintf(stderr, "Error setting up SSL_CTX. Try -P 0 to disable SSL support.\n");
			ERR_print_errors_fp(stderr);
			exit(1);
	 	}
	}

	gopt.evb = event_base_new();
	XASSERT(gopt.evb != NULL, "Could not initialize libevent!\n");

	// Start listening
	add_listen_sock(gopt.port, &gopt.ev_listen, cb_accept);
	add_listen_sock(gopt.port_ssl, &gopt.ev_listen_ssl, cb_accept_ssl);
	// add_listen_sock(gopt.port_con, &gopt.ev_listen_con, cb_accept_con);
}

static void
usage(char *err)
{
	if (err)
		fprintf(stderr, "%s", err);

	fprintf(stderr, "Version %s\n"
" -p <port>     TCP listening port [default=%d]\n"
" -P <port>     SSL listening port. Use 0 to disable SSL support [default=%d]\n"
" -C            Listen for cnc connections [default=no]\n"
" -c <port>     TCP port of cnc [default=%d]\n"
" -d <IP>       Destination IP of CNC server [default=none]\n"
"", VERSION, GSRN_DEFAULT_PORT, GSRN_DEFAULT_PORT_SSL, GSRN_DEFAULT_PORT_CON);

	if (err)
		exit(255);

	exit(0);
}

void
do_getopt(int argc, char *argv[])
{
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, "p:P:c:d:hv")) != -1)
	{
		switch (c)
		{
			case 'p':
				gopt.port = atoi(optarg);
				break;
			case 'P':
				gopt.port_ssl = atoi(optarg);
				break;
			case 'C':
				gopt.is_concentrator = 1;
				break;
			case 'c':
				gopt.port_con = atoi(optarg);
				break;
			case 'd':
				gopt.ip_con = inet_addr(optarg);
				break;
			case 'v':
				gopt.verbosity += 1;
				break;
			case 'h':
				usage(NULL);
				break;
			default:
				usage("Wrong parameter\n");
		}
	}
}
