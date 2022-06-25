
#include "common.h"
#include "gsrnd.h"
#include "utils.h"
#include "net.h"
#include "engine.h"
#include "gopt.h"

struct _gopt gopt;
struct _gd gd;
#ifdef DEBUG
struct _g_debug_ctx g_dbg_ctx;
#endif

// static prg_t g_prg;
static void cb_gs_log(struct _gs_log_info *l);

const char *
strx128(uint128_t x, char *val, size_t sz)
{
	if (x >> 64 > 0)
		snprintf(val, sz, "%"PRIx64"%"PRIx64, INT128_HIGH(x), INT128_LOW(x));
	else
		snprintf(val, sz, "%"PRIx64, (uint64_t)x);

	return val;
}

const char *
strx128x(uint128_t x)
{
	static char valstr[64];
	strx128(x, valstr, sizeof valstr);

	return valstr;
}


static void
init_defaults_gsrnd(void)
{
	gopt.port = GSRN_DEFAULT_PORT;
	gopt.port_ssl = GSRN_DEFAULT_PORT_SSL;
}

static void
init_defaults_cli()
{
}

void
init_defaults(prg_t prg)
{
	gopt.prg = prg;
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;
	gopt.ip_cli = ntohl(inet_addr("127.0.0.1"));
	gopt.port_cli = CLI_DEFAULT_PORT;

	// Must ignore SIGPIPE. Epoll may signal that socket is ready for wiriting
	// but gets closed by remote before calling write().
	signal(SIGPIPE, SIG_IGN);

	if (prg == PRG_GSRND)
		init_defaults_gsrnd();
	else if (prg == PRG_CLI)
		init_defaults_cli();
}

void
add_listen_sock(uint32_t ip, int port, struct event **evptr, event_callback_fn cb_func)
{
	if (evptr == NULL)
		return;

	if (port <= 0)
		return;

	int ls;
	int ret;
	ls = fd_new_socket(SOCK_STREAM);
	ret = fd_net_listen(ls, ip, port);
	if (ret < 0)
	{
		GS_LOG("ERR: listen(%d): %s\n", port, strerror(errno));
		DEBUGF("listen(%d): %s\n", port, strerror(errno));
		return;
	}

	*evptr = event_new(gopt.evb, ls, EV_READ|EV_PERSIST, cb_func, evptr);
	event_add(*evptr, NULL);
}

void
close_del_ev(struct event **evptr)
{
	int fd;
	if ((evptr == NULL) || (*evptr == NULL))
		return;

	struct event *ev = *evptr;

	fd = event_get_fd(ev);
	if (fd < 0)
		return;
	event_del(ev);
	close(fd);
	*evptr = NULL;
}

void
init_vars(void)
{
	GS_library_init(gopt.err_fp, /* Debug Output */ gopt.err_fp, cb_gs_log);

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

	init_engine();

	// if (gopt.prg == PRG_GSRND)
	// {
	// 	// add_listen_sock(gopt.port_con, &gopt.ev_listen_con, cb_accept_con);

	// } else if (gopt.prg == PRG_CLI) {

	// }
}

static int is_fdlim_init;

int
fd_limit_init(void)
{
	if (is_fdlim_init != 0)
		return 0;

	is_fdlim_init = 1;
	return getrlimit(RLIMIT_NOFILE, &gopt.rlim_fd);
}

int
fd_limit_unlimited()
{
	struct rlimit *r = &gopt.rlim_fd;

	fd_limit_init();

	r->rlim_cur = r->rlim_max;
	return setrlimit(RLIMIT_NOFILE, r);
}

int
fd_limit_limited()
{
	struct rlimit *r = &gopt.rlim_fd;

	fd_limit_init();

	r->rlim_cur = r->rlim_max - GSRN_FD_RESERVE;
	return setrlimit(RLIMIT_NOFILE, r);
}

static void
usage(char *err)
{
	if (err)
		fprintf(stderr, "%s", err);

	fprintf(stderr, "Version %s\n"
" -p <port>     TCP listening port [default=%d]\n"
" -P <port>     SSL listening port. Use 0 to disable SSL support [default=%d]\n"
" -m <port>     TCP port for cli [default=%d]\n"
" -C            Listen for cnc connections [default=no]\n"
" -c <port>     TCP port of cnc [default=%d]\n"
" -d <IP>       Destination IP of CNC server [default=none]\n"
" -L <file>     Logfile [default=stderr]\n"
" -v            Verbosity level\n"
" -a            Log IP addresses [disabled by default]\n"
"", VERSION, GSRN_DEFAULT_PORT, GSRN_DEFAULT_PORT_SSL, CLI_DEFAULT_PORT, GSRN_DEFAULT_PORT_CON);

	if (err)
		exit(255);

	exit(0);
}

void
do_getopt(int argc, char *argv[])
{
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, "L:p:P:c:d:m:hva")) != -1)
	{
		switch (c)
		{
			case 'L':
				gopt.log_fp = fopen(optarg, "a");
				if (gopt.log_fp == NULL)
					ERREXIT("fopen(%s): %s\n", optarg, strerror(errno));
				gopt.err_fp = gopt.log_fp;
				break;
			case 'p':
				gopt.port = atoi(optarg);
				break;
			case 'P':
				gopt.port_ssl = atoi(optarg);
				break;
			case 'm':
				gopt.port_cli = atoi(optarg);
				break;
			case 'C':
				gopt.is_concentrator = 1;
				break;
			case 'c':
				gopt.port_cnc = atoi(optarg);
				break;
			case 'd':
				gopt.ip_cnc = inet_addr(optarg);
				break;
			case 'v':
				gopt.verbosity += 1;
				break;
			case 'a':
				gd.is_log_ip = 1;
				break;
			case 'h':
				usage(NULL);
				break;
			default:
				usage("Wrong parameter\n");
		}
	}
}

static void
cb_gs_log(struct _gs_log_info *l)
{
	if (l == NULL)
		return;

#ifndef DEBUG
	// Return if this is _NOT_ a DEBUG-build but we get a TYPE_DEBUG
	// (should not happen).
	if (l->type == GS_LOG_TYPE_DEBUG)
		return;
#endif

	FILE *fp = gopt.log_fp;
	if (l->type == GS_LOG_TYPE_ERROR)
		fp = gopt.err_fp;

	if (fp == NULL)
		return;

	if (l->level > gopt.verbosity)
		return; // Not interested. 

	fprintf(fp, "%s %s\n", GS_logtime(), l->msg);
	fflush(fp);
}

#define BEV_ERR_ADD(dst, end, rem, what, check)  do{ \
	if (!(what & check)) { break; } \
	rem &= ~check; \
	int rv; \
	rv = snprintf(dst, end - dst, "|%s", #check); \
	if (rv <= 0) { break; } \
	dst += rv; \
} while (0)

// Return BEV_EVENT_ errors as string
const char *
BEV_strerror(short what)
{
	static char err[128];
	char *d = &err[0];
	char *e = d + sizeof err;
	short rem = what; // remaining flags

	*d = 0;

	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_READING);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_WRITING);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_EOF);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_ERROR);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_TIMEOUT);
	BEV_ERR_ADD(d, e, rem, what, BEV_EVENT_CONNECTED);

	if (rem != 0)
		snprintf(d, e - d, "|UNKNOWN-%x", rem);

	return err;
}

static const char *peer_l_names[MAX_LISTS_BY_ADDR] = {
	"LISTEN",
	"WAIT  ",
	"WAIT-A",
	"ACCEPT",
	"ESTABL"
};


const char *
PEER_L_name(uint8_t pl_id)
{
	return peer_l_names[pl_id];
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winitializer-overrides"
static const uint8_t hextable[] = {
   [0 ... 255] = -1, // bit aligned access into this table is considerably
   ['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // faster for most modern processors,
   ['A'] = 10, 11, 12, 13, 14, 15,
   ['a'] = 10, 11, 12, 13, 14, 15 
};
#pragma GCC diagnostic pop

uint32_t
GS_hexto32(const char *hex) {
   uint32_t ret = 0; 
   while (*hex && ret >= 0) {
      ret = (ret << 4) | hextable[(unsigned char)*hex++];
   }
   return ret; 
}

uint128_t
GS_hexto128(const char *hex) {
   uint128_t ret = 0; 
   while (*hex && ret >= 0) {
      ret = (ret << 4) | hextable[(unsigned char)*hex++];
   }
   return ret; 
}

char *
GS_addr128hex(char *dst, uint128_t addr)
{
	addr = htobe128(addr);
	return GS_addr2hex(dst, &addr);
}

// Do not log ip addresses or port numbers by default. This function
// returns anonymized IP:PORT string unless ip-logging has been enabled.
//
// Convert an IP/PORT in HBO to a string (if logging allows this).
const char *
gs_log_ipport2str_r(char *dst, size_t dsz, uint32_t ip, uint16_t port)
{
	if (gd.is_log_ip == 0)
	{
		snprintf(dst, dsz, "#.#.#.#:%u", port);
		return dst;
	}

	ip = htonl(ip);
	snprintf(dst, dsz, "%s:%u", int_ntoa(ip), port);

	return dst;
}

// HostByteOrder (HBO)
const char *
gs_log_ipport2str(uint32_t ip, uint16_t port)
{
	static char ipport[32];

	return gs_log_ipport2str_r(ipport, sizeof ipport, ip, port);
}

const char *
gs_log_in_addr2str_r(char *dst, size_t dsz, struct sockaddr_in *addr_in /*NBO*/)
{
	if (addr_in == NULL)
		return "#.#.#.#:0";

	return gs_log_ipport2str_r(dst, dsz, ntohl(addr_in->sin_addr.s_addr), ntohs(addr_in->sin_port));
}

const char *
gs_log_in_addr2str(struct sockaddr_in *addr_in /*NBO*/)
{
	static char ipport[32];

	return gs_log_in_addr2str_r(ipport, sizeof ipport, addr_in);
}





