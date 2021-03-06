
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

static int PORT_add_listen(struct _port *pt, uint32_t ip, event_callback_fn cb_func, void *arg);
static void PORT_close(struct _port *pt);
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
	TAILQ_INIT(&gopt.ports_head);
	TAILQ_INIT(&gopt.ports_cli_head);
}

static void
init_defaults_cli()
{
	gopt.port_cli = CLI_DEFAULT_PORT;
}

void
init_defaults(prg_t prg)
{
	gopt.prg = prg;
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;
	gopt.ip_cli = ntohl(inet_addr("127.0.0.1"));
	// gopt.port_cli = CLI_DEFAULT_PORT;

	// Must ignore SIGPIPE. Epoll may signal that socket is ready for wiriting
	// but gets closed by remote before calling write().
	signal(SIGPIPE, SIG_IGN);

	if (prg == PRG_GSRND)
		init_defaults_gsrnd();
	else if (prg == PRG_CLI)
		init_defaults_cli();
}

void
PORTSQ_add(struct _port_listhead *head, int port)
{
	struct _port *pt;

	pt = calloc(1, sizeof (struct _port));
	XASSERT(pt != NULL, "calloc() failed\n");

	pt->port = port;

	TAILQ_INSERT_TAIL(head, pt, ll);
}

void
PORTSQ_listen(struct _port_listhead *head, uint32_t ip, uint16_t port_default, event_callback_fn cb_func)
{
	if (TAILQ_EMPTY(head))
		PORTSQ_add(head, port_default);

	struct _port *pt;
	int ret;
	TAILQ_FOREACH(pt, head, ll)
	{
		DEBUGF("port=%u\n", pt->port);
		ret = PORT_add_listen(pt, ip, cb_func, pt);
		if (ret != 0)
		{
			GS_LOG("ERR: listen(%d): %s\n", pt->port, strerror(errno));
			DEBUGF("listen(%d): %s\n", pt->port, strerror(errno));
		}
	}
}

static void
PORT_close(struct _port *pt)
{
	if (pt->ev == NULL)
		return;

	int fd;
	fd = event_get_fd(pt->ev);
	if (fd < 0)
		return;

	event_del(pt->ev);
	event_free(pt->ev);
	pt->ev = NULL;

	close(fd);
}

// Close all ports (and free all events). Do not free Q as we later may want
// to cal PORTSQ_listen() again.
void
PORTSQ_close(struct _port_listhead *head)
{
	struct _port *pt;

	TAILQ_FOREACH(pt, head, ll)
	{
		PORT_close(pt);
	}
}

void
PORTSQ_free(struct _port_listhead *head)
{
	struct _port *pt;
	struct _port *temp_pt;

	TAILQ_FOREACH_SAFE(pt, head, ll, temp_pt)
	{
		PORT_close(pt);
		TAILQ_REMOVE(head, pt, ll);
	}
}

static int
PORT_add_listen(struct _port *pt, uint32_t ip, event_callback_fn cb_func, void *arg)
{
	int ls;
	int ret;

	ls = fd_new_socket(SOCK_STREAM);
	if (ls < 0)
		goto err;
	ret = fd_net_listen(ls, ip, pt->port);
	if (ret < 0)
		goto err;

	pt->ev = event_new(gopt.evb, ls, EV_READ|EV_PERSIST, cb_func, arg);
	XASSERT(pt->ev != NULL, "event_new() failed\n");

	event_add(pt->ev, NULL);
	return 0;
err:
	XCLOSE(ls);
	return -1;
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

	srandom(GS_usec());
#if 0
	SSL_load_error_strings();
	SSL_library_init();
	gopt.ssl_ctx = SSL_CTX_new(TLS_server_method() /*SSLv23_client_method()*/);
	XASSERT(gopt.ssl_ctx != NULL, "Failed creating SSL context\n");
	
	// FIXME: What we want is that port 443 supports cleartext and SSL.
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
#endif

	gopt.evb = event_base_new();
	XASSERT(gopt.evb != NULL, "Could not initialize libevent!\n");

	init_engine(); // either in engine_client.c or engine_server.c
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
	"ESTABL",
	"B-AUTH" 
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





