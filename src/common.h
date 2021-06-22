
#ifndef __GSRN_COMMON_H__
#define __GSRN_COMMON_H__ 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/queue.h>
#ifdef HAVE_SYS_LOADAVG_H
# include <sys/loadavg.h> // Solaris11
#endif
#ifdef HAVE_SYS_ENDIAN_H
# include <sys/endian.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif
#include <stdio.h>
#include <string.h>
#include <strings.h>    // Solaris11
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>		/* basename() */
#include <termios.h>
#include <pwd.h>
#include <wordexp.h>
#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#endif
#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif
#ifdef HAVE_LIBUTIL_H
# include <libutil.h>	/* FreeBSD */
#endif
#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#ifdef HAVE_UTIL_H
# include <util.h>		/* MacOS */
#endif
#if defined __sun || defined __hpux /* Solaris, HP-UX */
# include <stropts.h>
#endif
#include <search.h>  // tsearch
#include <locale.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/srp.h>
// LibEvent
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
// gsocket
#include <gsocket/gsocket.h>

#ifdef __sun
# ifdef HAVE_OPEN64
#  define IS_SOL10      1   // Solaris 10
# else
#  define IS_SOL11      1   // Solaris 11
# endif
# define IS_SOLARIS     1
#endif

#ifndef O_NOCTTY
# warning "O_NOCTTY not defined. Using 0."
# define O_NOCTTY 0
#endif

// Older fbsd's dont have this defined
#ifndef UT_NAMESIZE
# define UT_NAMESIZE	32
#endif

// debian-hurd does not define PATH_MAX (and has no limit on filename length)
#ifndef PATH_MAX
# define GS_PATH_MAX      4096
#else
# define GS_PATH_MAX      PATH_MAX
#endif

#ifndef HAVE_UINT128_T
# ifndef HAVE___UINT128_T
#  error "Compiler does not know about __uint128_t. Try on a 64-bit system."
# else
   typedef __uint128_t uint128_t;
# endif
#endif

#if defined(__sun)
# if !defined(be64toh) // Solaris11
#  define be64toh(x) ntohll(x)
#  define htobe64(x) htonll(x)
# endif
# if !defined(htonll) // Solaris10
#  if __BIG_ENDIAN__
#   define htonll(x) (x)
#   define ntohll(x) (x)
#  else
#   define htonll(x) ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((uint64_t)(x) >> 32)
#   define ntohll(x) ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((uint64_t)(x) >> 32)
#  endif
# endif
#endif

#ifndef htonll
# define htonll(x)  htobe64(x)
#endif
#ifndef ntohll
# define ntohll(x)  be64toh(x)
#endif

#if !defined(be128toh)
# define be128toh(x) ((uint128_t)ntohll(x) & 0xFFFFFFFFFFFFFFFF) << 64 | ntohll((uint128_t)(x) >> 64)
# define htob128(x) ((uint128_t)htonll(x) & 0xFFFFFFFFFFFFFFFF) << 64| htonll((uint128_t)(x) >> 64)
#endif

#define INT128_HIGH(x)   (uint64_t)(x>>64)
#define INT128_LOW(x)    (uint64_t)(x)

#define SOMAXCON       (64 * 1024)  // listen()

#define EX_EXECFAILED  248
#define EX_NOTREACHED  249
#define EX_BADWRITE    250  // write() failed
#define EX_UNKNWNCMD   251  // Unknown command line parameter

#define EX_BADSELECT   253
#define EX_SIGTERM     254
#define EX_FATAL       255
#define EX_CONNREFUSED  61  // Used by deploy.sh to verify that server is responding


extern struct _gopt gopt; // declared in utils.c

#define xfprintf(fp, a...) do {if (fp != NULL) { fprintf(fp, a); fflush(fp); } } while (0)

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#ifndef MAX
# define MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef MIN
# define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#define D_RED(a)	"\033[0;31m"a"\033[0m"
#define D_GRE(a)	"\033[0;32m"a"\033[0m"
#define D_YEL(a)	"\033[0;33m"a"\033[0m"
#define D_BLU(a)	"\033[0;34m"a"\033[0m"
#define D_MAG(a)	"\033[0;35m"a"\033[0m"
#define D_BRED(a)	"\033[1;31m"a"\033[0m"
#define D_BGRE(a)	"\033[1;32m"a"\033[0m"
#define D_BYEL(a)	"\033[1;33m"a"\033[0m"
#define D_BBLU(a)	"\033[1;34m"a"\033[0m"
#define D_BMAG(a)	"\033[1;35m"a"\033[0m"

#ifdef DEBUG
struct _g_debug_ctx
{
	struct timeval tv_last;
	struct timeval tv_now;
};

extern struct _g_debug_ctx g_dbg_ctx; // declared in utils.c

#define DEBUGF_T(xcolor, a...) do { \
	gettimeofday(&g_dbg_ctx.tv_now, NULL); \
	if (g_dbg_ctx.tv_last.tv_sec == 0) { memcpy(&g_dbg_ctx.tv_last, &g_dbg_ctx.tv_now, sizeof g_dbg_ctx.tv_last); } \
	xfprintf(gopt.err_fp, "DEBUG %4"PRIu64" %s:%d %s", GS_TV_TO_MSEC(&g_dbg_ctx.tv_now) - GS_TV_TO_MSEC(&g_dbg_ctx.tv_last), __func__, __LINE__, xcolor?xcolor:""); \
	memcpy(&g_dbg_ctx.tv_last, &g_dbg_ctx.tv_now, sizeof g_dbg_ctx.tv_last); \
	xfprintf(gopt.err_fp, a); \
	if (xcolor) { xfprintf(gopt.err_fp, "\033[0m"); } \
} while (0)

# define DEBUGF(a...) do{DEBUGF_T(NULL, a); } while(0)
# define DEBUGF_R(a...) do{DEBUGF_T("\033[1;31m", a); } while(0)
# define DEBUGF_G(a...) do{DEBUGF_T("\033[1;32m", a); } while(0)
# define DEBUGF_B(a...) do{DEBUGF_T("\033[1;34m", a); } while(0)
# define DEBUGF_Y(a...) do{DEBUGF_T("\033[1;33m", a); } while(0)
# define DEBUGF_M(a...) do{DEBUGF_T("\033[1;35m", a); } while(0)
# define DEBUGF_C(a...) do{DEBUGF_T("\033[1;36m", a); } while(0)
# define DEBUGF_W(a...) do{DEBUGF_T("\033[1;37m", a); } while(0)
#else // DEBUG
# define DEBUGF(a...)
# define DEBUGF_R(a...)
# define DEBUGF_G(a...)
# define DEBUGF_B(a...)
# define DEBUGF_Y(a...)
# define DEBUGF_M(a...)
# define DEBUGF_C(a...)
# define DEBUGF_W(a...)
# define DEBUGF_A(a...)
#endif

// Increase ptr by number of characters added to ptr.
#define SXPRINTF(ptr, len, a...) do {\
	size_t n = snprintf(ptr, len, a); \
	ptr += MIN(n, len); \
} while(0)

// Overcome GCC warning for truncation. Abort() if truncation happen.
#define SNPRINTF_ABORT(...)	(snprintf(__VA_ARGS__) < 0 ? abort() : (void)0)

#define VOUT(level, a...) do { \
	if (level > gopt.verboselevel) \
		break; \
	xfprintf(gopt.out, a); \
	fflush(gopt.out); \
} while (0)

#define XFREE(ptr)      do{if(ptr) free(ptr); ptr = NULL;}while(0)
#define XBIO_FREE(ptr)  do{if(ptr) BIO_free(ptr); ptr = NULL;}while(0)
#define XBEV_FREE(ptr)  do{if(ptr) bufferevent_free(ptr); ptr = NULL;}while(0)


#ifdef DEBUG
# define ERREXIT(a...)   do { \
		xfprintf(gopt.err_fp, "ERROR "); \
        xfprintf(gopt.err_fp, "%s():%d ", __func__, __LINE__); \
        xfprintf(gopt.err_fp, a); \
        exit(255); \
} while (0)
#else
# define ERREXIT(a...)   do { \
		xfprintf(gopt.err_fp, "ERROR: "); \
        xfprintf(gopt.err_fp, a); \
        exit(255); \
} while (0)
#endif

#ifndef XASSERT
# define XASSERT(expr, a...) do { \
	if (!(expr)) { \
		xfprintf(gopt.err_fp, "%s:%d:%s() ASSERT(%s) ", __FILE__, __LINE__, __func__, #expr); \
		xfprintf(gopt.err_fp, a); \
		xfprintf(gopt.err_fp, " Exiting...\n"); \
		exit(255); \
	} \
} while (0)
#endif

#define XCLOSE(fd)      do { \
        if (fd < 0) { DEBUGF_R("*** WARNING *** Closing BAD fd\n"); exit(255); break; } \
        DEBUGF_W("Closing fd = %d\n", fd); \
        close(fd); \
        fd = -1; \
} while (0)

#define XFCLOSE(fp)		do { \
		if (fp == NULL) { DEBUGF_R("*** WARNING *** Closing BAD fp\n"); break; } \
		fclose(fp); \
		fp = NULL; \
} while (0)


#define XFD_SET(fd, set) do { \
        if (fd < 0) { DEBUGF_R("WARNING: FD_SET(%d, )\n", fd); break; } \
        FD_SET(fd, set); \
} while (0)

#ifdef DEBUG
# define HEXDUMP(a, _len)        do { \
        size_t _n = 0; \
        xfprintf(gopt.err_fp, "%s:%d HEX[%zd] ", __FILE__, __LINE__, _len); \
        while (_n < (_len)) xfprintf(gopt.err_fp, "%2.2x", ((unsigned char *)a)[_n++]); \
        xfprintf(gopt.err_fp, "\n"); \
} while (0)
# define HEXDUMPF(a, len, m...) do{xfprintf(gopt.err_fp, m); HEXDUMP(a, len);}while(0)
#else
# define HEXDUMP(a, len)
# define HEXDUMPF(a, len, m...)
#endif

#endif /* !__GSRN_COMMON_H__ */
