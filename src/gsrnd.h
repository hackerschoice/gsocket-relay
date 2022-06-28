
#ifndef __GSRN_GSRND_H__
#define __GSRN_GSRND_H__ 1

// Seconds to wait for first GSRN message
#define GSRN_1STMSG_TIMEOUT         (5)
#define GSRN_MSG_TIMEOUT            (GSRN_DEFAULT_PING_INTERVAL + 10)
#define GSRN_FLUSH_TV_TIMEOUT       (3)
// Seconds to wait for ACCEPT after START was send in buddy_up()
#define GSRN_ACCEPT_TIMEOUT         (5)
#define GSRN_SHORTWAIT_TIMEOUT      (5)
// 2h and 5 seconds. This can be further restricted by systemwide
// TCP Keepalive messages rather than by application layer.
#define GSRN_IDLE_TIMEOUT           (60*60*2+5)
// listening token to 'linger' for 15 seconds before allowing new
// listening gsocket with different token (same gsocket addr).
#define GSRN_SHUTDOWN_IDLE_TIMEOUT  (10)
// Delay BAD_AUTH error by DELAY+random(JITTER) if 2 or more BAD_AUTH within
// BAD_AUTH_WINDOW happen. This happens when user starts 'gs-nc -l' multiple
// times and using the same GS_SECRET.
#define GSRN_BAD_AUTH_WINDOW        (180)
#define GSRN_BAD_AUTH_DELAY         (120)  // Wait DELAY+JITTER seconds before returning BAD-AUTH
#define GSRN_BAD_AUTH_JITTER        (10)

// Keep at least 10 FD's as reseve so if we run out of FD's that
// CLI can still connect
#define GSRN_FD_RESERVE             (10)

#define TVSEC(sec)                &(struct timeval){sec, 0} // convert 'sec' to 'struct timeval'
#define TVMSEC(msec)              &(struct timeval){msec / 1000, (msec % 1000) * 1000} // convert 'msec' to 'struct timeval'


struct _gstats
{
	uint64_t start_usec;   // TS when GSRN started
	uint64_t reset_usec;   // TS when stat got reset last.
	uint64_t n_gs_connect; // GS-CONNECT count
	uint64_t n_gs_listen;  // GS-LISTEN count
	uint64_t n_bad_auth;   // BAD-AUTH count
	uint64_t n_gs_refused; // GS Buddy not listening
};

#endif // !__GSRN_GSRND_H__
