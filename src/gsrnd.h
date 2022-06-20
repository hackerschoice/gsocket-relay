
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
#define GSRN_TOKEN_LINGER           (7)
#define GSRN_SHUTDOWN_IDLE_TIMEOUT  (10)
// Delay BAD_AUTH error by 30 seconds if 2 or more BAD_AUTH within
// 60 seconds happen. This happens when user starts 'gs-nc -l' multiple
// times and using the same GS_SECRET.
#define GSRN_BAD_AUTH_WINDOW        (60)
#define GSRN_BAD_AUTH_DELAY         (30)

#define TVSEC(sec)                &(struct timeval){sec, 0} // convert 'sec' to 'struct timeval'
#define TVMSEC(msec)              &(struct timeval){msec / 1000, (msec % 1000) * 1000} // convert 'msec' to 'struct timeval'

#endif // !__GSRN_GSRND_H__
