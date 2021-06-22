
#ifndef __GSRN_GSRND_H__
#define __GSRN_GSRND_H__ 1

// Seconds to wait for first GSRN message
#define GSRN_1STMSG_TIMEOUT       (5)
#define GSRN_MSG_TIMEOUT          (GSRN_DEFAULT_PING_INTERVAL + 10)
#define GSRN_FLUSH_TV_TIMEOUT     (3)
// Seconds to wait for ACCEPT after START was send in buddy_up()
#define GSRN_ACCEPT_TIMEOUT       (5)
#define GSRN_SHORTWAIT_TIMEOUT    (5)
// 2h and 5 seconds. This can be further restricted by systemwide
// TCP Keepalive messages rather than by application layer.
#define GSRN_IDLE_TIMEOUT         (60*60*2+5)
// listening token to 'linger' for 15 seconds before allowing new
// listening gsocket with different token (same gsocket addr).
#define GSRN_TOKEN_LINGER         (7)

#define TVSEC(sec)                &(struct timeval){sec, 0} // convert 'sec' to 'struct timeval'

#endif // !__GSRN_GSRND_H__