
#ifndef __GSRN_GSRND_H__
#define __GSRN_GSRND_H__ 1

// Seconds to wait for first GSRN message
#define GSRN_1STMSG_TIMEOUT       (5)
#define GSRN_MSG_TIMEOUT          &(struct timeval){GSRN_DEFAULT_PING_INTERVAL + 10, 0}
#define GSRN_FLUSH_TV_TIMEOUT     &(struct timeval){3, 0}
// Seconds to wait for ACCEPT after START was send in buddy_up()
#define GSRN_ACCEPT_TIMEOUT       &(struct timeval){5, 0}
// 2h and 5 seconds. This can be further restricted by systemwide
// TCP Keepalive messages rather than by application layer.
#define GSRN_IDLE_TIMEOUT         &(struct timeval){60*60*2+5, 0}


#endif // !__GSRN_GSRND_H__