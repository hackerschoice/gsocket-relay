#ifndef __GSRN_PROTOCOL_H__
#define __GSRN_PROTOCOL_H__ 1

#include "peer.h"

void GSRN_send_status(struct _peer *p, uint8_t err_type, uint8_t err_code, const char *msg);
void GSRN_send_start(struct _peer *p, uint8_t flags);
void GSRN_send_pong(struct _peer *p, uint8_t *payload);

#define GSRN_send_status_fatal(p, c, m)     GSRN_send_status(p, GS_STATUS_TYPE_FATAL, c, m);
#define GSRN_send_status_warn(p, c, m)      GSRN_send_status(p, GS_STATUS_TYPE_WARN, c, m);
void GSRN_change_state(struct _peer *p, uint8_t state);

#define GSRN_STATE_INIT        (0x00)
#define GSRN_STATE_LISTEN      (0x01)
#define GSRN_STATE_CONNECT     (0x02)
#define GSRN_STATE_BUDDY_UP    (0x03)
#define GSRN_STATE_ACCEPT      (0x04)
#define GSRN_STATE_FINISHED    (0x05)


#endif // !__GRSRN_PROTOCOL_H__
