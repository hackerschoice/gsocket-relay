#include "common.h"
#include "engine.h"
#include "protocol.h"

#define GSRN_msg_init(msg, xtype)   do {memset(msg, 0, sizeof *msg); (msg)->type = xtype;}while(0)

void
GSRN_send_status(struct _peer *p, uint8_t err_type, uint8_t code, const char *err)
{
	struct _gs_status msg;

	GSRN_msg_init(&msg, GS_PKT_TYPE_STATUS);
	msg.err_type = err_type;
	msg.code = code;

	if (err != NULL)
		snprintf((char *)msg.msg, sizeof msg.msg, "%s", err);

	bufferevent_write(p->bev, &msg, sizeof msg);
}

void
GSRN_send_start(struct _peer *p, uint8_t flags)
{
	struct _gs_start msg;

	GSRN_msg_init(&msg, GS_PKT_TYPE_START);
	msg.flags = flags;

	bufferevent_write(p->bev, &msg, sizeof msg);
}

void
GSRN_send_pong(struct _peer *p, uint8_t *payload)
{
	struct _gs_pong msg;

	GSRN_msg_init(&msg, GS_PKT_TYPE_PONG);
	memcpy(msg.payload, payload, sizeof msg.payload);

	bufferevent_write(p->bev, &msg, sizeof msg);
}

// Set messages that we are allowed to accept given current-type
void
GSRN_change_state(struct _peer *p, uint8_t state)
{
	switch (state)
	{
		case GSRN_STATE_INIT:
			// Allowed
			PKT_setcb(&p->pkt, GS_PKT_TYPE_LISTEN , sizeof (struct _gs_listen) , cb_gsrn_listen, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_CONNECT, sizeof (struct _gs_connect), cb_gsrn_connect, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_PING   , sizeof (struct _gs_ping)   , cb_gsrn_ping, p);
			// Not allowed
			PKT_setcb(&p->pkt, GS_PKT_TYPE_ACCEPT, sizeof (struct _gs_accept), cb_gsrn_protocol_error, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_START , sizeof (struct _gs_start) , cb_gsrn_protocol_error, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_PONG  , sizeof (struct _gs_pong)  , cb_gsrn_protocol_error, p);
			break;
		case GSRN_STATE_LISTEN:
		case GSRN_STATE_CONNECT:
			PKT_setcb(&p->pkt, GS_PKT_TYPE_LISTEN, sizeof (struct _gs_listen), cb_gsrn_protocol_error, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_CONNECT, sizeof (struct _gs_connect), cb_gsrn_protocol_error, p);
			break;
		case GSRN_STATE_ACCEPT:
			// Accept no further GSRN messages
			PKT_setcb(&p->pkt, GS_PKT_TYPE_LISTEN, sizeof (struct _gs_listen), cb_gsrn_protocol_error, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_CONNECT, sizeof (struct _gs_connect), cb_gsrn_protocol_error, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_PING, sizeof (struct _gs_ping), cb_gsrn_protocol_error, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_ACCEPT, sizeof (struct _gs_accept), cb_gsrn_protocol_error, p);
			break;
		case GSRN_STATE_BUDDY_UP:
			// Disallow
			PKT_setcb(&p->pkt, GS_PKT_TYPE_LISTEN, sizeof (struct _gs_listen), cb_gsrn_protocol_error, p);
			PKT_setcb(&p->pkt, GS_PKT_TYPE_CONNECT, sizeof (struct _gs_connect), cb_gsrn_protocol_error, p);
			// Ignore
			PKT_setcb(&p->pkt, GS_PKT_TYPE_PING, sizeof (struct _gs_ping), NULL, p);
			// Allow
			PKT_setcb(&p->pkt, GS_PKT_TYPE_ACCEPT, sizeof (struct _gs_accept), cb_gsrn_accept, p);
			break;
	}
}
