
#ifndef __GSRN_PACKET_H__
#define __GSRN_PACKET_H__ 1

typedef void (*pkt_cb_t)(struct evbuffer *evbuf, size_t len, void *arg);

typedef struct
{
	int type;            // current type
	pkt_cb_t funcs[256];
	size_t lengths[256];
	void *args[256];
	int is_init;
	int is_malloc;
} PKT;

PKT *PKT_new(void);
int PKT_init(PKT *pkt);
void PKT_setcb(PKT *pkt, uint8_t type, size_t len, pkt_cb_t func, void *arg);
void PKT_delcb(PKT *pkt, uint8_t type);
void PKT_dispatch(PKT *pkt, struct evbuffer *evbuf);
void PKT_set_void(PKT *pkt);
void PKT_free(PKT *pkt);

#endif // !__GSRN_PACKET_H__