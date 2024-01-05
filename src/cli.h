#ifndef __GSRN_CLI_H__
#define __GSRN_CLI_H__ 1

#include "packet.h"
#include "proto_cli.h"

struct _cli
{
	struct bufferevent *bev;
	struct evbuffer *eb;
	PKT pkt;

	int flags;
};

#define FL_CLI_IS_CONNECTED    (0x01)
#define FL_CLI_IS_LOGSTREAM    (0x02)

struct _cli *CLI_new(int fd, SSL *ssl, int is_server);
void CLI_free(struct _cli *c);
void CLI_write(struct _cli *c, struct evbuffer *eb);
void CLI_payload(struct _cli *c, uint8_t type, uint16_t len, const void *payload);
void CLI_msg(struct _cli *c, const void *msg, size_t sz);
void CLI_printf(struct _cli *c, const char *fmt, ...);

#endif // !__GSRN_CLI_H__