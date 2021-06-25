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

struct _cli *CLI_new(int fd, SSL *ssl, int is_server);
void CLI_free(struct _cli *c);
void CLI_write(struct _cli *c, struct evbuffer *eb);
void CLI_send(struct _cli *c, uint8_t type, uint16_t len, uint8_t *payload);

#endif // !__GSRN_CLI_H__