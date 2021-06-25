#include "common.h"
#include "engine_cli.h"
#include "cli.h"
#include "gopt.h"

struct _cli *
CLI_new(int fd, SSL *ssl, int is_server)
{
	struct _cli *c;

	c = calloc(1, sizeof *c);
	if (c == NULL)
		return NULL;

	PKT_init(&c->pkt);
	// c->fd = fd;

	// if (c->ssl)
	// 	c->bev = bufferevent_openssl_socket_new(gopt.evb, -1, c->ssl, BUFFEREVENT_SSL_ACCEPTING/CONNECTING, BEV_OPT_DEFER_CALLBACKS)
	// else
	c->bev = bufferevent_socket_new(gopt.evb, fd, BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(c->bev, cb_bev_read_cli, cb_bev_write_cli, cb_bev_status_cli, c);

	c->eb = evbuffer_new();


	return c;
}

void
CLI_free(struct _cli *c)
{
	evbuffer_free(c->eb);
	XBEV_FREE(c->bev);
	// XCLOSE(c->fd);
	XFREE(c);
}

void
CLI_write(struct _cli *c, struct evbuffer *eb)
{
	bufferevent_write_buffer(c->bev, eb);
}

void
CLI_send(struct _cli *c, uint8_t type, uint16_t len, uint8_t *payload)
{
	uint16_t nlen;

	evbuffer_add(c->eb, &type, type);
	nlen = htons(len);
	evbuffer_add(c->eb, &nlen, sizeof nlen);
	if (payload != NULL)
		evbuffer_add(c->eb, payload, len);

	CLI_write(c, c->eb);
}

