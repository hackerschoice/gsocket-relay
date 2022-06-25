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

// Send a variable length message
void
CLI_payload(struct _cli *c, uint8_t type, uint16_t payload_len, const void *payload)
{
	struct _cli_hdr_tlv hdr;

	hdr.type = type;
	hdr.len = payload==NULL?0:htons(payload_len);
	evbuffer_add(c->eb, &hdr, sizeof hdr);
	if (payload != NULL)
		evbuffer_add(c->eb, payload, payload_len);

	CLI_write(c, c->eb);
}

void
CLI_msg(struct _cli *c, const void *msg, size_t sz)
{
	evbuffer_add(c->eb, msg, sz);

	CLI_write(c, c->eb);
}

void
CLI_printf(struct _cli *c, const char *fmt, ...)
{
	va_list ap;
	int rv;
	char buf[1024];

	va_start(ap, fmt);
	rv = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	rv = MIN(sizeof buf, rv);

	CLI_payload(c, GSRN_CLI_TYPE_MSG, rv, buf);
}
