
#ifndef __GSRN_ENGINE_H__
#define __GSRN_ENGINE_H__ 1

void cb_accept(int fd, short ev, void *arg);
void cb_accept_ssl(int fd, short ev, void *arg);
void cb_accept_con(int fd, short ev, void *arg);

void cb_bev_status(struct bufferevent *bev, short what, void *arg);
void cb_bev_write(struct bufferevent *bev, void *arg);
void cb_bev_read(struct bufferevent *bev, void *arg);

// void cb_bev_relay_read(struct bufferevent *bev, void *arg);

void cb_gsrn_protocol_error(struct evbuffer *eb, size_t len, void *arg);
void cb_gsrn_listen(struct evbuffer *eb, size_t len, void *arg);
void cb_gsrn_connect(struct evbuffer *eb, size_t len, void *arg);
void cb_gsrn_accept(struct evbuffer *eb, size_t len, void *arg);
void cb_gsrn_ping(struct evbuffer *eb, size_t len, void *arg);

#endif // !__GSRN_ENGINE_H__