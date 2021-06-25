
#ifndef __GSRN_ENGINE_CLI_H__
#define __GSRN_ENGINE_CLI_H__ 1

void cb_bev_status_cli(struct bufferevent *bev, short what, void *arg);
void cb_bev_write_cli(struct bufferevent *bev, void *arg);
void cb_bev_read_cli(struct bufferevent *bev, void *arg);

#endif // !__GSRN_ENGINE_CLI_H__
