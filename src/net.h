
#ifndef __GSRN_NET_H___
#define __GSRN_NET_H___ 1

int fd_net_bind(int fd, uint32_t ip, uint16_t port);
int fd_net_listen(int fd, uint32_t ip, uint16_t port);
int fd_new_socket(int type);
int fd_net_accept(int listen_fd);

#endif // !__GSRN_NET_H__