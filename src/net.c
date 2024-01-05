
#include "common.h"

int
fd_net_bind(int fd, uint32_t ip, uint16_t port)
{
	struct sockaddr_in addr;
	int ret;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(ip);
	addr.sin_port = htons(port);

	ret = bind(fd, (struct sockaddr *)&addr, sizeof addr);
	if (ret < 0)
		return ret;

	return 0;
}

int
fd_net_listen(int fd, uint32_t ip, uint16_t port)
{
	int ret;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof (int));

	ret = fd_net_bind(fd, ip, port);
	if (ret < 0)
		return ret;

	ret = listen(fd, SOMAXCON);
	if (ret != 0)
		return -1;

	return 0;
}

int
fd_new_socket(int type)
{
	int fd;
	int ret;

	fd = socket(PF_INET, type, 0);
	if (fd < 0)
		return -2;

	ret = fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
	if (ret != 0)
		return -2;

	return fd;
}

int
fd_net_accept(int listen_fd)
{
	int sox;
	int val = 1;
	// int ret;

	sox = accept(listen_fd, NULL, NULL);
	if (sox < 0)
	{
		return -2;
	}

	setsockopt(sox, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof (val));
	// val = 60;
	// setsockopt(sox, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof (val));
	// val = 15;
	// setsockopt(sox, IPPROTO_TCP, TCP_KEEPINTVL, &val, sizeof (val));
	// val = 4;
	// setsockopt(sox, IPPROTO_TCP, TCP_KEEPCNT, &val, sizeof (val));
	// ret = fcntl(sox, F_SETFL, O_NONBLOCK | fcntl(sox, F_GETFL, 0));
	// if (ret != 0)
		// return -2;

	return sox;
}

