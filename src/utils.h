
#ifndef __GSRN_UTILS_H__
#define __GSRN_UTILS_H__ 1

typedef enum
{
	PRG_GSRND = 0,
	PRG_CLI = 1	
} prg_t;

const char *strx128(uint128_t x, char *val, size_t sz);
const char *strx128x(uint128_t x);
void init_defaults(prg_t prg);
void init_vars(void);
void do_getopt(int argc, char *argv[]);
const char *BEV_strerror(short what);
void add_listen_sock(uint32_t ip, int port, struct event **evptr, event_callback_fn cb_func);
void close_del_ev(struct event **evptr);
const char *PEER_L_name(uint8_t pl_id);
uint128_t GS_hexto128(const char *hex);
char * GS_addr128hex(char *dst, uint128_t addr);
const char *gs_log_ipport2str_r(char *dst, size_t dsz, uint32_t ip, uint16_t port);
const char *gs_log_ipport2str(uint32_t ip, uint16_t port);
const char *gs_log_in_addr2str_r(char *dst, size_t dsz, struct sockaddr_in *addr_in);
const char *gs_log_in_addr2str(struct sockaddr_in *addr_in);
int fd_limit_init(void);
int fd_limit_unlimited(void);
int fd_limit_limited(void);

#endif // !__GSRN_UTILS_H__
