
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

#endif // !__GSRN_UTILS_H__
