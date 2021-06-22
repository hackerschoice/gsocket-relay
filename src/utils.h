
#ifndef __GSRN_UTILS_H__
#define __GSRN_UTILS_H__ 1

const char *strx128(uint128_t x, char *val, size_t sz);
void init_defaults();
void init_vars(void);
void do_getopt(int argc, char *argv[]);


#endif // !__GSRN_UTILS_H__
