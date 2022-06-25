
#include "common.h"

const char *
SSL_strerror(int err)
{
	switch (err)
	{
		case SSL_ERROR_NONE:
			return D_GRE("None");
		case SSL_ERROR_ZERO_RETURN:
			return "ZERO_RETURN (close-notify recv)";
		case SSL_ERROR_WANT_READ:
			return D_YEL("WANT_READ");
		case SSL_ERROR_WANT_WRITE:
			return D_YEL("WANT_WRITE");
		case SSL_ERROR_WANT_CONNECT:
			return "WANT CONNECT";
		case SSL_ERROR_WANT_ACCEPT:
			return "WANT ACCEPT";
		case SSL_ERROR_WANT_X509_LOOKUP:
			return "WANT X509 LOOKUP";
#ifdef SSL_ERROR_WANT_ASYNC
		case SSL_ERROR_WANT_ASYNC:
			return "WANT_ASYNC";
#endif
		case SSL_ERROR_SYSCALL:
			return D_RED("SYSCALL");
		case SSL_ERROR_SSL:
			return D_RED("FATAL ERROR");
	}
	return "unknown :/";
}
