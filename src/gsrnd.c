
#if 0

TODO:
- Complete GSRN-SSL_shutdown (it is initiated by client so server does not have to do anything?)
- Implement FAST-CONNECT where all data after CONNECT is app-layer data.
- Implement propper event timeouts and do not piggy back on bufferevents read timeout (verify source)
#endif

#include "common.h"
#include "utils.h"
#include "peer.h"
#include "gopt.h"

// extern struct _gopt gopt;


int
main(int argc, char *argv[])
{

	init_defaults();
	do_getopt(argc, argv);
	init_vars();

	event_base_dispatch(gopt.evb);
	exit(0);
	return 255; // NOT REACHED
}