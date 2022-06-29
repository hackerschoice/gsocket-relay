
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

static void
usage(char *err)
{
	if (err)
		fprintf(stderr, "%s", err);

	fprintf(stderr, "Version %s\n"
" -p <port>     TCP listening port [default=%d]\n"
" -m <port>     TCP port for cli [default=%d]\n"
" -C            Listen for cnc connections [default=no]\n"
" -c <port>     TCP port of cnc [default=%d]\n"
" -d <IP>       Destination IP of CNC server [default=none]\n"
" -L <file>     Logfile [default=stderr]\n"
" -v            Verbosity level\n"
" -a            Log IP addresses [disabled by default]\n"
"", VERSION, GSRN_DEFAULT_PORT, CLI_DEFAULT_PORT, GSRN_DEFAULT_PORT_CON);

	if (err)
		exit(255);

	exit(0);
}

static void
do_getopt(int argc, char *argv[])
{
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, "L:p:c:d:m:hva")) != -1)
	{
		switch (c)
		{
			case 'L':
				gopt.log_fp = fopen(optarg, "a");
				if (gopt.log_fp == NULL)
					ERREXIT("fopen(%s): %s\n", optarg, strerror(errno));
				gopt.err_fp = gopt.log_fp;
				break;
			case 'p':
				DEBUGF("Adding port %d\n", atoi(optarg));
				PORTSQ_add(&gopt.ports_head, atoi(optarg));
				// gopt.port = atoi(optarg);
				break;
			case 'm':
				PORTSQ_add(&gopt.ports_cli_head, atoi(optarg));
				// gopt.port_cli = atoi(optarg);
				break;
			case 'C':
				gopt.is_concentrator = 1;
				break;
			case 'c':
				gopt.port_cnc = atoi(optarg);
				break;
			case 'd':
				gopt.ip_cnc = inet_addr(optarg);
				break;
			case 'v':
				gopt.verbosity += 1;
				break;
			case 'a':
				gd.is_log_ip = 1;
				break;
			case 'h':
				usage(NULL);
				break;
			default:
				usage("Wrong parameter\n");
		}
	}
}

int
main(int argc, char *argv[])
{
	init_defaults(PRG_GSRND);
	do_getopt(argc, argv);
	init_vars();

	event_base_dispatch(gopt.evb);
	exit(0);
	return 255; // NOT REACHED
}