#include "common.h"
#include "gopt.h"

static void
usage_cli(char *err)
{
	if (err)
		fprintf(stderr, "%s", err);

	fprintf(stderr, "Version %s\n"
" -p <port>     CLI port [default=%d]\n"
" -d <IP>       CLI IP address [default=127.0.0.1]\n"
"", VERSION, CLI_DEFAULT_PORT);

	if (err)
		exit(255);

	exit(0);
}

static void
do_getopt_cli(int argc, char *argv[])
{
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, "p:i:v")) != -1)
	{
		switch (c)
		{
			case 'p':
				gopt.port_cli = atoi(optarg);
				break;
			case 'h':
				gopt.ip_cli = inet_addr(optarg);
				break;
			case 'v':
				gopt.verbosity += 1;
				break;
			default:
				usage_cli("Wrong parameter\n");
		}

	}
}

int
main(int argc, char *argv[])
{
	init_defaults(PRG_CLI);

	do_getopt_cli(argc, argv);
	init_vars();

	event_base_dispatch(gopt.evb);
}