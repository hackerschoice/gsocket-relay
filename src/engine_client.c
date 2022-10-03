// Only linked against gsrn_cli
#include "common.h"
#include "utils.h"
#include "engine.h"
#include "engine_cli.h"
#include "net.h"
#include "cli.h"
#include "gopt.h"

#define PROMPT    "gsrn> "
static struct evbuffer *g_evb;
struct _cli *g_cli;
static int g_is_tty;
static struct event *g_ev_stdin;

typedef void (*dp_func_t)(char *line, char *end);

static void cmd_nocmd(char *opt, char *end);

static void cmd_help(char *opt, char *end);
static void cmd_list(char *opt, char *end);
static void cmd_kill(char *opt, char *end);
static void cmd_exit(char *opt, char *end);
static void cmd_stats(char *opt, char *end);

static void cmd_list_server(char *opt, char *end);
static void cmd_list_client(char *opt, char *end);
static void cmd_list_bad(char *opt, char *end);

static void cmd_stop(char *opt, char *end);
static void cmd_stop_listen(char *opt, char *end);
static void cmd_stop_listen_tcp(char *opt, char *end);
static void cmd_stop_listen_gsocket(char *opt, char *end);

static void cmd_set(char *opt, char *end);
static void cmd_set_port_cli(char *opt, char *end);
static void cmd_set_proto(char *opt, char *end);

static void cmd_set_log_ip(char *opt, char *end);
static void cmd_set_log_verbosity(char *opt, char *end);

static void cmd_help_list(char *opt, char *end);
static void cmd_help_set(char *opt, char *end);

static void cmd_shutdown(char *opt, char *end);

static void print_prompt(void);

#define NOCMD_PRINT() 	do {printf("Unknown command. Try 'help'.\n"); print_prompt();} while(0)

// tuples of 'cmd-string' <=> 'function' 
struct dp
{
	char *cmd;
	dp_func_t func;
};

struct dp dps[] = {
	{ NULL      , cmd_nocmd}, // default action if cmd not found
	{ "help"    , cmd_help},
	{ "list"    , cmd_list},
	{ "ls"      , cmd_list},    // 'list' can have nested commands
	{ "kill"    , cmd_kill},
	{ "stop"    , cmd_stop},
	{ "set"     , cmd_set},
	{ "shutdown", cmd_shutdown},
	{ "stats"   , cmd_stats},
	{ "status"  , cmd_stats},
	{ "exit"    , cmd_exit},
	{ "quit"    , cmd_exit}
};

// nested 'list' commands
struct dp dp_list[] = {
	{ NULL          , cmd_nocmd}, // default action if cmd not found
	{ "all"         , cmd_list},
	{ "server"      , cmd_list_server},
	{ "established" , cmd_list_client},
	{ "client"      , cmd_list_client},
	{ "bad"         , cmd_list_bad}
};

struct dp dp_stop[] = {
	{ NULL          , cmd_nocmd /*stop_default*/},
	{ "listen"      , cmd_stop_listen}
};

struct dp dp_stop_listen[] = {
	{ NULL      , cmd_nocmd /*stop_listen_default*/},
	{ "tcp"     , cmd_stop_listen_tcp},
	{ "gsocket" , cmd_stop_listen_gsocket}
};

struct dp dp_set[] = {
	{ NULL           , cmd_nocmd},
	{ "protocol"     , cmd_set_proto},
	{ "port.cli"     , cmd_set_port_cli},
	{ "log.verbosity", cmd_set_log_verbosity},
	{ "log.verbose"  , cmd_set_log_verbosity},
	{ "log.ip"       , cmd_set_log_ip}
};

struct dp dp_help[] = {
	{ NULL      , cmd_nocmd},
	{ "list"    , cmd_help_list},
	{ "set"     , cmd_help_set}
};

void
cb_bev_status_cli(struct bufferevent *bev, short what, void *arg)
{
	struct _cli *c = (struct _cli *)arg;

	// DEBUGF("status=%d (%s)\n", what, BEV_strerror(what));

	if (what & BEV_EVENT_CONNECTED)
	{
		c->flags |= FL_CLI_IS_CONNECTED;
		bufferevent_enable(bev, EV_READ);
		return;
	}

	if (what & BEV_EVENT_ERROR)
	{
		uint32_t ip = htonl(gopt.ip_cli);
		if (!(c->flags & FL_CLI_IS_CONNECTED))
			fprintf(stderr, "\nERROR: connect(%s:%d): %s\n", int_ntoa(ip), gopt.port_cli, strerror(errno));
		else
			fprintf(stderr, "\n%s\n", strerror(errno));
	}

	if (what & BEV_EVENT_EOF)
	{
		fprintf(stderr, "ERROR: Connection closed by foreign host.\n");
	}
	fflush(stdout);

	CLI_free(c);
	exit(127);
}

// Dispatch commands such as 'lis serv more options here' would call
// cmd_list_server "more options here"
static void
dispatch(char *l, char *end, struct dp *d, int n)
{
	int i;
	char *lend = end;

	if (end - l <= 0)
		return;

	// Example: 'lis serv more optinos here'
	char *opt = strchr(l, ' ');
	if (opt != NULL)
	{
		lend = opt;
		*opt = '\0';
		opt += 1;
		while (*opt == ' ')
			opt += 1;
	} else {
		opt = end;
	}

	for (i = 1; i < n; i++)
	{
		if (memcmp(l, d[i].cmd, MIN(strlen(d[i].cmd), lend - l)) != 0)
			continue;

		(*d[i].func)(opt, end);
		return;
	}

	// Execute default function
	(*d[0].func)(opt, end);
}

#define DP_TRYCALL_NESTED(xopt, xend, _xdpl)      do{ \
	if (xend - xopt <= 0) \
		break; \
	dispatch(xopt, xend, _xdpl, sizeof _xdpl / sizeof *_xdpl); \
	return; \
} while (0)

static void
cmd_stats(char *opt, char *end)
{
	struct _cli_stats msg;
	memset(&msg, 0, sizeof msg);
	msg.hdr.type = GSRN_CLI_TYPE_STATS;

	if (*opt == 'r')
		msg.opcode = GSRN_CLI_OP_STATS_RESET;

	CLI_msg(g_cli, &msg, sizeof msg);
}

////////////////// DP-LIST

static void
cmd_list_msg(uint8_t opcode)
{
	struct _cli_list msg;
	memset(&msg, 0, sizeof msg);
	msg.hdr.type = GSRN_CLI_TYPE_LIST;

	msg.opcode = opcode;

	CLI_msg(g_cli, &msg, sizeof msg);
}

static void
cmd_list_server(char *opt, char *end)
{
	cmd_list_msg(GSRN_CLI_OP_LIST_LISTEN);
}

static void
cmd_list_client(char *opt, char *end)
{
	cmd_list_msg(GSRN_CLI_OP_LIST_ESTAB);
}

static void
cmd_list_bad(char *opt, char *end)
{
	cmd_list_msg(GSRN_CLI_OP_LIST_BAD);
}

static void
cmd_list(char *opt, char *end)
{
	DP_TRYCALL_NESTED(opt, end, dp_list);

	struct _cli_list msg;
	memset(&msg, 0, sizeof msg);
	msg.hdr.type = GSRN_CLI_TYPE_LIST;

	CLI_msg(g_cli, &msg, sizeof msg);
}

/////////////////// DP-STOP
static void
cmd_stop(char *opt, char *end)
{
	DP_TRYCALL_NESTED(opt, end, dp_stop);

	NOCMD_PRINT();
}

static void
cmd_stop_listen(char *opt, char *end)
{
	DP_TRYCALL_NESTED(opt, end, dp_stop_listen);

	NOCMD_PRINT();
}

static void
cmd_stop_listen_tcp(char *opt, char *end)
{
	struct _cli_stop msg;

	memset(&msg, 0, sizeof msg);

	msg.hdr.type = GSRN_CLI_TYPE_STOP;
	msg.opcode = GSRN_CLI_OP_STOP_LISTEN_TCP;

	CLI_msg(g_cli, &msg, sizeof msg);
}

static void
cmd_stop_listen_gsocket(char *opt, char *end)
{
	printf("Not yet implemented\n"); fflush(stdout);
}

///////////////// SHUTDOWN
static void
cmd_shutdown(char *opt, char *end)
{
	struct _cli_shutdown msg;
	memset(&msg, 0, sizeof msg);

	msg.hdr.type = GSRN_CLI_TYPE_SHUTDOWN;

	CLI_msg(g_cli, &msg, sizeof msg);
}

//////////////// DP-SET
static void
cmd_set(char *opt, char *end)
{
	DP_TRYCALL_NESTED(opt, end, dp_set);

	NOCMD_PRINT();
}

static void
cmd_set_msg(uint8_t opcode, uint8_t op1, uint8_t vmajor, uint8_t vminor, uint16_t port)
{
	struct _cli_set msg;
	memset(&msg, 0, sizeof msg);
	msg.hdr.type = GSRN_CLI_TYPE_SET;

	msg.opcode = opcode;
	msg.opvalue1 = op1;
	msg.version_major = vmajor;
	msg.version_minor = vminor;
	msg.port = port;

	CLI_msg(g_cli, &msg, sizeof msg);
}
static void
cmd_set_proto(char *opt, char *end)
{
	char *str;
	str = strchr(opt, '.');
	if (str == NULL)
		goto err;

	cmd_set_msg(GSRN_CLI_OP_SET_PROTO, 0, atoi(opt), atoi(str + 1), 0);
	return;
err:
	NOCMD_PRINT();
}

static void
cmd_set_port_cli(char *opt, char *end)
{
	cmd_set_msg(GSRN_CLI_OP_SET_PORT_CLI, 0, 0, 0, atoi(opt));
}

static void
cmd_set_log_ip(char *opt, char *end)
{
	cmd_set_msg(GSRN_CLI_OP_SET_LOG_IP, atoi(opt), 0, 0, 0);
}

static void
cmd_set_log_verbosity(char *opt, char *end)
{
	cmd_set_msg(GSRN_CLI_OP_SET_LOG_VERBOSITY, atoi(opt), 0, 0, 0);
}

static void
cmd_kill(char *opt, char *end)
{
	struct _cli_kill msg;

	memset(&msg, 0, sizeof msg);
	// STOP HERE: converting to strx128 deadbeef and back does not always give 16 char hex string (which it shoudl!)
	// and also could implement 'kill address id'
	msg.hdr.type = GSRN_CLI_TYPE_KILL;
	if (end - opt <= 10)
		msg.peer_id = htonl(atoi(opt)); // It's a PEER-ID
	else // ..or a hex address
		msg.addr = htobe128(GS_hexto128(opt)); // FIXME, convert hex to addr

	CLI_msg(g_cli, &msg, sizeof msg);
}

///////////////// DP

static void
cmd_nocmd(char *opt, char *end)
{
	NOCMD_PRINT();
}

static void
cmd_exit(char *opt_notused, char *end)
{
	printf("[Bye]\n");
	exit(0);
}

static void
print_prompt(void)
{
	if (g_is_tty)
		printf(D_RED(PROMPT));

	fflush(stdout);
}

static void
cmd_help_list(char *opt, char *end)
{
	//  for i in 6a 6b 6c 6d 6e 71 74 75 76 77 78; do printf "0x$i \x$i \x1b(0\x$i\x1b(B\n"; done
	printf(""
"all            - list all connections\n"
"server         - list listening servers\n"
"client         - list connected clients\n"
"bad            - list bad peers\n"
"Note:             HSXFLWAI\n"
"    Domain prefix ┘││││││└─ Minor Version\n"
"      SRP enabled ─┘││││└── Major Version\n"
" Client or Server ──┘││└─── Client Waiting\n"
"     Fast Connect ───┘└──── Low Latency (interactive)\n"
"");

	print_prompt();
}

static void
cmd_help_set(char *opt, char *end)
{
	printf(""
"proto <x.y>       - Set minimum accepted protocol version\n"
"log.ip [0/1]      - Toggle IP logging\n"
"log.verbose [012] - Set verbosity level\n"
"port.cli <port>   - Change CLI listening Port\n"
"");

	print_prompt();
}

static void
cmd_help(char *opt, char *end)
{
	DP_TRYCALL_NESTED(opt, end, dp_help);

	printf(""
"help              - this help. Try 'help [command]' for details.\n"
"stats             - Show statistics.\n"
"list              - list all peers\n"
"stop listen tcp   - Stop accepting GSRN connections (TCP & SSL)\n"
"kill <id/addr>    - Disconnect peer by id or address\n"
"set               - Toggle settings\n"
"shutdown [timer]  - Disconnect GS-listeners\n"
"quit              - Quit\n"
"");

	print_prompt();
}

static void
cb_read_stdin(int fd, short what, void *arg)
{
	char *l;
	size_t len;
	int ret;

	ret = evbuffer_read(g_evb, fd, -1 /*all available*/);
	if (ret <= 0)
	{
		if (!g_is_tty)
			exit(0);
		ERREXIT("read(%d)=%d: %s\n", fd, ret, strerror(errno));
	}

	while (1)
	{
		l = evbuffer_readln(g_evb, &len, EVBUFFER_EOL_CRLF);
		if (l == NULL)
			break;

		if (*l == '\0')
			print_prompt();
		// DEBUGF("line='%s'\n", l);
		dispatch(l, l+len, dps, sizeof dps / sizeof *dps);
		free(l);
	}
}

static void
cb_cli_log(struct evbuffer *eb, size_t len, void *arg)
{
	// struct _cli *c = (struct _cli *)arg;

	DEBUGF("Received a log message from gsrnd.\n");
}

static void
cb_cli_list_r(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli_list_r msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	if (msg.flags & GSRN_FL_CLI_LIST_START)
		printf("[       ID] Address                          HSXFLWAI State     Age Server Address        - Client Address        (  idle) Traffic [      bps]\n");
	//          [        4] 435701b27bf6e7467bef67fb3a4f2c17 a-----11 LISTEN     2s 10.0.2.2:521          - 10.0.2.2:526          (    2s)   2.6KB [  1.3KB/s]
	//          [        4] 435701b27bf6e7467bef67fb3a4f2c17 zSXFLW12 ESTABL 99h05m 123.456.789.123:65123 - 111.222.333.444:64567 (99h03m)   2.6KB [  1.3KB/s]

	uint8_t hostname_id;
	hostname_id = GS_ADDR_get_hostname_id((uint8_t *)&msg.addr); // Network Byte Order
	msg.peer_id = ntohl(msg.peer_id);
	msg.in_n = ntohll(msg.in_n);
	msg.out_n = ntohll(msg.out_n);

	uint32_t age_sec = htonl(msg.age_sec);

	char traffic[16];
	GS_format_bps(traffic, sizeof traffic, msg.in_n + msg.out_n, NULL);

	msg.bps[sizeof msg.bps - 1] = '\0';

	char since[GS_SINCE_MAXSIZE];
	GS_format_since(since, sizeof since, age_sec);

	char idle[GS_SINCE_MAXSIZE];
	GS_format_since(idle, sizeof idle, ntohl(msg.idle_sec));

	char ipport[32];
	uint32_t ip;
	memcpy(&ip, &msg.ip, sizeof ip);
	snprintf(ipport, sizeof ipport, "%s:%u", int_ntoa(ip), ntohs(msg.port));

	printf("[%9u] %32s %c%7.7s %s %*s %-21s", msg.peer_id, GS_addr2hex(NULL, &msg.addr), 'a'+hostname_id, msg.flagstr, PEER_L_name(msg.pl_id), GS_SINCE_MAXSIZE - 1, since, ipport);

	if (msg.buddy_port != 0)
	{
		memcpy(&ip, &msg.buddy_ip, sizeof ip); // align
		snprintf(ipport, sizeof ipport, "%s:%u", int_ntoa(ip), ntohs(msg.buddy_port));
		printf(" - %-21s (%*s) %s [%s/s] \n", ipport, GS_SINCE_MAXSIZE - 1, idle, traffic, msg.bps);
	} else {
		printf("\n");
	}
}

static void
printt(const char *prefix, uint64_t usec)
{
	char buf[64];
	time_t t = time(NULL);
	time_t sec = GS_USEC_TO_SEC(usec);
	time_t msec = GS_USEC_TO_MSEC(usec);

	t = t - sec;

	char *cstr = asctime(gmtime(&t));
	cstr[strcspn(cstr, "\r\n")] = 0;

	printf("%s%s UTC; %s; %.03f sec\n", prefix, cstr, GS_format_since(buf, sizeof buf, sec), (float)msec / 1000);
}

static void
cb_cli_stats_r(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli_stats_r msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	printt("Uptime      : ", msg.uptime_usec);
	printt("Period      : ", msg.since_reset_usec);
	printf("GS-Listen   : %"PRIu64"\n", msg.n_gs_listen);
	printf("GS-Bad Auth : %"PRIu64"\n", msg.n_bad_auth);
	printf("GS-Connect  : %"PRIu64"\n", msg.n_gs_connect);
	printf("GS-Refused  : %"PRIu64"\n", msg.n_gs_refused);
	printf("Listening   : %"PRIu32"\n", msg.n_peers_listening);
	printf("Connected   : %"PRIu32"\n", msg.n_peers_connected);
	printf("BadAuthWait : %"PRIu32"\n", msg.n_peers_badauthwait);
	printf("Waiting     : %"PRId32"\n", msg.n_peers_total - (msg.n_peers_listening + msg.n_peers_connected + msg.n_peers_badauthwait));

	print_prompt();
}

// Variable legnth
static void
cb_cli_msg(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli_msg msg;
	char buf[len - sizeof msg + 1];

	evbuffer_remove(eb, &msg, GSRN_CLI_HDR_TLV_SIZE);
	evbuffer_remove(eb, buf, len - GSRN_CLI_HDR_TLV_SIZE);
	buf[sizeof buf - 1] = '\0';

	// An empty string triggers just the prompt but no output or \n
	if (buf[0] != '\0')
		printf("%s\n", buf);

	print_prompt();
}

void
init_engine(void)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(gopt.ip_cli);
	addr.sin_port = htons(gopt.port_cli);

	g_is_tty = isatty(STDIN_FILENO);
	g_cli = CLI_new(-1, NULL, 0 /*is_server*/);
	bufferevent_socket_connect(g_cli->bev, (struct sockaddr *)&addr, sizeof addr);

	PKT_setcb(&g_cli->pkt, GSRN_CLI_TYPE_LOG, 0 /*variable lenght*/, cb_cli_log, g_cli);
	PKT_setcb(&g_cli->pkt, GSRN_CLI_TYPE_LIST_RESPONSE, sizeof (struct _cli_list_r), cb_cli_list_r, g_cli);
	PKT_setcb(&g_cli->pkt, GSRN_CLI_TYPE_MSG, 0 /*variable length*/, cb_cli_msg, g_cli);
	PKT_setcb(&g_cli->pkt, GSRN_CLI_TYPE_STATS_RESPONSE, sizeof (struct _cli_stats_r), cb_cli_stats_r, g_cli);

	g_evb = evbuffer_new();
	g_ev_stdin = event_new(gopt.evb, STDIN_FILENO, EV_READ | EV_PERSIST, cb_read_stdin, NULL);
	event_add(g_ev_stdin, NULL);

	print_prompt();
}
