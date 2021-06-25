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

typedef void (*dp_func_t)(char *line, char *end);

static void cmd_default(char *opt, char *end);
static void cmd_help(char *opt, char *end);
static void cmd_list(char *opt, char *end);
static void cmd_exit(char *opt, char *end);

static void cmd_list_default(char *opt_notused, char *end);
static void cmd_list_server(char *opt, char *end);
static void cmd_list_client(char *opt, char *end);


// tuples of 'cmd-string' <=> 'function' 
struct dp
{
	char *cmd;
	dp_func_t func;
};

struct dp dps[] = {
	{ NULL      , cmd_default}, // default action if cmd not found
	{ "help"    , cmd_help},
	{ "list"    , cmd_list},
	{ "ls"      , cmd_list},    // 'list' can have nested commands
	{ "exit"    , cmd_exit},
	{ "quit"    , cmd_exit}
};

// nested 'list' commands
struct dp dp_list[] = {
	{ NULL      , cmd_list_default}, // default action if cmd not found
	{ "server"  , cmd_list_server},
	{ "client"  , cmd_list_client}
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

////////////////// DP-LIST

static void
cmd_list_default(char *opt_notused, char *end)
{
	printf("Unknown command. Try 'help list'.\n");
	fflush(stdout);
}

static void
cmd_list_server(char *opt, char *end)
{
	DEBUGF("list servers...\n");

}

static void
cmd_list_client(char *opt, char *end)
{

}

static void
cmd_list(char *opt, char *end)
{

	if (end - opt > 0)
	{
		dispatch(opt, end, dp_list, sizeof dp_list / sizeof *dp_list);
		return;
	}

	// HERE: 'list' command without parameters.	
	CLI_send(g_cli, GSRN_CLI_TYPE_LIST, 0, NULL);
}


///////////////// DP

static void
cmd_default(char *opt_notused, char *end)
{
	printf("Unknown command. Try 'help'.\n");
	fflush(stdout);
}

static void
cmd_exit(char *opt_notused, char *end)
{
	printf("[Bye]\n");
	exit(0);
}

static void
cmd_help(char *opt, char *end)
{
	DEBUGF_Y("called (%s)\n", opt);

}

static void
cb_read_stdin(int fd, short what, void *arg)
{
	char *l;
	size_t len;
	int ret;

	ret = evbuffer_read(g_evb, fd, -1 /*all available*/);
	if (ret <= 0)
		ERREXIT("read(): %s\n", strerror(errno));

	while (1)
	{
		l = evbuffer_readln(g_evb, &len, EVBUFFER_EOL_CRLF);
		if (l == NULL)
			break;

		// DEBUGF("line='%s'\n", l);
		dispatch(l, l+len+1, dps, sizeof dps / sizeof *dps);
		free(l);
	}
	printf(PROMPT); fflush(stdout);
}

static void
cb_cli_log(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli *c = (struct _cli *)arg;

	DEBUGF("Received a log message from gsrnd.\n");
}

#define net_extract(name, confunc, src)  do{ memcpy(&name, src, sizeof name); name = confunc(name); }while(0)
static void
cb_cli_list_r(struct evbuffer *eb, size_t len, void *arg)
{
	struct _cli_list_r msg;

	evbuffer_remove(eb, &msg, sizeof msg);

	if (msg.flags & GSRN_FL_CLI_LIST_FIRSTCALL)
		printf("[    ID] Address                          State     Age Server Address        - Client Address        (  idle) Traffic [      bps]\n");
	//          [     4] 435701b27bf6e7467bef67fb3a4f2c17 LISTEN     2s 10.0.2.2:521          - 10.0.2.2:526          (    2s)   2.6KB [  1.3KB/s]
	//          [     4] 435701b27bf6e7467bef67fb3a4f2c17 ESTABL 99h05m 123.456.789.123:65123 - 111.222.333.444:64567 (99h03m)   2.6KB [  1.3KB/s]

	// uint128_t addr;
	// net_extract(addr, htobe128, &msg.addr);

	msg.addr = htobe128(msg.addr);
	msg.peer_id = ntohl(msg.peer_id);
	msg.in_n = ntohll(msg.in_n);
	msg.out_n = ntohll(msg.out_n);

	uint32_t age_sec = htonl(msg.age_sec);

	char valstr[64]; strx128(msg.addr, valstr, sizeof valstr);

	char traffic[16];
	GS_format_bps(traffic, sizeof traffic, msg.in_n + msg.out_n, NULL);

	msg.bps[sizeof msg.bps - 1] = '\0';

	char since[GS_SINCE_MAXSIZE];
	GS_format_since(since, sizeof since, age_sec);

	char idle[GS_SINCE_MAXSIZE];
	GS_format_since(idle, sizeof idle, ntohl(msg.idle_sec));

	char ipport[32];
	snprintf(ipport, sizeof ipport, "%s:%u", int_ntoa(msg.ip), ntohs(msg.port));

	printf("[%6u] %32s %s %*s %-21s", msg.peer_id, valstr, PEER_L_name(msg.pl_id), GS_SINCE_MAXSIZE - 1, since, ipport);

	if (msg.buddy_port != 0)
	{
		snprintf(ipport, sizeof ipport, "%s:%u", int_ntoa(msg.buddy_ip), ntohs(msg.buddy_port));
		printf(" - %-21s (%*s) %s [%s/s] \n", ipport, GS_SINCE_MAXSIZE - 1, idle, traffic, msg.bps);
	} else {
		printf("\n");
	}
}


// static void
// testme()
// {
// 	ssize_t n;
// 	int32_t sec;

// 	char buf[128];
// 	char since[7];
// 	while (1)
// 	{
// 		n = read(0, buf, sizeof buf);
// 		if (n <= 0)
// 			break;

// 		sec = atoi(buf);
// 		printf("%d -> %s\n", sec, GS_format_since(since, sizeof since, sec));
// 	}
// 	exit(0);
// }

void
init_engine(void)
{
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(gopt.ip_cli);
	addr.sin_port = htons(gopt.port_cli);

	g_cli = CLI_new(-1, NULL, 0 /*is_server*/);
	bufferevent_socket_connect(g_cli->bev, (struct sockaddr *)&addr, sizeof addr);

	PKT_setcb(&g_cli->pkt, GSRN_CLI_TYPE_LOG, 0, cb_cli_log, g_cli);
	PKT_setcb(&g_cli->pkt, GSRN_CLI_TYPE_LIST_RESPONSE, sizeof (struct _cli_list_r), cb_cli_list_r, g_cli);

	g_evb = evbuffer_new();
	event_assign(&gcli.ev_stdin, gopt.evb, 0 /*stdin*/, EV_READ | EV_PERSIST, cb_read_stdin, NULL);
	event_add(&gcli.ev_stdin, NULL);

	printf(PROMPT); fflush(stdout);
}
