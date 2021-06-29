#if 0

A packet dispatch stack.

Most of the time, an application wants to perform certain action when receiving a certain
message.

The caller can configure the stack to have callbacks called when certain messages
are received.

Fixed length messages and TLV (Type-Lengt-Value) messages are supported.

The callbacks are set with PKT_setcb() and removed with PKT_delcb().

Type type field is 8 bit and the optional length field is 16 bit (or 0 bit for
fixed length messages).
#endif

#include "common.h"
#include "utils.h"
#include "packet.h"
#include "gopt.h"

static void
cb_dummy(struct evbuffer *eb, size_t len, void *arg)
{
#ifdef DEBUG
	PKT *pkt = (PKT *)arg;

	DEBUGF_R("Unhandled function for type %u\n", pkt->type);
#endif
	evbuffer_drain(eb, len);
}


int
PKT_init(PKT *pkt)
{
	memset(pkt, 0, sizeof *pkt);
	int i;

	for (i = 0; i < sizeof pkt->funcs / sizeof *pkt->funcs; i++)
	{
		PKT_delcb(pkt, i);
	}

	pkt->is_init = 1;
	return 0;
}

// Redirect all packets to nirvana but keeping all type's and length fields intact.
void
PKT_set_void(PKT *pkt)
{
	int i;

	for (i = 0; i < sizeof pkt->funcs / sizeof *pkt->funcs; i++)
	{
		pkt->funcs[i] = NULL;
	}
}

PKT *
PKT_new(void)
{
	PKT *pkt;

	pkt = malloc(sizeof *pkt);
	if (pkt == NULL)
		goto err;

	pkt->is_malloc = 1;
	if (PKT_init(pkt) != 0)
		goto err;

	return pkt;
err:
	XFREE(pkt);
	return NULL;
}

void
PKT_free(PKT *pkt)
{
	pkt->is_init = 0;

	if (pkt->is_malloc)
	{
		free(pkt);
	}
}

// Set a callback for message type. 2 kinds of messages are supported:
// Fixed length messsage (len != 0) or a variable length message (TLV; len == 0).
// The format of the (incoming) messages shall look like this:
//
// A. [ 1 octet type ] [ value ]
// B. [ 1 octet type ] [ 2 octet length ] [ variable lenght value ]
//
// The message is expected to be of len length or of variable length if len is
// set to 0.
void
PKT_setcb(PKT *pkt, uint8_t type, size_t len, pkt_cb_t func, void *arg)
{
	if (type == 0)
		return;

	pkt->funcs[type] = func;
	pkt->args[type] = arg;
	pkt->lengths[type] = len;
}

void
PKT_delcb(PKT *pkt, uint8_t type)
{
	PKT_setcb(pkt, type, 0 /*variable*/, cb_dummy, pkt);
}

// Dispatch a single packet (try if there is sufficient data in eb)
static int
dispatch(PKT *pkt, struct evbuffer *eb)
{
	size_t eb_sz;
	size_t ex_len = 0; // expected length
	eb_sz = evbuffer_get_length(eb);

	if (eb_sz <= 0)
		goto more_data;

	if (pkt->type == 0)
	{
		uint8_t type;
		evbuffer_copyout(eb, &type, 1);

		// Set the length we need. This is 0 for packets that have
		// variable length and are of format TLV
		// [ 1 octet Type | 2 octet length | value ]
		ex_len = pkt->lengths[type];
		if (ex_len == 0)
		{
			// HERE: It's a variable length message (TLV)
			if (eb_sz < 3)
				goto more_data;
			uint16_t len;
			#if 0
			struct evbuffer_ptr ev_pos;
			evbuffer_ptr_set(eb, &ev_pos, 1, EVBUFFER_PTR_SET);
			evbuffer_copyout_from(eb, &ev_pos, &len, sizeof len);
			#endif
			uint8_t buf[3];
			evbuffer_copyout(eb, buf, 3);
			memcpy(&len, buf+1, sizeof len);
			ex_len = ntohs(len) + 3;
			// DEBUGF("type=%u Variable Lenght=%zu\n", type, ex_len);
		}

		pkt->type = type;
	}

	if (eb_sz < ex_len)
		goto more_data;

	// Call Callback
	// DEBUGF_G("Calling for type=%u ex_len=%zu\n", pkt->type, ex_len);
	if (pkt->funcs[pkt->type] != NULL)
		(*pkt->funcs[pkt->type])(eb, ex_len, pkt->args[pkt->type]);

	if (evbuffer_get_length(eb) == eb_sz)
	{
		// Remove data if caller did not remove the data already.
		// (e.g. for dummy calls or if funcs == NULL)
		evbuffer_drain(eb, ex_len);
	}
	pkt->type = 0;

	return 0;
more_data:

	return -1;
}

void
PKT_dispatch(PKT *pkt, struct evbuffer *eb)
{
	int ret;

	// Maybe
	while (1)
	{
		ret = dispatch(pkt, eb);
		if (ret != 0)
			break;
		// The callback might call PKT_free() to stop processing
		// packets. This happens when an GS-ACCEPT is received (which is the
		// last valid PKT message) but the bufferevent subsystem read part
		// client's SRP handshake already...do not process this with PKT_dispatch()...
		if (pkt->is_init == 0)
			break;
	}
}
