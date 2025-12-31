//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <string.h>

#include "core/nng_impl.h"
#include "nng/protocol/reqrep0/rep.h"

typedef struct xrep0_pipe xrep0_pipe;
typedef struct xrep0_sock xrep0_sock;

static void xrep0_sock_getq_cb(void *);
static void xrep0_pipe_getq_cb(void *);
static void xrep0_pipe_putq_cb(void *);
static void xrep0_pipe_send_cb(void *);
static void xrep0_pipe_recv_cb(void *);
static void xrep0_pipe_fini(void *);

struct xrep0_sock {
	nni_msgq *     uwq;
	nni_msgq *     urq;
	nni_mtx        lk;
	nni_atomic_int ttl;
	nni_id_map     pipes;
	nni_aio        aio_getq;
};

struct xrep0_pipe {
	nni_pipe *  pipe;
	xrep0_sock *rep;
	nni_msgq *  sendq;
	nni_aio     aio_getq;
	nni_aio     aio_send;
	nni_aio     aio_recv;
	nni_aio     aio_putq;
};

static void
xrep0_sock_fini(void *arg)
{
	xrep0_sock *s = arg;

	nni_aio_fini(&s->aio_getq);
	nni_id_map_fini(&s->pipes);
	nni_mtx_fini(&s->lk);
}

static void
xrep0_sock_init(void *arg, nni_sock *sock)
{
	xrep0_sock *s = arg;

	nni_mtx_init(&s->lk);
	nni_aio_init(&s->aio_getq, xrep0_sock_getq_cb, s);
	nni_atomic_init(&s->ttl);
	nni_atomic_set(&s->ttl, 8);
	s->uwq = nni_sock_sendq(sock);
	s->urq = nni_sock_recvq(sock);

	nni_id_map_init(&s->pipes, 0, 0, false);
}

static void
xrep0_sock_open(void *arg)
{
	xrep0_sock *s = arg;

	nni_msgq_aio_get(s->uwq, &s->aio_getq);
}

static void
xrep0_sock_close(void *arg)
{
	xrep0_sock *s = arg;

	nni_aio_close(&s->aio_getq);
}

static void
xrep0_pipe_stop(void *arg)
{
	xrep0_pipe *p = arg;

	nni_aio_stop(&p->aio_getq);
	nni_aio_stop(&p->aio_send);
	nni_aio_stop(&p->aio_recv);
	nni_aio_stop(&p->aio_putq);
}

static void
xrep0_pipe_fini(void *arg)
{
	xrep0_pipe *p = arg;

	nni_aio_fini(&p->aio_getq);
	nni_aio_fini(&p->aio_send);
	nni_aio_fini(&p->aio_recv);
	nni_aio_fini(&p->aio_putq);
	nni_msgq_fini(p->sendq);
}

static int
xrep0_pipe_init(void *arg, nni_pipe *pipe, void *s)
{
	xrep0_pipe *p = arg;
	int         rv;

	nni_aio_init(&p->aio_getq, xrep0_pipe_getq_cb, p);
	nni_aio_init(&p->aio_send, xrep0_pipe_send_cb, p);
	nni_aio_init(&p->aio_recv, xrep0_pipe_recv_cb, p);
	nni_aio_init(&p->aio_putq, xrep0_pipe_putq_cb, p);

	p->pipe = pipe;
	p->rep  = s;

	if ((rv = nni_msgq_init(&p->sendq, 64)) != 0) {
		xrep0_pipe_fini(p);
		return (rv);
	}
	return (0);
}

static int
xrep0_pipe_start(void *arg)
{
	xrep0_pipe *p = arg;
	xrep0_sock *s = p->rep;
	int         rv;

	if (nni_pipe_peer(p->pipe) != NNG_REP0_PEER) {
		return (NNG_EPROTO);
	}

	nni_mtx_lock(&s->lk);
	rv = nni_id_set(&s->pipes, nni_pipe_id(p->pipe), p);
	nni_mtx_unlock(&s->lk);
	if (rv != 0) {
		return (rv);
	}

	nni_msgq_aio_get(p->sendq, &p->aio_getq);
	nni_pipe_recv(p->pipe, &p->aio_recv);
	return (0);
}

static void
xrep0_pipe_close(void *arg)
{
	xrep0_pipe *p = arg;
	xrep0_sock *s = p->rep;

	nni_aio_close(&p->aio_getq);
	nni_aio_close(&p->aio_send);
	nni_aio_close(&p->aio_recv);
	nni_aio_close(&p->aio_putq);
	nni_msgq_close(p->sendq);

	nni_mtx_lock(&s->lk);
	nni_id_remove(&s->pipes, nni_pipe_id(p->pipe));
	nni_mtx_unlock(&s->lk);
}

static void
xrep0_sock_getq_cb(void *arg)
{
	xrep0_sock *s   = arg;
	nni_msgq *  uwq = s->uwq;
	nni_msg *   msg;
	uint32_t    id;
	xrep0_pipe *p;

	if (nni_aio_result(&s->aio_getq) != 0) {
		return;
	}

	msg = nni_aio_get_msg(&s->aio_getq);
	nni_aio_set_msg(&s->aio_getq, NULL);

	if (nni_msg_header_len(msg) < 4) {
		nni_msg_free(msg);

		nni_msgq_aio_get(uwq, &s->aio_getq);
		return;
	}

	id = nni_msg_header_trim_u32(msg);

	nni_mtx_lock(&s->lk);
	if (((p = nni_id_get(&s->pipes, id)) == NULL) ||
	    (nni_msgq_tryput(p->sendq, msg) != 0)) {
		nni_msg_free(msg);
	}
	nni_mtx_unlock(&s->lk);

	nni_msgq_aio_get(uwq, &s->aio_getq);
}

static void
xrep0_pipe_getq_cb(void *arg)
{
	xrep0_pipe *p = arg;

	if (nni_aio_result(&p->aio_getq) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	nni_aio_set_msg(&p->aio_send, nni_aio_get_msg(&p->aio_getq));
	nni_aio_set_msg(&p->aio_getq, NULL);

	nni_pipe_send(p->pipe, &p->aio_send);
}

static void
xrep0_pipe_send_cb(void *arg)
{
	xrep0_pipe *p = arg;

	if (nni_aio_result(&p->aio_send) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_send));
		nni_aio_set_msg(&p->aio_send, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_msgq_aio_get(p->sendq, &p->aio_getq);
}

static void
xrep0_pipe_recv_cb(void *arg)
{
	xrep0_pipe *p = arg;
	xrep0_sock *s = p->rep;
	nni_msg *   msg;
	int         hops;
	int         ttl;

	if (nni_aio_result(&p->aio_recv) != 0) {
		nni_pipe_close(p->pipe);
		return;
	}

	ttl = nni_atomic_get(&s->ttl);

	msg = nni_aio_get_msg(&p->aio_recv);
	nni_aio_set_msg(&p->aio_recv, NULL);

	nni_msg_set_pipe(msg, nni_pipe_id(p->pipe));

	nni_msg_header_append_u32(msg, nni_pipe_id(p->pipe));

	hops = 1;
	for (;;) {
		bool     end;
		uint8_t *body;
		if (hops > ttl) {
			goto drop;
		}
		hops++;
		if (nni_msg_len(msg) < 4) {
			nni_msg_free(msg);
			nni_pipe_close(p->pipe);
			return;
		}
		body = nni_msg_body(msg);
		end  = ((body[0] & 0x80u) != 0);
		if (nni_msg_header_append(msg, body, 4) != 0) {
			goto drop;
		}
		nni_msg_trim(msg, 4);
		if (end) {
			break;
		}
	}

	nni_aio_set_msg(&p->aio_putq, msg);
	nni_msgq_aio_put(s->urq, &p->aio_putq);
	return;

drop:
	nni_msg_free(msg);
	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static void
xrep0_pipe_putq_cb(void *arg)
{
	xrep0_pipe *p = arg;

	if (nni_aio_result(&p->aio_putq) != 0) {
		nni_msg_free(nni_aio_get_msg(&p->aio_putq));
		nni_aio_set_msg(&p->aio_putq, NULL);
		nni_pipe_close(p->pipe);
		return;
	}

	nni_pipe_recv(p->pipe, &p->aio_recv);
}

static int
xrep0_sock_set_maxttl(void *arg, const void *buf, size_t sz, nni_opt_type t)
{
	xrep0_sock *s = arg;
	int         ttl;
	int         rv;
	if ((rv = nni_copyin_int(&ttl, buf, sz, 1, NNI_MAX_MAX_TTL, t)) == 0) {
		nni_atomic_set(&s->ttl, ttl);
	}
	return (rv);
}

static int
xrep0_sock_get_maxttl(void *arg, void *buf, size_t *szp, nni_opt_type t)
{
	xrep0_sock *s = arg;
	return (nni_copyout_int(nni_atomic_get(&s->ttl), buf, szp, t));
}

static void
xrep0_sock_send(void *arg, nni_aio *aio)
{
	xrep0_sock *s = arg;

	nni_msgq_aio_put(s->uwq, aio);
}

static void
xrep0_sock_recv(void *arg, nni_aio *aio)
{
	xrep0_sock *s = arg;

	nni_msgq_aio_get(s->urq, aio);
}

static nni_proto_pipe_ops xrep0_pipe_ops = {
	.pipe_size  = sizeof(xrep0_pipe),
	.pipe_init  = xrep0_pipe_init,
	.pipe_fini  = xrep0_pipe_fini,
	.pipe_start = xrep0_pipe_start,
	.pipe_close = xrep0_pipe_close,
	.pipe_stop  = xrep0_pipe_stop,
};

static nni_option xrep0_sock_options[] = {
	{
	    .o_name = NNG_OPT_MAXTTL,
	    .o_get  = xrep0_sock_get_maxttl,
	    .o_set  = xrep0_sock_set_maxttl,
	},
	{
	    .o_name = NULL,
	},
};

static nni_proto_sock_ops xrep0_sock_ops = {
	.sock_size    = sizeof(xrep0_sock),
	.sock_init    = xrep0_sock_init,
	.sock_fini    = xrep0_sock_fini,
	.sock_open    = xrep0_sock_open,
	.sock_close   = xrep0_sock_close,
	.sock_options = xrep0_sock_options,
	.sock_send    = xrep0_sock_send,
	.sock_recv    = xrep0_sock_recv,
};

static nni_proto xrep0_proto = {
	.proto_version  = NNI_PROTOCOL_VERSION,
	.proto_self     = { NNG_REP0_SELF, NNG_REP0_SELF_NAME },
	.proto_peer     = { NNG_REP0_PEER, NNG_REP0_PEER_NAME },
	.proto_flags    = NNI_PROTO_FLAG_SNDRCV | NNI_PROTO_FLAG_RAW,
	.proto_sock_ops = &xrep0_sock_ops,
	.proto_pipe_ops = &xrep0_pipe_ops,
};

int
nng_rep0_open_raw(nng_socket *sidp)
{
	return (nni_proto_open(sidp, &xrep0_proto));
}
