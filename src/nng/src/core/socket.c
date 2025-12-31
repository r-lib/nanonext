//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "list.h"
#include "nng/supplemental/tls/tls.h"
#include "sockimpl.h"

#include <stdio.h>
#include <string.h>

struct nni_ctx {
	nni_list_node     c_node;
	nni_sock         *c_sock;
	nni_proto_ctx_ops c_ops;
	void             *c_data;
	size_t            c_size;
	bool              c_closed;
	unsigned          c_ref;
	uint32_t          c_id;
	nng_duration      c_sndtimeo;
	nng_duration      c_rcvtimeo;
};

typedef struct nni_sockopt {
	nni_list_node node;
	char         *name;
	nni_type      typ;
	size_t        sz;
	void         *data;
} nni_sockopt;

typedef struct nni_sock_pipe_cb {
	nng_pipe_cb cb_fn;
	void       *cb_arg;
} nni_sock_pipe_cb;

struct nni_socket {
	nni_list_node s_node;
	nni_mtx       s_mx;
	nni_cv        s_cv;
	nni_cv        s_close_cv;

	uint32_t s_id;
	uint32_t s_flags;
	unsigned s_ref;
	void    *s_data;
	size_t   s_size;

	nni_msgq *s_uwq;
	nni_msgq *s_urq;

	nni_proto_id s_self_id;
	nni_proto_id s_peer_id;

	nni_proto_pipe_ops s_pipe_ops;
	nni_proto_sock_ops s_sock_ops;
	nni_proto_ctx_ops  s_ctx_ops;

	nni_duration s_sndtimeo;
	nni_duration s_rcvtimeo;
	nni_duration s_reconn;
	nni_duration s_reconnmax;
	size_t       s_rcvmaxsz;
	nni_list     s_options;
	char         s_name[64];

	nni_list s_listeners;
	nni_list s_dialers;
	nni_list s_pipes;
	nni_list s_ctxs;

	bool s_closing;
	bool s_closed;

	nni_mtx          s_pipe_cbs_mtx;
	nni_sock_pipe_cb s_pipe_cbs[NNG_PIPE_EV_NUM];

#ifdef NNG_ENABLE_STATS
	nni_stat_item st_root;
	nni_stat_item st_id;
	nni_stat_item st_name;
	nni_stat_item st_protocol;
	nni_stat_item st_dialers;
	nni_stat_item st_listeners;
	nni_stat_item st_pipes;
	nni_stat_item st_rx_bytes;
	nni_stat_item st_tx_bytes;
	nni_stat_item st_rx_msgs;
	nni_stat_item st_tx_msgs;
	nni_stat_item st_rejects;
#endif
};

static nni_list sock_list  = NNI_LIST_INITIALIZER(sock_list, nni_sock, s_node);
static nni_mtx  sock_lk    = NNI_MTX_INITIALIZER;
static nni_id_map sock_ids = NNI_ID_MAP_INITIALIZER(1, 0x7fffffff, 0);
static nni_id_map ctx_ids  = NNI_ID_MAP_INITIALIZER(1, 0x7fffffff, 0);

static void nni_ctx_destroy(nni_ctx *);

#define SOCK(s) ((nni_sock *) (s))

static int
sock_get_fd(void *s, unsigned flag, int *fdp)
{
	int           rv;
	nni_pollable *p;

	if ((flag & nni_sock_flags(SOCK(s))) == 0) {
		return (NNG_ENOTSUP);
	}

	if (flag == NNI_PROTO_FLAG_SND) {
		rv = nni_msgq_get_sendable(SOCK(s)->s_uwq, &p);
	} else {
		rv = nni_msgq_get_recvable(SOCK(s)->s_urq, &p);
	}

	if (rv == 0) {
		rv = nni_pollable_getfd(p, fdp);
	}

	return (rv);
}

static int
sock_get_sendfd(void *s, void *buf, size_t *szp, nni_type t)
{
	int fd;
	int rv;

	if ((rv = sock_get_fd(SOCK(s), NNI_PROTO_FLAG_SND, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
sock_get_recvfd(void *s, void *buf, size_t *szp, nni_type t)
{
	int fd;
	int rv;

	if ((rv = sock_get_fd(SOCK(s), NNI_PROTO_FLAG_RCV, &fd)) != 0) {
		return (rv);
	}
	return (nni_copyout_int(fd, buf, szp, t));
}

static int
sock_get_raw(void *s, void *buf, size_t *szp, nni_type t)
{
	bool raw = ((nni_sock_flags(SOCK(s)) & NNI_PROTO_FLAG_RAW) != 0);
	return (nni_copyout_bool(raw, buf, szp, t));
}

static int
sock_set_recvtimeo(void *s, const void *buf, size_t sz, nni_type t)
{
	return (nni_copyin_ms(&SOCK(s)->s_rcvtimeo, buf, sz, t));
}

static int
sock_get_recvtimeo(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_ms(SOCK(s)->s_rcvtimeo, buf, szp, t));
}

static int
sock_set_sendtimeo(void *s, const void *buf, size_t sz, nni_type t)
{
	return (nni_copyin_ms(&SOCK(s)->s_sndtimeo, buf, sz, t));
}

static int
sock_get_sendtimeo(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_ms(SOCK(s)->s_sndtimeo, buf, szp, t));
}

static int
sock_set_recvbuf(void *s, const void *buf, size_t sz, nni_type t)
{
	int len;
	int rv;

	if ((rv = nni_copyin_int(&len, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	return (nni_msgq_resize(SOCK(s)->s_urq, len));
}

static int
sock_get_recvbuf(void *s, void *buf, size_t *szp, nni_type t)
{
	int len = nni_msgq_cap(SOCK(s)->s_urq);

	return (nni_copyout_int(len, buf, szp, t));
}

static int
sock_set_sendbuf(void *s, const void *buf, size_t sz, nni_type t)
{
	int len;
	int rv;

	if ((rv = nni_copyin_int(&len, buf, sz, 0, 8192, t)) != 0) {
		return (rv);
	}
	return (nni_msgq_resize(SOCK(s)->s_uwq, len));
}

static int
sock_get_sendbuf(void *s, void *buf, size_t *szp, nni_type t)
{
	int len = nni_msgq_cap(SOCK(s)->s_uwq);

	return (nni_copyout_int(len, buf, szp, t));
}

static int
sock_get_sockname(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_str(SOCK(s)->s_name, buf, szp, t));
}

static int
sock_set_sockname(void *s, const void *buf, size_t sz, nni_type t)
{
	int rv;
	rv = (nni_copyin_str(
	    SOCK(s)->s_name, buf, sizeof(SOCK(s)->s_name), sz, t));
#ifdef NNG_ENABLE_STATS
	if (rv == 0) {
		nni_stat_set_string(&SOCK(s)->st_name, SOCK(s)->s_name);
	}
#endif
	return (rv);
}

static int
sock_get_proto(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_int(nni_sock_proto_id(SOCK(s)), buf, szp, t));
}

static int
sock_get_peer(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_int(nni_sock_peer_id(SOCK(s)), buf, szp, t));
}

static int
sock_get_protoname(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_str(nni_sock_proto_name(SOCK(s)), buf, szp, t));
}

static int
sock_get_peername(void *s, void *buf, size_t *szp, nni_type t)
{
	return (nni_copyout_str(nni_sock_peer_name(SOCK(s)), buf, szp, t));
}

static const nni_option sock_options[] = {
	{
	    .o_name = NNG_OPT_RECVTIMEO,
	    .o_get  = sock_get_recvtimeo,
	    .o_set  = sock_set_recvtimeo,
	},
	{
	    .o_name = NNG_OPT_SENDTIMEO,
	    .o_get  = sock_get_sendtimeo,
	    .o_set  = sock_set_sendtimeo,
	},
	{
	    .o_name = NNG_OPT_RECVFD,
	    .o_get  = sock_get_recvfd,
	},
	{
	    .o_name = NNG_OPT_SENDFD,
	    .o_get  = sock_get_sendfd,
	},
	{
	    .o_name = NNG_OPT_RECVBUF,
	    .o_get  = sock_get_recvbuf,
	    .o_set  = sock_set_recvbuf,
	},
	{
	    .o_name = NNG_OPT_SENDBUF,
	    .o_get  = sock_get_sendbuf,
	    .o_set  = sock_set_sendbuf,
	},
	{
	    .o_name = NNG_OPT_SOCKNAME,
	    .o_get  = sock_get_sockname,
	    .o_set  = sock_set_sockname,
	},
	{
	    .o_name = NNG_OPT_RAW,
	    .o_get  = sock_get_raw,
	},
	{
	    .o_name = NNG_OPT_PROTO,
	    .o_get  = sock_get_proto,
	},
	{
	    .o_name = NNG_OPT_PEER,
	    .o_get  = sock_get_peer,
	},
	{
	    .o_name = NNG_OPT_PROTONAME,
	    .o_get  = sock_get_protoname,
	},
	{
	    .o_name = NNG_OPT_PEERNAME,
	    .o_get  = sock_get_peername,
	},
	{
	    .o_name = NULL,
	},
};

static void
nni_free_opt(nni_sockopt *opt)
{
	if ((strcmp(opt->name, NNG_OPT_TLS_CONFIG) == 0) &&
	    (opt->sz == sizeof(nng_tls_config *))) {
		nng_tls_config_free(*(nng_tls_config **) (opt->data));
	}
	nni_strfree(opt->name);
	nni_free(opt->data, opt->sz);
	NNI_FREE_STRUCT(opt);
}

uint32_t
nni_sock_id(nni_sock *s)
{
	return (s->s_id);
}

nni_msgq *
nni_sock_sendq(nni_sock *s)
{
	return (s->s_uwq);
}

nni_msgq *
nni_sock_recvq(nni_sock *s)
{
	return (s->s_urq);
}

int
nni_sock_find(nni_sock **sockp, uint32_t id)
{
	int       rv;
	nni_sock *s;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock_lk);
	if ((s = nni_id_get(&sock_ids, id)) != NULL) {
		if (s->s_closed) {
			rv = NNG_ECLOSED;
		} else {
			s->s_ref++;
			*sockp = s;
		}
	} else {
		rv = NNG_ECLOSED;
	}
	nni_mtx_unlock(&sock_lk);

	return (rv);
}

void
nni_sock_hold(nni_sock *s)
{
	nni_mtx_lock(&sock_lk);
	s->s_ref++;
	nni_mtx_unlock(&sock_lk);
}

void
nni_sock_rele(nni_sock *s)
{
	nni_mtx_lock(&sock_lk);
	s->s_ref--;
	if (s->s_closed && (s->s_ref < 2)) {
		nni_cv_wake(&s->s_close_cv);
	}
	nni_mtx_unlock(&sock_lk);
}

#ifdef NNG_ENABLE_STATS
static void
sock_stat_init(nni_sock *s, nni_stat_item *item, const nni_stat_info *info)
{
	nni_stat_init(item, info);
	nni_stat_add(&s->st_root, item);
}

static void
sock_stats_init(nni_sock *s)
{
	static const nni_stat_info root_info = {
		.si_name = "socket",
		.si_desc = "socket statistics",
		.si_type = NNG_STAT_SCOPE,
	};
	static const nni_stat_info id_info = {
		.si_name = "id",
		.si_desc = "socket identifier",
		.si_type = NNG_STAT_ID,
	};
	static const nni_stat_info name_info = {
		.si_name  = "name",
		.si_desc  = "socket name",
		.si_type  = NNG_STAT_STRING,
		.si_alloc = true,
	};
	static const nni_stat_info protocol_info = {
		.si_name = "protocol",
		.si_desc = "socket protocol",
		.si_type = NNG_STAT_STRING,
	};
	static const nni_stat_info dialers_info = {
		.si_name   = "dialers",
		.si_desc   = "open dialers",
		.si_type   = NNG_STAT_LEVEL,
		.si_atomic = true,
	};
	static const nni_stat_info listeners_info = {
		.si_name   = "listeners",
		.si_desc   = "open listeners",
		.si_type   = NNG_STAT_LEVEL,
		.si_atomic = true,
	};
	static const nni_stat_info pipes_info = {
		.si_name   = "pipes",
		.si_desc   = "open pipes",
		.si_type   = NNG_STAT_LEVEL,
		.si_atomic = true,
	};
	static const nni_stat_info reject_info = {
		.si_name   = "reject",
		.si_desc   = "rejected pipes",
		.si_type   = NNG_STAT_COUNTER,
		.si_atomic = true,
	};
	static const nni_stat_info tx_msgs_info = {
		.si_name   = "tx_msgs",
		.si_desc   = "sent messages",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};
	static const nni_stat_info rx_msgs_info = {
		.si_name   = "rx_msgs",
		.si_desc   = "received messages",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_MESSAGES,
		.si_atomic = true,
	};
	static const nni_stat_info tx_bytes_info = {
		.si_name   = "tx_bytes",
		.si_desc   = "sent bytes",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_BYTES,
		.si_atomic = true,
	};
	static const nni_stat_info rx_bytes_info = {
		.si_name   = "rx_bytes",
		.si_desc   = "received messages",
		.si_type   = NNG_STAT_COUNTER,
		.si_unit   = NNG_UNIT_BYTES,
		.si_atomic = true,
	};

	nni_stat_init(&s->st_root, &root_info);
	sock_stat_init(s, &s->st_id, &id_info);
	sock_stat_init(s, &s->st_name, &name_info);
	sock_stat_init(s, &s->st_protocol, &protocol_info);
	sock_stat_init(s, &s->st_dialers, &dialers_info);
	sock_stat_init(s, &s->st_listeners, &listeners_info);
	sock_stat_init(s, &s->st_pipes, &pipes_info);
	sock_stat_init(s, &s->st_rejects, &reject_info);
	sock_stat_init(s, &s->st_tx_msgs, &tx_msgs_info);
	sock_stat_init(s, &s->st_rx_msgs, &rx_msgs_info);
	sock_stat_init(s, &s->st_tx_bytes, &tx_bytes_info);
	sock_stat_init(s, &s->st_rx_bytes, &rx_bytes_info);

	nni_stat_set_id(&s->st_id, (int) s->s_id);
	nni_stat_set_string(&s->st_name, s->s_name);
	nni_stat_set_string(&s->st_protocol, nni_sock_proto_name(s));
}
#endif

static void
sock_destroy(nni_sock *s)
{
	nni_sockopt *sopt;

#ifdef NNG_ENABLE_STATS
	nni_stat_unregister(&s->st_root);
#endif

	if (s->s_data != NULL) {
		s->s_sock_ops.sock_fini(s->s_data);
	}

	nni_mtx_lock(&s->s_mx);
	while ((sopt = nni_list_first(&s->s_options)) != NULL) {
		nni_list_remove(&s->s_options, sopt);
		nni_free_opt(sopt);
	}
	nni_mtx_unlock(&s->s_mx);

	nni_msgq_fini(s->s_urq);
	nni_msgq_fini(s->s_uwq);
	nni_cv_fini(&s->s_close_cv);
	nni_cv_fini(&s->s_cv);
	nni_mtx_fini(&s->s_mx);
	nni_mtx_fini(&s->s_pipe_cbs_mtx);
	nni_free(s, s->s_size);
}

static int
nni_sock_create(nni_sock **sp, const nni_proto *proto)
{
	int       rv;
	nni_sock *s;
	bool      on;
	size_t    sz;

	sz = NNI_ALIGN_UP(sizeof(*s)) + proto->proto_sock_ops->sock_size;
	if ((s = nni_zalloc(sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	s->s_data      = s + 1;
	s->s_sndtimeo  = -1;
	s->s_rcvtimeo  = -1;
	s->s_reconn    = NNI_SECOND;
	s->s_reconnmax = 0;
	s->s_rcvmaxsz  = 0;
	s->s_id        = 0;
	s->s_ref       = 0;
	s->s_self_id   = proto->proto_self;
	s->s_peer_id   = proto->proto_peer;
	s->s_flags     = proto->proto_flags;
	s->s_sock_ops  = *proto->proto_sock_ops;
	s->s_pipe_ops  = *proto->proto_pipe_ops;
	s->s_closed    = false;
	s->s_closing   = false;

	if (proto->proto_ctx_ops != NULL) {
		s->s_ctx_ops = *proto->proto_ctx_ops;
	}

	NNI_ASSERT(s->s_sock_ops.sock_open != NULL);
	NNI_ASSERT(s->s_sock_ops.sock_close != NULL);

	NNI_LIST_NODE_INIT(&s->s_node);
	NNI_LIST_INIT(&s->s_options, nni_sockopt, node);
	NNI_LIST_INIT(&s->s_ctxs, nni_ctx, c_node);
	NNI_LIST_INIT(&s->s_pipes, nni_pipe, p_sock_node);
	NNI_LIST_INIT(&s->s_listeners, nni_listener, l_node);
	NNI_LIST_INIT(&s->s_dialers, nni_dialer, d_node);
	nni_mtx_init(&s->s_mx);
	nni_mtx_init(&s->s_pipe_cbs_mtx);
	nni_cv_init(&s->s_cv, &s->s_mx);
	nni_cv_init(&s->s_close_cv, &sock_lk);

#ifdef NNG_ENABLE_STATS
	sock_stats_init(s);
#endif

	if (((rv = nni_msgq_init(&s->s_uwq, 0)) != 0) ||
	    ((rv = nni_msgq_init(&s->s_urq, 1)) != 0)) {
		sock_destroy(s);
		return (rv);
	}
	s->s_sock_ops.sock_init(s->s_data, s);

	(void) nni_sock_setopt(s, NNG_OPT_SENDTIMEO, &s->s_sndtimeo,
	    sizeof(nni_duration), NNI_TYPE_DURATION);
	(void) nni_sock_setopt(s, NNG_OPT_RECVTIMEO, &s->s_rcvtimeo,
	    sizeof(nni_duration), NNI_TYPE_DURATION);
	(void) nni_sock_setopt(s, NNG_OPT_RECONNMINT, &s->s_reconn,
	    sizeof(nni_duration), NNI_TYPE_DURATION);
	(void) nni_sock_setopt(s, NNG_OPT_RECONNMAXT, &s->s_reconnmax,
	    sizeof(nni_duration), NNI_TYPE_DURATION);
	(void) nni_sock_setopt(s, NNG_OPT_RECVMAXSZ, &s->s_rcvmaxsz,
	    sizeof(size_t), NNI_TYPE_SIZE);

	on = true;
	(void) nni_sock_setopt(
	    s, NNG_OPT_TCP_NODELAY, &on, sizeof(on), NNI_TYPE_BOOL);
	on = false;
	(void) nni_sock_setopt(
	    s, NNG_OPT_TCP_KEEPALIVE, &on, sizeof(on), NNI_TYPE_BOOL);

	*sp = s;
	return (rv);
}

int
nni_sock_open(nni_sock **sockp, const nni_proto *proto)
{
	nni_sock *s = NULL;
	int       rv;

	if (proto->proto_version != NNI_PROTOCOL_VERSION) {
		return (NNG_ENOTSUP);
	}

	if (((rv = nni_init()) != 0) ||
	    ((rv = nni_sock_create(&s, proto)) != 0)) {
		return (rv);
	}

	nni_mtx_lock(&sock_lk);
	if ((rv = nni_id_alloc32(&sock_ids, &s->s_id, s)) != 0) {
		nni_mtx_unlock(&sock_lk);
		sock_destroy(s);
		return (rv);
	} else {
		nni_list_append(&sock_list, s);
		s->s_sock_ops.sock_open(s->s_data);
		*sockp = s;
	}
	nni_mtx_unlock(&sock_lk);

	(void) snprintf(s->s_name, sizeof(s->s_name), "%u", s->s_id);

#ifdef NNG_ENABLE_STATS
	nni_stat_set_id(&s->st_id, (int) s->s_id);
	nni_stat_set_id(&s->st_root, (int) s->s_id);
	nni_stat_set_string(&s->st_name, s->s_name);

	nni_stat_register(&s->st_root);
#endif

	return (0);
}

int
nni_sock_shutdown(nni_sock *sock)
{
	nni_pipe     *pipe;
	nni_dialer   *d;
	nni_listener *l;
	nni_ctx      *ctx;
	nni_ctx      *nctx;

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		return (NNG_ECLOSED);
	}
	sock->s_closing = true;

	while ((l = nni_list_first(&sock->s_listeners)) != NULL) {
		nni_listener_hold(l);
		nni_mtx_unlock(&sock->s_mx);
		nni_listener_close(l);
		nni_mtx_lock(&sock->s_mx);
	}

	while ((d = nni_list_first(&sock->s_dialers)) != NULL) {
		nni_dialer_hold(d);
		nni_mtx_unlock(&sock->s_mx);
		nni_dialer_close(d);
		nni_mtx_lock(&sock->s_mx);
	}
	nni_mtx_unlock(&sock->s_mx);

	nni_msgq_close(sock->s_urq);
	nni_msgq_close(sock->s_uwq);

	nni_mtx_lock(&sock_lk);
	nctx = nni_list_first(&sock->s_ctxs);
	while ((ctx = nctx) != NULL) {
		nctx          = nni_list_next(&sock->s_ctxs, ctx);
		ctx->c_closed = true;
		if (ctx->c_ref == 0) {
			nni_id_remove(&ctx_ids, ctx->c_id);
			nni_list_remove(&sock->s_ctxs, ctx);
			nni_ctx_destroy(ctx);
		}
	}

	while (!nni_list_empty(&sock->s_ctxs)) {
		nni_cv_wait(&sock->s_close_cv);
	}
	nni_mtx_unlock(&sock_lk);

	nni_mtx_lock(&sock->s_mx);

	NNI_LIST_FOREACH (&sock->s_pipes, pipe) {
		nni_pipe_close(pipe);
	}

	while (!nni_list_empty(&sock->s_pipes)) {
		nni_cv_wait(&sock->s_cv);
	}

	sock->s_sock_ops.sock_close(sock->s_data);

	nni_cv_wake(&sock->s_cv);

	NNI_ASSERT(nni_list_first(&sock->s_pipes) == NULL);

	nni_mtx_unlock(&sock->s_mx);

	return (0);
}

void
nni_sock_close(nni_sock *s)
{
	nni_sock_shutdown(s);

	nni_mtx_lock(&sock_lk);
	if (s->s_closed) {
		nni_mtx_unlock(&sock_lk);
		nni_sock_rele(s);
		return;
	}
	s->s_closed = true;
	nni_id_remove(&sock_ids, s->s_id);

	nni_list_node_remove(&s->s_node);

	while ((s->s_ref > 1) || (!nni_list_empty(&s->s_ctxs))) {
		nni_cv_wait(&s->s_close_cv);
	}
	nni_mtx_unlock(&sock_lk);

	nni_mtx_lock(&s->s_mx);
	NNI_ASSERT(nni_list_empty(&s->s_dialers));
	NNI_ASSERT(nni_list_empty(&s->s_listeners));
	NNI_ASSERT(nni_list_empty(&s->s_pipes));
	nni_mtx_unlock(&s->s_mx);

	sock_destroy(s);
}

void
nni_sock_closeall(void)
{
	nni_sock *s;

	for (;;) {
		nni_mtx_lock(&sock_lk);
		if ((s = nni_list_first(&sock_list)) == NULL) {
			nni_mtx_unlock(&sock_lk);
			return;
		}
		s->s_ref++;
		nni_list_node_remove(&s->s_node);
		nni_mtx_unlock(&sock_lk);
		nni_sock_close(s);
	}
}

void
nni_sock_send(nni_sock *sock, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, sock->s_sndtimeo);
	sock->s_sock_ops.sock_send(sock->s_data, aio);
}

void
nni_sock_recv(nni_sock *sock, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, sock->s_rcvtimeo);
	sock->s_sock_ops.sock_recv(sock->s_data, aio);
}

uint16_t
nni_sock_proto_id(nni_sock *sock)
{
	return (sock->s_self_id.p_id);
}

uint16_t
nni_sock_peer_id(nni_sock *sock)
{
	return (sock->s_peer_id.p_id);
}

const char *
nni_sock_proto_name(nni_sock *sock)
{
	return (sock->s_self_id.p_name);
}

const char *
nni_sock_peer_name(nni_sock *sock)
{
	return (sock->s_peer_id.p_name);
}

bool
nni_sock_raw(nni_sock *sock)
{
  return ((nni_sock_flags(sock) & NNI_PROTO_FLAG_RAW) != 0);
}

struct nni_proto_pipe_ops *
nni_sock_proto_pipe_ops(nni_sock *sock)
{
	return (&sock->s_pipe_ops);
}

struct nni_proto_sock_ops *
nni_sock_proto_ops(nni_sock *sock)
{
  return (&sock->s_sock_ops);
}

struct nni_proto_ctx_ops *
nni_ctx_proto_ops(nni_ctx *ctx)
{
  return (&ctx->c_ops);
}

void *
nni_sock_proto_data(nni_sock *sock)
{
	return (sock->s_data);
}

void *
nni_ctx_proto_data(nni_ctx *ctx)
{
  return (ctx->c_data);
}

int
nni_sock_add_listener(nni_sock *s, nni_listener *l)
{
	nni_sockopt *sopt;
	int          rv;

	if ((rv = nni_listener_hold(l)) != 0) {
		return (rv);
	}

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		nni_listener_rele(l);
		return (NNG_ECLOSED);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		int rv;
		rv = nni_listener_setopt(
		    l, sopt->name, sopt->data, sopt->sz, sopt->typ);
		if ((rv != 0) && (rv != NNG_ENOTSUP)) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	nni_list_append(&s->s_listeners, l);

#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&s->st_listeners, 1);
#endif

	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_remove_listener(nni_listener *l)
{
	nni_sock *s = l->l_sock;
	nni_mtx_lock(&s->s_mx);
	NNI_ASSERT(nni_list_node_active(&l->l_node));
	nni_list_node_remove(&l->l_node);
	nni_mtx_unlock(&s->s_mx);

	nni_listener_rele(l);
}

int
nni_sock_add_dialer(nni_sock *s, nni_dialer *d)
{
	nni_sockopt *sopt;
	int rv;

	if ((rv = nni_dialer_hold(d)) != 0) {
		return (rv);
	}

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		nni_dialer_rele(d);
		return (NNG_ECLOSED);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		int rv;
		rv = nni_dialer_setopt(
		    d, sopt->name, sopt->data, sopt->sz, sopt->typ);
		if ((rv != 0) && (rv != NNG_ENOTSUP)) {
			nni_mtx_unlock(&s->s_mx);
			return (rv);
		}
	}

	nni_list_append(&s->s_dialers, d);

#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&s->st_dialers, 1);
#endif

	nni_mtx_unlock(&s->s_mx);
	return (0);
}

void
nni_sock_remove_dialer(nni_dialer *d)
{
	nni_sock *s = d->d_sock;
	nni_mtx_lock(&s->s_mx);
	NNI_ASSERT(nni_list_node_active(&d->d_node));
	nni_list_node_remove(&d->d_node);
	nni_mtx_unlock(&s->s_mx);

	nni_dialer_rele(d);
}

int
nni_sock_setopt(
    nni_sock *s, const char *name, const void *v, size_t sz, nni_type t)
{
	int          rv;
	nni_sockopt *optv;
	nni_sockopt *oldv = NULL;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	rv = nni_setopt(s->s_sock_ops.sock_options, name, s->s_data, v, sz, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	rv = nni_setopt(sock_options, name, s, v, sz, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}
	nni_mtx_unlock(&s->s_mx);

	if ((strcmp(name, NNG_OPT_RECONNMINT) == 0) ||
	    (strcmp(name, NNG_OPT_RECONNMAXT) == 0)) {
		if ((rv = nni_copyin_ms(NULL, v, sz, t)) != 0) {
			return (rv);
		}

	} else if (strcmp(name, NNG_OPT_RECVMAXSZ) == 0) {
		if ((rv = nni_copyin_size(NULL, v, sz, 0, NNI_MAXSZ, t)) !=
		    0) {
			return (rv);
		}

#if !defined(NNG_ELIDE_DEPRECATED)
	} else if ((strcmp(name, NNG_OPT_TCP_KEEPALIVE) == 0) ||
	    (strcmp(name, NNG_OPT_TCP_NODELAY)) == 0) {
		if ((rv = nni_copyin_bool(NULL, v, sz, t)) != 0) {
			return (rv);
		}
#endif

#if defined(NNG_SUPP_TLS) && !defined(NNG_ELIDE_DEPRECATED)
	} else if (strcmp(name, NNG_OPT_TLS_CONFIG) == 0) {
		nng_tls_config *tc;
		if ((rv = nni_copyin_ptr((void **) &tc, v, sz, t)) != 0) {
			return (rv);
		}
		nng_tls_config_hold(tc);

	} else if ((strcmp(name, NNG_OPT_TLS_SERVER_NAME) == 0) ||
	    (strcmp(name, NNG_OPT_TLS_CA_FILE) == 0) ||
	    (strcmp(name, NNG_OPT_TLS_CERT_KEY_FILE) == 0)) {
		if ((t != NNI_TYPE_OPAQUE) && (t != NNI_TYPE_STRING)) {
			return (NNG_EBADTYPE);
		}
		if (nni_strnlen(v, sz) >= sz) {
			return (NNG_EINVAL);
		}
	} else if ((strcmp(name, NNG_OPT_TLS_AUTH_MODE) == 0)) {
		if ((rv = nni_copyin_int(NULL, v, sz, 0, 2, t)) != 0) {
			return (rv);
		}
#endif

#if defined(NNG_PLATFORM_POSIX) && !defined(NNG_ELIDE_DEPRECATED)
	} else if (strcmp(name, NNG_OPT_IPC_PERMISSIONS) == 0) {
		if ((rv = nni_copyin_int(NULL, v, sz, 0, 07777, t)) != 0) {
			return (rv);
		}
#endif

#if defined(NNG_PLATFORM_WINDOWS) && !defined(NNG_ELIDE_DEPRECATED)
	} else if (strcmp(name, NNG_OPT_IPC_SECURITY_DESCRIPTOR) == 0) {
		if ((rv = nni_copyin_ptr(NULL, v, sz, t)) == 0) {
			return (rv);
		}
#endif
	}

	if ((optv = NNI_ALLOC_STRUCT(optv)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((optv->data = nni_alloc(sz)) == NULL) {
		NNI_FREE_STRUCT(optv);
		return (NNG_ENOMEM);
	}
	if ((optv->name = nni_strdup(name)) == NULL) {
		nni_free(optv->data, sz);
		NNI_FREE_STRUCT(optv);
		return (NNG_ENOMEM);
	}
	memcpy(optv->data, v, sz);
	optv->sz  = sz;
	optv->typ = t;
	NNI_LIST_NODE_INIT(&optv->node);

	nni_mtx_lock(&s->s_mx);
	NNI_LIST_FOREACH (&s->s_options, oldv) {
		if (strcmp(oldv->name, name) == 0) {
			if ((oldv->sz != sz) ||
			    (memcmp(oldv->data, v, sz) != 0)) {
				break;
			}

			nni_mtx_unlock(&s->s_mx);
			nni_free_opt(optv);
			return (0);
		}
	}

#ifndef NNG_ELIDE_DEPRECATED
	nni_dialer   *d;
	nni_listener *l;

	NNI_LIST_FOREACH (&s->s_listeners, l) {
		int x;
		x = nni_listener_setopt(l, optv->name, optv->data, sz, t);
		if (x != NNG_ENOTSUP) {
			if ((rv = x) != 0) {
				nni_mtx_unlock(&s->s_mx);
				nni_free_opt(optv);
				return (rv);
			}
		}
	}
	NNI_LIST_FOREACH (&s->s_dialers, d) {
		int x;
		x = nni_dialer_setopt(d, optv->name, optv->data, sz, t);
		if (x != NNG_ENOTSUP) {
			if ((rv = x) != 0) {
				nni_mtx_unlock(&s->s_mx);
				nni_free_opt(optv);
				return (rv);
			}
		}
	}
#endif

	if (rv == 0) {
		if (oldv != NULL) {
			nni_list_remove(&s->s_options, oldv);
			nni_free_opt(oldv);
		}

		nni_list_append(&s->s_options, optv);
	} else {
		nni_free_opt(optv);
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

int
nni_sock_getopt(
    nni_sock *s, const char *name, void *val, size_t *szp, nni_type t)
{
	int          rv;
	nni_sockopt *sopt;

	nni_mtx_lock(&s->s_mx);
	if (s->s_closing) {
		nni_mtx_unlock(&s->s_mx);
		return (NNG_ECLOSED);
	}

	rv = nni_getopt(
	    s->s_sock_ops.sock_options, name, s->s_data, val, szp, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	rv = nni_getopt(sock_options, name, s, val, szp, t);
	if (rv != NNG_ENOTSUP) {
		nni_mtx_unlock(&s->s_mx);
		return (rv);
	}

	NNI_LIST_FOREACH (&s->s_options, sopt) {
		if (strcmp(sopt->name, name) == 0) {
			size_t sz = sopt->sz;

			if ((sopt->typ != NNI_TYPE_OPAQUE) &&
			    (t != sopt->typ)) {

				if (t != NNI_TYPE_OPAQUE) {
					nni_mtx_unlock(&s->s_mx);
					return (NNG_EBADTYPE);
				}
				if (*szp != sopt->sz) {
					nni_mtx_unlock(&s->s_mx);
					return (NNG_EINVAL);
				}
			}

			if (szp != NULL) {
				if (sopt->sz > *szp) {
					sz = *szp;
				}
				*szp = sopt->sz;
			}
			memcpy(val, sopt->data, sz);
			rv = 0;
			break;
		}
	}

	nni_mtx_unlock(&s->s_mx);
	return (rv);
}

uint32_t
nni_sock_flags(nni_sock *sock)
{
	return (sock->s_flags);
}

void
nni_sock_set_pipe_cb(nni_sock *s, int ev, nng_pipe_cb cb, void *arg)
{
	if ((ev >= 0) && (ev < NNG_PIPE_EV_NUM)) {
		nni_mtx_lock(&s->s_pipe_cbs_mtx);
		s->s_pipe_cbs[ev].cb_fn  = cb;
		s->s_pipe_cbs[ev].cb_arg = arg;
		nni_mtx_unlock(&s->s_pipe_cbs_mtx);
	}
}

int
nni_ctx_find(nni_ctx **cp, uint32_t id, bool closing)
{
	int      rv;
	nni_ctx *ctx;

	if ((rv = nni_init()) != 0) {
		return (rv);
	}
	nni_mtx_lock(&sock_lk);
	if ((ctx = nni_id_get(&ctx_ids, id)) != NULL) {
		if (ctx->c_closed || ((!closing) && ctx->c_sock->s_closed)) {
			rv = NNG_ECLOSED;
		} else {
			ctx->c_ref++;
			*cp = ctx;
		}
	} else {
		rv = NNG_ECLOSED;
	}
	nni_mtx_unlock(&sock_lk);

	return (rv);
}

static void
nni_ctx_destroy(nni_ctx *ctx)
{
	if (ctx->c_data != NULL) {
		ctx->c_ops.ctx_fini(ctx->c_data);
	}

	nni_free(ctx, ctx->c_size);
}

void
nni_ctx_rele(nni_ctx *ctx)
{
	nni_sock *sock = ctx->c_sock;
	nni_mtx_lock(&sock_lk);
	ctx->c_ref--;
	if ((ctx->c_ref > 0) || (!ctx->c_closed)) {
		nni_mtx_unlock(&sock_lk);
		return;
	}

	nni_id_remove(&ctx_ids, ctx->c_id);
	nni_list_remove(&sock->s_ctxs, ctx);
	nni_cv_wake(&sock->s_close_cv);
	nni_mtx_unlock(&sock_lk);

	nni_ctx_destroy(ctx);
}

int
nni_ctx_open(nni_ctx **ctxp, nni_sock *sock)
{
	nni_ctx *ctx;
	int      rv;
	size_t   sz;

	if (sock->s_ctx_ops.ctx_init == NULL) {
		return (NNG_ENOTSUP);
	}

	sz = NNI_ALIGN_UP(sizeof(*ctx)) + sock->s_ctx_ops.ctx_size;
	if ((ctx = nni_zalloc(sz)) == NULL) {
		return (NNG_ENOMEM);
	}
	ctx->c_size     = sz;
	ctx->c_data     = ctx + 1;
	ctx->c_closed   = false;
	ctx->c_ref      = 1;
	ctx->c_sock     = sock;
	ctx->c_ops      = sock->s_ctx_ops;
	ctx->c_rcvtimeo = sock->s_rcvtimeo;
	ctx->c_sndtimeo = sock->s_sndtimeo;

	nni_mtx_lock(&sock_lk);
	if (sock->s_closed) {
		nni_mtx_unlock(&sock_lk);
		nni_free(ctx, ctx->c_size);
		return (NNG_ECLOSED);
	}
	if ((rv = nni_id_alloc32(&ctx_ids, &ctx->c_id, ctx)) != 0) {
		nni_mtx_unlock(&sock_lk);
		nni_free(ctx, ctx->c_size);
		return (rv);
	}

	sock->s_ctx_ops.ctx_init(ctx->c_data, sock->s_data);

	nni_list_append(&sock->s_ctxs, ctx);
	nni_mtx_unlock(&sock_lk);

	nni_mtx_lock(&sock->s_mx);
	if (sock->s_closing) {
		nni_mtx_unlock(&sock->s_mx);
		nni_ctx_rele(ctx);
		return (NNG_ECLOSED);
	}
	nni_mtx_unlock(&sock->s_mx);
	*ctxp = ctx;

	return (0);
}

void
nni_ctx_close(nni_ctx *ctx)
{
	nni_mtx_lock(&sock_lk);
	ctx->c_closed = true;
	nni_mtx_unlock(&sock_lk);

	nni_ctx_rele(ctx);
}

uint32_t
nni_ctx_id(nni_ctx *ctx)
{
	return (ctx->c_id);
}

void
nni_ctx_send(nni_ctx *ctx, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, ctx->c_sndtimeo);
	ctx->c_ops.ctx_send(ctx->c_data, aio);
}

void
nni_ctx_recv(nni_ctx *ctx, nni_aio *aio)
{
	nni_aio_normalize_timeout(aio, ctx->c_rcvtimeo);
	ctx->c_ops.ctx_recv(ctx->c_data, aio);
}

int
nni_ctx_getopt(nni_ctx *ctx, const char *opt, void *v, size_t *szp, nni_type t)
{
	nni_sock   *sock = ctx->c_sock;
	nni_option *o;
	int         rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (strcmp(opt, NNG_OPT_RECVTIMEO) == 0) {
		rv = nni_copyout_ms(ctx->c_rcvtimeo, v, szp, t);
	} else if (strcmp(opt, NNG_OPT_SENDTIMEO) == 0) {
		rv = nni_copyout_ms(ctx->c_sndtimeo, v, szp, t);
	} else if (ctx->c_ops.ctx_options != NULL) {
		for (o = ctx->c_ops.ctx_options; o->o_name != NULL; o++) {
			if (strcmp(opt, o->o_name) != 0) {
				continue;
			}
			if (o->o_get == NULL) {
				rv = NNG_EWRITEONLY;
				break;
			}
			rv = o->o_get(ctx->c_data, v, szp, t);
			break;
		}
	}
	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}

int
nni_ctx_setopt(
    nni_ctx *ctx, const char *opt, const void *v, size_t sz, nni_type t)
{
	nni_sock   *sock = ctx->c_sock;
	nni_option *o;
	int         rv = NNG_ENOTSUP;

	nni_mtx_lock(&sock->s_mx);
	if (strcmp(opt, NNG_OPT_RECVTIMEO) == 0) {
		rv = nni_copyin_ms(&ctx->c_rcvtimeo, v, sz, t);
	} else if (strcmp(opt, NNG_OPT_SENDTIMEO) == 0) {
		rv = nni_copyin_ms(&ctx->c_sndtimeo, v, sz, t);
	} else if (ctx->c_ops.ctx_options != NULL) {
		for (o = ctx->c_ops.ctx_options; o->o_name != NULL; o++) {
			if (strcmp(opt, o->o_name) != 0) {
				continue;
			}
			if (o->o_set == NULL) {
				rv = NNG_EREADONLY;
				break;
			}
			rv = o->o_set(ctx->c_data, v, sz, t);
			break;
		}
	}

	nni_mtx_unlock(&sock->s_mx);
	return (rv);
}

static void
dialer_timer_start_locked(nni_dialer *d)
{
	nni_duration back_off;

	back_off = d->d_currtime;
	if (d->d_maxrtime > 0) {
		d->d_currtime *= 2;
		if (d->d_currtime > d->d_maxrtime) {
			d->d_currtime = d->d_maxrtime;
		}
	}

	nni_sleep_aio(back_off ? (nng_duration) (nni_random() % back_off) : 0,
               &d->d_tmo_aio);
}

void
nni_dialer_timer_start(nni_dialer *d)
{
	nni_sock *s = d->d_sock;
	nni_mtx_lock(&s->s_mx);
	dialer_timer_start_locked(d);
	nni_mtx_unlock(&s->s_mx);
}

void
nni_dialer_add_pipe(nni_dialer *d, void *tpipe)
{
	nni_sock *s = d->d_sock;
	nni_pipe *p;

	nni_mtx_lock(&s->s_mx);

	if (nni_pipe_create_dialer(&p, d, tpipe) != 0) {
		nni_mtx_unlock(&s->s_mx);
		return;
	}

	nni_list_append(&d->d_pipes, p);
	nni_list_append(&s->s_pipes, p);
	d->d_pipe     = p;
	d->d_currtime = d->d_inirtime;
	nni_mtx_unlock(&s->s_mx);
#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&s->st_pipes, 1);
	nni_stat_inc(&d->st_pipes, 1);
#endif

	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_PRE);

	if (nni_pipe_is_closed(p)) {
#ifdef NNG_ENABLE_STATS
		nni_stat_inc(&d->st_reject, 1);
		nni_stat_inc(&s->st_rejects, 1);
#endif
		nni_pipe_rele(p);
		return;
	}

	if (p->p_proto_ops.pipe_start(p->p_proto_data) != 0) {
#ifdef NNG_ENABLE_STATS
		nni_stat_inc(&d->st_reject, 1);
		nni_stat_inc(&s->st_rejects, 1);
#endif
		nni_pipe_close(p);
		nni_pipe_rele(p);
		return;
	}
#ifdef NNG_ENABLE_STATS
	nni_stat_set_id(&p->st_root, (int) p->p_id);
	nni_stat_set_id(&p->st_id, (int) p->p_id);
	nni_stat_register(&p->st_root);
#endif
	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_POST);
	nni_pipe_rele(p);
}

void
nni_dialer_shutdown(nni_dialer *d)
{
	nni_sock *s = d->d_sock;
	nni_pipe *p;

	if (nni_atomic_flag_test_and_set(&d->d_closing)) {
		return;
	}

	nni_dialer_stop(d);

	nni_mtx_lock(&s->s_mx);
	NNI_LIST_FOREACH (&d->d_pipes, p) {
		nni_pipe_close(p);
	}
	nni_mtx_unlock(&s->s_mx);
}

static void dialer_reap(void *);

static nni_reap_list dialer_reap_list = {
	.rl_offset = offsetof(nni_dialer, d_reap),
	.rl_func   = dialer_reap,
};

static void
dialer_reap(void *arg)
{
	nni_dialer *d = arg;
	nni_sock   *s = d->d_sock;

#ifdef NNG_ENABLE_STATS
	nni_stat_unregister(&d->st_root);
#endif

	nni_mtx_lock(&s->s_mx);
	if (!nni_list_empty(&d->d_pipes)) {
		nni_pipe *p;
		NNI_LIST_FOREACH (&d->d_pipes, p) {
			nni_pipe_close(p);
		}
		nni_mtx_unlock(&s->s_mx);
		nni_dialer_reap(d);
		return;
	}

	nni_mtx_unlock(&s->s_mx);

	nni_sock_rele(s);

	nni_dialer_destroy(d);
}

void
nni_dialer_reap(nni_dialer *d)
{
	nni_reap(&dialer_reap_list, d);
}

void
nni_listener_add_pipe(nni_listener *l, void *tpipe)
{
	nni_sock *s = l->l_sock;
	nni_pipe *p;

	nni_mtx_lock(&s->s_mx);
	if (nni_pipe_create_listener(&p, l, tpipe) != 0) {
		nni_mtx_unlock(&s->s_mx);
		return;
	}

	nni_list_append(&l->l_pipes, p);
	nni_list_append(&s->s_pipes, p);
	nni_mtx_unlock(&s->s_mx);
#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&l->st_pipes, 1);
	nni_stat_inc(&s->st_pipes, 1);
#endif

	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_PRE);

	if (nni_pipe_is_closed(p)) {
#ifdef NNG_ENABLE_STATS
		nni_stat_inc(&l->st_reject, 1);
		nni_stat_inc(&s->st_rejects, 1);
#endif
		nni_pipe_rele(p);
		return;
	}
	if (p->p_proto_ops.pipe_start(p->p_proto_data) != 0) {
#ifdef NNG_ENABLE_STATS
		nni_stat_inc(&l->st_reject, 1);
		nni_stat_inc(&s->st_rejects, 1);
#endif
		nni_pipe_close(p);
		nni_pipe_rele(p);
		return;
	}
#ifdef NNG_ENABLE_STATS
	nni_stat_set_id(&p->st_root, (int) p->p_id);
	nni_stat_set_id(&p->st_id, (int) p->p_id);
	nni_stat_register(&p->st_root);
#endif
	nni_pipe_run_cb(p, NNG_PIPE_EV_ADD_POST);
	nni_pipe_rele(p);
}

void
nni_listener_shutdown(nni_listener *l)
{
	nni_sock *s = l->l_sock;
	nni_pipe *p;

	if (nni_atomic_flag_test_and_set(&l->l_closing)) {
		return;
	}

	nni_listener_stop(l);

	nni_mtx_lock(&s->s_mx);
	NNI_LIST_FOREACH (&l->l_pipes, p) {
		nni_pipe_close(p);
	}
	nni_mtx_unlock(&s->s_mx);
}

static void listener_reap(void *);

static nni_reap_list listener_reap_list = {
	.rl_offset = offsetof(nni_listener, l_reap),
	.rl_func   = listener_reap,
};

static void
listener_reap(void *arg)
{
	nni_listener *l = arg;
	nni_sock     *s = l->l_sock;

#ifdef NNG_ENABLE_STATS
	nni_stat_unregister(&l->st_root);
#endif

	nni_mtx_lock(&s->s_mx);
	if (!nni_list_empty(&l->l_pipes)) {
		nni_pipe *p;
		NNI_LIST_FOREACH (&l->l_pipes, p) {
			nni_pipe_close(p);
		}
		nni_mtx_unlock(&s->s_mx);
		nni_reap(&listener_reap_list, l);
		return;
	}

	nni_list_node_remove(&l->l_node);
	nni_mtx_unlock(&s->s_mx);

	nni_sock_rele(s);

	nni_listener_destroy(l);
}

void
nni_listener_reap(nni_listener *l)
{
	nni_reap(&listener_reap_list, l);
}

void
nni_pipe_run_cb(nni_pipe *p, nng_pipe_ev ev)
{
	nni_sock   *s = p->p_sock;
	nng_pipe_cb cb;
	void       *arg;

	nni_mtx_lock(&s->s_pipe_cbs_mtx);
	if (!p->p_cbs) {
		if (ev == NNG_PIPE_EV_ADD_PRE) {
			p->p_cbs = true;
		} else {
			nni_mtx_unlock(&s->s_pipe_cbs_mtx);
			return;
		}
	}
	cb  = s->s_pipe_cbs[ev].cb_fn;
	arg = s->s_pipe_cbs[ev].cb_arg;
	nni_mtx_unlock(&s->s_pipe_cbs_mtx);

	if (cb != NULL) {
		nng_pipe pid;
		pid.id = p->p_id;
		cb(pid, ev, arg);
	}
}

void
nni_pipe_remove(nni_pipe *p)
{
	nni_sock   *s = p->p_sock;
	nni_dialer *d = p->p_dialer;

	nni_mtx_lock(&s->s_mx);
#ifdef NNG_ENABLE_STATS
	if (nni_list_node_active(&p->p_sock_node)) {
		nni_stat_dec(&s->st_pipes, 1);
	}
	if (p->p_listener != NULL) {
		nni_stat_dec(&p->p_listener->st_pipes, 1);
	}
	if (p->p_dialer != NULL) {
		nni_stat_dec(&p->p_dialer->st_pipes, 1);
	}
#endif
	nni_list_node_remove(&p->p_sock_node);
	nni_list_node_remove(&p->p_ep_node);
	p->p_listener = NULL;
	p->p_dialer   = NULL;
	if ((d != NULL) && (d->d_pipe == p)) {
		d->d_pipe = NULL;
		dialer_timer_start_locked(d);
	}
	nni_cv_wake(&s->s_cv);
	nni_mtx_unlock(&s->s_mx);
}

void
nni_sock_add_stat(nni_sock *s, nni_stat_item *stat)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_add(&s->st_root, stat);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(stat);
#endif
}

void
nni_sock_bump_tx(nni_sock *s, uint64_t sz)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&s->st_tx_msgs, 1);
	nni_stat_inc(&s->st_tx_bytes, sz);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(sz);
#endif
}

void
nni_sock_bump_rx(nni_sock *s, uint64_t sz)
{
#ifdef NNG_ENABLE_STATS
	nni_stat_inc(&s->st_rx_msgs, 1);
	nni_stat_inc(&s->st_rx_bytes, sz);
#else
	NNI_ARG_UNUSED(s);
	NNI_ARG_UNUSED(sz);
#endif
}
