//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_SOCKET_H
#define CORE_SOCKET_H

extern int         nni_sock_find(nni_sock **, uint32_t);
extern void        nni_sock_hold(nni_sock *);
extern void        nni_sock_rele(nni_sock *);
extern int         nni_sock_open(nni_sock **, const nni_proto *);
extern void        nni_sock_close(nni_sock *);
extern void        nni_sock_closeall(void);
extern int         nni_sock_shutdown(nni_sock *);
extern uint16_t    nni_sock_proto_id(nni_sock *);
extern uint16_t    nni_sock_peer_id(nni_sock *);
extern const char *nni_sock_proto_name(nni_sock *);
extern const char *nni_sock_peer_name(nni_sock *);
extern bool        nni_sock_raw(nni_sock *);
extern void       *nni_sock_proto_data(nni_sock *);
extern void        nni_sock_add_stat(nni_sock *, nni_stat_item *);

extern struct nni_proto_sock_ops *nni_sock_proto_ops(nni_sock *);
extern struct nni_proto_pipe_ops *nni_sock_proto_pipe_ops(nni_sock *);
extern struct nni_proto_ctx_ops  *nni_ctx_proto_ops(nni_ctx *);

extern int nni_sock_setopt(
    nni_sock *, const char *, const void *, size_t, nni_opt_type);
extern int nni_sock_getopt(
    nni_sock *, const char *, void *, size_t *, nni_opt_type);
extern void     nni_sock_send(nni_sock *, nni_aio *);
extern void     nni_sock_recv(nni_sock *, nni_aio *);
extern uint32_t nni_sock_id(nni_sock *);

extern nni_msgq *nni_sock_sendq(nni_sock *);

extern nni_msgq *nni_sock_recvq(nni_sock *);

extern uint32_t nni_sock_flags(nni_sock *);

extern void nni_sock_set_pipe_cb(nni_sock *sock, int, nng_pipe_cb, void *);

extern int nni_ctx_open(nni_ctx **, nni_sock *);

extern int nni_ctx_find(nni_ctx **, uint32_t, bool);

extern void nni_ctx_rele(nni_ctx *);

extern void nni_ctx_close(nni_ctx *);

extern uint32_t nni_ctx_id(nni_ctx *);

extern void *nni_ctx_proto_data(nni_ctx *);

extern void nni_ctx_recv(nni_ctx *, nni_aio *);

extern void nni_ctx_send(nni_ctx *, nni_aio *);

extern int nni_ctx_getopt(
    nni_ctx *, const char *, void *, size_t *, nni_opt_type);

extern int nni_ctx_setopt(
    nni_ctx *, const char *, const void *, size_t, nni_opt_type);

extern void nni_sock_bump_rx(nni_sock *s, uint64_t sz);

extern void nni_sock_bump_tx(nni_sock *s, uint64_t sz);

#endif
