//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PROTOCOL_H
#define CORE_PROTOCOL_H

#include "core/options.h"

struct nni_proto_pipe_ops {

	size_t pipe_size;

	int (*pipe_init)(void *, nni_pipe *, void *);

	void (*pipe_fini)(void *);

	int (*pipe_start)(void *);

	void (*pipe_close)(void *);

	void (*pipe_stop)(void *);
};

struct nni_proto_ctx_ops {

	size_t ctx_size;

	void (*ctx_init)(void *, void *);

	void (*ctx_fini)(void *);

	void (*ctx_recv)(void *, nni_aio *);

	void (*ctx_send)(void *, nni_aio *);

	nni_option *ctx_options;
};

struct nni_proto_sock_ops {

	size_t sock_size;

	void (*sock_init)(void *, nni_sock *);

	void (*sock_fini)(void *);

	void (*sock_open)(void *);

	void (*sock_close)(void *);

	void (*sock_send)(void *, nni_aio *);

	void (*sock_recv)(void *, nni_aio *);

	nni_option *sock_options;
};

typedef struct nni_proto_id {
	uint16_t    p_id;
	const char *p_name;
} nni_proto_id;

struct nni_proto {
	uint32_t                  proto_version;
	nni_proto_id              proto_self;
	nni_proto_id              proto_peer;
	uint32_t                  proto_flags;
	const nni_proto_sock_ops *proto_sock_ops;
	const nni_proto_pipe_ops *proto_pipe_ops;
	const nni_proto_ctx_ops * proto_ctx_ops;
};

#define NNI_PROTOCOL_V3 0x50520003u
#define NNI_PROTOCOL_VERSION NNI_PROTOCOL_V3

#define NNI_PROTO_FLAG_RCV 1u
#define NNI_PROTO_FLAG_SND 2u
#define NNI_PROTO_FLAG_SNDRCV 3u
#define NNI_PROTO_FLAG_RAW 4u

extern int nni_proto_open(nng_socket *, const nni_proto *);

#define NNI_PROTO(major, minor) (((major) *16) + (minor))

#endif
