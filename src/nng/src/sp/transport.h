//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2018 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PROTOCOL_SP_TRANSPORT_H
#define PROTOCOL_SP_TRANSPORT_H

#include "core/options.h"

struct nni_sp_dialer_ops {

	int (*d_init)(void **, nni_url *, nni_dialer *);

	void (*d_fini)(void *);

	void (*d_connect)(void *, nni_aio *);

	void (*d_close)(void *);

	int (*d_getopt)(void *, const char *, void *, size_t *, nni_type);

	int (*d_setopt)(void *, const char *, const void *, size_t, nni_type);

	nni_option *d_options;
};

struct nni_sp_listener_ops {

	int (*l_init)(void **, nni_url *, nni_listener *);

	void (*l_fini)(void *);

	int (*l_bind)(void *);

	void (*l_accept)(void *, nni_aio *);

	void (*l_close)(void *);

	int (*l_getopt)(void *, const char *, void *, size_t *, nni_type);

	int (*l_setopt)(void *, const char *, const void *, size_t, nni_type);

	nni_option *l_options;
};

struct nni_sp_pipe_ops {

	int (*p_init)(void *, nni_pipe *);

	void (*p_fini)(void *);

	void (*p_stop)(void *);

	void (*p_send)(void *, nni_aio *);

	void (*p_recv)(void *, nni_aio *);

	void (*p_close)(void *);

	uint16_t (*p_peer)(void *);

	int (*p_getopt)(void *, const char *, void *, size_t *, nni_type);
};

struct nni_sp_tran {

	nni_list_node tran_link;

	const char *tran_scheme;

	const nni_sp_dialer_ops *tran_dialer;

	const nni_sp_listener_ops *tran_listener;

	const nni_sp_pipe_ops *tran_pipe;

	void (*tran_init)(void);

	void (*tran_fini)(void);
};

extern nni_sp_tran *nni_sp_tran_find(nni_url *);
extern void         nni_sp_tran_sys_init(void);
extern void         nni_sp_tran_sys_fini(void);
extern void         nni_sp_tran_register(nni_sp_tran *);

#endif // PROTOCOL_SP_TRANSPORT_H
