//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_PIPE_H
#define CORE_PIPE_H

#include "core/defs.h"
#include "core/thread.h"
#include "sp/transport.h"

extern void nni_pipe_recv(nni_pipe *, nni_aio *);
extern void nni_pipe_send(nni_pipe *, nni_aio *);

extern uint32_t nni_pipe_id(nni_pipe *);

extern void nni_pipe_close(nni_pipe *);

extern uint16_t nni_pipe_peer(nni_pipe *);

extern int nni_pipe_getopt(
    nni_pipe *, const char *, void *, size_t *, nni_opt_type);

extern int nni_pipe_find(nni_pipe **, uint32_t);

extern uint32_t nni_pipe_sock_id(nni_pipe *);

extern uint32_t nni_pipe_listener_id(nni_pipe *);

extern uint32_t nni_pipe_dialer_id(nni_pipe *);

extern void nni_pipe_rele(nni_pipe *);

extern void nni_pipe_add_stat(nni_pipe *, nni_stat_item *);

extern void nni_pipe_bump_rx(nni_pipe *, size_t);
extern void nni_pipe_bump_tx(nni_pipe *, size_t);
extern void nni_pipe_bump_error(nni_pipe *, int);

#endif
