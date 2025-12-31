//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_MSGQUEUE_H
#define CORE_MSGQUEUE_H

#include "nng_impl.h"
#include "pollable.h"

typedef struct nni_msgq nni_msgq;

extern int nni_msgq_init(nni_msgq **, unsigned);

extern void nni_msgq_fini(nni_msgq *);

extern void nni_msgq_aio_put(nni_msgq *, nni_aio *);
extern void nni_msgq_aio_get(nni_msgq *, nni_aio *);

extern int nni_msgq_tryput(nni_msgq *, nni_msg *);

extern void nni_msgq_close(nni_msgq *);

extern int nni_msgq_resize(nni_msgq *, int);

extern int nni_msgq_cap(nni_msgq *mq);

extern int nni_msgq_get_recvable(nni_msgq *mq, nni_pollable **);
extern int nni_msgq_get_sendable(nni_msgq *mq, nni_pollable **);

#endif
