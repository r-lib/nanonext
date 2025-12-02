//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_AIO_H
#define CORE_AIO_H

#include "core/defs.h"
#include "core/list.h"
#include "core/reap.h"
#include "core/taskq.h"
#include "core/thread.h"

typedef void (*nni_aio_cancel_fn)(nni_aio *, void *, int);

extern void nni_aio_init(nni_aio *, nni_cb, void *arg);

extern void nni_aio_fini(nni_aio *);

extern void nni_aio_reap(nni_aio *);

extern int nni_aio_alloc(nni_aio **, nni_cb, void *arg);

extern void nni_aio_free(nni_aio *aio);
extern void nni_aio_free_cb(void *aio);

extern void nni_aio_stop(nni_aio *);

extern void nni_aio_close(nni_aio *);

extern void nni_aio_set_input(nni_aio *, unsigned, void *);

extern void *nni_aio_get_input(nni_aio *, unsigned);

extern void nni_aio_set_output(nni_aio *, unsigned, void *);

extern void *nni_aio_get_output(nni_aio *, unsigned);

extern void     nni_aio_set_msg(nni_aio *, nni_msg *);
extern nni_msg *nni_aio_get_msg(nni_aio *);

extern int nni_aio_result(nni_aio *);

extern size_t nni_aio_count(nni_aio *);

extern bool nni_aio_busy(nni_aio *);

extern void nni_aio_wait(nni_aio *);

extern void nni_aio_list_init(nni_list *);
extern void nni_aio_list_append(nni_list *, nni_aio *);
extern void nni_aio_list_remove(nni_aio *);
extern int  nni_aio_list_active(nni_aio *);

extern void nni_aio_finish(nni_aio *, int, size_t);

extern void nni_aio_finish_sync(nni_aio *, int, size_t);
extern void nni_aio_finish_error(nni_aio *, int);
extern void nni_aio_finish_msg(nni_aio *, nni_msg *);

extern void nni_aio_abort(nni_aio *, int rv);

extern int nni_aio_begin(nni_aio *);

extern void *nni_aio_get_prov_data(nni_aio *);
extern void  nni_aio_set_prov_data(nni_aio *, void *);

extern size_t nni_aio_iov_advance(nni_aio *, size_t);
extern size_t nni_aio_iov_count(nni_aio *);

extern int nni_aio_set_iov(nni_aio *, unsigned, const nni_iov *);

extern void         nni_aio_set_timeout(nni_aio *, nng_duration);
extern void         nni_aio_set_expire(nni_aio *, nni_time);
extern nng_duration nni_aio_get_timeout(nni_aio *);
extern void         nni_aio_get_iov(nni_aio *, unsigned *, nni_iov **);
extern void         nni_aio_normalize_timeout(nni_aio *, nng_duration);
extern void         nni_aio_bump_count(nni_aio *, size_t);

extern int nni_aio_schedule(nni_aio *, nni_aio_cancel_fn, void *);

extern void nni_sleep_aio(nni_duration, nni_aio *);

typedef void *nni_aio_completions;

extern void nni_aio_completions_init(nni_aio_completions *);

extern void nni_aio_completions_run(nni_aio_completions *);

extern void nni_aio_completions_add(
    nni_aio_completions *, nni_aio *, int, size_t);

extern int  nni_aio_sys_init(void);
extern void nni_aio_sys_fini(void);

typedef struct nni_aio_expire_q nni_aio_expire_q;

struct nng_aio {
	size_t       a_count;      // Bytes transferred (I/O only)
	nni_time     a_expire;     // Absolute timeout
	nni_duration a_timeout;    // Relative timeout
	int          a_result;     // Result code (nng_errno)
	bool         a_stop;       // Shutting down (no new operations)
	bool         a_sleep;      // Sleeping with no action
	bool         a_expire_ok;  // Expire from sleep is ok
	bool         a_expiring;   // Expiration in progress
	bool         a_use_expire; // Use expire instead of timeout
	nni_task     a_task;

	nni_iov  a_iov[8];
	unsigned a_nio;

	nni_msg *a_msg;

	void *a_inputs[4];
	void *a_outputs[4];

	nni_aio_cancel_fn a_cancel_fn;
	void             *a_cancel_arg;
	void             *a_prov_data;
	nni_list_node     a_prov_node; // Linkage on provider list.
	nni_aio_expire_q *a_expire_q;
	nni_list_node     a_expire_node; // Expiration node
	nni_reap_node     a_reap_node;
};

#endif // CORE_AIO_H
