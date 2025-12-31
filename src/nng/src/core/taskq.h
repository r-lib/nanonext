//
// Copyright 2022 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_TASKQ_H
#define CORE_TASKQ_H

#include "core/defs.h"
#include "core/list.h"

typedef struct nni_taskq nni_taskq;
typedef struct nni_task  nni_task;

extern int  nni_taskq_init(nni_taskq **, int);
extern void nni_taskq_fini(nni_taskq *);

extern void nni_task_dispatch(nni_task *);

extern void nni_task_exec(nni_task *);

extern void nni_task_prep(nni_task *);

extern void nni_task_abort(nni_task *);

extern bool nni_task_busy(nni_task *);

extern void nni_task_wait(nni_task *);
extern void  nni_task_init(nni_task *, nni_taskq *, nni_cb, void *);

extern void nni_task_fini(nni_task *);

extern int  nni_taskq_sys_init(void);
extern void nni_taskq_sys_fini(void);

struct nni_task {
	nni_list_node task_node;
	void *        task_arg;
	nni_cb        task_cb;
	nni_taskq *   task_tq;
	unsigned      task_busy;
	bool          task_prep;
	nni_mtx       task_mtx;
	nni_cv        task_cv;
};

#endif
