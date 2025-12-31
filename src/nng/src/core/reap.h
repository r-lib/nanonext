//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_REAP_H
#define CORE_REAP_H

#include "core/defs.h"
#include "core/list.h"

typedef struct nni_reap_node nni_reap_node;
struct nni_reap_node {
	nni_reap_node *rn_next;
};

typedef struct nni_reap_list nni_reap_list;
struct nni_reap_list {
	nni_reap_list *rl_next;
	nni_reap_node *rl_nodes;
	size_t         rl_offset;
	nni_cb         rl_func;
	bool           rl_inited;
};

extern void nni_reap(nni_reap_list *, void *);

extern void nni_reap_drain(void);

extern int  nni_reap_sys_init(void);
extern void nni_reap_sys_fini(void);

#endif
