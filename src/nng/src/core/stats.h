//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_STATS_H
#define CORE_STATS_H

#include "core/defs.h"

typedef struct nni_stat_item nni_stat_item;
typedef struct nni_stat_info nni_stat_info;

typedef void (*nni_stat_update)(nni_stat_item *);
typedef enum nng_stat_type_enum nni_stat_type;
typedef enum nng_unit_enum      nni_stat_unit;

struct nni_stat_item {
	nni_list_node        si_node;
	nni_list             si_children;
	const nni_stat_info *si_info;
	union {
		uint64_t       sv_number;
		nni_atomic_u64 sv_atomic;
		char *         sv_string;
		bool           sv_bool;
		int            sv_id;
	} si_u;
};

struct nni_stat_info {
	const char *    si_name;
	const char *    si_desc;
	nni_stat_type   si_type;
	nni_stat_unit   si_unit;
	nni_stat_update si_update;
	bool            si_atomic : 1;
	bool            si_alloc : 1;
};

void nni_stat_add(nni_stat_item *, nni_stat_item *);

void nni_stat_register(nni_stat_item *);

void nni_stat_unregister(nni_stat_item *);

void nni_stat_set_value(nni_stat_item *, uint64_t);
void nni_stat_set_id(nni_stat_item *, int);
void nni_stat_set_bool(nni_stat_item *, bool);
void nni_stat_set_string(nni_stat_item *, const char *);
void nni_stat_init(nni_stat_item *, const nni_stat_info *);
void nni_stat_inc(nni_stat_item *, uint64_t);
void nni_stat_dec(nni_stat_item *, uint64_t);

#endif
