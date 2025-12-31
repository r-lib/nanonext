//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef CORE_INIT_H
#define CORE_INIT_H

#include "core/nng_impl.h"

int nni_init(void);

void nni_fini(void);

void nni_init_set_param(nng_init_parameter, uint64_t value);

uint64_t nni_init_get_param(nng_init_parameter parameter, uint64_t default_value);

void nni_init_set_effective(nng_init_parameter p, uint64_t value);

#endif
