//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef PLATFORM_POSIX_PEERID_H
#define PLATFORM_POSIX_PEERID_H

#include "core/nng_impl.h"
#include <sys/types.h>

int nni_posix_peerid(
    int fd, uint64_t *euid, uint64_t *egid, uint64_t *prid, uint64_t *znid);

#endif
