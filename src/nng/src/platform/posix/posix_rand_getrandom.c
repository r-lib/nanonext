//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <stddef.h>
#include <sys/random.h>

#include "core/nng_impl.h"

#ifdef NNG_HAVE_GETRANDOM

uint32_t
nni_random(void)
{
	uint32_t val;

	if (getrandom(&val, sizeof(val), 0) != sizeof(val)) {
		nni_panic("getrandom failed");
	}
	return (val);
}

#endif
