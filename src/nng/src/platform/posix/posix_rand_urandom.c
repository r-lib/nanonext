//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/nng_impl.h"

static int             urandom_fd   = -1;
static pthread_mutex_t urandom_lock = PTHREAD_MUTEX_INITIALIZER;

#ifndef O_CLOEXEC
#define O_CLOEXEC 0u
#endif

uint32_t
nni_random(void)
{
	int      fd;
	uint32_t val;

	(void) pthread_mutex_lock(&urandom_lock);
	if ((fd = urandom_fd) == -1) {
		if ((fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC)) < 0) {
			(void) pthread_mutex_unlock(&urandom_lock);
			nni_panic("failed to open /dev/urandom");
		}
		urandom_fd = fd;
	}
	(void) pthread_mutex_unlock(&urandom_lock);

	if (read(fd, &val, sizeof(val)) != sizeof(val)) {
		nni_panic("failed reading /dev/urandom");
	}
	return (val);
}