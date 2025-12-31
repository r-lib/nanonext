//
// Copyright 2022 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2017 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <errno.h>
#include <string.h>
#include <time.h>

#if defined(NNG_HAVE_CLOCK_GETTIME) && !defined(NNG_USE_GETTIMEOFDAY)

nni_time
nni_clock(void)
{
	struct timespec ts;
	nni_time        msec;

	if (clock_gettime(NNG_USE_CLOCKID, &ts) != 0) {
		nni_panic("clock_gettime failed: %s", strerror(errno));
	}

	msec = ts.tv_sec;
	msec *= 1000;
	msec += (ts.tv_nsec / 1000000);
	return (msec);
}

void
nni_msleep(nni_duration ms)
{
	struct timespec ts;

	ts.tv_sec  = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000;

	while (ts.tv_sec || ts.tv_nsec) {
		if (nanosleep(&ts, &ts) == 0) {
			break;
		}
	}
}

#else

#include <poll.h>
#include <pthread.h>
#include <sys/time.h>

nni_time
nni_clock(void)
{
	nni_time ms;

	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0) {
		nni_panic("gettimeofday failed: %s", strerror(errno));
	}

	ms = tv.tv_sec;
	ms *= 1000;
	ms += (tv.tv_usec / 1000);
	return (ms);
}

void
nni_msleep(nni_duration ms)
{
	struct pollfd pfd;
	nni_time      now;
	nni_time      expire;

	pfd.fd     = -1;
	pfd.events = 0;

	now    = nni_clock();
	expire = now + ms;

	while (now < expire) {
		(void) poll(&pfd, 0, (int) (expire - now));
		now = nni_clock();
	}
}

#endif

#endif
