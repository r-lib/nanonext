//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include <time.h>

#ifdef NNG_PLATFORM_POSIX
#if !defined(NNG_USE_DEVURANDOM) && !defined(NNG_USE_GETENTROPY) && \
    !defined(NNG_USE_GETRANDOM) && !defined(NNG_USE_ARC4RANDOM)
#if defined(NNG_HAVE_GETENTROPY)
#define NNG_USE_GETENTROPY 1
#elif defined(NNG_HAVE_GETRANDOM)
#define NNG_USE_GETRANDOM 1
#elif defined(NNG_HAVE_ARC4RANDOM)
#define NNG_USE_ARC4RANDOM
#else
#define NNG_USE_DEVURANDOM 1
#endif
#endif

#ifndef NNG_USE_CLOCKID
#if defined(__APPLE__)
#define NNG_USE_CLOCKID CLOCK_REALTIME
#elif defined(CLOCK_MONOTONIC)
#define NNG_USE_CLOCKID CLOCK_MONOTONIC
#elif defined(CLOCK_REALTIME)
#define NNG_USE_CLOCKID CLOCK_REALTIME
#else
#define NNG_USE_GETTIMEOFDAY
#endif
#endif

#define NNG_USE_POSIX_RESOLV_GAI 1

#endif // NNG_PLATFORM_POSIX
