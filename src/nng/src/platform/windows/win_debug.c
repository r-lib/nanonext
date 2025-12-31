//
// Copyright 2024 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_WINDOWS

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
nni_plat_abort(void)
{
	abort();
}

void
nni_plat_printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void) vprintf(fmt, ap);
	va_end(ap);
}

void
nni_plat_println(const char *message)
{
	(void) fprintf(stderr, "%s\n", message);
}

const char *
nni_plat_strerror(int errnum)
{
	if (errnum > NNG_ESYSERR) {
		errnum -= NNG_ESYSERR;
	}
	return (strerror(errnum));
}

static struct {
	int sys_err;
	int nng_err;
} nni_plat_errnos[] = {
	// clang-format off
	{ ENOENT,	NNG_ENOENT },
	{ EINTR,	NNG_EINTR },
	{ EINVAL,	NNG_EINVAL },
	{ ENOMEM,	NNG_ENOMEM },
	{ EACCES,	NNG_EPERM },
	{ EAGAIN,	NNG_EAGAIN },
	{ EBADF,	NNG_ECLOSED },
	{ EBUSY,	NNG_EBUSY },
	{ ENAMETOOLONG,	NNG_EINVAL },
	{ EPERM,	NNG_EPERM },
	{ EPIPE,	NNG_ECLOSED },
	{ 0,		0 }
	// clang-format on
};

int
nni_plat_errno(int errnum)
{
	int i;

	if (errnum == 0) {
		return (0);
	}
	for (i = 0; nni_plat_errnos[i].nng_err != 0; i++) {
		if (errnum == nni_plat_errnos[i].sys_err) {
			return (nni_plat_errnos[i].nng_err);
		}
	}
	return (NNG_ESYSERR + errnum);
}

static struct {
	int win_err;
	int nng_err;
} nni_win_errnos[] = {
	// clang-format off
	{ ERROR_FILE_NOT_FOUND,	    NNG_ENOENT	     },
	{ ERROR_PATH_NOT_FOUND,	    NNG_ENOENT	     },
	{ ERROR_ACCESS_DENIED,	    NNG_EPERM	     },
	{ ERROR_INVALID_HANDLE,	    NNG_ECLOSED	     },
	{ ERROR_NOT_ENOUGH_MEMORY,  NNG_ENOMEM	     },
	{ ERROR_INVALID_ACCESS,	    NNG_EPERM	     },
	{ ERROR_INVALID_DATA,	    NNG_EINVAL	     },
	{ ERROR_OUTOFMEMORY,	    NNG_ENOMEM	     },
	{ ERROR_HANDLE_EOF,	    NNG_ECLOSED	     },
	{ ERROR_NOT_SUPPORTED,	    NNG_ENOTSUP	     },
	{ ERROR_OUT_OF_STRUCTURES,  NNG_ENOMEM	     },
	{ ERROR_INVALID_PARAMETER,  NNG_EINVAL	     },
	{ ERROR_CONNECTION_REFUSED, NNG_ECONNREFUSED },
  { ERROR_DUP_NAME,           NNG_EADDRINUSE   },
	{ ERROR_BROKEN_PIPE,	    NNG_ECLOSED	     },
	{ ERROR_BAD_PIPE,	    NNG_ECLOSED	     },
	{ ERROR_NO_DATA,	    NNG_ECONNRESET	     },
	{ ERROR_PIPE_NOT_CONNECTED, NNG_ECLOSED	     },
	{ ERROR_OPERATION_ABORTED,  NNG_ECLOSED	     },
	{ ERROR_SHARING_VIOLATION,  NNG_EBUSY        },
	{ WAIT_TIMEOUT,		    NNG_ETIMEDOUT    },
	{ WSAEINTR,		    NNG_EINTR	     },
	{ WSAEBADF,		    NNG_ECLOSED	     },
	{ WSAEACCES,		    NNG_EPERM	     },
	{ WSAEWOULDBLOCK,	    NNG_EAGAIN	     },
	{ WSAEINPROGRESS,	    NNG_EAGAIN	     },
	{ WSAENOTSOCK,		    NNG_ECLOSED	     },
	{ WSAEINVAL,		    NNG_EINVAL       },
	{ WSAEMSGSIZE,		    NNG_EMSGSIZE     },
	{ WSAENOPROTOOPT,	    NNG_ENOTSUP	     },
	{ WSAEPROTONOSUPPORT,	    NNG_ENOTSUP	     },
	{ WSAEPROTONOSUPPORT,	    NNG_ENOTSUP	     },
	{ WSAESOCKTNOSUPPORT,	    NNG_ENOTSUP      },
	{ WSAEOPNOTSUPP,	    NNG_ENOTSUP      },
	{ WSAEPFNOSUPPORT,	    NNG_ENOTSUP      },
	{ WSAEAFNOSUPPORT,	    NNG_ENOTSUP      },
	{ WSAEADDRINUSE,	    NNG_EADDRINUSE   },
	{ WSAEADDRNOTAVAIL,	    NNG_EADDRINVAL   },
	{ WSAENETDOWN,		    NNG_EUNREACHABLE },
	{ WSAENETUNREACH,	    NNG_EUNREACHABLE },
	{ WSAECONNABORTED,	    NNG_ETIMEDOUT    },
	{ WSAECONNRESET,	    NNG_ECLOSED	     },
	{ WSAENOBUFS,		    NNG_ENOMEM	     },
	{ WSAENOTCONN,		    NNG_ECLOSED	     },
	{ WSAESHUTDOWN,		    NNG_ECLOSED	     },
	{ WSAETIMEDOUT,		    NNG_ETIMEDOUT    },
	{ WSAECONNREFUSED,	    NNG_ECONNREFUSED },
	{ WSAEHOSTDOWN,		    NNG_EUNREACHABLE },
	{ WSAEHOSTUNREACH,	    NNG_EUNREACHABLE },
	{ WSAVERNOTSUPPORTED,	    NNG_ENOTSUP	     },
	{ WSAEDISCON,		    NNG_ECLOSED	     },
	{ WSAECANCELLED,	    NNG_ECANCELED    },
	{ WSA_E_CANCELLED,	    NNG_ECANCELED    },
	{ WSAHOST_NOT_FOUND,	    NNG_EADDRINVAL   },
	{ WSATRY_AGAIN,		    NNG_EAGAIN	     },
	{ WSANO_DATA,		    NNG_EADDRINVAL   },

	{			 0,		   0 },
	// clang-format on
};

int
nni_win_error(int errnum)
{
	int i;

	if (errnum == 0) {
		return (0);
	}
	for (i = 0; nni_win_errnos[i].win_err != 0; i++) {
		if (errnum == nni_win_errnos[i].win_err) {
			return (nni_win_errnos[i].nng_err);
		}
	}
	return (NNG_ESYSERR + errnum);
}

#endif
