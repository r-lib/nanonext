//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <errno.h>

#undef NNG_USE_EVENTFD

#ifdef NNG_USE_EVENTFD

#include <fcntl.h>
#include <sys/eventfd.h>
#include <unistd.h>

#ifdef EFD_CLOEXEC
#define NNI_EVENTFD_FLAGS EFD_CLOEXEC
#else
#define NNI_EVENTFD_FLAGS 0
#endif

int
nni_plat_pipe_open(int *wfd, int *rfd)
{
	int fd;

	if ((fd = eventfd(0, NNI_EVENTFD_FLAGS)) < 0) {
		return (nni_plat_errno(errno));
	}
	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);

	*wfd = *rfd = fd;
	return (0);
}

void
nni_plat_pipe_raise(int wfd)
{
	uint64_t one = 1;

	(void) write(wfd, &one, sizeof(one));
}

void
nni_plat_pipe_clear(int rfd)
{
	uint64_t val;

	(void) read(rfd, &val, sizeof(val));
}

void
nni_plat_pipe_close(int wfd, int rfd)
{
	NNI_ASSERT(wfd == rfd);
	(void) close(wfd);
}

#else

#include <fcntl.h>
#include <unistd.h>

int
nni_plat_pipe_open(int *wfd, int *rfd)
{
	int fds[2];

	if (pipe(fds) < 0) {
		return (nni_plat_errno(errno));
	}
	*wfd = fds[1];
	*rfd = fds[0];

	(void) fcntl(fds[0], F_SETFD, FD_CLOEXEC);
	(void) fcntl(fds[1], F_SETFD, FD_CLOEXEC);
	(void) fcntl(fds[0], F_SETFL, O_NONBLOCK);
	(void) fcntl(fds[1], F_SETFL, O_NONBLOCK);

	return (0);
}

void
nni_plat_pipe_raise(int wfd)
{
	char c = 1;

	if (write(wfd, &c, 1)) {}
}

void
nni_plat_pipe_clear(int rfd)
{
	char buf[32];

	for (;;) {
		if (read(rfd, buf, sizeof(buf)) <= 0) {
			return;
		}
	}
}

void
nni_plat_pipe_close(int wfd, int rfd)
{
	(void) close(wfd);
	(void) close(rfd);
}

#endif

#endif
