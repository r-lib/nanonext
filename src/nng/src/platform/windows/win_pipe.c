//
// Copyright 2017 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#include <stdio.h>

#ifdef NNG_PLATFORM_WINDOWS

int
nni_plat_pipe_open(int *wfdp, int *rfdp)
{
	SOCKET rfd = INVALID_SOCKET;
	SOCKET wfd = INVALID_SOCKET;
	SOCKET afd;

	struct sockaddr_in addr;
	socklen_t          alen;
	int                one;
	ULONG              yes;
	int                rv;

	ZeroMemory(&addr, sizeof(addr));

	addr.sin_family      = AF_INET;
	addr.sin_port        = 0;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	afd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (afd == INVALID_SOCKET) {
		goto fail;
	}

	one = 1;
	if (setsockopt(afd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *) (&one),
	        sizeof(one)) != 0) {
		goto fail;
	}

	alen = sizeof(addr);
	if (bind(afd, (struct sockaddr *) &addr, alen) != 0) {
		goto fail;
	}
	if (getsockname(afd, (struct sockaddr *) &addr, &alen) != 0) {
		goto fail;
	}

	if (listen(afd, 1) != 0) {
		goto fail;
	}

	rfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (afd == INVALID_SOCKET) {
		goto fail;
	}
	if (connect(rfd, (struct sockaddr *) &addr, alen) != 0) {
		goto fail;
	}

	wfd = accept(afd, NULL, 0);
	if (wfd == INVALID_SOCKET) {
		goto fail;
	}

	yes = 1;
	if (ioctlsocket(rfd, FIONBIO, &yes) != 0) {
		goto fail;
	}
	yes = 1;
	if (ioctlsocket(wfd, FIONBIO, &yes) != 0) {
		goto fail;
	}

	closesocket((SOCKET) afd);
	*rfdp = (int) rfd;
	*wfdp = (int) wfd;
	return (0);

fail:
	rv = nni_win_error(GetLastError());
	if (afd != INVALID_SOCKET) {
		closesocket(afd);
	}
	if (rfd != INVALID_SOCKET) {
		closesocket(rfd);
	}
	if (wfd != INVALID_SOCKET) {
		closesocket(wfd);
	}

	return (rv);
}

void
nni_plat_pipe_raise(int wfd)
{
	char c = 1;

	send((SOCKET) wfd, &c, 1, 0);
}

void
nni_plat_pipe_clear(int rfd)
{
	char buf[32];

	for (;;) {
		if (recv((SOCKET) rfd, buf, sizeof(buf), 0) <= 0) {
			return;
		}
	}
}

void
nni_plat_pipe_close(int wfd, int rfd)
{
	closesocket((SOCKET) wfd);
	closesocket((SOCKET) rfd);
}

#endif
