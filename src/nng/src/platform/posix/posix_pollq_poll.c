//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"
#include "platform/posix/posix_pollq.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

typedef struct nni_posix_pollq nni_posix_pollq;

struct nni_posix_pollq {
	nni_mtx  mtx;
	int      nfds;
	int      wakewfd;
	int      wakerfd;
	bool     closing;
	bool     closed;
	nni_thr  thr;
	nni_list pollq;
	nni_list reapq;
};

struct nni_posix_pfd {
	nni_posix_pollq *pq;
	int              fd;
	nni_list_node    node;
	nni_cv           cv;
	nni_mtx          mtx;
	unsigned         events;
	nni_posix_pfd_cb cb;
	void *           arg;
};

static nni_posix_pollq nni_posix_global_pollq;

int
nni_posix_pfd_init(nni_posix_pfd **pfdp, int fd)
{
	nni_posix_pfd *  pfd;
	nni_posix_pollq *pq = &nni_posix_global_pollq;

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	(void) fcntl(fd, F_SETFL, O_NONBLOCK);
#ifdef SO_NOSIGPIPE
	int one = 1;
	(void) setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif

	if ((pfd = NNI_ALLOC_STRUCT(pfd)) == NULL) {
		return (NNG_ENOMEM);
	}
	NNI_LIST_NODE_INIT(&pfd->node);
	nni_mtx_init(&pfd->mtx);
	nni_cv_init(&pfd->cv, &pq->mtx);
	pfd->fd     = fd;
	pfd->events = 0;
	pfd->cb     = NULL;
	pfd->arg    = NULL;
	pfd->pq     = pq;
	nni_mtx_lock(&pq->mtx);
	if (pq->closing) {
		nni_mtx_unlock(&pq->mtx);
		nni_cv_fini(&pfd->cv);
		nni_mtx_fini(&pfd->mtx);
		NNI_FREE_STRUCT(pfd);
		return (NNG_ECLOSED);
	}
	nni_list_append(&pq->pollq, pfd);
	pq->nfds++;
	nni_mtx_unlock(&pq->mtx);
	*pfdp = pfd;
	return (0);
}

void
nni_posix_pfd_set_cb(nni_posix_pfd *pfd, nni_posix_pfd_cb cb, void *arg)
{
	nni_mtx_lock(&pfd->mtx);
	pfd->cb  = cb;
	pfd->arg = arg;
	nni_mtx_unlock(&pfd->mtx);
}

int
nni_posix_pfd_fd(nni_posix_pfd *pfd)
{
	return (pfd->fd);
}

void
nni_posix_pfd_close(nni_posix_pfd *pfd)
{
	(void) shutdown(pfd->fd, SHUT_RDWR);
}

void
nni_posix_pfd_fini(nni_posix_pfd *pfd)
{
	nni_posix_pollq *pq = pfd->pq;

	nni_posix_pfd_close(pfd);

	nni_mtx_lock(&pq->mtx);
	if (nni_list_active(&pq->pollq, pfd)) {
		nni_list_remove(&pq->pollq, pfd);
		pq->nfds--;
	}

	if ((!nni_thr_is_self(&pq->thr)) && (!pq->closed)) {
		nni_list_append(&pq->reapq, pfd);
		nni_plat_pipe_raise(pq->wakewfd);
		while (nni_list_active(&pq->reapq, pfd)) {
			nni_cv_wait(&pfd->cv);
		}
	}
	nni_mtx_unlock(&pq->mtx);

	(void) close(pfd->fd);
	nni_cv_fini(&pfd->cv);
	nni_mtx_fini(&pfd->mtx);
	NNI_FREE_STRUCT(pfd);
}

int
nni_posix_pfd_arm(nni_posix_pfd *pfd, unsigned events)
{
	nni_posix_pollq *pq = pfd->pq;

	nni_mtx_lock(&pfd->mtx);
	pfd->events |= events;
	nni_mtx_unlock(&pfd->mtx);

	if (!nni_thr_is_self(&pq->thr)) {
		nni_plat_pipe_raise(pq->wakewfd);
	}
	return (0);
}

static void
nni_posix_poll_thr(void *arg)
{
	nni_posix_pollq *pq     = arg;
	int              nalloc = 0;
	struct pollfd *  fds    = NULL;
	nni_posix_pfd ** pfds   = NULL;

	for (;;) {
		int            nfds;
		unsigned       events;
		nni_posix_pfd *pfd;

		nni_mtx_lock(&pq->mtx);
		while (nalloc < (pq->nfds + 1)) {
			int n = pq->nfds + 128;

			nni_mtx_unlock(&pq->mtx);

			NNI_FREE_STRUCTS(fds, nalloc);
			NNI_FREE_STRUCTS(pfds, nalloc);
			nalloc = 0;

			if ((pfds = NNI_ALLOC_STRUCTS(pfds, n)) == NULL) {
				nni_msleep(10);
			} else if ((fds = NNI_ALLOC_STRUCTS(fds, n)) == NULL) {
				NNI_FREE_STRUCTS(pfds, n);
				nni_msleep(10);
			} else {
				nalloc = n;
			}
			nni_mtx_lock(&pq->mtx);
		}

		fds[0].fd      = pq->wakerfd;
		fds[0].events  = POLLIN;
		fds[0].revents = 0;
		pfds[0]        = NULL;
		nfds           = 1;

		while ((pfd = nni_list_first(&pq->reapq)) != NULL) {
			nni_list_remove(&pq->reapq, pfd);
			nni_cv_wake(&pfd->cv);
		}

		if (pq->closing) {
			pq->closed = true;
			nni_mtx_unlock(&pq->mtx);
			break;
		}

		NNI_LIST_FOREACH (&pq->pollq, pfd) {

			nni_mtx_lock(&pfd->mtx);
			events = pfd->events;
			nni_mtx_unlock(&pfd->mtx);

			if (events != 0) {
				fds[nfds].fd      = pfd->fd;
				fds[nfds].events  = events;
				fds[nfds].revents = 0;
				pfds[nfds]        = pfd;
				nfds++;
			}
		}
		nni_mtx_unlock(&pq->mtx);

		(void) poll(fds, nfds, -1);

		if (fds[0].revents & POLLIN) {
			NNI_ASSERT(fds[0].fd == pq->wakerfd);
			nni_plat_pipe_clear(pq->wakerfd);
		}

		for (int i = 1; i < nfds; i++) {
			if ((events = fds[i].revents) != 0) {
				nni_posix_pfd_cb cb;
				void *           arg;

				pfd = pfds[i];

				nni_mtx_lock(&pfd->mtx);
				cb  = pfd->cb;
				arg = pfd->arg;
				pfd->events &= ~events;
				nni_mtx_unlock(&pfd->mtx);

				if (cb) {
					cb(pfd, events, arg);
				}
			}
		}
	}

	NNI_FREE_STRUCTS(fds, nalloc);
	NNI_FREE_STRUCTS(pfds, nalloc);
}

static void
nni_posix_pollq_destroy(nni_posix_pollq *pq)
{
	nni_mtx_lock(&pq->mtx);
	pq->closing = true;
	nni_mtx_unlock(&pq->mtx);

	nni_plat_pipe_raise(pq->wakewfd);

	nni_thr_fini(&pq->thr);
	nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
	nni_mtx_fini(&pq->mtx);
}

static int
nni_posix_pollq_create(nni_posix_pollq *pq)
{
	int rv;

	NNI_LIST_INIT(&pq->pollq, nni_posix_pfd, node);
	NNI_LIST_INIT(&pq->reapq, nni_posix_pfd, node);
	pq->closing = false;
	pq->closed  = false;

	if ((rv = nni_plat_pipe_open(&pq->wakewfd, &pq->wakerfd)) != 0) {
		return (rv);
	}
	if ((rv = nni_thr_init(&pq->thr, nni_posix_poll_thr, pq)) != 0) {
		nni_plat_pipe_close(pq->wakewfd, pq->wakerfd);
		return (rv);
	}
	nni_thr_set_name(&pq->thr, "nng:poll:poll");
	nni_mtx_init(&pq->mtx);
	nni_thr_run(&pq->thr);
	return (0);
}

int
nni_posix_pollq_sysinit(void)
{
	return (nni_posix_pollq_create(&nni_posix_global_pollq));
}

void
nni_posix_pollq_sysfini(void)
{
	nni_posix_pollq_destroy(&nni_posix_global_pollq);
}
