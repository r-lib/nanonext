//
// Copyright 2021 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "nng_impl.h"

struct nni_msgq {
	nni_mtx   mq_lock;
	unsigned  mq_cap;
	unsigned  mq_alloc;
	unsigned  mq_len;
	unsigned  mq_get;
	unsigned  mq_put;
	bool      mq_closed;
	nni_msg **mq_msgs;

	nni_list mq_aio_putq;
	nni_list mq_aio_getq;

	nni_pollable mq_sendable;
	nni_pollable mq_recvable;
};

static void nni_msgq_run_notify(nni_msgq *);

int
nni_msgq_init(nni_msgq **mqp, unsigned cap)
{
	struct nni_msgq *mq;
	unsigned         alloc;

	alloc = cap + 2;

	if ((mq = NNI_ALLOC_STRUCT(mq)) == NULL) {
		return (NNG_ENOMEM);
	}
	if ((mq->mq_msgs = nni_zalloc(sizeof(nng_msg *) * alloc)) == NULL) {
		NNI_FREE_STRUCT(mq);
		return (NNG_ENOMEM);
	}
	nni_aio_list_init(&mq->mq_aio_putq);
	nni_aio_list_init(&mq->mq_aio_getq);
	nni_mtx_init(&mq->mq_lock);
	nni_pollable_init(&mq->mq_recvable);
	nni_pollable_init(&mq->mq_sendable);

	mq->mq_cap    = cap;
	mq->mq_alloc  = alloc;
	mq->mq_len    = 0;
	mq->mq_get    = 0;
	mq->mq_put    = 0;
	mq->mq_closed = 0;
	*mqp          = mq;

	return (0);
}

void
nni_msgq_fini(nni_msgq *mq)
{
	if (mq == NULL) {
		return;
	}
	nni_mtx_fini(&mq->mq_lock);

	
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get >= mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}

	nni_pollable_fini(&mq->mq_sendable);
	nni_pollable_fini(&mq->mq_recvable);

	nni_free(mq->mq_msgs, mq->mq_alloc * sizeof(nng_msg *));
	NNI_FREE_STRUCT(mq);
}

static void
nni_msgq_run_putq(nni_msgq *mq)
{
	nni_aio *waio;

	while ((waio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
		nni_msg *msg = nni_aio_get_msg(waio);
		size_t   len = nni_msg_len(msg);
		nni_aio *raio;

		if ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {

			nni_aio_set_msg(waio, NULL);
			nni_aio_list_remove(waio);
			nni_aio_list_remove(raio);
			nni_aio_finish_msg(raio, msg);
			nni_aio_finish(waio, 0, len);
			continue;
		}

		if (mq->mq_len < mq->mq_cap) {
			nni_list_remove(&mq->mq_aio_putq, waio);
			mq->mq_msgs[mq->mq_put++] = msg;
			if (mq->mq_put == mq->mq_alloc) {
				mq->mq_put = 0;
			}
			mq->mq_len++;
			nni_aio_set_msg(waio, NULL);
			nni_aio_finish(waio, 0, len);
			continue;
		}

		break;
	}
}

static void
nni_msgq_run_getq(nni_msgq *mq)
{
	nni_aio *raio;

	while ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {
		nni_aio *waio;
		if (mq->mq_len != 0) {
			nni_msg *msg = mq->mq_msgs[mq->mq_get++];
			if (mq->mq_get == mq->mq_alloc) {
				mq->mq_get = 0;
			}
			mq->mq_len--;

			nni_aio_list_remove(raio);
			nni_aio_finish_msg(raio, msg);
			continue;
		}

		if ((waio = nni_list_first(&mq->mq_aio_putq)) != NULL) {
			nni_msg *msg;
			size_t   len;
			msg = nni_aio_get_msg(waio);
			len = nni_msg_len(msg);

			nni_aio_set_msg(waio, NULL);
			nni_aio_list_remove(waio);
			nni_aio_finish(waio, 0, len);

			nni_aio_list_remove(raio);
			nni_aio_finish_msg(raio, msg);

			continue;
		}

		break;
	}
}

static void
nni_msgq_run_notify(nni_msgq *mq)
{
	if (mq->mq_len < mq->mq_cap || !nni_list_empty(&mq->mq_aio_getq)) {
		nni_pollable_raise(&mq->mq_sendable);
	} else {
		nni_pollable_clear(&mq->mq_sendable);
	}
	if ((mq->mq_len != 0) || !nni_list_empty(&mq->mq_aio_putq)) {
		nni_pollable_raise(&mq->mq_recvable);
	} else {
		nni_pollable_clear(&mq->mq_recvable);
	}
}

static void
nni_msgq_cancel(nni_aio *aio, void *arg, int rv)
{
	nni_msgq *mq = arg;

	nni_mtx_lock(&mq->mq_lock);
	if (nni_aio_list_active(aio)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, rv);
	}
	nni_msgq_run_notify(mq);
	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_aio_put(nni_msgq *mq, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&mq->mq_lock);

	rv = nni_aio_schedule(aio, nni_msgq_cancel, mq);
	if ((rv != 0) && (mq->mq_len >= mq->mq_cap) &&
	    (nni_list_empty(&mq->mq_aio_getq))) {
		nni_mtx_unlock(&mq->mq_lock);
		nni_aio_finish_error(aio, rv);
		return;
	}
	nni_aio_list_append(&mq->mq_aio_putq, aio);
	nni_msgq_run_putq(mq);
	nni_msgq_run_notify(mq);

	nni_mtx_unlock(&mq->mq_lock);
}

void
nni_msgq_aio_get(nni_msgq *mq, nni_aio *aio)
{
	int rv;

	if (nni_aio_begin(aio) != 0) {
		return;
	}
	nni_mtx_lock(&mq->mq_lock);
	rv = nni_aio_schedule(aio, nni_msgq_cancel, mq);
	if ((rv != 0) && (mq->mq_len == 0) &&
	    (nni_list_empty(&mq->mq_aio_putq))) {
		nni_mtx_unlock(&mq->mq_lock);
		nni_aio_finish_error(aio, rv);
		return;
	}

	nni_aio_list_append(&mq->mq_aio_getq, aio);
	nni_msgq_run_getq(mq);
	nni_msgq_run_notify(mq);

	nni_mtx_unlock(&mq->mq_lock);
}

int
nni_msgq_tryput(nni_msgq *mq, nni_msg *msg)
{
	nni_aio *raio;

	nni_mtx_lock(&mq->mq_lock);
	if (mq->mq_closed) {
		nni_mtx_unlock(&mq->mq_lock);
		return (NNG_ECLOSED);
	}

	if ((raio = nni_list_first(&mq->mq_aio_getq)) != NULL) {

		nni_list_remove(&mq->mq_aio_getq, raio);
		nni_aio_finish_msg(raio, msg);
		nni_msgq_run_notify(mq);
		nni_mtx_unlock(&mq->mq_lock);
		return (0);
	}

	if (mq->mq_len < mq->mq_cap) {
		mq->mq_msgs[mq->mq_put++] = msg;
		if (mq->mq_put == mq->mq_alloc) {
			mq->mq_put = 0;
		}
		mq->mq_len++;
		nni_msgq_run_notify(mq);
		nni_mtx_unlock(&mq->mq_lock);
		return (0);
	}

	nni_mtx_unlock(&mq->mq_lock);
	return (NNG_EAGAIN);
}

void
nni_msgq_close(nni_msgq *mq)
{
	nni_aio *aio;

	nni_mtx_lock(&mq->mq_lock);
	mq->mq_closed = true;
	while (mq->mq_len > 0) {
		nni_msg *msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get >= mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}

	while (((aio = nni_list_first(&mq->mq_aio_getq)) != NULL) ||
	    ((aio = nni_list_first(&mq->mq_aio_putq)) != NULL)) {
		nni_aio_list_remove(aio);
		nni_aio_finish_error(aio, NNG_ECLOSED);
	}

	nni_mtx_unlock(&mq->mq_lock);
}

int
nni_msgq_cap(nni_msgq *mq)
{
	int rv;

	nni_mtx_lock(&mq->mq_lock);
	rv = (int) mq->mq_cap;
	nni_mtx_unlock(&mq->mq_lock);
	return (rv);
}

int
nni_msgq_resize(nni_msgq *mq, int cap)
{
	unsigned  alloc;
	nni_msg  *msg;
	nni_msg **newq, **oldq;
	unsigned  oldget;
	unsigned  oldlen;
	unsigned  oldalloc;

	alloc = cap + 2;

	if (alloc > mq->mq_alloc) {
		newq = nni_zalloc(sizeof(nni_msg *) * alloc);
		if (newq == NULL) {
			return (NNG_ENOMEM);
		}
	} else {
		newq = NULL;
	}

	nni_mtx_lock(&mq->mq_lock);
	while (mq->mq_len > ((unsigned)cap + 1)) {
		msg = mq->mq_msgs[mq->mq_get++];
		if (mq->mq_get > mq->mq_alloc) {
			mq->mq_get = 0;
		}
		mq->mq_len--;
		nni_msg_free(msg);
	}
	if (newq == NULL) {
		mq->mq_cap = cap;
		goto out;
	}

	oldq     = mq->mq_msgs;
	oldget   = mq->mq_get;
	oldalloc = mq->mq_alloc;
	oldlen   = mq->mq_len;

	mq->mq_msgs = newq;
	mq->mq_len = mq->mq_get = mq->mq_put = 0;
	mq->mq_cap                           = cap;
	mq->mq_alloc                         = alloc;

	while (oldlen) {
		mq->mq_msgs[mq->mq_put++] = oldq[oldget++];
		if (oldget == oldalloc) {
			oldget = 0;
		}
		if (mq->mq_put == mq->mq_alloc) {
			mq->mq_put = 0;
		}
		mq->mq_len++;
		oldlen--;
	}
	nni_free(oldq, sizeof(nni_msg *) * oldalloc);

out:
	nni_mtx_unlock(&mq->mq_lock);
	return (0);
}

int
nni_msgq_get_recvable(nni_msgq *mq, nni_pollable **sp)
{
	nni_mtx_lock(&mq->mq_lock);
	nni_msgq_run_notify(mq);
	nni_mtx_unlock(&mq->mq_lock);

	*sp = &mq->mq_recvable;
	return (0);
}

int
nni_msgq_get_sendable(nni_msgq *mq, nni_pollable **sp)
{
	nni_mtx_lock(&mq->mq_lock);
	nni_msgq_run_notify(mq);
	nni_mtx_unlock(&mq->mq_lock);

	*sp = &mq->mq_sendable;
	return (0);
}
