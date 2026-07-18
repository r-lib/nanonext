// nanonext - dispatcher implementation -----------------------------------------

#define NANONEXT_PROTOCOLS
#include "nanonext.h"

// L'Ecuyer-CMRG RNG stream advancement ----------------------------------------
//
// Pure-C implementation of MRG32k3a stream jumping. Moduli and jump matrix
// constants below are from the RngStreams package by Pierre L'Ecuyer,
// University of Montreal (https://github.com/umontreal-simul/RngStreams),
// licensed under the Apache License, Version 2.0. The original copyright
// notice requests citation of:
//
//   P. L'Ecuyer, "Good Parameter Sets for Combined Multiple Recursive Random
//     Number Generators", Operations Research, 47, 1 (1999), 159-164.
//   P. L'Ecuyer, R. Simard, E. J. Chen, and W. D. Kelton, "An Objected-
//     Oriented Random-Number Package with Many Long Streams and Substreams",
//     Operations Research, 50, 6 (2002), 1073-1075.
//

#define M1 4294967087ULL
#define M2 4294944443ULL

// Jump matrices A1^(2^127) mod m1 and A2^(2^127) mod m2
static const unsigned long long A1p127[3][3] = {
  { 2427906178ULL, 3580155704ULL,  949770784ULL },
  {  226153695ULL, 1230515664ULL, 3580155704ULL },
  { 1988835001ULL,  986791581ULL, 1230515664ULL }
};
static const unsigned long long A2p127[3][3] = {
  { 1464411153ULL,  277697599ULL, 1610723613ULL },
  {   32183930ULL, 1464411153ULL, 1022607788ULL },
  { 2824425944ULL,   32183930ULL, 2093834863ULL }
};

static void mat_vec_mod(const unsigned long long A[3][3],
                        const unsigned long long *v,
                        unsigned long long *out, unsigned long long m) {
  for (int i = 0; i < 3; i++) {
    unsigned long long s = 0;
    for (int j = 0; j < 3; j++) {
      s = (s + (A[i][j] * v[j]) % m) % m;
    }
    out[i] = s;
  }
}

static void next_rng_stream_c(int *seed) {
  unsigned long long v1[3] = { (unsigned int) seed[0], (unsigned int) seed[1], (unsigned int) seed[2] };
  unsigned long long v2[3] = { (unsigned int) seed[3], (unsigned int) seed[4], (unsigned int) seed[5] };
  unsigned long long out1[3], out2[3];
  mat_vec_mod(A1p127, v1, out1, M1);
  mat_vec_mod(A2p127, v2, out2, M2);
  for (int i = 0; i < 3; i++) {
    seed[i]     = (int) out1[i];
    seed[i + 3] = (int) out2[i];
  }
}

// data structures -------------------------------------------------------------

#define DISPATCH_INITIAL_SIZE 16

typedef struct nano_dispatcher_s nano_dispatcher;

typedef struct nano_dispatch_task_s {
  nng_ctx ctx;
  nng_msg *msg;
  int msgid;
  int is_sync;
  struct nano_dispatch_task_s *next;
} nano_dispatch_task;

enum { DAEMON_INIT, DAEMON_IDLE, DAEMON_BUSY };

typedef struct nano_dsend_s {
  nano_dispatcher *d;
  nng_aio *aio;
  int pipe;
  int sending;
  struct nano_dsend_s *next;
} nano_dsend;

typedef struct nano_reply_s {
  nano_dispatcher *d;
  nng_aio *aio;
  nng_ctx ctx;
  struct nano_reply_s *next;
} nano_reply;

typedef struct nano_signode_s {
  nng_msg *msg;
  struct nano_signode_s *next;
} nano_signode;

typedef struct nano_dispatch_daemon_s {
  int pipe;
  uint8_t state;
  int msgid;
  int sync_gen;
  nng_ctx ctx;
  nano_dsend *ds;
} nano_dispatch_daemon;

struct nano_dispatcher_s {
  nng_socket *rep_sock;
  nng_socket *poly_sock;
  nano_cv *cv;
  nano_monitor *monitor;
  nano_dispatch_task *inq_head;
  nano_dispatch_task *inq_tail;
  nano_dispatch_daemon *daemons;
  int inq_count;
  int outq_capacity;
  int nslots;
  int outq_count;
  int connections;
  int count;
  int executing;
  int stopped;
  nng_aio *host_aio;
  nng_aio *daemon_aio;
  nng_ctx host_ctx;
  int host_recv_ready;
  int daemon_recv_ready;
  nng_aio *sig_aio;
  int sig_active;
  nano_signode *sig_head;
  nano_signode *sig_tail;
  nano_dsend *retired;
  nano_reply *reply_reap;
  int replies_active;
  int rng_seed[6];
  unsigned char *init_template;
  size_t init_template_len;
  size_t init_seed_offset;
  unsigned char *conn_reset_buf;
  size_t conn_reset_len;
  int syncing;
  int sync_generation;
  int *pipe_events;
  int pipe_events_size;
  size_t limit_bytes;
  size_t queued_bytes;
  size_t peak_queued_bytes;
};

// forward declarations --------------------------------------------------------

static void dispatch_shutdown(nano_dispatcher *d);
static void dispatch_handle_connect(nano_dispatcher *d, int pipe);
static void dispatch_handle_disconnect(nano_dispatcher *d, int pipe);
static void dispatch_dispatch_tasks(nano_dispatcher *d);
static int dispatch_cancel_inq(nano_dispatcher *d, int id);
static nano_dispatch_daemon *dispatch_find_idle_daemon(nano_dispatcher *d);

// daemon array operations -----------------------------------------------------

static nano_dispatch_daemon *dispatch_find_daemon(nano_dispatcher *d, int pipe) {

  for (int i = 0; i < d->nslots; i++)
    if (d->daemons[i].pipe == pipe)
      return &d->daemons[i];

  return NULL;

}

// insert a slot in DAEMON_INIT state; called under d->cv->mtx
static nano_dispatch_daemon *dispatch_insert_daemon(nano_dispatcher *d, int pipe, nano_dsend *ds) {

  if (d->nslots >= d->outq_capacity) {
    int new_cap = d->outq_capacity * 2;
    nano_dispatch_daemon *new_arr = realloc(d->daemons, new_cap * sizeof(nano_dispatch_daemon));
    if (new_arr == NULL)
      return NULL;
    d->daemons = new_arr;
    d->outq_capacity = new_cap;
  }

  nano_dispatch_daemon *dd = &d->daemons[d->nslots++];
  dd->pipe = pipe;
  dd->state = DAEMON_INIT;
  dd->msgid = 0;
  dd->sync_gen = d->sync_generation - 1;
  dd->ds = ds;
  return dd;

}

// pop-swap a slot, retiring its sender for lazy reap; called under d->cv->mtx
static void dispatch_remove_daemon(nano_dispatcher *d, nano_dispatch_daemon *dd) {

  nano_dsend *ds = dd->ds;
  ds->next = d->retired;
  d->retired = ds;
  if (dd->state != DAEMON_INIT)
    d->outq_count--;
  *dd = d->daemons[--d->nslots];

}

// queue operations ------------------------------------------------------------

static void dispatch_enqueue(nano_dispatcher *d, nng_ctx ctx,
                             nng_msg *msg, int msgid, int is_sync) {

  nano_dispatch_task *t = malloc(sizeof(nano_dispatch_task));
  if (t == NULL) {
    nng_ctx_close(ctx);
    nng_msg_free(msg);
    return;
  }
  t->ctx = ctx;
  t->msg = msg;
  t->msgid = msgid;
  t->is_sync = is_sync;
  t->next = NULL;

  if (d->inq_tail)
    d->inq_tail->next = t;
  else
    d->inq_head = t;
  d->inq_tail = t;
  d->inq_count++;
  d->queued_bytes += nng_msg_len(msg);
  if (d->queued_bytes > d->peak_queued_bytes)
    d->peak_queued_bytes = d->queued_bytes;

}

static void dispatch_dequeue(nano_dispatcher *d) {

  nano_dispatch_task *t = d->inq_head;
  if (t) {
    d->inq_head = t->next;
    if (d->inq_head == NULL)
      d->inq_tail = NULL;
    d->inq_count--;
    free(t);
  }

}

static void dispatch_free_task(nano_dispatch_task *t) {

  nng_ctx_close(t->ctx);
  if (t->msg)
    nng_msg_free(t->msg);
  free(t);

}

// send operations -------------------------------------------------------------
//
// All sends from callback context are asynchronous: a blocking send from an
// NNG task thread can occupy the entire task pool and deadlock the socket's
// own send cycle. Per-pipe invariant on the poly socket: at most one task
// send plus one zero-length signal in flight per daemon (the pair1-poly
// per-pipe send queue has depth 2 and drops silently on overflow).

static void dispatch_dsend_cb(void *arg) {

  nano_dsend *ds = (nano_dsend *) arg;
  nano_dispatcher *d = ds->d;
  const int res = nng_aio_result(ds->aio);
  if (res != 0)
    nng_msg_free(nng_aio_get_msg(ds->aio));

  nng_mtx_lock(d->cv->mtx);
  ds->sending = 0;
  nano_dispatch_daemon *dd = dispatch_find_daemon(d, ds->pipe);
  if (res == 0 && dd != NULL && dd->ds == ds && dd->state == DAEMON_INIT) {
    dd->state = DAEMON_IDLE;
    d->connections++;
    d->outq_count++;
    nng_cv_wake(d->cv->cv);
  }
  nng_mtx_unlock(d->cv->mtx);

  dispatch_dispatch_tasks(d);

}

// start a send to a slot's daemon, taking ownership of msg; must be called
// under d->cv->mtx: the lock orders send initiation against slot retirement
// and against shutdown's stop of the send aios
static void dispatch_start_send(nano_dispatcher *d, nano_dispatch_daemon *dd, nng_msg *msg) {

  nano_dsend *ds = dd->ds;
  nng_msg_set_pipe(msg, (nng_pipe) {.id = (uint32_t) dd->pipe});
  ds->sending = 1;
  nng_aio_set_msg(ds->aio, msg);
  nng_send_aio(*d->poly_sock, ds->aio);

}

// queue a zero-length signal to a daemon; called under d->cv->mtx
static void dispatch_queue_signal(nano_dispatcher *d, int pipe) {

  if (d->stopped)
    return;

  nng_msg *msg;
  if (nng_msg_alloc(&msg, 0))
    return;
  nng_msg_set_pipe(msg, (nng_pipe) {.id = (uint32_t) pipe});

  if (!d->sig_active) {
    d->sig_active = 1;
    nng_aio_set_msg(d->sig_aio, msg);
    nng_send_aio(*d->poly_sock, d->sig_aio);
    return;
  }

  nano_signode *node = malloc(sizeof(nano_signode));
  if (node == NULL) {
    nng_msg_free(msg);
    return;
  }
  node->msg = msg;
  node->next = NULL;
  if (d->sig_tail)
    d->sig_tail->next = node;
  else
    d->sig_head = node;
  d->sig_tail = node;

}

static void dispatch_sig_cb(void *arg) {

  nano_dispatcher *d = (nano_dispatcher *) arg;
  if (nng_aio_result(d->sig_aio) != 0)
    nng_msg_free(nng_aio_get_msg(d->sig_aio));

  nano_signode *node = NULL;
  nng_mtx_lock(d->cv->mtx);
  if (!d->stopped && d->sig_head != NULL) {
    node = d->sig_head;
    d->sig_head = node->next;
    if (d->sig_head == NULL)
      d->sig_tail = NULL;
    nng_aio_set_msg(d->sig_aio, node->msg);
    nng_send_aio(*d->poly_sock, d->sig_aio);
  } else {
    d->sig_active = 0;
  }
  nng_mtx_unlock(d->cv->mtx);
  free(node);

}

static void dispatch_reply_cb(void *arg) {

  nano_reply *r = (nano_reply *) arg;
  nano_dispatcher *d = r->d;

  if (nng_aio_result(r->aio) != 0)
    nng_msg_free(nng_aio_get_msg(r->aio));
  nng_ctx_close(r->ctx);

  nng_mtx_lock(d->cv->mtx);
  r->next = d->reply_reap;
  d->reply_reap = r;
  d->replies_active--;
  if (d->stopped)
    nng_cv_wake(d->cv->cv);
  nng_mtx_unlock(d->cv->mtx);

}

// forward a reply to the host, taking ownership of ctx and msg; the holder's
// callback closes the ctx once the send completes
static void dispatch_send_reply(nano_dispatcher *d, nng_ctx ctx, nng_msg *msg) {

  nano_reply *reap, *r = malloc(sizeof(nano_reply));
  if (r == NULL) {
    nng_msg_free(msg);
    nng_ctx_close(ctx);
    return;
  }
  if (nng_aio_alloc(&r->aio, dispatch_reply_cb, r)) {
    free(r);
    nng_msg_free(msg);
    nng_ctx_close(ctx);
    return;
  }
  r->d = d;
  r->ctx = ctx;

  nng_mtx_lock(d->cv->mtx);
  d->replies_active++;
  reap = d->reply_reap;
  d->reply_reap = NULL;
  nng_mtx_unlock(d->cv->mtx);

  nng_aio_set_msg(r->aio, msg);
  nng_ctx_send(ctx, r->aio);

  while (reap != NULL) {
    nano_reply *next = reap->next;
    nng_aio_stop(reap->aio);
    nng_aio_free(reap->aio);
    free(reap);
    reap = next;
  }

}

static void dispatch_send_conn_reset(nano_dispatcher *d, nng_ctx ctx) {

  nng_msg *msg;
  if (nng_msg_alloc(&msg, d->conn_reset_len)) {
    nng_ctx_close(ctx);
    return;
  }
  memcpy(nng_msg_body(msg), d->conn_reset_buf, d->conn_reset_len);
  dispatch_send_reply(d, ctx, msg);

}

// free retired senders whose last operation has completed; entries with a
// send still in flight stay on the list for a later pass
static void dispatch_reap_retired(nano_dispatcher *d) {

  nano_dsend *list = NULL, **pp;

  nng_mtx_lock(d->cv->mtx);
  pp = &d->retired;
  while (*pp != NULL) {
    nano_dsend *ds = *pp;
    if (!ds->sending) {
      *pp = ds->next;
      ds->next = list;
      list = ds;
    } else {
      pp = &ds->next;
    }
  }
  nng_mtx_unlock(d->cv->mtx);

  while (list != NULL) {
    nano_dsend *next = list->next;
    nng_aio_stop(list->aio);
    nng_aio_free(list->aio);
    free(list);
    list = next;
  }

}

// AIO Callbacks ---------------------------------------------------------------

static void host_recv_cb(void *arg) {

  nano_dispatcher *d = (nano_dispatcher *) arg;
  nng_mtx *mtx = d->cv->mtx;

  nng_mtx_lock(mtx);
  d->host_recv_ready = 1;
  d->cv->condition++;
  nng_cv_wake(d->cv->cv);
  nng_mtx_unlock(mtx);

}

static void daemon_recv_cb(void *arg) {

  nano_dispatcher *d = (nano_dispatcher *) arg;
  nng_mtx *mtx = d->cv->mtx;

  nng_mtx_lock(mtx);
  d->daemon_recv_ready = 1;
  d->cv->condition++;
  nng_cv_wake(d->cv->cv);
  nng_mtx_unlock(mtx);

}

// message utilities -----------------------------------------------------------

static inline void dispatch_read_msg_info(unsigned char *buf, size_t len,
                                          int *msgid, int *is_sync) {

  if (len > 12 && buf[0] == 0x7) {
    memcpy(msgid, buf + 4, sizeof(int));
    *is_sync = buf[3] == 0x1;
  } else {
    *msgid = 0;
    *is_sync = 0;
  }

}

// init template ---------------------------------------------------------------

static int dispatch_prepare_init_template(nano_dispatcher *d, SEXP stream,
                                          SEXP serial) {

  int *sdata = INTEGER(stream);
  for (int i = 0; i < 6; i++)
    d->rng_seed[i] = sdata[i + 1];

  int saved[6];
  memcpy(saved, sdata + 1, 6 * sizeof(int));

  const int sentinel_val = 0x7F7F7F7F;
  for (int i = 0; i < 6; i++)
    sdata[i + 1] = sentinel_val;

  SEXP init_data;
  PROTECT(init_data = Rf_allocVector(VECSXP, 2));
  SET_VECTOR_ELT(init_data, 0, stream);
  SET_VECTOR_ELT(init_data, 1, serial);

  nano_buf buf;
  nano_serialize(&buf, init_data, serial, 0, 0);
  UNPROTECT(1);

  memcpy(sdata + 1, saved, 6 * sizeof(int));

  unsigned char sentinel[24];
  memset(sentinel, 0x7F, 24);
  size_t offset = 0;
  int found = 0;

  for (size_t i = 0; i + 24 <= buf.cur; i++) {
    if (memcmp(buf.buf + i, sentinel, 24) == 0) {
      offset = i;
      found = 1;
      break;
    }
  }

  if (!found) {
    NANO_FREE(buf);
    return -1;
  }

  d->init_template = malloc(buf.cur);
  if (d->init_template == NULL) {
    NANO_FREE(buf);
    return -1;
  }
  memcpy(d->init_template, buf.buf, buf.cur);
  d->init_template_len = buf.cur;
  d->init_seed_offset = offset;
  NANO_FREE(buf);

  return 0;

}

// event handlers --------------------------------------------------------------

static void dispatch_handle_connect(nano_dispatcher *d, int pipe) {

  dispatch_reap_retired(d);

  nng_msg *msg;
  if (nng_msg_alloc(&msg, d->init_template_len))
    return;
  unsigned char *buf = nng_msg_body(msg);
  memcpy(buf, d->init_template, d->init_template_len);

  nano_dsend *ds = calloc(1, sizeof(nano_dsend));
  if (ds == NULL) {
    nng_msg_free(msg);
    return;
  }
  ds->d = d;
  ds->pipe = pipe;
  if (nng_aio_alloc(&ds->aio, dispatch_dsend_cb, ds)) {
    free(ds);
    nng_msg_free(msg);
    return;
  }

  nng_mtx_lock(d->cv->mtx);
  if (d->stopped || dispatch_insert_daemon(d, pipe, ds) == NULL) {
    nng_mtx_unlock(d->cv->mtx);
    nng_aio_free(ds->aio);
    free(ds);
    nng_msg_free(msg);
    return;
  }
  next_rng_stream_c(d->rng_seed);
  memcpy(buf + d->init_seed_offset, d->rng_seed, sizeof(d->rng_seed));
  nng_msg_set_pipe(msg, (nng_pipe) {.id = (uint32_t) pipe});
  ds->sending = 1;
  nng_aio_set_msg(ds->aio, msg);
  nng_send_aio(*d->poly_sock, ds->aio);
  nng_mtx_unlock(d->cv->mtx);

}

static void dispatch_handle_disconnect(nano_dispatcher *d, int pipe) {

  nng_mtx_lock(d->cv->mtx);
  nano_dispatch_daemon *dd = dispatch_find_daemon(d, pipe);
  if (dd == NULL) {
    nng_mtx_unlock(d->cv->mtx);
    return;
  }

  const int busy = dd->state == DAEMON_BUSY;
  const int stopped = d->stopped;
  nng_ctx ctx;
  if (busy) {
    d->executing--;
    ctx = dd->ctx;
  }
  dispatch_remove_daemon(d, dd);
  nng_cv_wake(d->cv->cv);
  nng_mtx_unlock(d->cv->mtx);

  if (busy) {
    if (stopped)
      nng_ctx_close(ctx);
    else
      dispatch_send_conn_reset(d, ctx);
  }

}

static void dispatch_handle_host_recv(nano_dispatcher *d) {

  nng_msg *msg = nng_aio_get_msg(d->host_aio);
  int msgid, is_sync;
  dispatch_read_msg_info(nng_msg_body(msg), nng_msg_len(msg), &msgid, &is_sync);

  nng_mtx_lock(d->cv->mtx);
  if (d->stopped) {
    nng_mtx_unlock(d->cv->mtx);
    nng_msg_free(msg);
    return;
  }
  d->count++;

  nano_dispatch_daemon *dd = dispatch_find_idle_daemon(d);
  if (dd != NULL) {
    dd->ctx = d->host_ctx;
    dd->msgid = msgid;
    dd->state = DAEMON_BUSY;
    d->executing++;
    if (is_sync) {
      dd->sync_gen = d->sync_generation;
      d->syncing = 1;
    } else if (d->syncing) {
      d->syncing = 0;
      d->sync_generation++;
    }
    dispatch_start_send(d, dd, msg);
  } else {
    dispatch_enqueue(d, d->host_ctx, msg, msgid, is_sync);
  }
  nng_mtx_unlock(d->cv->mtx);

  if (nng_ctx_open(&d->host_ctx, *d->rep_sock) == 0) {
    nng_ctx_recv(d->host_ctx, d->host_aio);
  } else {
    nng_mtx_lock(d->cv->mtx);
    d->stopped = 1;
    nng_cv_wake(d->cv->cv);
    nng_mtx_unlock(d->cv->mtx);
  }

}

static void dispatch_handle_daemon_recv(nano_dispatcher *d) {

  nng_msg *msg = nng_aio_get_msg(d->daemon_aio);
  nng_pipe pipe = nng_msg_get_pipe(msg);
  int pipe_id = (int) pipe.id;
  int dummy, is_marker;
  dispatch_read_msg_info(nng_msg_body(msg), nng_msg_len(msg), &dummy, &is_marker);

  nng_mtx_lock(d->cv->mtx);
  nano_dispatch_daemon *dd = dispatch_find_daemon(d, pipe_id);
  if (!d->stopped && dd != NULL && dd->state == DAEMON_BUSY) {
    d->executing--;
    nng_ctx ctx = dd->ctx;

    if (is_marker) {
      dispatch_remove_daemon(d, dd);
      dispatch_queue_signal(d, pipe_id);
      nng_cv_wake(d->cv->cv);
    } else {
      dd->state = DAEMON_IDLE;
      dd->msgid = 0;
    }
    nng_mtx_unlock(d->cv->mtx);

    dispatch_send_reply(d, ctx, msg);
  } else {
    nng_mtx_unlock(d->cv->mtx);
    nng_msg_free(msg);
  }

  nng_recv_aio(*d->poly_sock, d->daemon_aio);

}

// helper functions ------------------------------------------------------------

static int dispatch_cancel_inq(nano_dispatcher *d, int id) {

  nano_dispatch_task **pp = &d->inq_head;
  nano_dispatch_task *prev = NULL;
  while (*pp) {
    if ((*pp)->msgid == id) {
      nano_dispatch_task *t = *pp;
      *pp = t->next;
      if (t == d->inq_tail)
        d->inq_tail = prev;
      d->queued_bytes -= nng_msg_len(t->msg);
      dispatch_free_task(t);
      d->inq_count--;
      if (d->limit_bytes > 0)
        nng_cv_wake(d->cv->cv);
      return 1;
    }
    prev = *pp;
    pp = &(*pp)->next;
  }
  return 0;

}

static nano_dispatch_daemon *dispatch_find_idle_daemon(nano_dispatcher *d) {

  for (int i = 0; i < d->nslots; i++) {
    nano_dispatch_daemon *dd = &d->daemons[i];
    if (dd->state == DAEMON_IDLE && !dd->ds->sending &&
        !(d->syncing && dd->sync_gen == d->sync_generation))
      return dd;
  }

  return NULL;

}

// task dispatcher -------------------------------------------------------------

static void dispatch_dispatch_tasks(nano_dispatcher *d) {

  int dequeued = 0;

  nng_mtx_lock(d->cv->mtx);
  if (d->stopped) {
    nng_mtx_unlock(d->cv->mtx);
    return;
  }

  while (d->inq_head) {
    nano_dispatch_task *t = d->inq_head;

    nano_dispatch_daemon *dd = dispatch_find_idle_daemon(d);
    if (dd == NULL)
      break;

    nng_msg *msg = t->msg;
    t->msg = NULL;
    d->queued_bytes -= nng_msg_len(msg);
    dd->ctx = t->ctx;
    dd->msgid = t->msgid;
    dd->state = DAEMON_BUSY;
    d->executing++;

    if (t->is_sync) {
      dd->sync_gen = d->sync_generation;
      d->syncing = 1;
    } else if (d->syncing) {
      d->syncing = 0;
      d->sync_generation++;
    }

    dispatch_dequeue(d);
    dispatch_start_send(d, dd, msg);
    dequeued = 1;
  }

  if (d->limit_bytes > 0 && dequeued)
    nng_cv_wake(d->cv->cv);

  nng_mtx_unlock(d->cv->mtx);

}

// main event loop -------------------------------------------------------------

static int dispatch_wait_cv(nano_dispatcher *d, int *host_ready,
                            int *daemon_ready, int *monitor_count) {

  nng_mtx *mtx = d->cv->mtx;
  nng_cv *cv = d->cv->cv;
  nano_monitor *m = d->monitor;
  int stop;

  nng_mtx_lock(mtx);
  while (d->cv->condition == 0 && !d->stopped)
    nng_cv_wait(cv);
  stop = d->stopped;
  d->cv->condition = 0;
  *host_ready = d->host_recv_ready;
  *daemon_ready = d->daemon_recv_ready;
  d->host_recv_ready = 0;
  d->daemon_recv_ready = 0;

  *monitor_count = m->updates;
  if (m->updates) {
    int *tmp_ids = d->pipe_events;
    int tmp_size = d->pipe_events_size;
    d->pipe_events = m->ids;
    d->pipe_events_size = m->size;
    m->ids = tmp_ids;
    m->size = tmp_size;
    m->updates = 0;
  }

  nng_mtx_unlock(mtx);

  return stop;

}

static void dispatch_loop(nano_dispatcher *d) {

  int host_ready, daemon_ready, monitor_events;

  while (1) {
    if (dispatch_wait_cv(d, &host_ready, &daemon_ready, &monitor_events))
      return;

    for (int i = 0; i < monitor_events; i++) {
      if (d->pipe_events[i] > 0)
        dispatch_handle_connect(d, d->pipe_events[i]);
      else
        dispatch_handle_disconnect(d, -d->pipe_events[i]);
    }

    if (host_ready) {
      if (nng_aio_result(d->host_aio) == 0)
        dispatch_handle_host_recv(d);
      else
        nng_ctx_recv(d->host_ctx, d->host_aio);
    }

    if (daemon_ready) {
      if (nng_aio_result(d->daemon_aio) == 0)
        dispatch_handle_daemon_recv(d);
      else
        nng_recv_aio(*d->poly_sock, d->daemon_aio);
    }

    dispatch_dispatch_tasks(d);
  }

}

// shutdown --------------------------------------------------------------------

static void dispatch_shutdown(nano_dispatcher *d) {

  // stop intake and signal aios (each waits for any in-flight callback);
  // d->stopped is already set, so callbacks no longer start operations
  nng_aio_stop(d->host_aio);
  nng_aio_stop(d->daemon_aio);
  nng_aio_stop(d->sig_aio);

  // close the poly socket: daemon pipes close and in-flight per-daemon sends
  // complete with an error (their callbacks free the messages)
  nng_close(*d->poly_sock);

  // reap all per-daemon senders: retired entries and remaining slots
  for (nano_dsend *ds = d->retired; ds != NULL; ) {
    nano_dsend *next = ds->next;
    nng_aio_stop(ds->aio);
    nng_aio_free(ds->aio);
    free(ds);
    ds = next;
  }
  for (int i = 0; i < d->nslots; i++) {
    nano_dispatch_daemon *dd = &d->daemons[i];
    nng_aio_stop(dd->ds->aio);
    nng_aio_free(dd->ds->aio);
    free(dd->ds);
    if (dd->state == DAEMON_BUSY)
      nng_ctx_close(dd->ctx);
  }
  free(d->daemons);

  // every rep ctx held here must be closed before the rep socket is:
  // nng_close blocks until the socket's ctx list is empty
  nng_ctx_close(d->host_ctx);
  while (d->inq_head) {
    nano_dispatch_task *t = d->inq_head;
    d->inq_head = t->next;
    nng_ctx_close(t->ctx);
    if (t->msg)
      nng_msg_free(t->msg);
    free(t);
  }

  // closing the rep socket aborts in-flight reply sends; the holders' own
  // callbacks close their ctxs, unblocking the close, then self-reap
  nng_close(*d->rep_sock);

  nng_mtx_lock(d->cv->mtx);
  while (d->replies_active > 0)
    nng_cv_until(d->cv->cv, nng_clock() + 20);
  nng_mtx_unlock(d->cv->mtx);

  for (nano_reply *r = d->reply_reap; r != NULL; ) {
    nano_reply *next = r->next;
    nng_aio_stop(r->aio);
    nng_aio_free(r->aio);
    free(r);
    r = next;
  }

  for (nano_signode *node = d->sig_head; node != NULL; ) {
    nano_signode *next = node->next;
    nng_msg_free(node->msg);
    free(node);
    node = next;
  }

  nng_aio_free(d->host_aio);
  nng_aio_free(d->daemon_aio);
  nng_aio_free(d->sig_aio);
  free(d->init_template);
  free(d->conn_reset_buf);
  free(d->pipe_events);
  free(d);

}

// in-process dispatcher -------------------------------------------------------

typedef struct nano_dispatcher_handle_s {
  nano_dispatcher *d;
  nng_thread *thr;
  nng_socket poly_sock;
  nng_socket rep_sock;
  nano_cv *priv_cv;
  nano_monitor *monitor;
  int owns_resources;
} nano_dispatcher_handle;

static void dispatch_thread_func(void *arg) {
  nano_dispatcher *d = (nano_dispatcher *) arg;
  dispatch_loop(d);
}

static void dispatcher_handle_release(nano_dispatcher_handle *h) {

  if (!h->owns_resources) return;

  nng_mtx_lock(h->priv_cv->mtx);
  h->d->stopped = 1;
  nng_cv_wake(h->priv_cv->cv);
  nng_mtx_unlock(h->priv_cv->mtx);

  nng_thread_destroy(h->thr);
  dispatch_shutdown(h->d);
  h->d = NULL;

  if (h->monitor) {
    free(h->monitor->ids);
    free(h->monitor);
  }
  nng_cv_free(h->priv_cv->cv);
  nng_mtx_free(h->priv_cv->mtx);
  free(h->priv_cv);
  h->owns_resources = 0;

}

static void dispatcher_handle_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(xptr);
  dispatcher_handle_release(h);
  free(h);

}

int dispatch_cancel_direct(void *handle, int id) {

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) handle;
  nano_dispatcher *d = h->d;
  if (d == NULL)
    return 0;
  
  int found = 0;

  nng_mtx_lock(d->cv->mtx);

  for (int i = 0; i < d->nslots; i++) {
    if (d->daemons[i].state == DAEMON_BUSY && d->daemons[i].msgid == id) {
      dispatch_queue_signal(d, d->daemons[i].pipe);
      found = 1;
      break;
    }
  }
  if (!found)
    found = dispatch_cancel_inq(d, id);

  nng_mtx_unlock(d->cv->mtx);

  return found;

}

SEXP rnng_dispatcher_start(SEXP url, SEXP disp_url, SEXP tls,
                           SEXP serial, SEXP stream,
                           SEXP capacity, SEXP cvar) {

  int xc;
  nng_listener listener = NNG_LISTENER_INITIALIZER;
  nano_dispatcher_handle *h = NULL;
  nano_dispatcher *d = NULL;
  nano_cv *priv = NULL;

  h = calloc(1, sizeof(nano_dispatcher_handle));
  if (h == NULL) { xc = 2; goto fail; }

  d = calloc(1, sizeof(nano_dispatcher));
  if (d == NULL) { xc = 2; goto fail; }
  h->d = d;

  // Private mutex/cv owned by the dispatcher (cvar accepted for signature
  // stability; unused pending mirai update)
  (void) cvar;
  priv = calloc(1, sizeof(nano_cv));
  if (priv == NULL) { xc = 2; goto fail; }
  if ((xc = nng_mtx_alloc(&priv->mtx)))
    goto fail;
  if ((xc = nng_cv_alloc(&priv->cv, priv->mtx)))
    goto fail;
  h->priv_cv = priv;
  d->cv = priv;
  if (capacity == R_NilValue) {
    d->limit_bytes = 0;
  } else {
    double mb = Rf_asReal(capacity);
    d->limit_bytes = (R_FINITE(mb) && mb > 0.0) ? (size_t) (mb * 1e6) : 0;
  }

  // POLY socket for daemon connections
  if ((xc = nng_pair1_open_poly(&h->poly_sock)))
    goto fail;

  d->poly_sock = &h->poly_sock;

  // Monitor on the POLY socket
  const int n = 8;
  nano_monitor *monitor = calloc(1, sizeof(nano_monitor));
  if (monitor == NULL) { xc = 2; goto fail; }
  monitor->ids = calloc(n, sizeof(int));
  if (monitor->ids == NULL) { free(monitor); xc = 2; goto fail; }
  monitor->size = n;
  monitor->cv = priv;
  h->monitor = monitor;
  d->monitor = monitor;

  if ((xc = nng_pipe_notify(h->poly_sock, NNG_PIPE_EV_ADD_POST, pipe_cb_monitor, monitor)))
    goto fail;
  if ((xc = nng_pipe_notify(h->poly_sock, NNG_PIPE_EV_REM_POST, pipe_cb_monitor, monitor)))
    goto fail;

  // Listen for daemon connections
  const char *url_str = CHAR(STRING_ELT(url, 0));
  if (TYPEOF(tls) != NILSXP && !NANO_PTR_CHECK(tls, nano_TlsSymbol)) {
    nng_tls_config *cfg = (nng_tls_config *) NANO_PTR(tls);
    if ((xc = nng_listener_create(&listener, h->poly_sock, url_str)) ||
        (xc = nng_listener_set_ptr(listener, NNG_OPT_TLS_CONFIG, cfg)) ||
        (xc = nng_listener_start(listener, 0)))
      goto fail;
  } else {
    if ((xc = nng_listen(h->poly_sock, url_str, &listener, 0)))
      goto fail;
  }

  // REP socket dials into the host's inproc:// REQ socket
  if ((xc = nng_rep0_open(&h->rep_sock)))
    goto fail;
  d->rep_sock = &h->rep_sock;

  const char *disp_url_str = CHAR(STRING_ELT(disp_url, 0));
  if ((xc = nng_dial(h->rep_sock, disp_url_str, NULL, 0)))
    goto fail;

  // Serialize mk_error(19) for conn_reset_buf
  SEXP err;
  PROTECT(err = mk_error(19));
  nano_buf reset_buf;
  nano_serialize(&reset_buf, err, R_NilValue, 0, 0);
  UNPROTECT(1);
  d->conn_reset_buf = reset_buf.buf;
  d->conn_reset_len = reset_buf.cur;

  // Prepare init template
  if (dispatch_prepare_init_template(d, stream, serial)) { xc = 2; goto fail; }

  // Allocate daemon array
  d->outq_capacity = DISPATCH_INITIAL_SIZE;
  d->daemons = calloc(d->outq_capacity, sizeof(nano_dispatch_daemon));
  if (d->daemons == NULL) { xc = 2; goto fail; }

  // Allocate AIOs and open host context
  if ((xc = nng_aio_alloc(&d->host_aio, host_recv_cb, d)) ||
      (xc = nng_aio_alloc(&d->daemon_aio, daemon_recv_cb, d)) ||
      (xc = nng_aio_alloc(&d->sig_aio, dispatch_sig_cb, d)) ||
      (xc = nng_ctx_open(&d->host_ctx, *d->rep_sock)))
    goto fail;

  // Start initial receive operations
  nng_ctx_recv(d->host_ctx, d->host_aio);
  nng_recv_aio(*d->poly_sock, d->daemon_aio);

  // Create the dispatcher thread
  if ((xc = nng_thread_create(&h->thr, dispatch_thread_func, d)))
    goto fail;

  h->owns_resources = 1;

  // Build external pointer with finalizer
  SEXP xptr;
  PROTECT(xptr = R_MakeExternalPtr(h, nano_ThreadSymbol, R_NilValue));
  R_RegisterCFinalizerEx(xptr, dispatcher_handle_finalizer, TRUE);

  // Attach resolved listener URL as attribute
  SEXP resolved_url = url;
  nng_url *up;
  if (nng_url_parse(&up, url_str) == 0) {
    if (up->u_port != NULL && up->u_port[0] == '0' && up->u_port[1] == '\0') {
      int port;
      if (nng_listener_get_int(listener, NNG_OPT_TCP_BOUND_PORT, &port) == 0)
        resolved_url = nano_url_with_port(up, port);
    }
    nng_url_free(up);
  }
  Rf_setAttrib(xptr, nano_UrlSymbol, resolved_url);

  UNPROTECT(1);
  return xptr;

  fail:
  if (d) {
    if (d->sig_aio) { nng_aio_stop(d->sig_aio); nng_aio_free(d->sig_aio); }
    if (d->daemon_aio) { nng_aio_stop(d->daemon_aio); nng_aio_free(d->daemon_aio); }
    if (d->host_aio) { nng_aio_stop(d->host_aio); nng_aio_free(d->host_aio); }
    free(d->daemons);
    free(d->init_template);
    free(d->conn_reset_buf);
    free(d->pipe_events);
    free(d);
  }
  if (h) {
    nng_close(h->rep_sock);
    nng_close(h->poly_sock);
    if (h->monitor) { free(h->monitor->ids); free(h->monitor); }
    free(h);
  }
  if (priv) {
    if (priv->cv) nng_cv_free(priv->cv);
    if (priv->mtx) nng_mtx_free(priv->mtx);
    free(priv);
  }
  ERROR_OUT(xc);

}

SEXP rnng_dispatcher_stop(SEXP disp) {

  if (NANO_PTR_CHECK(disp, nano_ThreadSymbol))
    return R_NilValue;

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);

  dispatcher_handle_release(h);

  NANO_SET_TAG(disp, R_NilValue);

  return R_NilValue;

}

SEXP rnng_dispatcher_wait(SEXP disp, SEXP n) {

  if (NANO_PTR_CHECK(disp, nano_ThreadSymbol))
    return R_NilValue;

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;
  const int target = nano_integer(n);
  nng_cv *cv = d->cv->cv;
  nng_mtx *mtx = d->cv->mtx;

  nng_mtx_lock(mtx);
  while (d->outq_count < target && !d->stopped) {
    nng_time time = nng_clock() + 400;
    nng_cv_until(cv, time);
    nng_mtx_unlock(mtx);
    R_CheckUserInterrupt();
    nng_mtx_lock(mtx);
  }
  nng_mtx_unlock(mtx);

  return R_NilValue;

}

SEXP rnng_dispatcher_info(SEXP disp) {

  if (NANO_PTR_CHECK(disp, nano_ThreadSymbol))
    return Rf_allocVector(INTSXP, 5);

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;

  int result[5];
  nng_mtx_lock(d->cv->mtx);
  result[0] = d->outq_count;
  result[1] = d->connections;
  result[2] = d->inq_count;
  result[3] = d->executing;
  result[4] = d->count - d->inq_count - d->executing;
  nng_mtx_unlock(d->cv->mtx);

  SEXP out = PROTECT(Rf_allocVector(INTSXP, 5));
  memcpy(NANO_DATAPTR(out), result, sizeof(result));
  UNPROTECT(1);

  return out;

}

SEXP rnng_dispatcher_capacity(SEXP disp) {

  static const char *names[] = {"used", "peak", "capacity", ""};
  SEXP out = PROTECT(Rf_mkNamed(REALSXP, names));
  double *p = REAL(out);

  if (NANO_PTR_CHECK(disp, nano_ThreadSymbol)) {
    p[0] = NA_REAL;
    p[1] = NA_REAL;
    p[2] = NA_REAL;
    UNPROTECT(1);
    return out;
  }

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;

  size_t queued, peak, limit;
  nng_mtx_lock(d->cv->mtx);
  queued = d->queued_bytes;
  peak = d->peak_queued_bytes;
  limit = d->limit_bytes;
  nng_mtx_unlock(d->cv->mtx);

  p[0] = (double) queued / 1e6;
  p[1] = (double) peak / 1e6;
  p[2] = limit > 0 ? (double) limit / 1e6 : NA_REAL;
  UNPROTECT(1);

  return out;

}

SEXP rnng_dispatcher_gate(SEXP disp) {

  if (NANO_PTR_CHECK(disp, nano_ThreadSymbol))
    return R_NilValue;

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;

  if (d->limit_bytes > 0) {
    nng_mtx_lock(d->cv->mtx);
    while (d->queued_bytes >= d->limit_bytes && !d->stopped) {
      nng_time time = nng_clock() + 400;
      nng_cv_until(d->cv->cv, time);
      nng_mtx_unlock(d->cv->mtx);
      R_CheckUserInterrupt();
      nng_mtx_lock(d->cv->mtx);
    }
    nng_mtx_unlock(d->cv->mtx);
  }

  return Rf_ScalarLogical(1);

}

SEXP rnng_dispatcher_try_gate(SEXP disp) {

  if (NANO_PTR_CHECK(disp, nano_ThreadSymbol))
    return R_NilValue;

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;

  int allowed = 1;
  if (d->limit_bytes > 0) {
    nng_mtx_lock(d->cv->mtx);
    allowed = d->queued_bytes < d->limit_bytes;
    nng_mtx_unlock(d->cv->mtx);
  }

  return Rf_ScalarLogical(allowed);

}

