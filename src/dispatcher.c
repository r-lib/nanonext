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

typedef struct nano_dispatch_task_s {
  nng_ctx ctx;
  nng_msg *msg;
  int msgid;
  struct nano_dispatch_task_s *next;
} nano_dispatch_task;

typedef struct nano_dispatch_daemon_s {
  int pipe;
  nng_ctx ctx;
  int msgid;
  int sync_gen;
  struct nano_dispatch_daemon_s *next;
} nano_dispatch_daemon;

typedef struct nano_dispatcher_s {
  nng_socket *rep_sock;
  nng_socket *poly_sock;
  nano_cv *cv;
  nano_cv *limit_cv;
  nano_monitor *monitor;
  nano_dispatch_task *inq_head;
  nano_dispatch_task *inq_tail;
  nano_dispatch_daemon **outq_table;
  int inq_count;
  int outq_size;
  int outq_count;
  int connections;
  int count;
  int executing;
  nng_aio *host_aio;
  nng_aio *daemon_aio;
  nng_ctx host_ctx;
  int host_recv_ready;
  int daemon_recv_ready;
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
  int limit;
  int inflight;
} nano_dispatcher;

// forward declarations --------------------------------------------------------

static void dispatch_shutdown(nano_dispatcher *d);
static void dispatch_handle_connect(nano_dispatcher *d, int pipe);
static void dispatch_handle_disconnect(nano_dispatcher *d, int pipe);
static void dispatch_dispatch_tasks(nano_dispatcher *d);
static int dispatch_cancel_inq(nano_dispatcher *d, int id);
static nano_dispatch_daemon *dispatch_find_idle_daemon(nano_dispatcher *d);

// hash table operations -------------------------------------------------------

static inline int dispatch_hash(int pipe, int size) {

  return ((unsigned int) pipe) & (size - 1);

}

static nano_dispatch_daemon *dispatch_find_daemon(nano_dispatcher *d, int pipe) {

  int idx = dispatch_hash(pipe, d->outq_size);
  for (nano_dispatch_daemon *dd = d->outq_table[idx]; dd; dd = dd->next)
    if (dd->pipe == pipe)
      return dd;

  return NULL;

}

static void dispatch_resize_table(nano_dispatcher *d, int new_size) {

  nano_dispatch_daemon **new_table = calloc(new_size, sizeof(nano_dispatch_daemon *));
  if (new_table == NULL) return;

  for (int i = 0; i < d->outq_size; i++) {
    nano_dispatch_daemon *dd = d->outq_table[i];
    while (dd) {
      nano_dispatch_daemon *next = dd->next;
      int idx = dispatch_hash(dd->pipe, new_size);
      dd->next = new_table[idx];
      new_table[idx] = dd;
      dd = next;
    }
  }

  free(d->outq_table);
  d->outq_table = new_table;
  d->outq_size = new_size;

}

static void dispatch_insert_daemon(nano_dispatcher *d, int pipe) {

  if (d->outq_count * 4 > d->outq_size * 3)
    dispatch_resize_table(d, d->outq_size * 2);

  nano_dispatch_daemon *dd = calloc(1, sizeof(nano_dispatch_daemon));
  if (dd == NULL) {
    REprintf("dispatcher: allocation failed for pipe %d\n", pipe);
    return;
  }

  dd->pipe = pipe;
  dd->msgid = 0;
  dd->sync_gen = d->sync_generation - 1;

  int idx = dispatch_hash(pipe, d->outq_size);
  dd->next = d->outq_table[idx];
  d->outq_table[idx] = dd;
  d->outq_count++;

}

static void dispatch_remove_daemon(nano_dispatcher *d, int pipe) {

  int idx = dispatch_hash(pipe, d->outq_size);
  nano_dispatch_daemon **pp = &d->outq_table[idx];

  while (*pp) {
    if ((*pp)->pipe == pipe) {
      nano_dispatch_daemon *dd = *pp;
      *pp = dd->next;
      free(dd);
      d->outq_count--;
      return;
    }
    pp = &(*pp)->next;
  }

}

// queue operations ------------------------------------------------------------

static void dispatch_enqueue(nano_dispatcher *d, nng_ctx ctx,
                             nng_msg *msg, int msgid) {

  nano_dispatch_task *t = malloc(sizeof(nano_dispatch_task));
  if (t == NULL) {
    nng_ctx_close(ctx);
    nng_msg_free(msg);
    return;
  }
  t->ctx = ctx;
  t->msg = msg;
  t->msgid = msgid;
  t->next = NULL;

  if (d->inq_tail)
    d->inq_tail->next = t;
  else
    d->inq_head = t;
  d->inq_tail = t;
  d->inq_count++;

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

static int dispatch_send_to_daemon(nano_dispatcher *d, int pipe,
                                   unsigned char *data, size_t len) {

  nng_msg *msg;
  if (nng_msg_alloc(&msg, len))
    return -1;
  if (len)
    memcpy(nng_msg_body(msg), data, len);
  nng_msg_set_pipe(msg, (nng_pipe) {.id = (uint32_t) pipe});
  int xc = nng_sendmsg(*d->poly_sock, msg, 0);
  if (xc != 0)
    nng_msg_free(msg);
  return xc;

}

static int dispatch_send_msg_to_daemon(nano_dispatcher *d, int pipe, nng_msg *msg) {

  nng_msg_set_pipe(msg, (nng_pipe) {.id = (uint32_t) pipe});
  return nng_sendmsg(*d->poly_sock, msg, 0);

}

static int dispatch_send_reply(nng_ctx ctx, unsigned char *data, size_t len) {

  nng_msg *msg;
  if (nng_msg_alloc(&msg, len))
    return -1;
  memcpy(nng_msg_body(msg), data, len);
  int xc = nng_ctx_sendmsg(ctx, msg, 0);
  if (xc != 0)
    nng_msg_free(msg);
  return xc;

}

static int dispatch_send_msg_reply(nng_ctx ctx, nng_msg *msg) {

  return nng_ctx_sendmsg(ctx, msg, 0);

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

static inline int dispatch_read_header(unsigned char *buf, size_t len) {

  int msgid = 0;
  if (len > 12 && buf[0] == 0x7)
    memcpy(&msgid, buf + 4, sizeof(int));
  return msgid;

}

static inline int dispatch_read_marker(unsigned char *buf, size_t len) {

  return len > 12 && buf[0] == 0x7 && buf[3] == 0x1;

}

// monitor processing ----------------------------------------------------------

static int dispatch_ensure_pipe_events(nano_dispatcher *d, int needed) {

  if (needed <= d->pipe_events_size)
    return 1;

  int new_size = d->pipe_events_size ? d->pipe_events_size : DISPATCH_INITIAL_SIZE;
  while (new_size < needed)
    new_size *= 2;

  int *new_buf = realloc(d->pipe_events, new_size * sizeof(int));
  if (new_buf == NULL)
    return 0;

  d->pipe_events = new_buf;
  d->pipe_events_size = new_size;
  return 1;

}

static int dispatch_process_monitor(nano_dispatcher *d) {

  nano_monitor *m = d->monitor;
  nng_mtx *mtx = m->cv->mtx;

  nng_mtx_lock(mtx);
  int count = m->updates;
  if (count == 0) {
    nng_mtx_unlock(mtx);
    return 0;
  }

  if (!dispatch_ensure_pipe_events(d, count)) {
    nng_mtx_unlock(mtx);
    return 0;
  }

  memcpy(d->pipe_events, m->ids, count * sizeof(int));
  m->updates = 0;
  nng_mtx_unlock(mtx);

  for (int i = 0; i < count; i++) {
    if (d->pipe_events[i] > 0)
      dispatch_handle_connect(d, d->pipe_events[i]);
    else
      dispatch_handle_disconnect(d, -d->pipe_events[i]);
  }

  return count;

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
  nano_serialize(&buf, init_data, serial, 0);
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

  d->connections++;

  next_rng_stream_c(d->rng_seed);

  unsigned char *buf = malloc(d->init_template_len);
  if (buf == NULL) return;
  memcpy(buf, d->init_template, d->init_template_len);

  for (int i = 0; i < 6; i++)
    memcpy(buf + d->init_seed_offset + i * 4, &d->rng_seed[i], sizeof(int));

  if (dispatch_send_to_daemon(d, pipe, buf, d->init_template_len) == 0)
    dispatch_insert_daemon(d, pipe);
  free(buf);

}

static void dispatch_handle_disconnect(nano_dispatcher *d, int pipe) {

  nano_dispatch_daemon *dd = dispatch_find_daemon(d, pipe);
  if (dd == NULL) return;

  if (dd->msgid != 0) {
    d->executing--;
    dispatch_send_reply(dd->ctx, d->conn_reset_buf, d->conn_reset_len);
    nng_ctx_close(dd->ctx);
    if (d->limit > 0) {
      nng_mtx_lock(d->limit_cv->mtx);
      d->inflight--;
      nng_cv_wake(d->limit_cv->cv);
      nng_mtx_unlock(d->limit_cv->mtx);
    }
  }

  dispatch_remove_daemon(d, pipe);

}

static void dispatch_handle_host_recv(nano_dispatcher *d) {

  nng_msg *msg = nng_aio_get_msg(d->host_aio);
  unsigned char *buf = nng_msg_body(msg);
  size_t len = nng_msg_len(msg);

  if (buf[0] == 0) {
    int id = 0;
    if (len >= 8)
      memcpy(&id, buf + 4, sizeof(int));

    if (id == 0) {
      // Status query - send raw integer array
      int completed = d->count - d->inq_count - d->executing;
      int result[5] = {d->outq_count, d->connections, d->inq_count, d->executing, completed};
      dispatch_send_reply(d->host_ctx, (unsigned char *) result, sizeof(result));
    } else {
      // Cancel query - send raw integer (0 = FALSE, 1 = TRUE)
      int found = 0;
      for (int i = 0; i < d->outq_size && !found; i++) {
        for (nano_dispatch_daemon *dd = d->outq_table[i]; dd; dd = dd->next) {
          if (dd->msgid == id) {
            dispatch_send_to_daemon(d, dd->pipe, NULL, 0);
            found = 1;
            break;
          }
        }
      }
      if (!found)
        found = dispatch_cancel_inq(d, id);
      dispatch_send_reply(d->host_ctx, (unsigned char *) &found, sizeof(int));
    }
    nng_ctx_close(d->host_ctx);
  } else {
    d->count++;
    int msgid = dispatch_read_header(buf, len);
    int is_sync = dispatch_read_marker(buf, len);

    nano_dispatch_daemon *dd = dispatch_find_idle_daemon(d);
    if (dd != NULL && dispatch_send_msg_to_daemon(d, dd->pipe, msg) == 0) {
      msg = NULL;
      dd->ctx = d->host_ctx;
      dd->msgid = msgid;
      d->executing++;
      if (is_sync) {
        dd->sync_gen = d->sync_generation;
        d->syncing = 1;
      } else if (d->syncing) {
        d->syncing = 0;
        d->sync_generation++;
      }
    } else {
      dispatch_enqueue(d, d->host_ctx, msg, msgid);
      msg = NULL;
    }
  }

  if (msg)
    nng_msg_free(msg);

  if (nng_ctx_open(&d->host_ctx, *d->rep_sock) == 0) {
    nng_ctx_recv(d->host_ctx, d->host_aio);
  } else {
    nng_mtx_lock(d->cv->mtx);
    d->cv->flag = -1;
    nng_cv_wake(d->cv->cv);
    nng_mtx_unlock(d->cv->mtx);
  }

}

static void dispatch_handle_daemon_recv(nano_dispatcher *d) {

  nng_msg *msg = nng_aio_get_msg(d->daemon_aio);
  nng_pipe pipe = nng_msg_get_pipe(msg);
  int pipe_id = (int) pipe.id;

  nano_dispatch_daemon *dd = dispatch_find_daemon(d, pipe_id);
  if (dd != NULL && dd->msgid != 0) {
    d->executing--;
    int is_marker = dispatch_read_marker(nng_msg_body(msg), nng_msg_len(msg));

    if (dispatch_send_msg_reply(dd->ctx, msg) == 0)
      msg = NULL;
    nng_ctx_close(dd->ctx);

    if (d->limit > 0) {
      nng_mtx_lock(d->limit_cv->mtx);
      d->inflight--;
      nng_cv_wake(d->limit_cv->cv);
      nng_mtx_unlock(d->limit_cv->mtx);
    }

    if (is_marker) {
      dispatch_send_to_daemon(d, pipe_id, NULL, 0);
      dispatch_remove_daemon(d, pipe_id);
    } else {
      dd->msgid = 0;
    }
  }

  nng_msg_free(msg);

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
      dispatch_free_task(t);
      d->inq_count--;
      if (d->limit > 0) {
        nng_mtx_lock(d->limit_cv->mtx);
        d->inflight--;
        nng_cv_wake(d->limit_cv->cv);
        nng_mtx_unlock(d->limit_cv->mtx);
      }
      return 1;
    }
    prev = *pp;
    pp = &(*pp)->next;
  }
  return 0;

}

static nano_dispatch_daemon *dispatch_find_idle_daemon(nano_dispatcher *d) {

  for (int i = 0; i < d->outq_size; i++)
    for (nano_dispatch_daemon *dd = d->outq_table[i]; dd; dd = dd->next)
      if (dd->msgid == 0 && !(d->syncing && dd->sync_gen == d->sync_generation))
        return dd;

  return NULL;

}

// task dispatcher -------------------------------------------------------------

static void dispatch_dispatch_tasks(nano_dispatcher *d) {

  while (d->inq_head) {
    nano_dispatch_task *t = d->inq_head;

    int is_sync = dispatch_read_marker(nng_msg_body(t->msg), nng_msg_len(t->msg));

    nano_dispatch_daemon *dd = dispatch_find_idle_daemon(d);
    if (dd == NULL)
      break;

    if (dispatch_send_msg_to_daemon(d, dd->pipe, t->msg) != 0)
      break;

    t->msg = NULL;
    dd->ctx = t->ctx;
    dd->msgid = t->msgid;
    d->executing++;

    if (is_sync) {
      dd->sync_gen = d->sync_generation;
      d->syncing = 1;
    } else if (d->syncing) {
      d->syncing = 0;
      d->sync_generation++;
    }

    dispatch_dequeue(d);
  }

}

// main event loop -------------------------------------------------------------

static void dispatch_wait_cv(nano_dispatcher *d, int *host_ready, int *daemon_ready) {

  nng_mtx *mtx = d->cv->mtx;
  nng_cv *cv = d->cv->cv;

  nng_mtx_lock(mtx);
  while (d->cv->condition == 0 && d->cv->flag >= 0)
    nng_cv_wait(cv);
  d->cv->condition = 0;
  *host_ready = d->host_recv_ready;
  *daemon_ready = d->daemon_recv_ready;
  d->host_recv_ready = 0;
  d->daemon_recv_ready = 0;
  nng_mtx_unlock(mtx);

}

static int dispatch_loop(nano_dispatcher *d) {

  int host_ready, daemon_ready;

  while (1) {
    dispatch_wait_cv(d, &host_ready, &daemon_ready);

    if (d->cv->flag < 0) return 0;

    dispatch_process_monitor(d);

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

    if (d->inq_head)
      dispatch_dispatch_tasks(d);
  }

}

// shutdown --------------------------------------------------------------------

static void dispatch_shutdown(nano_dispatcher *d) {

  if (d == NULL) return;

  if (d->host_aio) {
    nng_aio_stop(d->host_aio);
    nng_aio_wait(d->host_aio);
  }
  if (d->daemon_aio) {
    nng_aio_stop(d->daemon_aio);
    nng_aio_wait(d->daemon_aio);
  }

  nng_ctx_close(d->host_ctx);

  if (d->outq_table) {
    for (int i = 0; i < d->outq_size; i++)
      for (nano_dispatch_daemon *dd = d->outq_table[i]; dd; dd = dd->next)
        if (dd->msgid != 0)
          nng_ctx_close(dd->ctx);
  }

  while (d->inq_head) {
    nano_dispatch_task *t = d->inq_head;
    d->inq_head = t->next;
    nng_ctx_close(t->ctx);
    if (t->msg)
      nng_msg_free(t->msg);
    free(t);
  }

  if (d->outq_table) {
    for (int i = 0; i < d->outq_size; i++) {
      nano_dispatch_daemon *dd = d->outq_table[i];
      while (dd) {
        nano_dispatch_daemon *next = dd->next;
        free(dd);
        dd = next;
      }
    }
    free(d->outq_table);
  }

  nng_aio_free(d->host_aio);
  nng_aio_free(d->daemon_aio);
  free(d->init_template);
  free(d->conn_reset_buf);
  free(d->pipe_events);
  free(d);

}

// public entry point ----------------------------------------------------------

SEXP rnng_dispatcher_run(SEXP rep, SEXP poly, SEXP mon, SEXP reset,
                         SEXP serial, SEXP envir, SEXP next_stream_fun) {

  if (NANO_PTR_CHECK(rep, nano_SocketSymbol))
    Rf_error("`rep` is not a valid Socket");
  if (NANO_PTR_CHECK(poly, nano_SocketSymbol))
    Rf_error("`poly` is not a valid Socket");
  if (NANO_PTR_CHECK(mon, nano_MonitorSymbol))
    Rf_error("`mon` is not a valid Monitor");

  SEXP stream;
  PROTECT(stream = Rf_eval(Rf_lang2(next_stream_fun, envir), R_GlobalEnv));

  int xc;
  nano_dispatcher *d = calloc(1, sizeof(nano_dispatcher));
  if (d == NULL) { UNPROTECT(1); xc = 2; goto fail; }

  d->rep_sock = (nng_socket *) NANO_PTR(rep);
  d->poly_sock = (nng_socket *) NANO_PTR(poly);
  d->monitor = (nano_monitor *) NANO_PTR(mon);
  d->cv = d->monitor->cv;

  size_t reset_len = XLENGTH(reset);
  d->conn_reset_buf = malloc(reset_len);
  if (d->conn_reset_buf == NULL) { UNPROTECT(1); xc = 2; goto fail; }
  memcpy(d->conn_reset_buf, DATAPTR_RO(reset), reset_len);
  d->conn_reset_len = reset_len;

  if (dispatch_prepare_init_template(d, stream, serial)) {
    UNPROTECT(1);
    xc = 2;
    goto fail;
  }
  UNPROTECT(1);

  d->outq_size = DISPATCH_INITIAL_SIZE;
  d->outq_table = calloc(d->outq_size, sizeof(nano_dispatch_daemon *));
  if (d->outq_table == NULL) { xc = 2; goto fail; }

  if ((xc = nng_aio_alloc(&d->host_aio, host_recv_cb, d)) ||
      (xc = nng_aio_alloc(&d->daemon_aio, daemon_recv_cb, d)) ||
      (xc = nng_ctx_open(&d->host_ctx, *d->rep_sock)))
    goto fail;

  nng_ctx_recv(d->host_ctx, d->host_aio);
  nng_recv_aio(*d->poly_sock, d->daemon_aio);

  xc = dispatch_loop(d);
  dispatch_shutdown(d);

  return Rf_ScalarInteger(xc);

  fail:
  dispatch_shutdown(d);
  ERROR_OUT(xc);

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

static void dispatcher_handle_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(xptr);

  if (h->owns_resources) {
    nng_mtx_lock(h->priv_cv->mtx);
    h->priv_cv->flag = -1;
    nng_cv_wake(h->priv_cv->cv);
    nng_mtx_unlock(h->priv_cv->mtx);

    nng_thread_destroy(h->thr);
    dispatch_shutdown(h->d);

    nng_close(h->poly_sock);
    nng_close(h->rep_sock);

    if (h->monitor) {
      free(h->monitor->ids);
      free(h->monitor);
    }
    free(h->priv_cv);
    h->owns_resources = 0;
  }

  SETCAR(xptr, NULL);
  free(h);

}

SEXP rnng_dispatcher_start(SEXP url, SEXP reset, SEXP serial,
                           SEXP stream, SEXP disp_url, SEXP limit,
                           SEXP cvar, SEXP tls) {

  int xc;
  nng_listener listener = NNG_LISTENER_INITIALIZER;

  nano_dispatcher_handle *h = calloc(1, sizeof(nano_dispatcher_handle));
  if (h == NULL) Rf_error("memory allocation failed");

  nano_dispatcher *d = calloc(1, sizeof(nano_dispatcher));
  if (d == NULL) { free(h); Rf_error("memory allocation failed"); }
  h->d = d;

  // Private CV sharing mutex/cv with shared CV
  nano_cv *shared = (nano_cv *) NANO_PTR(cvar);
  nano_cv *priv = calloc(1, sizeof(nano_cv));
  if (priv == NULL) { free(d); free(h); Rf_error("memory allocation failed"); }
  priv->mtx = shared->mtx;
  priv->cv = shared->cv;
  priv->condition = 0;
  priv->flag = 0;
  h->priv_cv = priv;
  d->cv = priv;
  d->limit_cv = shared;
  d->limit = limit == R_NilValue ? 0 : nano_integer(limit);

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
  const char *url_str = NANO_STRING(url);
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

  const char *disp_url_str = NANO_STRING(disp_url);
  if ((xc = nng_dial(h->rep_sock, disp_url_str, NULL, 0)))
    goto fail;

  // Copy conn_reset_buf
  size_t reset_len = XLENGTH(reset);
  d->conn_reset_buf = malloc(reset_len);
  if (d->conn_reset_buf == NULL) { xc = 2; goto fail; }
  memcpy(d->conn_reset_buf, DATAPTR_RO(reset), reset_len);
  d->conn_reset_len = reset_len;

  // Prepare init template
  if (dispatch_prepare_init_template(d, stream, serial)) { xc = 2; goto fail; }

  // Allocate hash table
  d->outq_size = DISPATCH_INITIAL_SIZE;
  d->outq_table = calloc(d->outq_size, sizeof(nano_dispatch_daemon *));
  if (d->outq_table == NULL) { xc = 2; goto fail; }

  // Allocate AIOs and open host context
  if ((xc = nng_aio_alloc(&d->host_aio, host_recv_cb, d)) ||
      (xc = nng_aio_alloc(&d->daemon_aio, daemon_recv_cb, d)) ||
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
  PROTECT(xptr = R_MakeExternalPtr(h, R_NilValue, R_NilValue));
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
  if (d->daemon_aio) { nng_aio_stop(d->daemon_aio); nng_aio_free(d->daemon_aio); d->daemon_aio = NULL; }
  if (d->host_aio) { nng_aio_stop(d->host_aio); nng_aio_free(d->host_aio); d->host_aio = NULL; }
  free(d->outq_table); d->outq_table = NULL;
  free(d->init_template); d->init_template = NULL;
  free(d->conn_reset_buf); d->conn_reset_buf = NULL;
  nng_close(h->rep_sock);
  nng_close(h->poly_sock);
  if (h->monitor) { free(h->monitor->ids); free(h->monitor); }
  free(priv);
  free(d->pipe_events);
  free(d);
  free(h);
  ERROR_OUT(xc);

}

SEXP rnng_dispatcher_stop(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL)
    return R_NilValue;

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(xptr);

  if (h->owns_resources) {
    nng_mtx_lock(h->priv_cv->mtx);
    h->priv_cv->flag = -1;
    nng_cv_wake(h->priv_cv->cv);
    nng_mtx_unlock(h->priv_cv->mtx);

    nng_thread_destroy(h->thr);
    dispatch_shutdown(h->d);

    nng_close(h->poly_sock);
    nng_close(h->rep_sock);

    if (h->monitor) {
      free(h->monitor->ids);
      free(h->monitor);
    }
    free(h->priv_cv);
    h->owns_resources = 0;
  }

  SETCAR(xptr, NULL);
  free(h);

  return R_NilValue;

}

SEXP rnng_dispatcher_wait_n(SEXP disp, SEXP n) {

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;
  int target = Rf_asInteger(n);
  nng_cv *cv = d->cv->cv;
  nng_mtx *mtx = d->cv->mtx;

  nng_mtx_lock(mtx);
  while (d->connections < target && d->cv->flag >= 0) {
    nng_time time = nng_clock() + 400;
    nng_cv_until(cv, time);
    nng_mtx_unlock(mtx);
    R_CheckUserInterrupt();
    nng_mtx_lock(mtx);
  }
  nng_mtx_unlock(mtx);

  return R_NilValue;

}

SEXP rnng_limit_gate(SEXP disp) {

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;

  if (d->limit > 0) {
    nng_mtx *mtx = d->limit_cv->mtx;
    nng_cv *cv = d->limit_cv->cv;

    nng_mtx_lock(mtx);
    while (d->inflight >= d->limit) {
      nng_time time = nng_clock() + 400;
      nng_cv_until(cv, time);
      nng_mtx_unlock(mtx);
      R_CheckUserInterrupt();
      nng_mtx_lock(mtx);
    }
    d->inflight++;
    nng_mtx_unlock(mtx);
  }

  return R_NilValue;

}

SEXP rnng_limit_release(SEXP disp) {

  nano_dispatcher_handle *h = (nano_dispatcher_handle *) NANO_PTR(disp);
  nano_dispatcher *d = h->d;

  if (d->limit > 0) {
    nng_mtx *mtx = d->limit_cv->mtx;
    nng_cv *cv = d->limit_cv->cv;

    nng_mtx_lock(mtx);
    d->inflight--;
    nng_cv_wake(cv);
    nng_mtx_unlock(mtx);
  }

  return R_NilValue;

}
