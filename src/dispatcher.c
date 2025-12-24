// nanonext - dispatcher implementation -----------------------------------------

#include "nanonext.h"
#include <stdlib.h>
#include <string.h>

// Data Structures -------------------------------------------------------------

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

#define DISPATCH_INITIAL_SIZE 16

typedef struct nano_dispatcher_s {
  nng_socket *rep_sock;
  nng_socket *poly_sock;
  nano_cv *cv;
  nano_monitor *monitor;
  nano_dispatch_task *inq_head;
  nano_dispatch_task *inq_tail;
  nano_dispatch_daemon **outq_table;
  int inq_count;
  int outq_size;
  int outq_count;
  int connections;
  int count;
  nng_aio *host_aio;
  nng_aio *daemon_aio;
  nng_ctx host_ctx;
  int host_recv_ready;
  int daemon_recv_ready;
  SEXP serial;
  SEXP envir;
  SEXP next_stream_fun;
  unsigned char *conn_reset_buf;
  size_t conn_reset_len;
  int syncing;
  int sync_generation;
  int *pipe_events;
  int pipe_events_size;
} nano_dispatcher;

// Forward Declarations --------------------------------------------------------

static void dispatch_shutdown(nano_dispatcher *d);
static void dispatch_handle_connect(nano_dispatcher *d, int pipe);
static void dispatch_handle_disconnect(nano_dispatcher *d, int pipe);
static void dispatch_dispatch_tasks(nano_dispatcher *d);
static int dispatch_count_executing(nano_dispatcher *d);
static int dispatch_cancel_inq(nano_dispatcher *d, int id);
static nano_dispatch_daemon *dispatch_find_idle_daemon(nano_dispatcher *d);

// Hash Table Operations -------------------------------------------------------

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

// Queue Operations ------------------------------------------------------------

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

// Send Operations -------------------------------------------------------------

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

// Message Utilities -----------------------------------------------------------

static inline int dispatch_read_header(unsigned char *buf, size_t len) {

  int msgid = 0;
  if (len > 12 && buf[0] == 0x7)
    memcpy(&msgid, buf + 4, sizeof(int));
  return msgid;

}

static inline int dispatch_read_marker(unsigned char *buf, size_t len) {

  return len > 12 && buf[0] == 0x7 && buf[3] == 0x1;

}

static inline int dispatch_read_msg_marker(nng_msg *msg) {

  return dispatch_read_marker(nng_msg_body(msg), nng_msg_len(msg));

}

// Monitor Processing ----------------------------------------------------------

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

// Event Handlers --------------------------------------------------------------

static void dispatch_handle_connect(nano_dispatcher *d, int pipe) {

  d->connections++;

  SEXP init_data = PROTECT(Rf_allocVector(VECSXP, 2));
  SEXP call = PROTECT(Rf_lang2(d->next_stream_fun, d->envir));
  SEXP stream = Rf_eval(call, R_GlobalEnv);
  SET_VECTOR_ELT(init_data, 0, stream);
  SET_VECTOR_ELT(init_data, 1, d->serial);

  nano_buf buf;
  nano_serialize(&buf, init_data, d->serial, 0);
  UNPROTECT(2);

  if (dispatch_send_to_daemon(d, pipe, buf.buf, buf.cur) == 0)
    dispatch_insert_daemon(d, pipe);
  NANO_FREE(buf);

}

static void dispatch_handle_disconnect(nano_dispatcher *d, int pipe) {

  nano_dispatch_daemon *dd = dispatch_find_daemon(d, pipe);
  if (dd == NULL) return;

  if (dd->msgid != 0) {
    dispatch_send_reply(dd->ctx, d->conn_reset_buf, d->conn_reset_len);
    nng_ctx_close(dd->ctx);
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
      int executing = dispatch_count_executing(d);
      int completed = d->count - d->inq_count - executing;
      int result[5];
      result[0] = d->outq_count;
      result[1] = d->connections;
      result[2] = d->inq_count;
      result[3] = executing;
      result[4] = completed;
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
    unsigned char *buf = nng_msg_body(msg);
    size_t len = nng_msg_len(msg);
    int is_marker = dispatch_read_marker(buf, len);

    if (dispatch_send_msg_reply(dd->ctx, msg) == 0)
      msg = NULL;
    nng_ctx_close(dd->ctx);

    if (is_marker) {
      dispatch_send_to_daemon(d, pipe_id, NULL, 0);
      dispatch_remove_daemon(d, pipe_id);
    } else {
      dd->msgid = 0;
    }
  }

  if (msg)
    nng_msg_free(msg);

  nng_recv_aio(*d->poly_sock, d->daemon_aio);

}

// Helper Functions ------------------------------------------------------------

static int dispatch_count_executing(nano_dispatcher *d) {

  int count = 0;
  for (int i = 0; i < d->outq_size; i++)
    for (nano_dispatch_daemon *dd = d->outq_table[i]; dd; dd = dd->next)
      if (dd->msgid != 0)
        count++;
  return count;

}

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

// Task Dispatcher -------------------------------------------------------------

static void dispatch_dispatch_tasks(nano_dispatcher *d) {

  while (d->inq_head) {
    nano_dispatch_task *t = d->inq_head;

    int is_sync = dispatch_read_msg_marker(t->msg);

    nano_dispatch_daemon *dd = dispatch_find_idle_daemon(d);
    if (dd == NULL)
      break;

    if (dispatch_send_msg_to_daemon(d, dd->pipe, t->msg) != 0)
      break;

    t->msg = NULL;
    dd->ctx = t->ctx;
    dd->msgid = t->msgid;

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

// Main Event Loop -------------------------------------------------------------

static void dispatch_wait_cv(nano_dispatcher *d,
                             int *host_ready, int *daemon_ready) {

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

// Shutdown --------------------------------------------------------------------

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

  if (d->host_aio)
    nng_aio_free(d->host_aio);
  if (d->daemon_aio)
    nng_aio_free(d->daemon_aio);

  free(d->pipe_events);

  free(d);

}

// Public Entry Point ----------------------------------------------------------

SEXP rnng_dispatcher_run(SEXP rep, SEXP poly, SEXP mon, SEXP reset,
                         SEXP serial, SEXP envir, SEXP next_stream_fun) {

  if (NANO_PTR_CHECK(rep, nano_SocketSymbol))
    Rf_error("`rep` is not a valid Socket");
  if (NANO_PTR_CHECK(poly, nano_SocketSymbol))
    Rf_error("`poly` is not a valid Socket");
  if (NANO_PTR_CHECK(mon, nano_MonitorSymbol))
    Rf_error("`mon` is not a valid Monitor");

  int xc;
  nano_dispatcher *d = calloc(1, sizeof(nano_dispatcher));
  if (d == NULL) { xc = 2; goto fail; }

  d->rep_sock = (nng_socket *) NANO_PTR(rep);
  d->poly_sock = (nng_socket *) NANO_PTR(poly);
  d->monitor = (nano_monitor *) NANO_PTR(mon);
  d->cv = d->monitor->cv;
  d->conn_reset_buf = (unsigned char *) DATAPTR_RO(reset);
  d->conn_reset_len = XLENGTH(reset);
  d->serial = serial;
  d->envir = envir;
  d->next_stream_fun = next_stream_fun;

  d->outq_size = DISPATCH_INITIAL_SIZE;
  d->outq_table = calloc(d->outq_size, sizeof(nano_dispatch_daemon *));
  if (d->outq_table == NULL) { xc = 2; goto fail; }

  if ((xc = nng_aio_alloc(&d->host_aio, host_recv_cb, d)))
    goto fail;
  if ((xc = nng_aio_alloc(&d->daemon_aio, daemon_recv_cb, d)))
    goto fail;

  if ((xc = nng_ctx_open(&d->host_ctx, *d->rep_sock)))
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
