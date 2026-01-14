// nanonext - C level - HTTP/WebSocket Server ----------------------------------

#define NANONEXT_HTTP
#include "nanonext.h"

// internals -------------------------------------------------------------------

typedef struct {
  nano_ws_conn *conn;
  void *data;
  size_t len;
} ws_message;

static inline void prot_add(SEXP prot, SEXP obj) {
  SETCDR(prot, Rf_cons(obj, CDR(prot)));
}

static inline void prot_remove(SEXP prot, SEXP obj) {
  SEXP prev = prot;
  for (SEXP cur = CDR(prot); cur != R_NilValue; prev = cur, cur = CDR(cur)) {
    if (CAR(cur) == obj) {
      SETCDR(prev, CDR(cur));
      return;
    }
  }
}

static SEXP get_list_element(SEXP list, const char *name) {
  SEXP elem = Rf_getAttrib(list, Rf_install(name));
  if (elem == R_NilValue && TYPEOF(list) == VECSXP) {
    SEXP names = Rf_getAttrib(list, R_NamesSymbol);
    if (names != R_NilValue) {
      for (int i = 0; i < Rf_length(list); i++) {
        if (strcmp(CHAR(STRING_ELT(names, i)), name) == 0)
          return VECTOR_ELT(list, i);
      }
    }
  }
  return elem;
}

static void http_handler_cb(nng_aio *);
static void http_invoke_callback(void *);
static int http_request_unlink(nano_http_request *);
static void http_request_free(nano_http_request *);
static void http_cancel_pending_requests(nano_http_server *);
static void ws_accept_cb(void *);
static void ws_conn_unlink_locked(nano_ws_conn *);
static int ws_conn_begin_close_locked(nano_ws_conn *);
static void ws_conn_schedule_onclose(nano_ws_conn *);
static void ws_recv_cb(void *);
static void ws_conn_cleanup(nano_ws_conn *);
static void ws_invoke_onopen(void *);
static void ws_invoke_onmessage(void *);
static void ws_invoke_onclose(void *);
static void http_server_finalizer(SEXP);
static void http_server_do_stop(nano_http_server *);

// internals -------------------------------------------------------------------

// This runs in NNG's thread when an HTTP request arrives
static void http_handler_cb(nng_aio *aio) {

  nng_http_req *req = nng_aio_get_input(aio, 0);
  nng_http_handler *h = nng_aio_get_input(aio, 1);
  nano_http_handler_info *info = nng_http_handler_get_data(h);
  nano_http_server *srv = info->server;

  // Check if server is stopping
  if (srv->stopped) {
    nng_aio_finish(aio, NNG_ECANCELED);
    return;
  }

  // Package request data for R (copy strings - they may be freed)
  nano_http_request *r = calloc(1, sizeof(nano_http_request));
  if (r == NULL) {
    nng_aio_finish(aio, NNG_ENOMEM);
    return;
  }

  r->method = strdup(nng_http_req_get_method(req));
  r->uri = strdup(nng_http_req_get_uri(req));
  void *body_src;
  nng_http_req_get_data(req, &body_src, &r->body_len);
  if (r->body_len > 0) {
    r->body_copy = malloc(r->body_len);
    if (r->body_copy != NULL)
      memcpy(r->body_copy, body_src, r->body_len);
  }

  // Extract all headers using iterator
  int header_count = 0;
  for (nano_http_header_s *h = nano_http_header_first(req); h != NULL;
       h = nano_http_header_next(req, h))
    header_count++;

  if (header_count > 0) {
    r->header_names = malloc(header_count * sizeof(char *));
    r->header_values = malloc(header_count * sizeof(char *));
    if (r->header_names != NULL && r->header_values != NULL) {
      for (nano_http_header_s *h = nano_http_header_first(req); h != NULL;
           h = nano_http_header_next(req, h)) {
        r->header_names[r->header_count] = strdup(h->name);
        r->header_values[r->header_count] = strdup(h->value);
        r->header_count++;
      }
    }
  }

  r->aio = aio;
  r->callback = info->callback;
  r->server = srv;

  // Add to pending requests list (for cleanup on server stop)
  nng_mtx_lock(srv->mtx);
  r->next = srv->pending_reqs;
  if (srv->pending_reqs != NULL)
    srv->pending_reqs->prev = r;
  srv->pending_reqs = r;
  nng_mtx_unlock(srv->mtx);

  // Schedule R callback on main thread
  later2(http_invoke_callback, r);

}

// Helper: Remove request from pending list
// Returns 1 if request was cancelled, 0 otherwise
static int http_request_unlink(nano_http_request *r) {

  nano_http_server *srv = r->server;
  nng_mtx_lock(srv->mtx);
  if (r->prev != NULL) {
    r->prev->next = r->next;
  } else if (srv->pending_reqs == r) {
    srv->pending_reqs = r->next;
  }
  if (r->next != NULL) {
    r->next->prev = r->prev;
  }
  r->next = r->prev = NULL;
  const int cancelled = r->cancelled;
  nng_mtx_unlock(srv->mtx);

  return cancelled;

}

// Helper: Free request resources
static void http_request_free(nano_http_request *r) {

  free(r->method);
  free(r->uri);
  free(r->body_copy);
  for (int i = 0; i < r->header_count; i++) {
    free(r->header_names[i]);
    free(r->header_values[i]);
  }
  free(r->header_names);
  free(r->header_values);
  free(r);

}

// This runs on R's main thread
static void http_invoke_callback(void *arg) {

  nano_http_request *r = (nano_http_request *) arg;

  // Remove from pending list and check if cancelled (mutex-protected)
  const int cancelled = http_request_unlink(r);

  // Check if request was cancelled (server stopped)
  if (cancelled) {
    // Server stopped - AIO was already finished with error by server stop code
    http_request_free(r);
    return;
  }

  const char *names[] = {"method", "uri", "headers", "body", ""};
  SEXP req_list = PROTECT(Rf_mkNamed(VECSXP, names));
  SET_VECTOR_ELT(req_list, 0, Rf_mkString(r->method));
  SET_VECTOR_ELT(req_list, 1, Rf_mkString(r->uri));

  SEXP headers = Rf_allocVector(STRSXP, r->header_count);
  SET_VECTOR_ELT(req_list, 2, headers);
  SEXP hdr_names = Rf_allocVector(STRSXP, r->header_count);
  Rf_namesgets(headers, hdr_names);
  for (int i = 0; i < r->header_count; i++) {
    SET_STRING_ELT(headers, i, Rf_mkChar(r->header_values[i]));
    SET_STRING_ELT(hdr_names, i, Rf_mkChar(r->header_names[i]));
  }

  SEXP body = Rf_allocVector(RAWSXP, r->body_len);
  SET_VECTOR_ELT(req_list, 3, body);
  if (r->body_len > 0)
    memcpy(RAW(body), r->body_copy, r->body_len);

  SEXP call = PROTECT(Rf_lang2(r->callback, req_list));
  int err;
  SEXP result = R_tryEval(call, R_GlobalEnv, &err);
  UNPROTECT(2);

  nng_http_res *res = NULL;
  if (err) {
    nng_http_res_alloc_error(&res, 500);
  } else {
    PROTECT(result);
    nng_http_res_alloc(&res);

    SEXP status_elem = get_list_element(result, "status");
    int status_code = (status_elem != R_NilValue && TYPEOF(status_elem) == INTSXP) ?
                      NANO_INTEGER(status_elem) : 200;
    nng_http_res_set_status(res, (uint16_t) status_code);

    SEXP res_headers = get_list_element(result, "headers");
    if (TYPEOF(res_headers) == STRSXP) {
      PROTECT(res_headers);
      SEXP hdr_nm = Rf_getAttrib(res_headers, R_NamesSymbol);
      if (TYPEOF(hdr_nm) == STRSXP) {
        for (int i = 0; i < XLENGTH(res_headers); i++) {
          const char *name = NANO_STR_N(hdr_nm, i);
          const char *value = NANO_STR_N(res_headers, i);
          nng_http_res_set_header(res, name, value);
        }
      }
      UNPROTECT(1);
    }

    SEXP res_body = get_list_element(result, "body");
    if (res_body != R_NilValue) {
      switch (TYPEOF(res_body)) {
      case RAWSXP:
        nng_http_res_copy_data(res, NANO_DATAPTR(res_body), XLENGTH(res_body));
        break;
      case STRSXP:
        if (XLENGTH(res_body) > 0) {
          const char *str = CHAR(STRING_ELT(res_body, 0));
          nng_http_res_copy_data(res, str, strlen(str));
          if (nng_http_res_get_header(res, "Content-Type") == NULL)
            nng_http_res_set_header(res, "Content-Type", "text/plain; charset=utf-8");
        }
        break;
      default:
        break;
      }
    }

    UNPROTECT(1);
  }

  nng_aio_set_output(r->aio, 0, res);
  nng_aio_finish(r->aio, 0);
  http_request_free(r);

}

// Called during server stop to cancel all pending HTTP requests
static void http_cancel_pending_requests(nano_http_server *srv) {

  nng_mtx_lock(srv->mtx);
  nano_http_request *r = srv->pending_reqs;
  while (r != NULL) {
    nano_http_request *next = r->next;
    // Mark as cancelled - the later2 callback will see this and clean up
    r->cancelled = 1;
    // Finish the AIO with error so NNG knows the request is done
    nng_aio_finish(r->aio, NNG_ECANCELED);
    r = next;
  }
  nng_mtx_unlock(srv->mtx);

}

// WebSocket functions ---------------------------------------------------------

// AIO callback when new WebSocket connection is accepted
static void ws_accept_cb(void *arg) {

  nano_http_handler_info *info = (nano_http_handler_info *) arg;
  nano_http_server *srv = info->server;
  const int xc = nng_aio_result(info->ws_accept_aio);

  if (xc == 0) {
    // Get the accepted WebSocket stream
    nng_stream *stream = nng_aio_get_output(info->ws_accept_aio, 0);

    // Create connection object
    nano_ws_conn *conn = calloc(1, sizeof(nano_ws_conn));
    if (conn == NULL) {
      nng_stream_free(stream);
      goto next;
    }

    conn->stream = stream;
    conn->handler = info;
    conn->state = WS_STATE_OPEN;
    conn->xptr = R_NilValue;

    // Allocate AIOs for this connection
    if (nng_aio_alloc(&conn->recv_aio, ws_recv_cb, conn) ||
        nng_aio_alloc(&conn->send_aio, NULL, NULL)) {
      nng_aio_free(conn->recv_aio);
      nng_stream_free(stream);
      free(conn);
      goto next;
    }

    // Assign unique ID (server-wide) and add to handler's connection list
    nng_mtx_lock(srv->mtx);
    conn->id = ++srv->ws_conn_counter;
    conn->next = info->ws_conns;
    if (info->ws_conns != NULL)
      info->ws_conns->prev = conn;
    info->ws_conns = conn;
    nng_mtx_unlock(srv->mtx);

    // Schedule connection initialization and on_open callback
    later2(ws_invoke_onopen, conn);
  }

  next:
  // Continue accepting more connections
  if (!srv->stopped) {
    nng_stream_listener_accept(info->ws_listener, info->ws_accept_aio);
  }

}

// Helper: Remove connection from handler's linked list (must hold srv->mtx)
static void ws_conn_unlink_locked(nano_ws_conn *conn) {

  nano_http_handler_info *info = conn->handler;
  if (conn->prev != NULL) {
    conn->prev->next = conn->next;
  } else {
    info->ws_conns = conn->next;
  }
  if (conn->next != NULL) {
    conn->next->prev = conn->prev;
  }
  conn->next = conn->prev = NULL;

}

// Helper: Check if connection is open (thread-safe)
static inline int ws_conn_is_open(nano_ws_conn *conn) {

  nano_http_server *srv = conn->handler->server;
  nng_mtx_lock(srv->mtx);
  const int is_open = conn->state == WS_STATE_OPEN;
  nng_mtx_unlock(srv->mtx);
  return is_open;

}

// Helper: Initiate connection close (thread-safe, idempotent)
// Returns 1 if this call initiated the close, 0 if already closing/closed
// Caller must hold srv->mtx
static int ws_conn_begin_close_locked(nano_ws_conn *conn) {

  if (conn->state != WS_STATE_OPEN)
    return 0;

  conn->state = WS_STATE_CLOSING;
  nng_aio_cancel(conn->recv_aio);
  nng_aio_cancel(conn->send_aio);
  nng_stream_close(conn->stream);
  return 1;

}

// Convenience wrapper that acquires the mutex
static inline int ws_conn_begin_close(nano_ws_conn *conn) {

  nano_http_server *srv = conn->handler->server;
  nng_mtx_lock(srv->mtx);
  int result = ws_conn_begin_close_locked(conn);
  nng_mtx_unlock(srv->mtx);
  return result;

}

// Helper: Schedule on_close callback (called after close initiated)
static void ws_conn_schedule_onclose(nano_ws_conn *conn) {

  nano_http_handler_info *info = conn->handler;
  nano_http_server *srv = info->server;

  nng_mtx_lock(srv->mtx);
  if (conn->onclose_scheduled) {
    nng_mtx_unlock(srv->mtx);
    return;
  }
  conn->onclose_scheduled = 1;
  nng_mtx_unlock(srv->mtx);

  later2(ws_invoke_onclose, conn);

}

// AIO callback when WebSocket message is received
static void ws_recv_cb(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  const int xc = nng_aio_result(conn->recv_aio);

  if (xc == 0) {
    // Message received - get message from AIO
    nng_msg *msgp = nng_aio_get_msg(conn->recv_aio);
    const size_t len = nng_msg_len(msgp);
    unsigned char *buf = nng_msg_body(msgp);

    // Copy data for R callback
    ws_message *msg = malloc(sizeof(ws_message));
    if (msg != NULL) {
      msg->conn = conn;
      msg->data = malloc(len);
      if (msg->data != NULL) {
        msg->len = len;
        memcpy(msg->data, buf, len);
        later2(ws_invoke_onmessage, msg);
      } else {
        free(msg);
      }
    }

    nng_msg_free(msgp);

    // Continue receiving
    if (ws_conn_is_open(conn))
      nng_stream_recv(conn->stream, conn->recv_aio);

  } else if (xc == NNG_ECLOSED || xc == NNG_ECONNSHUT || xc == NNG_ECANCELED) {
    // Connection closed by peer or cancelled
    ws_conn_begin_close(conn);
    ws_conn_schedule_onclose(conn);
  }

}

// Runs on R main thread - creates external pointer and calls on_open
static void ws_invoke_onopen(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  if (!ws_conn_is_open(conn))
    return;
  nano_http_handler_info *info = conn->handler;

  // Create external pointer for this connection
  if (conn->xptr == R_NilValue) {
    conn->xptr = R_MakeExternalPtr(conn, nano_WsConnSymbol, R_NilValue);
    prot_add(info->server->prot, conn->xptr);
    NANO_CLASS2(conn->xptr, "nanoWsConn", "nano");
    Rf_setAttrib(conn->xptr, nano_IdSymbol, Rf_ScalarInteger(conn->id));
  }

  // Call R on_open callback
  if (info->on_open != R_NilValue) {
    SEXP call = PROTECT(Rf_lang2(info->on_open, conn->xptr));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }

  // Start receive loop after on_open completes (ensures correct lifecycle)
  nng_stream_recv(conn->stream, conn->recv_aio);

}

// Runs on R main thread - calls on_message with connection and data
static void ws_invoke_onmessage(void *arg) {

  ws_message *msg = (ws_message *) arg;
  nano_ws_conn *conn = msg->conn;
  if (!ws_conn_is_open(conn) || conn->xptr == R_NilValue) {
    free(msg->data);
    free(msg);
    return;
  }
  nano_http_handler_info *info = conn->handler;

  SEXP data;
  if (info->textframes) {
    PROTECT(data = Rf_ScalarString(Rf_mkCharLenCE((char *) msg->data, msg->len, CE_UTF8)));
  } else {
    PROTECT(data = Rf_allocVector(RAWSXP, msg->len));
    memcpy(NANO_DATAPTR(data), msg->data, msg->len);
  }

  if (info->callback != R_NilValue) {
    SEXP call = PROTECT(Rf_lang3(info->callback, conn->xptr, data));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }
  UNPROTECT(1);

  free(msg->data);
  free(msg);

}

// Runs on R main thread - calls on_close, then cleans up connection
static void ws_invoke_onclose(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  nano_http_handler_info *info = conn->handler;

  if (info->on_close != R_NilValue && conn->xptr != R_NilValue) {
    SEXP call = PROTECT(Rf_lang2(info->on_close, conn->xptr));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }

  ws_conn_cleanup(conn);

}

// Helper: Free connection resources
static void ws_conn_cleanup(nano_ws_conn *conn) {

  nano_http_handler_info *info = conn->handler;
  nano_http_server *srv = info->server;

  // Remove from handler's connection list
  nng_mtx_lock(srv->mtx);
  ws_conn_unlink_locked(conn);
  nng_mtx_unlock(srv->mtx);

  conn->state = WS_STATE_CLOSED;

  // Release the R external pointer
  if (conn->xptr != R_NilValue) {
    prot_remove(srv->prot, conn->xptr);
    R_ClearExternalPtr(conn->xptr);
    conn->xptr = R_NilValue;
  }

  // Free resources
  nng_stream_free(conn->stream);
  nng_aio_free(conn->recv_aio);
  nng_aio_free(conn->send_aio);
  free(conn);

}

// Shared helper: perform actual server stop operations
static void http_server_do_stop(nano_http_server *srv) {

  nng_http_server_stop(srv->server);
  http_cancel_pending_requests(srv);

  // Close all WebSocket handlers
  for (int i = 0; i < srv->handler_count; i++) {
    if (srv->handlers[i].ws_listener != NULL) {
      nng_aio_cancel(srv->handlers[i].ws_accept_aio);
      nng_stream_listener_close(srv->handlers[i].ws_listener);

      // Close all connections for this handler
      nng_mtx_lock(srv->mtx);
      for (nano_ws_conn *conn = srv->handlers[i].ws_conns; conn != NULL; conn = conn->next)
        ws_conn_begin_close_locked(conn);
      nng_mtx_unlock(srv->mtx);
    }
  }

}

// Shared helper: stop server and clear callbacks (idempotent)
static void http_server_stop_and_clear(nano_http_server *srv) {

  // Stop the server if still running
  if (srv->started && !srv->stopped) {
    srv->stopped = 1;
    http_server_do_stop(srv);
  }

  // Clear handler callback references (protection handled by prot pairlist on xptr)
  for (int i = 0; i < srv->handler_count; i++) {
    srv->handlers[i].callback = R_NilValue;
    srv->handlers[i].on_open = R_NilValue;
    srv->handlers[i].on_close = R_NilValue;
  }

}

static void http_server_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_http_server *srv = (nano_http_server *) NANO_PTR(xptr);

  // Stop and clear callbacks if not already done
  http_server_stop_and_clear(srv);

  // Free HTTP handlers and WebSocket resources
  for (int i = 0; i < srv->handler_count; i++) {
    if (srv->handlers[i].handler != NULL)
      nng_http_server_del_handler(srv->server, srv->handlers[i].handler);

    // Free WebSocket resources
    if (srv->handlers[i].ws_listener != NULL) {
      nng_stream_listener_free(srv->handlers[i].ws_listener);
      nng_aio_free(srv->handlers[i].ws_accept_aio);

      // Free remaining connections (shouldn't happen if stop was clean)
      nano_ws_conn *conn = srv->handlers[i].ws_conns;
      while (conn != NULL) {
        nano_ws_conn *next = conn->next;
        if (conn->xptr != R_NilValue)
          R_ClearExternalPtr(conn->xptr);
        nng_stream_free(conn->stream);
        nng_aio_free(conn->recv_aio);
        nng_aio_free(conn->send_aio);
        free(conn);
        conn = next;
      }
    }
  }
  free(srv->handlers);

  // Free NNG resources
  if (srv->tls != NULL) nng_tls_config_free(srv->tls);
  nng_http_server_release(srv->server);
  if (srv->mtx != NULL) nng_mtx_free(srv->mtx);
  free(srv);

}

// R-callable functions --------------------------------------------------------

SEXP rnng_http_server_create(SEXP url, SEXP handlers, SEXP tls) {

  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  const char *ur = CHAR(STRING_ELT(url, 0));
  nng_url *up = NULL;
  nng_http_server *server = NULL;
  nng_mtx *mtx = NULL;
  nano_http_handler_info *hinfo = NULL;
  int xc;
  int handlers_added = 0;

  nano_http_server *srv = calloc(1, sizeof(nano_http_server));
  NANO_ENSURE_ALLOC(srv);

  srv->xptr = R_NilValue;
  srv->prot = R_NilValue;

  SEXP prot = PROTECT(Rf_cons(R_NilValue, R_NilValue));

  if (eln2 == NULL)
    nano_load_later();

  if ((xc = nng_url_parse(&up, ur)))
    goto fail;

  if ((xc = nng_http_server_hold(&server, up)))
    goto fail;

  srv->server = server;

  if (tls != R_NilValue) {
    srv->tls = (nng_tls_config *) NANO_PTR(tls);
    nng_tls_config_hold(srv->tls);
    prot_add(prot, tls);
    if ((xc = nng_http_server_set_tls(srv->server, srv->tls)))
      goto fail;
  }

  const R_xlen_t handler_count = Rf_xlength(handlers);
  srv->handler_count = handler_count;
  srv->handlers = NULL;
  if (handler_count > 0) {
    hinfo = calloc(handler_count, sizeof(nano_http_handler_info));
    if (hinfo == NULL) { xc = NNG_ENOMEM; goto fail; }
    srv->handlers = hinfo;

    for (R_xlen_t i = 0; i < handler_count; i++) {
      srv->handlers[i].callback = R_NilValue;
      srv->handlers[i].on_open = R_NilValue;
      srv->handlers[i].on_close = R_NilValue;
    }

    for (R_xlen_t i = 0; i < handler_count; i++) {
      SEXP h = VECTOR_ELT(handlers, i);

      const int type = NANO_INTEGER(get_list_element(h, "type"));
      SEXP path_elem = get_list_element(h, "path");
      const char *path = CHAR(STRING_ELT(path_elem, 0));
      SEXP tree_elem = get_list_element(h, "tree");
      const int tree = (tree_elem != R_NilValue) ? NANO_INTEGER(tree_elem) : 0;

      switch (type) {
      case 1: {
        // Dynamic callback handler
        SEXP callback = get_list_element(h, "callback");
        SEXP method_elem = get_list_element(h, "method");
        const char *method = (method_elem != R_NilValue && TYPEOF(method_elem) == STRSXP) ?
                             CHAR(STRING_ELT(method_elem, 0)) : NULL;

        if ((xc = nng_http_handler_alloc(&srv->handlers[i].handler, path, http_handler_cb)))
          goto fail;
        if (method != NULL &&
            (xc = nng_http_handler_set_method(srv->handlers[i].handler, method)))
          goto fail;
        if (tree && (xc = nng_http_handler_set_tree(srv->handlers[i].handler)))
          goto fail;

        srv->handlers[i].callback = callback;
        prot_add(prot, callback);
        srv->handlers[i].server = srv;
        nng_http_handler_set_data(srv->handlers[i].handler, &srv->handlers[i], NULL);

        if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
          goto fail;
        handlers_added++;
        break;
      }
      case 2: {
        // WebSocket handler
        SEXP on_message = get_list_element(h, "on_message");
        SEXP on_open = get_list_element(h, "on_open");
        SEXP on_close = get_list_element(h, "on_close");
        SEXP textframes_elem = get_list_element(h, "textframes");
        const int textframes = (textframes_elem != R_NilValue) ? NANO_INTEGER(textframes_elem) : 0;

        // Build WebSocket URL for this path
        const char *scheme = strcmp(up->u_scheme, "https") == 0 ? "wss" : "ws";
        const size_t ws_url_len = strlen(scheme) + strlen(up->u_hostname) +
                                  strlen(up->u_port) + strlen(path) + 5;
        char ws_url[ws_url_len];
        snprintf(ws_url, ws_url_len, "%s://%s:%s%s",
                 scheme, up->u_hostname, up->u_port, path);

        // Create WebSocket listener for this path
        if ((xc = nng_stream_listener_alloc(&srv->handlers[i].ws_listener, ws_url)))
          goto fail;

        // Enable WebSocket message mode
        if ((xc = nng_stream_listener_set_bool(srv->handlers[i].ws_listener, "ws:msgmode", true)))
          goto fail;

        // Configure text frames if requested
        if (textframes) {
          if ((xc = nng_stream_listener_set_bool(srv->handlers[i].ws_listener, "ws:recv-text", true)) ||
              (xc = nng_stream_listener_set_bool(srv->handlers[i].ws_listener, "ws:send-text", true)))
            goto fail;
          srv->handlers[i].textframes = 1;
        }

        // Configure TLS for WebSocket listener
        if (srv->tls != NULL) {
          nng_stream_listener_set_ptr(srv->handlers[i].ws_listener, NNG_OPT_TLS_CONFIG, srv->tls);
        }

        // Store callbacks
        srv->handlers[i].callback = on_message;
        prot_add(prot, on_message);

        if (on_open != R_NilValue) {
          srv->handlers[i].on_open = on_open;
          prot_add(prot, on_open);
        }

        if (on_close != R_NilValue) {
          srv->handlers[i].on_close = on_close;
          prot_add(prot, on_close);
        }

        srv->handlers[i].server = srv;

        // Create accept AIO
        if ((xc = nng_aio_alloc(&srv->handlers[i].ws_accept_aio, ws_accept_cb, &srv->handlers[i])))
          goto fail;

        handlers_added++;
        break;
      }
      case 3: {
        // Static file handler
        SEXP file_elem = get_list_element(h, "file");
        const char *file = CHAR(STRING_ELT(file_elem, 0));
        if ((xc = nng_http_handler_alloc_file(&srv->handlers[i].handler, path, file)))
          goto fail;
        if (tree && (xc = nng_http_handler_set_tree(srv->handlers[i].handler)))
          goto fail;

        if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
          goto fail;
        handlers_added++;
        break;
      }
      case 4: {
        // Directory handler (tree is implicit)
        SEXP dir_elem = get_list_element(h, "directory");
        const char *dir = CHAR(STRING_ELT(dir_elem, 0));
        if ((xc = nng_http_handler_alloc_directory(&srv->handlers[i].handler, path, dir)))
          goto fail;

        if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
          goto fail;
        handlers_added++;
        break;
      }
      case 5: {
        // Inline static content handler
        SEXP data_elem = get_list_element(h, "data");
        SEXP ct_elem = get_list_element(h, "content_type");
        const char *content_type = (ct_elem != R_NilValue && TYPEOF(ct_elem) == STRSXP) ?
                                   CHAR(STRING_ELT(ct_elem, 0)) : "application/octet-stream";
        if ((xc = nng_http_handler_alloc_static(&srv->handlers[i].handler, path,
                                                 RAW(data_elem), XLENGTH(data_elem),
                                                 content_type)))
          goto fail;
        if (tree && (xc = nng_http_handler_set_tree(srv->handlers[i].handler)))
          goto fail;

        if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
          goto fail;
        handlers_added++;
        break;
      }
      case 6: {
        // Redirect handler
        SEXP loc_elem = get_list_element(h, "location");
        SEXP status_elem = get_list_element(h, "status");
        const char *location = CHAR(STRING_ELT(loc_elem, 0));
        const int status_int = NANO_INTEGER(status_elem);
        if ((xc = nng_http_handler_alloc_redirect(&srv->handlers[i].handler, path,
                                                   (uint16_t) status_int, location)))
          goto fail;
        if (tree && (xc = nng_http_handler_set_tree(srv->handlers[i].handler)))
          goto fail;

        if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
          goto fail;
        handlers_added++;
        break;
      }
      default:
        Rf_error("unknown handler type: %d", type);
      }
    }
  }

  if ((xc = nng_mtx_alloc(&mtx)))
    goto fail;
  srv->mtx = mtx;

  nng_url_free(up);

  SEXP xptr = PROTECT(R_MakeExternalPtr(srv, nano_HttpServerSymbol, prot));
  R_RegisterCFinalizerEx(xptr, http_server_finalizer, TRUE);
  srv->xptr = xptr;
  srv->prot = prot;

  NANO_CLASS2(xptr, "nanoServer", "nano");
  Rf_setAttrib(xptr, nano_UrlSymbol, url);
  Rf_setAttrib(xptr, nano_StateSymbol, Rf_mkString("not started"));

  UNPROTECT(2);
  return xptr;

  fail:
  // Release TLS config reference
  if (srv->tls != NULL)
    nng_tls_config_free(srv->tls);

  // Clean up handlers (callbacks protected by prot pairlist, released on UNPROTECT)
  for (int i = 0; i < handlers_added; i++) {
    if (srv->handlers[i].handler != NULL)
      nng_http_server_del_handler(server, srv->handlers[i].handler);
    if (srv->handlers[i].ws_listener != NULL)
      nng_stream_listener_free(srv->handlers[i].ws_listener);
    if (srv->handlers[i].ws_accept_aio != NULL)
      nng_aio_free(srv->handlers[i].ws_accept_aio);
  }
  // Clean up partially created handler if any
  if (hinfo != NULL && handlers_added < handler_count) {
    if (srv->handlers[handlers_added].handler != NULL)
      nng_http_handler_free(srv->handlers[handlers_added].handler);
    if (srv->handlers[handlers_added].ws_listener != NULL)
      nng_stream_listener_free(srv->handlers[handlers_added].ws_listener);
    if (srv->handlers[handlers_added].ws_accept_aio != NULL)
      nng_aio_free(srv->handlers[handlers_added].ws_accept_aio);
  }

  if (mtx != NULL) nng_mtx_free(mtx);
  if (server != NULL) nng_http_server_release(server);
  nng_url_free(up);
  free(hinfo);
  free(srv);
  failmem:
  ERROR_OUT(xc);

}

SEXP rnng_http_server_start(SEXP xptr) {

  if (NANO_PTR_CHECK(xptr, nano_HttpServerSymbol))
    Rf_error("`server` is not a valid HTTP Server");

  nano_http_server *srv = (nano_http_server *) NANO_PTR(xptr);

  if (srv->started) return R_NilValue;
  if (srv->stopped) Rf_error("server has been stopped");

  int xc;
  int ws_started = 0;

  // Start all WebSocket listeners (implicitly starts HTTP server)
  for (int i = 0; i < srv->handler_count; i++) {
    if (srv->handlers[i].ws_listener != NULL) {
      if ((xc = nng_stream_listener_listen(srv->handlers[i].ws_listener)))
        goto fail;
      nng_stream_listener_accept(srv->handlers[i].ws_listener, srv->handlers[i].ws_accept_aio);
      ws_started = 1;
    }
  }

  // If no WS handlers, start HTTP server explicitly
  if (!ws_started) {
    if ((xc = nng_http_server_start(srv->server)))
      ERROR_OUT(xc);
  }

  srv->started = 1;
  return nano_success;

  fail:
  // Close any already-started WS listeners
  for (int j = 0; j < srv->handler_count; j++) {
    if (srv->handlers[j].ws_listener != NULL)
      nng_stream_listener_close(srv->handlers[j].ws_listener);
  }
  ERROR_OUT(xc);

}

SEXP rnng_http_server_stop(SEXP xptr) {

  if (NANO_PTR_CHECK(xptr, nano_HttpServerSymbol))
    Rf_error("`server` is not a valid HTTP Server");

  nano_http_server *srv = (nano_http_server *) NANO_PTR(xptr);
  if (!srv->started || srv->stopped)
    return nano_success;

  srv->stopped = 1;
  http_server_do_stop(srv);

  return nano_success;

}

SEXP rnng_http_server_close(SEXP xptr) {

  if (NANO_PTR_CHECK(xptr, nano_HttpServerSymbol))
    Rf_error("`server` is not a valid HTTP Server");

  nano_http_server *srv = (nano_http_server *) NANO_PTR(xptr);
  if (srv == NULL) return nano_success;

  http_server_stop_and_clear(srv);

  return nano_success;

}

SEXP rnng_ws_send(SEXP xptr, SEXP data) {

  if (NANO_PTR_CHECK(xptr, nano_WsConnSymbol))
    Rf_error("`ws` is not a valid WebSocket connection");

  nano_ws_conn *conn = (nano_ws_conn *) NANO_PTR(xptr);
  nano_http_server *srv = conn->handler->server;

  // Check state
  nng_mtx_lock(srv->mtx);
  const int is_open = conn->state == WS_STATE_OPEN;
  nng_mtx_unlock(srv->mtx);
  if (!is_open)
    return mk_error(NNG_ECLOSED);

  // Get data to send
  unsigned char *buf;
  size_t len;
  switch (TYPEOF(data)) {
  case RAWSXP:
    buf = (unsigned char *) DATAPTR_RO(data);
    len = XLENGTH(data);
    break;
  case STRSXP:
    buf = (unsigned char *) NANO_STRING(data);
    len = strlen((char *) buf);
    break;
  default:
    Rf_error("`data` must be raw or character");
  }

  nng_msg *msgp = NULL;
  int xc;
  if ((xc = nng_msg_alloc(&msgp, len)))
    return mk_error(xc);
  memcpy(nng_msg_body(msgp), buf, len);

  nng_aio_set_msg(conn->send_aio, msgp);
  nng_stream_send(conn->stream, conn->send_aio);
  nng_aio_wait(conn->send_aio);
  
  if ((xc = nng_aio_result(conn->send_aio)))
    nng_msg_free(nng_aio_get_msg(conn->send_aio));

  return xc ? mk_error(xc) : nano_success;

}

SEXP rnng_ws_close(SEXP xptr) {

  if (NANO_PTR_CHECK(xptr, nano_WsConnSymbol))
    Rf_error("`ws` is not a valid WebSocket connection");

  nano_ws_conn *conn = (nano_ws_conn *) NANO_PTR(xptr);

  if (ws_conn_begin_close(conn)) {
    ws_conn_schedule_onclose(conn);
  }

  return nano_success;

}
