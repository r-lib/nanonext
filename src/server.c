// nanonext - C level - HTTP/WebSocket Server -----------------------------------

#define NANONEXT_HTTP
#include "nanonext.h"

// Common HTTP headers to extract (NNG doesn't expose header iteration)
static const char *http_common_headers[] = {
  "Content-Type", "Content-Length", "Authorization", "Accept",
  "User-Agent", "Host", "Origin", "Cookie", "X-Requested-With", NULL
};
#define HTTP_COMMON_HEADER_COUNT \
  (sizeof(http_common_headers) / sizeof(http_common_headers[0]) - 1)

// Message data passed to ws_invoke_onmessage
typedef struct {
  nano_ws_conn *conn;
  void *data;
  size_t len;
} ws_message;

// Forward declarations
static void http_handler_cb(nng_aio *);
static void http_invoke_callback(void *);
static int http_request_unlink(nano_http_request *);
static void http_request_free(nano_http_request *);
static void http_cancel_pending_requests(nano_http_server *);
static void ws_start_accept(nano_http_server *);
static void ws_accept_cb(void *);
static void ws_conn_unlink_locked(nano_ws_conn *);
static int ws_conn_begin_close_locked(nano_ws_conn *);
static int ws_conn_begin_close(nano_ws_conn *);
static void ws_conn_schedule_onclose(nano_ws_conn *);
static void ws_recv_cb(void *);
static void ws_conn_cleanup(nano_ws_conn *);
static void ws_invoke_onopen(void *);
static void ws_invoke_onmessage(void *);
static void ws_invoke_onclose(void *);
static void http_server_finalizer(SEXP);
static void http_server_do_stop(nano_http_server *);

// Helper: Get named element from R list (checks both attributes and list names)
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

  // Extract common headers (NNG doesn't expose header iteration)
  r->header_names = malloc(HTTP_COMMON_HEADER_COUNT * sizeof(char *));
  r->header_values = malloc(HTTP_COMMON_HEADER_COUNT * sizeof(char *));
  if (r->header_names != NULL && r->header_values != NULL) {
    r->header_count = 0;
    for (const char **hp = http_common_headers; *hp != NULL; hp++) {
      const char *val = nng_http_req_get_header(req, *hp);
      if (val != NULL) {
        r->header_names[r->header_count] = strdup(*hp);
        r->header_values[r->header_count] = strdup(val);
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

  // Create R list with request info
  const char *names[] = {"method", "uri", "headers", "body", ""};
  SEXP req_list = PROTECT(Rf_mkNamed(VECSXP, names));
  SET_VECTOR_ELT(req_list, 0, Rf_mkString(r->method));
  SET_VECTOR_ELT(req_list, 1, Rf_mkString(r->uri));

  // Build headers as named character vector
  SEXP headers = PROTECT(Rf_allocVector(STRSXP, r->header_count));
  SEXP hdr_names = PROTECT(Rf_allocVector(STRSXP, r->header_count));
  for (int i = 0; i < r->header_count; i++) {
    SET_STRING_ELT(headers, i, Rf_mkChar(r->header_values[i]));
    SET_STRING_ELT(hdr_names, i, Rf_mkChar(r->header_names[i]));
  }
  Rf_setAttrib(headers, R_NamesSymbol, hdr_names);
  SET_VECTOR_ELT(req_list, 2, headers);
  UNPROTECT(2);  // headers, hdr_names (now protected by req_list)

  // Build body as raw vector
  SEXP body = PROTECT(Rf_allocVector(RAWSXP, r->body_len));
  if (r->body_len > 0)
    memcpy(RAW(body), r->body_copy, r->body_len);
  SET_VECTOR_ELT(req_list, 3, body);
  UNPROTECT(1);  // body (now protected by req_list)

  // Call R function with error handling
  SEXP call = PROTECT(Rf_lang2(r->callback, req_list));
  int err;
  SEXP result = R_tryEval(call, R_GlobalEnv, &err);

  // Build HTTP response
  nng_http_res *res = NULL;
  if (err) {
    // R callback threw an error - return 500
    nng_http_res_alloc_error(&res, 500);
  } else {
    PROTECT(result);
    nng_http_res_alloc(&res);

    // Extract status from result$status (default 200)
    SEXP status_elem = get_list_element(result, "status");
    int status_code = (status_elem != R_NilValue && TYPEOF(status_elem) == INTSXP) ?
                      INTEGER(status_elem)[0] : 200;
    nng_http_res_set_status(res, (uint16_t) status_code);

    // Extract headers from result$headers (named character vector)
    SEXP res_headers = get_list_element(result, "headers");
    if (res_headers != R_NilValue && TYPEOF(res_headers) == STRSXP) {
      SEXP hdr_nm = Rf_getAttrib(res_headers, R_NamesSymbol);
      for (int i = 0; i < Rf_length(res_headers); i++) {
        if (hdr_nm != R_NilValue) {
          const char *name = CHAR(STRING_ELT(hdr_nm, i));
          const char *value = CHAR(STRING_ELT(res_headers, i));
          nng_http_res_set_header(res, name, value);
        }
      }
    }

    // Extract body from result$body (character or raw)
    SEXP res_body = get_list_element(result, "body");
    if (res_body != R_NilValue) {
      if (TYPEOF(res_body) == RAWSXP) {
        nng_http_res_copy_data(res, RAW(res_body), XLENGTH(res_body));
      } else if (TYPEOF(res_body) == STRSXP && XLENGTH(res_body) > 0) {
        const char *str = CHAR(STRING_ELT(res_body, 0));
        nng_http_res_copy_data(res, str, strlen(str));
        // Set Content-Type if not already set
        if (nng_http_res_get_header(res, "Content-Type") == NULL)
          nng_http_res_set_header(res, "Content-Type", "text/plain; charset=utf-8");
      }
    }
    UNPROTECT(1);  // result
  }

  // Complete the AIO with response - NNG takes ownership of res
  nng_aio_set_output(r->aio, 0, res);
  nng_aio_finish(r->aio, 0);

  // Cleanup
  UNPROTECT(2);  // call, req_list
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

// Called when server starts - begin accepting WebSocket connections
static void ws_start_accept(nano_http_server *srv) {

  nng_stream_listener_accept(srv->ws_listener, srv->accept_aio);

}

// AIO callback when new WebSocket connection is accepted
static void ws_accept_cb(void *arg) {

  nano_http_server *srv = (nano_http_server *) arg;
  const int xc = nng_aio_result(srv->accept_aio);

  if (xc == 0) {
    // Get the accepted WebSocket stream
    nng_stream *stream = nng_aio_get_output(srv->accept_aio, 0);

    // Create connection object
    nano_ws_conn *conn = calloc(1, sizeof(nano_ws_conn));
    if (conn == NULL) {
      nng_stream_free(stream);
      goto next;
    }

    conn->stream = stream;
    conn->server = srv;
    conn->id = ++srv->ws_conn_counter;
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

    // Add to connection list
    nng_mtx_lock(srv->mtx);
    conn->next = srv->ws_conns;
    if (srv->ws_conns != NULL)
      srv->ws_conns->prev = conn;
    srv->ws_conns = conn;
    nng_mtx_unlock(srv->mtx);

    // Schedule connection initialization and onWSOpen callback
    later2(ws_invoke_onopen, conn);

    // Start receive loop for this connection
    nng_stream_recv(conn->stream, conn->recv_aio);
  }

  next:
  // Continue accepting more connections
  if (!srv->stopped) {
    nng_stream_listener_accept(srv->ws_listener, srv->accept_aio);
  }

}

// Helper: Remove connection from server's linked list (must hold srv->mtx)
static void ws_conn_unlink_locked(nano_ws_conn *conn) {

  nano_http_server *srv = conn->server;
  if (conn->prev != NULL) {
    conn->prev->next = conn->next;
  } else {
    srv->ws_conns = conn->next;
  }
  if (conn->next != NULL) {
    conn->next->prev = conn->prev;
  }
  conn->next = conn->prev = NULL;

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
static int ws_conn_begin_close(nano_ws_conn *conn) {

  nano_http_server *srv = conn->server;
  nng_mtx_lock(srv->mtx);
  int result = ws_conn_begin_close_locked(conn);
  nng_mtx_unlock(srv->mtx);
  return result;

}

// Helper: Schedule onWSClose callback (called after close initiated)
static void ws_conn_schedule_onclose(nano_ws_conn *conn) {

  nano_http_server *srv = conn->server;

  nng_mtx_lock(srv->mtx);
  if (conn->onclose_scheduled || srv->onWSClose == R_NilValue) {
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
  nano_http_server *srv = conn->server;
  const int xc = nng_aio_result(conn->recv_aio);

  // Check if connection is still open
  nng_mtx_lock(srv->mtx);
  const int is_open = conn->state == WS_STATE_OPEN;
  nng_mtx_unlock(srv->mtx);

  if (!is_open)
    return;

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
    nng_mtx_lock(srv->mtx);
    const int still_open = conn->state == WS_STATE_OPEN;
    nng_mtx_unlock(srv->mtx);

    if (still_open) {
      nng_stream_recv(conn->stream, conn->recv_aio);
    }

  } else if (xc == NNG_ECLOSED || xc == NNG_ECONNSHUT || xc == NNG_ECANCELED) {
    // Connection closed by peer or cancelled
    ws_conn_begin_close(conn);
    ws_conn_schedule_onclose(conn);
  }

}

// Runs on R main thread - creates external pointer and calls onWSOpen
static void ws_invoke_onopen(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  nano_http_server *srv = conn->server;

  // Check if connection was closed before we got here
  nng_mtx_lock(srv->mtx);
  const int is_open = conn->state == WS_STATE_OPEN;
  nng_mtx_unlock(srv->mtx);
  if (!is_open)
    return;

  // Create external pointer for this connection
  if (conn->xptr == R_NilValue) {
    conn->xptr = PROTECT(R_MakeExternalPtr(conn, nano_WsConnSymbol, R_NilValue));
    NANO_CLASS2(conn->xptr, "nanoWsConn", "nano");
    Rf_setAttrib(conn->xptr, nano_IdSymbol, Rf_ScalarInteger(conn->id));
    R_PreserveObject(conn->xptr);
    UNPROTECT(1);
  }

  // Call R onWSOpen callback
  if (srv->onWSOpen != R_NilValue) {
    SEXP call = PROTECT(Rf_lang2(srv->onWSOpen, conn->xptr));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }

}

// Runs on R main thread - calls onWSMessage with connection and data
static void ws_invoke_onmessage(void *arg) {

  ws_message *msg = (ws_message *) arg;
  nano_ws_conn *conn = msg->conn;
  nano_http_server *srv = conn->server;

  // Check if connection was closed
  nng_mtx_lock(srv->mtx);
  const int is_open = conn->state == WS_STATE_OPEN;
  nng_mtx_unlock(srv->mtx);
  if (!is_open || conn->xptr == R_NilValue) {
    free(msg->data);
    free(msg);
    return;
  }

  // Create R data object (raw vector or string based on textframes setting)
  SEXP data;
  if (srv->textframes) {
    data = PROTECT(Rf_ScalarString(
      Rf_mkCharLenCE((char *) msg->data, msg->len, CE_UTF8)));
  } else {
    data = PROTECT(Rf_allocVector(RAWSXP, msg->len));
    memcpy(RAW(data), msg->data, msg->len);
  }

  // Call R onWSMessage callback
  if (srv->onWSMessage != R_NilValue) {
    SEXP call = PROTECT(Rf_lang3(srv->onWSMessage, conn->xptr, data));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);  // call
  }
  UNPROTECT(1);  // data

  free(msg->data);
  free(msg);

}

// Runs on R main thread - calls onWSClose, then cleans up connection
static void ws_invoke_onclose(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  nano_http_server *srv = conn->server;

  // Call R onWSClose callback if we have an external pointer
  if (srv->onWSClose != R_NilValue && conn->xptr != R_NilValue) {
    SEXP call = PROTECT(Rf_lang2(srv->onWSClose, conn->xptr));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }

  // Release the R external pointer
  if (conn->xptr != R_NilValue) {
    R_ReleaseObject(conn->xptr);
    conn->xptr = R_NilValue;
  }

  // Clean up connection resources
  ws_conn_cleanup(conn);

}

// Helper: Free connection resources
static void ws_conn_cleanup(nano_ws_conn *conn) {

  nano_http_server *srv = conn->server;

  // Remove from server's connection list
  nng_mtx_lock(srv->mtx);
  ws_conn_unlink_locked(conn);
  nng_mtx_unlock(srv->mtx);

  conn->state = WS_STATE_CLOSED;

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

  if (srv->ws_listener != NULL) {
    nng_aio_cancel(srv->accept_aio);
    nng_stream_listener_close(srv->ws_listener);
  }

  // Close all active WebSocket connections
  nng_mtx_lock(srv->mtx);
  for (nano_ws_conn *conn = srv->ws_conns; conn != NULL; conn = conn->next)
    ws_conn_begin_close_locked(conn);
  nng_mtx_unlock(srv->mtx);

}

// Shared helper: stop server and clear callbacks (idempotent)
static void http_server_stop_and_clear(nano_http_server *srv) {

  // Clear callbacks first to prevent scheduling new later2 callbacks
  srv->onWSOpen = R_NilValue;
  srv->onWSMessage = R_NilValue;
  srv->onWSClose = R_NilValue;

  // Release preserved R objects
  for (int i = 0; i < 4; i++) {
    if (srv->preserved[i] != NULL) {
      nano_ReleaseObject(srv->preserved[i]);
      srv->preserved[i] = NULL;
    }
  }

  // Release HTTP handler callbacks
  for (int i = 0; i < srv->handler_count; i++) {
    if (srv->handlers[i].preserved != NULL) {
      nano_ReleaseObject(srv->handlers[i].preserved);
      srv->handlers[i].preserved = NULL;
    }
  }

  // Stop the server if still running
  if (srv->started && !srv->stopped) {
    srv->stopped = 1;
    http_server_do_stop(srv);
  }

}

// Finalizer - called when R object is garbage collected
static void http_server_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_http_server *srv = (nano_http_server *) NANO_PTR(xptr);

  // Stop and clear callbacks if not already done
  http_server_stop_and_clear(srv);

  // Free HTTP handlers
  for (int i = 0; i < srv->handler_count; i++) {
    nng_http_server_del_handler(srv->server, srv->handlers[i].handler);
  }
  free(srv->handlers);

  // Free NNG resources
  if (srv->ws_listener != NULL) nng_stream_listener_free(srv->ws_listener);
  if (srv->accept_aio != NULL) nng_aio_free(srv->accept_aio);
  if (srv->tls != NULL) nng_tls_config_free(srv->tls);
  nng_http_server_release(srv->server);
  if (srv->mtx != NULL) nng_mtx_free(srv->mtx);
  free(srv);

  R_ClearExternalPtr(xptr);

}

// R-callable functions --------------------------------------------------------

SEXP rnng_http_server_create(SEXP url, SEXP handlers, SEXP ws_path,
                              SEXP onWSOpen, SEXP onWSMessage, SEXP onWSClose,
                              SEXP tls, SEXP textframes) {

  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  const char *ur = CHAR(STRING_ELT(url, 0));
  nng_url *up = NULL;
  nng_http_server *server = NULL;
  nng_stream_listener *ws_listener = NULL;
  nng_aio *accept_aio = NULL;
  nng_mtx *mtx = NULL;
  nano_http_handler_info *hinfo = NULL;
  int xc;

  nano_http_server *srv = calloc(1, sizeof(nano_http_server));
  NANO_ENSURE_ALLOC(srv);

  // Load the 'later' package if not already loaded
  if (eln2 == NULL)
    nano_load_later();

  // Parse URL
  if ((xc = nng_url_parse(&up, ur)))
    goto fail;

  // Get/create HTTP server for this URL
  if ((xc = nng_http_server_hold(&server, up)))
    goto fail;
  srv->server = server;

  // Configure TLS if provided
  if (tls != R_NilValue) {
    srv->tls = (nng_tls_config *) NANO_PTR(tls);
    nng_tls_config_hold(srv->tls);
    srv->tls_xptr = tls;
    srv->preserved[3] = nano_PreserveObject(tls);
    if ((xc = nng_http_server_set_tls(srv->server, srv->tls)))
      goto fail;
  }

  // Add HTTP handlers
  const int handler_count = Rf_length(handlers);
  int handlers_added = 0;
  srv->handler_count = handler_count;
  if (handler_count > 0) {
    hinfo = malloc(handler_count * sizeof(nano_http_handler_info));
    NANO_ENSURE_ALLOC(hinfo);
    memset(hinfo, 0, handler_count * sizeof(nano_http_handler_info));
    srv->handlers = hinfo;

    for (int i = 0; i < handler_count; i++) {
      SEXP h = VECTOR_ELT(handlers, i);
      const char *path = CHAR(STRING_ELT(VECTOR_ELT(h, 0), 0));
      SEXP callback = VECTOR_ELT(h, 1);
      const char *method = VECTOR_ELT(h, 2) == R_NilValue ? NULL :
                           CHAR(STRING_ELT(VECTOR_ELT(h, 2), 0));
      const int tree = NANO_INTEGER(VECTOR_ELT(h, 3));

      if ((xc = nng_http_handler_alloc(&srv->handlers[i].handler, path, http_handler_cb)))
        goto fail;
      if (method != NULL && (xc = nng_http_handler_set_method(srv->handlers[i].handler, method)))
        goto fail;
      if (tree && (xc = nng_http_handler_set_tree(srv->handlers[i].handler)))
        goto fail;

      srv->handlers[i].callback = callback;
      srv->handlers[i].preserved = nano_PreserveObject(callback);
      srv->handlers[i].server = srv;
      nng_http_handler_set_data(srv->handlers[i].handler, &srv->handlers[i], NULL);
      if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
        goto fail;
      handlers_added++;
    }
  }

  // Create WebSocket listener if callbacks provided
  if (onWSOpen != R_NilValue || onWSMessage != R_NilValue) {
    // Build WebSocket URL
    char ws_url[512];
    const char *scheme = strcmp(up->u_scheme, "https") == 0 ? "wss" : "ws";
    const char *path = ws_path != R_NilValue ? CHAR(STRING_ELT(ws_path, 0)) : "/";
    snprintf(ws_url, sizeof(ws_url), "%s://%s:%s%s",
             scheme, up->u_hostname, up->u_port, path);

    if ((xc = nng_stream_listener_alloc(&ws_listener, ws_url)))
      goto fail;
    srv->ws_listener = ws_listener;

    // Enable WebSocket message mode
    if ((xc = nng_stream_listener_set_bool(srv->ws_listener, "ws:msgmode", true)))
      goto fail;

    // Configure text frames if requested
    if (NANO_INTEGER(textframes)) {
      if ((xc = nng_stream_listener_set_bool(srv->ws_listener, "ws:recv-text", true)) ||
          (xc = nng_stream_listener_set_bool(srv->ws_listener, "ws:send-text", true)))
        goto fail;
      srv->textframes = 1;
    }

    // Configure TLS for WebSocket listener
    if (srv->tls != NULL) {
      nng_stream_listener_set_ptr(srv->ws_listener, NNG_OPT_TLS_CONFIG, srv->tls);
    }

    // Store callbacks
    srv->onWSOpen = onWSOpen;
    srv->onWSMessage = onWSMessage;
    srv->onWSClose = onWSClose;
    srv->preserved[0] = nano_PreserveObject(onWSOpen);
    srv->preserved[1] = nano_PreserveObject(onWSMessage);
    srv->preserved[2] = nano_PreserveObject(onWSClose);

    // Create accept AIO
    if ((xc = nng_aio_alloc(&accept_aio, ws_accept_cb, srv)))
      goto fail;
    srv->accept_aio = accept_aio;
  }

  if ((xc = nng_mtx_alloc(&mtx)))
    goto fail;
  srv->mtx = mtx;

  nng_url_free(up);

  // Return external pointer
  SEXP xptr = PROTECT(R_MakeExternalPtr(srv, nano_HttpServerSymbol, R_NilValue));
  R_RegisterCFinalizerEx(xptr, http_server_finalizer, TRUE);

  NANO_CLASS2(xptr, "nanoServer", "nano");
  Rf_setAttrib(xptr, nano_UrlSymbol, url);
  Rf_setAttrib(xptr, nano_StateSymbol, Rf_mkString("not started"));

  UNPROTECT(1);
  return xptr;

  fail:
  // Clean up preserved objects
  for (int i = 0; i < 4; i++) {
    if (srv->preserved[i] != NULL) nano_ReleaseObject(srv->preserved[i]);
  }

  // Release TLS config reference
  if (srv->tls != NULL)
    nng_tls_config_free(srv->tls);

  // Clean up HTTP handlers
  for (int i = 0; i < handlers_added; i++) {
    nng_http_server_del_handler(server, srv->handlers[i].handler);
    nano_ReleaseObject(srv->handlers[i].preserved);
  }
  if (hinfo != NULL && handlers_added < handler_count &&
      srv->handlers[handlers_added].handler != NULL) {
    nng_http_handler_free(srv->handlers[handlers_added].handler);
    if (srv->handlers[handlers_added].preserved != NULL)
      nano_ReleaseObject(srv->handlers[handlers_added].preserved);
  }

  if (mtx != NULL) nng_mtx_free(mtx);
  if (accept_aio != NULL) nng_aio_free(accept_aio);
  if (ws_listener != NULL) nng_stream_listener_free(ws_listener);
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

  // Start the HTTP server
  if ((xc = nng_http_server_start(srv->server)))
    ERROR_OUT(xc);

  // Start the WebSocket listener
  if (srv->ws_listener != NULL) {
    if ((xc = nng_stream_listener_listen(srv->ws_listener))) {
      nng_http_server_stop(srv->server);
      ERROR_OUT(xc);
    }

    ws_start_accept(srv);
  }

  srv->started = 1;
  return nano_success;

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
  nano_http_server *srv = conn->server;

  // Check state
  nng_mtx_lock(srv->mtx);
  const int is_open = conn->state == WS_STATE_OPEN;
  nng_mtx_unlock(srv->mtx);
  if (!is_open)
    return mk_error(NNG_ECLOSED);

  // Get data to send
  unsigned char *buf;
  size_t len;
  if (TYPEOF(data) == RAWSXP) {
    buf = RAW(data);
    len = XLENGTH(data);
  } else if (TYPEOF(data) == STRSXP) {
    const char *s = NANO_STRING(data);
    buf = (unsigned char *) s;
    len = strlen(s);
  } else {
    Rf_error("`data` must be raw or character");
  }

  // Allocate message
  nng_msg *msgp;
  int xc;
  if ((xc = nng_msg_alloc(&msgp, len)))
    return mk_error(xc);
  memcpy(nng_msg_body(msgp), buf, len);

  // Set message on AIO and send
  nng_aio_set_msg(conn->send_aio, msgp);
  nng_stream_send(conn->stream, conn->send_aio);

  // Wait for send to complete
  nng_aio_wait(conn->send_aio);
  xc = nng_aio_result(conn->send_aio);
  if (xc)
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
