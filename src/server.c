// nanonext - C level - HTTP/WebSocket Server ----------------------------------

#define NANONEXT_HTTP
#include "nanonext.h"

// internals -------------------------------------------------------------------

#define DL_PREPEND(head, node) do { \
  (node)->next = (head); \
  if ((head) != NULL) \
    (head)->prev = (node); \
  (head) = (node); \
} while (0)

#define DL_REMOVE(head, node) do { \
  if ((node)->prev != NULL) \
    (node)->prev->next = (node)->next; \
  else if ((head) == (node)) \
    (head) = (node)->next; \
  if ((node)->next != NULL) \
    (node)->next->prev = (node)->prev; \
  (node)->next = (node)->prev = NULL; \
} while (0)

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
  SEXP names = Rf_getAttrib(list, R_NamesSymbol);
  if (names != R_NilValue) {
    for (R_xlen_t i = 0; i < Rf_xlength(list); i++) {
      if (!strcmp(CHAR(STRING_ELT(names, i)), name))
        return VECTOR_ELT(list, i);
    }
  }
  return R_NilValue;
}

static void http_handler_cb(nng_aio *);
static void http_invoke_callback(void *);
static int http_request_unlink(nano_http_request *);
static void http_cancel_pending_requests(nano_http_server *);
static void ws_accept_cb(void *);
static int ws_conn_close_locked(nano_ws_conn *);
static void ws_conn_close(nano_ws_conn *);
static void ws_recv_cb(void *);
static void ws_conn_cleanup(nano_ws_conn *);
static void ws_invoke_onopen(void *);
static void ws_invoke_onmessage(void *);
static void ws_invoke_onclose(void *);
static void http_server_finalizer(SEXP);
static void http_server_stop(nano_http_server *);
static void http_server_cleanup(void *);

// On NNG threads --------------------------------------------------------------

static void http_handler_cb(nng_aio *aio) {

  nng_http_req *req = nng_aio_get_input(aio, 0);
  nng_http_handler *h = nng_aio_get_input(aio, 1);
  nano_http_handler_info *info = nng_http_handler_get_data(h);
  nano_http_server *srv = info->server;

  if (srv->state == SERVER_STOPPED) {
    nng_aio_finish(aio, NNG_ECANCELED);
    return;
  }

  nano_http_request *r = calloc(1, sizeof(nano_http_request));
  if (r == NULL) {
    nng_aio_finish(aio, NNG_ENOMEM);
    return;
  }
  r->aio = aio;
  r->req = req;
  r->callback = info->callback;
  r->server = srv;

  nng_mtx_lock(srv->mtx);
  DL_PREPEND(srv->pending_reqs, r);
  nng_mtx_unlock(srv->mtx);

  later2(http_invoke_callback, r);

}

static int http_request_unlink(nano_http_request *r) {

  nano_http_server *srv = r->server;
  nng_mtx_lock(srv->mtx);
  DL_REMOVE(srv->pending_reqs, r);
  const int cancelled = r->cancelled;
  nng_mtx_unlock(srv->mtx);

  return cancelled;

}

static void http_cancel_pending_requests(nano_http_server *srv) {

  nng_mtx_lock(srv->mtx);
  nano_http_request *r = srv->pending_reqs;
  while (r != NULL) {
    r->cancelled = 1;
    nng_aio_finish(r->aio, NNG_ECANCELED);
    r = r->next;
  }
  nng_mtx_unlock(srv->mtx);

}


static void http_server_stop(nano_http_server *srv) {

  nng_http_server_stop(srv->server);
  http_cancel_pending_requests(srv);

  for (int i = 0; i < srv->handler_count; i++) {
    if (srv->handlers[i].ws_listener != NULL) {
      nng_aio_stop(srv->handlers[i].ws_accept_aio);
      nng_stream_listener_close(srv->handlers[i].ws_listener);

      nng_mtx_lock(srv->mtx);
      for (nano_ws_conn *conn = srv->handlers[i].ws_conns; conn != NULL; conn = conn->next) {
        ws_conn_close_locked(conn);
        if (!conn->onclose_scheduled) {
          conn->onclose_scheduled = 1;
          later2(ws_invoke_onclose, conn);
        }
      }
      nng_mtx_unlock(srv->mtx);

      for (nano_ws_conn *conn = srv->handlers[i].ws_conns; conn != NULL; conn = conn->next)
        nng_aio_wait(conn->recv_aio);
    }
  }

}

// On R main thread ------------------------------------------------------------

static void http_server_cleanup(void *arg) {

  nano_http_server *srv = (nano_http_server *) arg;

  for (int i = 0; i < srv->handler_count; i++) {
    if (srv->handlers[i].handler != NULL)
      nng_http_server_del_handler(srv->server, srv->handlers[i].handler);

    if (srv->handlers[i].ws_listener != NULL) {
      nng_stream_listener_free(srv->handlers[i].ws_listener);
      nng_aio_free(srv->handlers[i].ws_accept_aio);

      // Free any connections not cleaned up by callbacks (shouldn't normally happen)
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

  if (srv->tls != NULL)
    nng_tls_config_free(srv->tls);
  nng_http_server_release(srv->server);
  if (srv->mtx != NULL)
    nng_mtx_free(srv->mtx);
  free(srv);

}

static void http_server_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_http_server *srv = (nano_http_server *) NANO_PTR(xptr);

  if (srv->state == SERVER_STARTED) {
    srv->state = SERVER_STOPPED;
    http_server_stop(srv);
  }

  // Suppress callbacks during shutdown - on_close won't fire for connections closed by server stop
  for (int i = 0; i < srv->handler_count; i++) {
    srv->handlers[i].callback = R_NilValue;
    srv->handlers[i].on_open = R_NilValue;
    srv->handlers[i].on_close = R_NilValue;
  }

  // Schedule deferred cleanup - runs after all pending later2 callbacks due to FIFO ordering
  later2(http_server_cleanup, srv);

}

static void http_invoke_callback(void *arg) {

  nano_http_request *r = (nano_http_request *) arg;

  const int cancelled = http_request_unlink(r);
  if (cancelled) {
    free(r);
    return;
  }

  nng_http_req *req = r->req;

  const char *names[] = {"method", "uri", "headers", "body", ""};
  SEXP req_list;
  PROTECT(req_list = Rf_mkNamed(VECSXP, names));
  SET_VECTOR_ELT(req_list, 0, Rf_mkString(nng_http_req_get_method(req)));
  SET_VECTOR_ELT(req_list, 1, Rf_mkString(nng_http_req_get_uri(req)));

  int header_count = 0;
  for (nano_http_header_s *hdr = nano_http_header_first(req); hdr != NULL;
       hdr = nano_http_header_next(req, hdr))
    header_count++;
  
  SEXP headers = Rf_allocVector(STRSXP, header_count);
  SET_VECTOR_ELT(req_list, 2, headers);
  SEXP hdr_names = Rf_allocVector(STRSXP, header_count);
  Rf_namesgets(headers, hdr_names);
  int i = 0;
  for (nano_http_header_s *hdr = nano_http_header_first(req); hdr != NULL;
       hdr = nano_http_header_next(req, hdr), i++) {
    SET_STRING_ELT(headers, i, Rf_mkChar(hdr->value));
    SET_STRING_ELT(hdr_names, i, Rf_mkChar(hdr->name));
  }

  void *body_data;
  size_t body_len;
  nng_http_req_get_data(req, &body_data, &body_len);
  SEXP body = Rf_allocVector(RAWSXP, body_len);
  SET_VECTOR_ELT(req_list, 3, body);
  if (body_len)
    memcpy(NANO_DATAPTR(body), body_data, body_len);

  SEXP call;
  PROTECT(call = Rf_lang2(r->callback, req_list));
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
    int status_code = TYPEOF(status_elem) == INTSXP ? NANO_INTEGER(status_elem) : 200;
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

    UNPROTECT(1);
  }

  nng_aio_set_output(r->aio, 0, res);
  nng_aio_finish(r->aio, 0);
  free(r);

}

// WebSocket functions ---------------------------------------------------------

static void ws_accept_cb(void *arg) {

  nano_http_handler_info *info = (nano_http_handler_info *) arg;
  nano_http_server *srv = info->server;
  const int xc = nng_aio_result(info->ws_accept_aio);

  if (xc == 0) {
    nng_stream *stream = nng_aio_get_output(info->ws_accept_aio, 0);

    nano_ws_conn *conn = calloc(1, sizeof(nano_ws_conn));
    if (conn == NULL) {
      nng_stream_free(stream);
      goto next;
    }
    conn->stream = stream;
    conn->handler = info;
    conn->state = WS_STATE_OPEN;
    conn->xptr = R_NilValue;

    if (nng_aio_alloc(&conn->recv_aio, ws_recv_cb, conn) ||
        nng_aio_alloc(&conn->send_aio, NULL, NULL)) {
      nng_aio_free(conn->recv_aio);
      nng_stream_free(stream);
      free(conn);
      goto next;
    }

    nng_mtx_lock(srv->mtx);
    conn->id = ++srv->ws_conn_counter;
    DL_PREPEND(info->ws_conns, conn);
    nng_mtx_unlock(srv->mtx);

    later2(ws_invoke_onopen, conn);
  }

  next:
  if (srv->state != SERVER_STOPPED) {
    nng_stream_listener_accept(info->ws_listener, info->ws_accept_aio);
  }

}

static inline int ws_conn_is_open(nano_ws_conn *conn) {

  nano_http_server *srv = conn->handler->server;
  nng_mtx_lock(srv->mtx);
  const int is_open = conn->state == WS_STATE_OPEN;
  nng_mtx_unlock(srv->mtx);
  return is_open;

}

// Caller must hold srv->mtx
static int ws_conn_close_locked(nano_ws_conn *conn) {

  if (conn->state != WS_STATE_OPEN)
    return 0;

  conn->state = WS_STATE_CLOSING;
  nng_aio_cancel(conn->recv_aio);
  nng_aio_cancel(conn->send_aio);
  nng_stream_close(conn->stream);
  return 1;

}

static void ws_conn_close(nano_ws_conn *conn) {

  nano_http_server *srv = conn->handler->server;
  nng_mtx_lock(srv->mtx);
  ws_conn_close_locked(conn);
  const int scheduled = conn->onclose_scheduled;
  conn->onclose_scheduled = 1;
  nng_mtx_unlock(srv->mtx);

  if (!scheduled)
    later2(ws_invoke_onclose, conn);

}

static void ws_recv_cb(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  const int xc = nng_aio_result(conn->recv_aio);

  if (xc == 0) {
    nng_msg *msgp = nng_aio_get_msg(conn->recv_aio);

    ws_message *msg = malloc(sizeof(ws_message));
    if (msg != NULL) {
      msg->conn = conn;
      msg->msg = msgp;
      later2(ws_invoke_onmessage, msg);
    } else {
      nng_msg_free(msgp);
    }

    if (ws_conn_is_open(conn))
      nng_stream_recv(conn->stream, conn->recv_aio);

  } else {
    ws_conn_close(conn);
  }

}

static void ws_conn_cleanup(nano_ws_conn *conn) {

  nano_http_handler_info *info = conn->handler;
  nano_http_server *srv = info->server;

  nng_mtx_lock(srv->mtx);
  DL_REMOVE(info->ws_conns, conn);
  nng_mtx_unlock(srv->mtx);

  conn->state = WS_STATE_CLOSED;

  if (conn->xptr != R_NilValue) {
    prot_remove(srv->prot, conn->xptr);
    R_ClearExternalPtr(conn->xptr);
    conn->xptr = R_NilValue;
  }

  nng_stream_free(conn->stream);
  nng_aio_free(conn->recv_aio);
  nng_aio_free(conn->send_aio);
  free(conn);

}

static void ws_invoke_onopen(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  if (!ws_conn_is_open(conn))
    return;
  nano_http_handler_info *info = conn->handler;

  SEXP xptr;
  PROTECT(xptr = R_MakeExternalPtr(conn, nano_WsConnSymbol, R_NilValue));
  NANO_CLASS2(xptr, "nanoWsConn", "nano");
  Rf_setAttrib(xptr, nano_IdSymbol, Rf_ScalarInteger(conn->id));
  prot_add(info->server->prot, xptr);
  conn->xptr = xptr;
  UNPROTECT(1);

  if (info->on_open != R_NilValue) {
    SEXP call;
    PROTECT(call = Rf_lang2(info->on_open, conn->xptr));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }

  nng_stream_recv(conn->stream, conn->recv_aio);

}

static void ws_invoke_onmessage(void *arg) {

  ws_message *wsmsg = (ws_message *) arg;
  nano_ws_conn *conn = wsmsg->conn;
  if (!ws_conn_is_open(conn)) {
    nng_msg_free(wsmsg->msg);
    free(wsmsg);
    return;
  }
  nano_http_handler_info *info = conn->handler;

  const size_t len = nng_msg_len(wsmsg->msg);
  unsigned char *buf = nng_msg_body(wsmsg->msg);

  SEXP data;
  if (info->textframes) {
    PROTECT(data = Rf_ScalarString(Rf_mkCharLenCE((char *) buf, len, CE_UTF8)));
  } else {
    PROTECT(data = Rf_allocVector(RAWSXP, len));
    memcpy(NANO_DATAPTR(data), buf, len);
  }

  if (info->callback != R_NilValue) {
    SEXP call;
    PROTECT(call = Rf_lang3(info->callback, conn->xptr, data));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }

  UNPROTECT(1);
  nng_msg_free(wsmsg->msg);
  free(wsmsg);

}

static void ws_invoke_onclose(void *arg) {

  nano_ws_conn *conn = (nano_ws_conn *) arg;
  nano_http_handler_info *info = conn->handler;

  if (info->on_close != R_NilValue) {
    SEXP call;
    PROTECT(call = Rf_lang2(info->on_close, conn->xptr));
    R_tryEval(call, R_GlobalEnv, NULL);
    UNPROTECT(1);
  }

  ws_conn_cleanup(conn);

}

// R-callable functions --------------------------------------------------------

SEXP rnng_http_server_create(SEXP url, SEXP handlers, SEXP tls) {

  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  if (eln2 == NULL)
    nano_load_later();

  const char *ur = CHAR(STRING_ELT(url, 0));
  nng_url *up = NULL;
  nano_http_handler_info *hinfo = NULL;
  int xc;
  int handlers_added = 0;

  nano_http_server *srv = calloc(1, sizeof(nano_http_server));
  if (srv == NULL) {
    xc = NNG_ENOMEM;
    goto fail;
  }
  srv->xptr = R_NilValue;
  srv->prot = R_NilValue;
  if ((xc = nng_mtx_alloc(&srv->mtx)))
    goto fail;

  SEXP prot;
  PROTECT(prot = Rf_cons(R_NilValue, R_NilValue));

  if ((xc = nng_url_parse(&up, ur)))
    goto fail;

  if ((xc = nng_http_server_hold(&srv->server, up)))
    goto fail;

  if (tls != R_NilValue) {
    srv->tls = (nng_tls_config *) NANO_PTR(tls);
    nng_tls_config_hold(srv->tls);
    prot_add(prot, tls);
    if ((xc = nng_http_server_set_tls(srv->server, srv->tls)))
      goto fail;
  }

  const R_xlen_t handler_count = Rf_xlength(handlers);
  srv->handler_count = handler_count;

  if (handler_count > 0) {
    hinfo = calloc(handler_count, sizeof(nano_http_handler_info));
    if (hinfo == NULL) {
      xc = NNG_ENOMEM;
      goto fail;
    }
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

        SEXP callback = get_list_element(h, "callback");
        prot_add(prot, callback);
        srv->handlers[i].callback = callback;
        srv->handlers[i].server = srv;
        nng_http_handler_set_data(srv->handlers[i].handler, &srv->handlers[i], NULL);

        if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
          goto fail;

        handlers_added++;
        break;
      }
      case 2: {
        // WebSocket handler
        SEXP textframes_elem = get_list_element(h, "textframes");
        const int textframes = textframes_elem != R_NilValue ? NANO_INTEGER(textframes_elem) : 0;

        const char *scheme = strcmp(up->u_scheme, "https") == 0 ? "wss" : "ws";
        const size_t ws_url_len = strlen(scheme) + strlen(up->u_hostname) +
                                  strlen(up->u_port) + strlen(path) + 5;
        if (ws_url_len > NANO_URL_MAX) {
          xc = NNG_EINVAL;
          goto fail;
        }
        char ws_url[ws_url_len];
        snprintf(ws_url, ws_url_len, "%s://%s:%s%s", scheme, up->u_hostname, up->u_port, path);

        if ((xc = nng_stream_listener_alloc(&srv->handlers[i].ws_listener, ws_url)) ||
            (xc = nng_stream_listener_set_bool(srv->handlers[i].ws_listener, "ws:msgmode", true)))
          goto fail;

        if (textframes) {
          if ((xc = nng_stream_listener_set_bool(srv->handlers[i].ws_listener, "ws:recv-text", true)) ||
              (xc = nng_stream_listener_set_bool(srv->handlers[i].ws_listener, "ws:send-text", true)))
            goto fail;

          srv->handlers[i].textframes = 1;
        }

        if (srv->tls != NULL) {
          nng_stream_listener_set_ptr(srv->handlers[i].ws_listener, NNG_OPT_TLS_CONFIG, srv->tls);
        }

        SEXP on_message = get_list_element(h, "on_message");
        prot_add(prot, on_message);
        srv->handlers[i].callback = on_message;
        SEXP on_open = get_list_element(h, "on_open");
        if (on_open != R_NilValue) {
          prot_add(prot, on_open);
          srv->handlers[i].on_open = on_open;
        }
        SEXP on_close = get_list_element(h, "on_close");
        if (on_close != R_NilValue) {
          prot_add(prot, on_close);
          srv->handlers[i].on_close = on_close;
        }

        srv->handlers[i].server = srv;

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
        SEXP ct_elem = get_list_element(h, "content_type");
        const char *content_type = TYPEOF(ct_elem) == STRSXP ?
                                   CHAR(STRING_ELT(ct_elem, 0)) : "application/octet-stream";
        SEXP data_elem = get_list_element(h, "data");
        const unsigned char *data;
        size_t size;

        switch (TYPEOF(data_elem)) {
        case STRSXP:
          data = (const unsigned char *) NANO_STRING(data_elem);
          size = strlen((const char *) data);
          break;
        default:
          data = NANO_DATAPTR(data_elem);
          size = (size_t) XLENGTH(data_elem);
        }

        if ((xc = nng_http_handler_alloc_static(&srv->handlers[i].handler,
                                                path, data, size, content_type)))
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
        const char *location = CHAR(STRING_ELT(loc_elem, 0));
        SEXP status_elem = get_list_element(h, "status");
        const int status_int = NANO_INTEGER(status_elem);
        if ((xc = nng_http_handler_alloc_redirect(&srv->handlers[i].handler,
                                                  path,
                                                  (uint16_t) status_int,
                                                  location)))
          goto fail;

        if (tree && (xc = nng_http_handler_set_tree(srv->handlers[i].handler)))
          goto fail;

        if ((xc = nng_http_server_add_handler(srv->server, srv->handlers[i].handler)))
          goto fail;

        handlers_added++;
        break;
      }
      default:
        xc = NNG_EINVAL;
        goto fail;
      }
    }
  }

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
  if (srv->tls != NULL)
    nng_tls_config_free(srv->tls);
  for (int i = 0; i < handlers_added; i++) {
    if (srv->handlers[i].handler != NULL)
      nng_http_server_del_handler(srv->server, srv->handlers[i].handler);
    if (srv->handlers[i].ws_listener != NULL)
      nng_stream_listener_free(srv->handlers[i].ws_listener);
    if (srv->handlers[i].ws_accept_aio != NULL)
      nng_aio_free(srv->handlers[i].ws_accept_aio);
  }
  if (hinfo != NULL && handlers_added < handler_count) {
    if (srv->handlers[handlers_added].handler != NULL)
      nng_http_handler_free(srv->handlers[handlers_added].handler);
    if (srv->handlers[handlers_added].ws_listener != NULL)
      nng_stream_listener_free(srv->handlers[handlers_added].ws_listener);
    if (srv->handlers[handlers_added].ws_accept_aio != NULL)
      nng_aio_free(srv->handlers[handlers_added].ws_accept_aio);
  }
  if (srv->server != NULL) nng_http_server_release(srv->server);
  if (srv->mtx != NULL) nng_mtx_free(srv->mtx);
  nng_url_free(up);
  free(hinfo);
  free(srv);
  ERROR_OUT(xc);

}

SEXP rnng_http_server_start(SEXP xptr) {

  if (NANO_PTR_CHECK(xptr, nano_HttpServerSymbol))
    Rf_error("`server` is not a valid HTTP Server");

  nano_http_server *srv = (nano_http_server *) NANO_PTR(xptr);

  if (srv->state == SERVER_STARTED)
    return R_NilValue;

  if (srv->state == SERVER_STOPPED)
    Rf_error("server has been stopped");

  int xc;

  if ((xc = nng_http_server_start(srv->server)))
    ERROR_OUT(xc);

  for (int i = 0; i < srv->handler_count; i++) {
    if (srv->handlers[i].ws_listener != NULL) {
      if ((xc = nng_stream_listener_listen(srv->handlers[i].ws_listener)))
        goto fail;
      nng_stream_listener_accept(srv->handlers[i].ws_listener, srv->handlers[i].ws_accept_aio);
    }
  }

  srv->state = SERVER_STARTED;
  return nano_success;

  fail:
  for (int j = 0; j < srv->handler_count; j++) {
    if (srv->handlers[j].ws_listener != NULL)
      nng_stream_listener_close(srv->handlers[j].ws_listener);
  }
  nng_http_server_stop(srv->server);
  ERROR_OUT(xc);

}

SEXP rnng_http_server_close(SEXP xptr) {

  if (NANO_PTR_CHECK(xptr, nano_HttpServerSymbol))
    Rf_error("`server` is not a valid HTTP Server");

  http_server_finalizer(xptr);
  R_ClearExternalPtr(xptr);
  Rf_setAttrib(xptr, nano_StateSymbol, Rf_mkString("closed"));

  return nano_success;

}

SEXP rnng_ws_send(SEXP xptr, SEXP data) {

  if (NANO_PTR_CHECK(xptr, nano_WsConnSymbol))
    Rf_error("`ws` is not a valid WebSocket connection");

  nano_ws_conn *conn = (nano_ws_conn *) NANO_PTR(xptr);

  unsigned char *buf;
  size_t len;
  switch (TYPEOF(data)) {
  case RAWSXP:
    buf = (unsigned char *) DATAPTR_RO(data);
    len = (size_t) XLENGTH(data);
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

  if ((xc = nng_aio_result(conn->send_aio))) {
    nng_msg_free(nng_aio_get_msg(conn->send_aio));
    return mk_error(xc);
  }

  return nano_success;

}

SEXP rnng_ws_close(SEXP xptr) {

  if (NANO_PTR_CHECK(xptr, nano_WsConnSymbol))
    Rf_error("`ws` is not a valid WebSocket connection");

  nano_ws_conn *conn = (nano_ws_conn *) NANO_PTR(xptr);
  ws_conn_close(conn);

  return nano_success;

}
