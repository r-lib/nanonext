// nanonext - C level - Communications Functions -------------------------------

#include "nanonext.h"

// internal --------------------------------------------------------------------

static int nano_fail_mode(SEXP mode) {

  if (TYPEOF(mode) == INTSXP)
    return NANO_INTEGER(mode);

  const char *mod = CHAR(STRING_ELT(mode, 0));
  const size_t slen = strlen(mod);

  switch (slen) {
  case 4:
    if (!memcmp(mod, "warn", slen)) return 1;
    if (!memcmp(mod, "none", slen)) return 3;
    break;
  case 5:
    if (!memcmp(mod, "error", slen)) return 2;
    break;
  }

  Rf_error("`fail` should be one of: warn, error, none");

}


// finalizers ------------------------------------------------------------------

static void context_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_ctx *xp = (nng_ctx *) NANO_PTR(xptr);
  nng_ctx_close(*xp);
  free(xp);

}

// contexts --------------------------------------------------------------------

SEXP rnng_ctx_open(SEXP socket) {

  if (NANO_PTR_CHECK(socket, nano_SocketSymbol))
    Rf_error("`socket` is not a valid Socket");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  SEXP context;
  int xc;
  nng_ctx *ctx = malloc(sizeof(nng_ctx));
  NANO_ENSURE_ALLOC(ctx);

  if ((xc = nng_ctx_open(ctx, *sock)))
    goto fail;

  PROTECT(context = R_MakeExternalPtr(ctx, nano_ContextSymbol, NANO_PROT(socket)));
  R_RegisterCFinalizerEx(context, context_finalizer, TRUE);

  NANO_CLASS2(context, "nanoContext", "nano");
  Rf_setAttrib(context, nano_IdSymbol, Rf_ScalarInteger(nng_ctx_id(*ctx)));
  Rf_setAttrib(context, nano_StateSymbol, Rf_mkString("opened"));
  Rf_setAttrib(context, nano_ProtocolSymbol, Rf_getAttrib(socket, nano_ProtocolSymbol));
  Rf_setAttrib(context, nano_SocketSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));

  UNPROTECT(1);
  return context;

  fail:
  free(ctx);
  failmem:
  ERROR_OUT(xc);

}

SEXP rnng_ctx_create(SEXP socket) {

  if (NANO_PTR_CHECK(socket, nano_SocketSymbol))
    Rf_error("`socket` is not a valid Socket");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  SEXP context;
  int xc;
  nng_ctx *ctx = malloc(sizeof(nng_ctx));
  NANO_ENSURE_ALLOC(ctx);

  if ((xc = nng_ctx_open(ctx, *sock)))
    goto fail;

  PROTECT(context = R_MakeExternalPtr(ctx, nano_ContextSymbol, NANO_PROT(socket)));
  R_RegisterCFinalizerEx(context, context_finalizer, TRUE);
  UNPROTECT(1);
  return context;

  fail:
  free(ctx);
  failmem:
  ERROR_OUT(xc);

}

SEXP rnng_ctx_close(SEXP context) {

  if (NANO_PTR_CHECK(context, nano_ContextSymbol))
    Rf_error("`context` is not a valid Context");
  nng_ctx *ctx = (nng_ctx *) NANO_PTR(context);

  const int xc = nng_ctx_close(*ctx);
  if (xc)
    ERROR_RET(xc);

  Rf_setAttrib(context, nano_StateSymbol, Rf_mkString("closed"));
  return nano_success;

}

// dialers and listeners -------------------------------------------------------

SEXP rnng_dial(SEXP socket, SEXP url, SEXP tls, SEXP autostart, SEXP fail) {

  if (NANO_PTR_CHECK(socket, nano_SocketSymbol))
    Rf_error("`socket` is not a valid Socket");

  const int sec = tls != R_NilValue;

  if (sec && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  const int failmode = nano_fail_mode(fail);

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  const int start = NANO_INTEGER(autostart);
  const char *ur = CHAR(STRING_ELT(url, 0));

  SEXP dialer, attr, newattr, xp;
  nng_tls_config *cfg = NULL;
  nng_url *up = NULL;
  int xc;

  nng_dialer *dp = malloc(sizeof(nng_dialer));
  NANO_ENSURE_ALLOC(dp);

  if (sec) {
    cfg = (nng_tls_config *) NANO_PTR(tls);
    if ((xc = nng_dialer_create(dp, *sock, ur)) ||
        (xc = nng_url_parse(&up, ur)) ||
        (xc = nng_tls_config_server_name(cfg, up->u_hostname)) ||
        (xc = nng_dialer_set_ptr(*dp, NNG_OPT_TLS_CONFIG, cfg)))
      goto fail;
    nng_url_free(up);
    if (start && (xc = nng_dialer_start(*dp, start == 1 ? NNG_FLAG_NONBLOCK : 0)))
        goto fail;
    nng_tls_config_hold(cfg);

    PROTECT_INDEX pxi;
    PROTECT_WITH_INDEX(xp = R_MakeExternalPtr(cfg, nano_TlsSymbol, R_NilValue), &pxi);
    R_RegisterCFinalizerEx(xp, tls_finalizer, TRUE);
    REPROTECT(dialer = R_MakeExternalPtr(dp, nano_DialerSymbol, xp), pxi);

  } else {

    if ((xc = start ? nng_dial(*sock, ur, dp, start == 1 ? NNG_FLAG_NONBLOCK : 0) : nng_dialer_create(dp, *sock, ur)))
      goto fail;

    PROTECT(dialer = R_MakeExternalPtr(dp, nano_DialerSymbol, R_NilValue));

  }
  R_RegisterCFinalizerEx(dialer, dialer_finalizer, TRUE);

  NANO_CLASS2(dialer, "nanoDialer", "nano");
  Rf_setAttrib(dialer, nano_IdSymbol, Rf_ScalarInteger(nng_dialer_id(*dp)));
  Rf_setAttrib(dialer, nano_UrlSymbol, url);
  Rf_setAttrib(dialer, nano_StateSymbol, Rf_mkString(start ? "started" : "not started"));
  Rf_setAttrib(dialer, nano_SocketSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));

  PROTECT(attr = Rf_getAttrib(socket, nano_DialerSymbol));
  R_xlen_t xlen = Rf_xlength(attr);
  PROTECT(newattr = Rf_allocVector(VECSXP, xlen + 1));
  for (R_xlen_t i = 0; i < xlen; i++) {
    SET_VECTOR_ELT(newattr, i, VECTOR_ELT(attr, i));
  }
  SET_VECTOR_ELT(newattr, xlen, dialer);
  Rf_setAttrib(socket, nano_DialerSymbol, newattr);

  UNPROTECT(3);
  return nano_success;

  fail:
  nng_url_free(up);
  free(dp);
  failmem:
  if (failmode == 2) {
    ERROR_OUT(xc);
  } else if (failmode == 3) {
    return mk_error(xc);
  }
  ERROR_RET(xc);

}

SEXP rnng_listen(SEXP socket, SEXP url, SEXP tls, SEXP autostart, SEXP fail) {

  if (NANO_PTR_CHECK(socket, nano_SocketSymbol))
    Rf_error("`socket` is not a valid Socket");

  const int sec = tls != R_NilValue;

  if (sec && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  const int failmode = nano_fail_mode(fail);

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  const int start = NANO_INTEGER(autostart);
  const char *ur = CHAR(STRING_ELT(url, 0));

  SEXP listener, attr, newattr, xp;
  nng_tls_config *cfg = NULL;
  int xc;

  nng_listener *lp = malloc(sizeof(nng_listener));
  NANO_ENSURE_ALLOC(lp);

  if (sec) {
    cfg = (nng_tls_config *) NANO_PTR(tls);
    if ((xc = nng_listener_create(lp, *sock, ur)) ||
        (xc = nng_listener_set_ptr(*lp, NNG_OPT_TLS_CONFIG, cfg)) ||
        (start && (xc = nng_listener_start(*lp, 0))))
      goto fail;
    nng_tls_config_hold(cfg);

    PROTECT_INDEX pxi;
    PROTECT_WITH_INDEX(xp = R_MakeExternalPtr(cfg, nano_TlsSymbol, R_NilValue), &pxi);
    R_RegisterCFinalizerEx(xp, tls_finalizer, TRUE);
    REPROTECT(listener = R_MakeExternalPtr(lp, nano_ListenerSymbol, xp), pxi);

  } else {

    if ((xc = start ? nng_listen(*sock, ur, lp, 0) : nng_listener_create(lp, *sock, ur)))
      goto fail;

    PROTECT(listener = R_MakeExternalPtr(lp, nano_ListenerSymbol, R_NilValue));

  }

  R_RegisterCFinalizerEx(listener, listener_finalizer, TRUE);

  NANO_CLASS2(listener, "nanoListener", "nano");
  Rf_setAttrib(listener, nano_IdSymbol, Rf_ScalarInteger(nng_listener_id(*lp)));
  if (start) {
    nng_url *up;
    if (nng_url_parse(&up, ur) == 0) {
      if (up->u_port != NULL && up->u_port[0] == '0' && up->u_port[1] == '\0') {
        int port;
        if (nng_listener_get_int(*lp, NNG_OPT_TCP_BOUND_PORT, &port) == 0)
          url = nano_url_with_port(up, port);
      }
      nng_url_free(up);
    }
  }
  Rf_setAttrib(listener, nano_UrlSymbol, url);
  Rf_setAttrib(listener, nano_StateSymbol, Rf_mkString(start ? "started" : "not started"));
  Rf_setAttrib(listener, nano_SocketSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));

  PROTECT(attr = Rf_getAttrib(socket, nano_ListenerSymbol));
  R_xlen_t xlen = Rf_xlength(attr);
  PROTECT(newattr = Rf_allocVector(VECSXP, xlen + 1));
  for (R_xlen_t i = 0; i < xlen; i++) {
    SET_VECTOR_ELT(newattr, i, VECTOR_ELT(attr, i));
  }
  SET_VECTOR_ELT(newattr, xlen, listener);
  Rf_setAttrib(socket, nano_ListenerSymbol, newattr);

  UNPROTECT(3);
  return nano_success;

  fail:
  free(lp);
  failmem:
  if (failmode == 2) {
    ERROR_OUT(xc);
  } else if (failmode == 3) {
    return mk_error(xc);
  }
  ERROR_RET(xc);

}

SEXP rnng_dialer_start(SEXP dialer, SEXP async) {

  if (NANO_PTR_CHECK(dialer, nano_DialerSymbol))
    Rf_error("`dialer` is not a valid Dialer");
  nng_dialer *dial = (nng_dialer *) NANO_PTR(dialer);
  const int flags = (NANO_INTEGER(async) == 1) * NNG_FLAG_NONBLOCK;
  const int xc = nng_dialer_start(*dial, flags);
  if (xc)
    ERROR_RET(xc);

  Rf_setAttrib(dialer, nano_StateSymbol, Rf_mkString("started"));
  return nano_success;

}

SEXP rnng_listener_start(SEXP listener) {

  if (NANO_PTR_CHECK(listener, nano_ListenerSymbol))
    Rf_error("`listener` is not a valid Listener");
  nng_listener *list = (nng_listener *) NANO_PTR(listener);
  const int xc = nng_listener_start(*list, 0);
  if (xc)
    ERROR_RET(xc);

  SEXP url = Rf_getAttrib(listener, nano_UrlSymbol);
  nng_url *up;
  if (nng_url_parse(&up, CHAR(STRING_ELT(url, 0))) == 0) {
    if (up->u_port != NULL && up->u_port[0] == '0' && up->u_port[1] == '\0') {
      int port;
      if (nng_listener_get_int(*list, NNG_OPT_TCP_BOUND_PORT, &port) == 0)
        Rf_setAttrib(listener, nano_UrlSymbol, nano_url_with_port(up, port));
    }
    nng_url_free(up);
  }
  Rf_setAttrib(listener, nano_StateSymbol, Rf_mkString("started"));
  return nano_success;

}

SEXP rnng_dialer_close(SEXP dialer) {

  if (NANO_PTR_CHECK(dialer, nano_DialerSymbol))
    Rf_error("`dialer` is not a valid Dialer");
  nng_dialer *dial = (nng_dialer *) NANO_PTR(dialer);
  const int xc = nng_dialer_close(*dial);
  if (xc)
    ERROR_RET(xc);
  Rf_setAttrib(dialer, nano_StateSymbol, Rf_mkString("closed"));
  return nano_success;

}

SEXP rnng_listener_close(SEXP listener) {

  if (NANO_PTR_CHECK(listener, nano_ListenerSymbol))
    Rf_error("`listener` is not a valid Listener");
  nng_listener *list = (nng_listener *) NANO_PTR(listener);
  const int xc = nng_listener_close(*list);
  if (xc)
    ERROR_RET(xc);
  Rf_setAttrib(listener, nano_StateSymbol, Rf_mkString("closed"));
  return nano_success;

}

// send and recv ---------------------------------------------------------------

SEXP rnng_send(SEXP con, SEXP data, SEXP mode, SEXP block, SEXP pipe) {

  const int flags = block == R_NilValue ? NNG_DURATION_DEFAULT : TYPEOF(block) == LGLSXP ? 0 : nano_integer(block);
  const int raw = nano_encode_mode(mode);
  nano_buf buf;
  int sock, xc;

  if ((sock = !NANO_PTR_CHECK(con, nano_SocketSymbol)) || !NANO_PTR_CHECK(con, nano_ContextSymbol)) {

    const int pipeid = sock ? nano_integer(pipe) : 0;
    if (raw) {
      nano_encode(&buf, data);
    } else {
      nano_serialize(&buf, data, NANO_PROT(con), 0);
    }
    nng_msg *msgp = NULL;

    if (flags <= 0) {

      if ((xc = nng_msg_alloc(&msgp, 0)))
        goto fail;

      if (pipeid) {
        nng_pipe p;
        p.id = (uint32_t) pipeid;
        nng_msg_set_pipe(msgp, p);
      }

      if ((xc = nng_msg_append(msgp, buf.buf, buf.cur)) ||
          (xc = sock ? nng_sendmsg(*(nng_socket *) NANO_PTR(con), msgp, flags ? NNG_FLAG_NONBLOCK : (NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK) :
                       nng_ctx_sendmsg(*(nng_ctx *) NANO_PTR(con), msgp, flags ? NNG_FLAG_NONBLOCK : (NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK))) {
        nng_msg_free(msgp);
        goto fail;
      }

      NANO_FREE(buf);

    } else {

      nng_aio *aiop = NULL;

      if ((xc = nng_msg_alloc(&msgp, 0)))
        goto fail;

      if (pipeid) {
        nng_pipe p;
        p.id = (uint32_t) pipeid;
        nng_msg_set_pipe(msgp, p);
      }

      if ((xc = nng_msg_append(msgp, buf.buf, buf.cur)) ||
          (xc = nng_aio_alloc(&aiop, NULL, NULL))) {
        nng_msg_free(msgp);
        goto fail;
      }

      nng_aio_set_msg(aiop, msgp);
      nng_aio_set_timeout(aiop, flags);
      sock ? nng_send_aio(*(nng_socket *) NANO_PTR(con), aiop) :
             nng_ctx_send(*(nng_ctx *) NANO_PTR(con), aiop);
      NANO_FREE(buf);
      nng_aio_wait(aiop);
      if ((xc = nng_aio_result(aiop)))
        nng_msg_free(nng_aio_get_msg(aiop));
      nng_aio_free(aiop);

    }

  } else if (!NANO_PTR_CHECK(con, nano_StreamSymbol)) {

    nano_encode(&buf, data);

    nano_stream *nst = (nano_stream *) NANO_PTR(con);
    nng_stream *sp = nst->stream;
    nng_aio *aiop = NULL;

    if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
      goto fail;

    if (nst->msgmode) {
      nng_msg *msgp;
      const size_t xlen = buf.cur - nst->textframes;
      if ((xc = nng_msg_alloc(&msgp, xlen))) {
        nng_aio_free(aiop);
        goto fail;
      }
      memcpy(nng_msg_body(msgp), buf.buf, xlen);
      nng_aio_set_msg(aiop, msgp);
    } else {
      nng_iov iov = {
        .iov_buf = buf.buf,
        .iov_len = buf.cur - nst->textframes
      };
      if ((xc = nng_aio_set_iov(aiop, 1u, &iov))) {
        nng_aio_free(aiop);
        goto fail;
      }
    }

    nng_aio_set_timeout(aiop, flags ? flags : (NANO_INTEGER(block) != 0) * NNG_DURATION_DEFAULT);
    nng_stream_send(sp, aiop);
    NANO_FREE(buf);
    nng_aio_wait(aiop);
    if ((xc = nng_aio_result(aiop)) && nst->msgmode)
      nng_msg_free(nng_aio_get_msg(aiop));
    nng_aio_free(aiop);

  } else {
    Rf_error("`con` is not a valid Socket, Context or Stream");
  }

  if (xc)
    return mk_error(xc);

  return nano_success;

  fail:
  NANO_FREE(buf);
  return mk_error(xc);

}

SEXP rnng_recv(SEXP con, SEXP mode, SEXP block, SEXP bytes) {

  const int flags = block == R_NilValue ? NNG_DURATION_DEFAULT : TYPEOF(block) == LGLSXP ? 0 : nano_integer(block);
  int xc;
  unsigned char *buf = NULL;
  size_t sz;
  SEXP res;

  if (!NANO_PTR_CHECK(con, nano_SocketSymbol)) {

    const int mod = nano_matcharg(mode);
    nng_socket *sock = (nng_socket *) NANO_PTR(con);
    nng_msg *msgp = NULL;

    if (flags <= 0) {

      if ((xc = nng_recvmsg(*sock, &msgp, (flags < 0 || NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK)))
        goto fail;
      
    } else {

      nng_aio *aiop = NULL;
      if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
        goto fail;
      nng_aio_set_timeout(aiop, flags);
      nng_recv_aio(*sock, aiop);
      nng_aio_wait(aiop);
      if ((xc = nng_aio_result(aiop))) {
        nng_aio_free(aiop);
        goto fail;
      }
      msgp = nng_aio_get_msg(aiop);
      nng_aio_free(aiop);
    }
    buf = nng_msg_body(msgp);
    sz = nng_msg_len(msgp);
    res = nano_decode(buf, sz, mod, NANO_PROT(con));
    nng_msg_free(msgp);

  } else if (!NANO_PTR_CHECK(con, nano_ContextSymbol)) {

    const int mod = nano_matcharg(mode);
    nng_ctx *ctxp = (nng_ctx *) NANO_PTR(con);
    nng_msg *msgp = NULL;

    if (flags <= 0) {

      if ((xc = nng_ctx_recvmsg(*ctxp, &msgp, (flags < 0 || NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK)))
        goto fail;

      buf = nng_msg_body(msgp);
      sz = nng_msg_len(msgp);
      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      nng_msg_free(msgp);

    } else {

      nng_aio *aiop = NULL;

      if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
        goto fail;
      nng_aio_set_timeout(aiop, flags);
      nng_ctx_recv(*ctxp, aiop);

      nng_aio_wait(aiop);
      if ((xc = nng_aio_result(aiop))) {
        nng_aio_free(aiop);
        goto fail;
      }

      msgp = nng_aio_get_msg(aiop);
      nng_aio_free(aiop);
      buf = nng_msg_body(msgp);
      sz = nng_msg_len(msgp);
      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      nng_msg_free(msgp);

    }

  } else if (!NANO_PTR_CHECK(con, nano_StreamSymbol)) {

    const int mod = nano_matcharg(mode) == 1 ? 2 : nano_matcharg(mode);
    nano_stream *nst = (nano_stream *) NANO_PTR(con);
    nng_stream *sp = nst->stream;
    nng_aio *aiop = NULL;

    if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
      goto fail;

    if (nst->msgmode) {
      nng_msg *msgp;
      nng_aio_set_timeout(aiop, flags ? flags : (NANO_INTEGER(block) != 0) * NNG_DURATION_DEFAULT);
      nng_stream_recv(sp, aiop);
      nng_aio_wait(aiop);
      if ((xc = nng_aio_result(aiop))) {
        nng_aio_free(aiop);
        goto fail;
      }
      msgp = nng_aio_get_msg(aiop);
      nng_aio_free(aiop);
      buf = nng_msg_body(msgp);
      sz = nng_msg_len(msgp);
      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      nng_msg_free(msgp);
    } else {
      const size_t xlen = (size_t) nano_integer(bytes);
      buf = malloc(xlen);
      NANO_ENSURE_ALLOC(buf);
      nng_iov iov = {
        .iov_buf = buf,
        .iov_len = xlen
      };
      if ((xc = nng_aio_set_iov(aiop, 1u, &iov))) {
        nng_aio_free(aiop);
        goto fail;
      }
      nng_aio_set_timeout(aiop, flags ? flags : (NANO_INTEGER(block) != 0) * NNG_DURATION_DEFAULT);
      nng_stream_recv(sp, aiop);
      nng_aio_wait(aiop);
      if ((xc = nng_aio_result(aiop))) {
        nng_aio_free(aiop);
        goto fail;
      }
      sz = nng_aio_count(aiop);
      nng_aio_free(aiop);
      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      free(buf);
    }

  } else {
    Rf_error("`con` is not a valid Socket, Context or Stream");
  }

  return res;

  fail:
  free(buf);
  failmem:
  return mk_error(xc);

}
