// nanonext - C level - Socket and Stream Constructors -------------------------

#define NANONEXT_PROTOCOLS
#include "nanonext.h"

// finalizers ------------------------------------------------------------------

static void stream_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_stream *xp = (nano_stream *) NANO_PTR(xptr);
  nng_stream_close(xp->stream);
  nng_stream_free(xp->stream);
  if (xp->mode == NANO_STREAM_LISTENER) {
    nng_stream_listener_close(xp->endpoint.list);
    nng_stream_listener_free(xp->endpoint.list);
  } else {
    nng_stream_dialer_close(xp->endpoint.dial);
    nng_stream_dialer_free(xp->endpoint.dial);
  }
  if (xp->tls != NULL)
    nng_tls_config_free(xp->tls);
  free(xp);

}

// sockets ---------------------------------------------------------------------

SEXP rnng_protocol_open(SEXP protocol, SEXP dial, SEXP listen, SEXP tls, SEXP autostart, SEXP raw) {

  const char *pro = CHAR(STRING_ELT(protocol, 0));
  const int rw = NANO_INTEGER(raw);
  size_t slen = strlen(pro);

  const char *pname;
  int xc;
  SEXP socket;

  nng_socket *sock = malloc(sizeof(nng_socket));
  NANO_ENSURE_ALLOC(sock);

  switch (slen) {
  case 1:
  case 2:
  case 3:
    if (!memcmp(pro, "bus", slen)) {
      pname = "bus";
      xc = rw ? nng_bus0_open_raw(sock) : nng_bus0_open(sock);
      break;
    }
    if (slen > 2) {
      if (!memcmp(pro, "pub", slen)) {
        pname = "pub";
        xc = rw ? nng_pub0_open_raw(sock) : nng_pub0_open(sock);
        break;
      }
      if (!memcmp(pro, "sub", slen)) {
        pname = "sub";
        xc = rw ? nng_sub0_open_raw(sock) : nng_sub0_open(sock);
        break;
      }
      if (!memcmp(pro, "req", slen)) {
        pname = "req";
        xc = rw ? nng_req0_open_raw(sock) : nng_req0_open(sock);
        break;
      }
      if (!memcmp(pro, "rep", slen)) {
        pname = "rep";
        xc = rw ? nng_rep0_open_raw(sock) : nng_rep0_open(sock);
        break;
      }
    }
  case 4:
    if (slen > 1) {
      if (!memcmp(pro, "pair", slen)) {
        pname = "pair";
        xc = rw ? nng_pair0_open_raw(sock) : nng_pair0_open(sock);
        break;
      }
      if (!memcmp(pro, "poly", slen)) {
        pname = "poly";
        xc = rw ? nng_pair1_open_raw(sock) : nng_pair1_open_poly(sock);
        break;
      }
      if (slen > 2) {
        if (!memcmp(pro, "push", slen)) {
          pname = "push";
          xc = rw ? nng_push0_open_raw(sock) : nng_push0_open(sock);
          break;
        }
        if (!memcmp(pro, "pull", slen)) {
          pname = "pull";
          xc = rw ? nng_pull0_open_raw(sock) : nng_pull0_open(sock);
          break;
        }
      }
    }
  case 5:
  case 6:
  case 7:
  case 8:
    if (slen > 2 && !memcmp(pro, "surveyor", slen)) {
      pname = "surveyor";
      xc = rw ? nng_surveyor0_open_raw(sock) : nng_surveyor0_open(sock);
      break;
    }
  case 9:
  case 10:
    if (slen > 2 && !memcmp(pro, "respondent", slen)) {
      pname = "respondent";
      xc = rw ? nng_respondent0_open_raw(sock) : nng_respondent0_open(sock);
      break;
    }
  default:
    free(sock);
    NANO_ERROR("'protocol' should be one of bus, pair, poly, push, pull, pub, sub, req, rep, surveyor, respondent");
  }

  if (xc) {
    free(sock);
    ERROR_OUT(xc);
  }

  PROTECT(socket = R_MakeExternalPtr(sock, nano_SocketSymbol, R_NilValue));
  R_RegisterCFinalizerEx(socket, socket_finalizer, TRUE);

  NANO_CLASS2(socket, "nanoSocket", "nano");
  Rf_setAttrib(socket, nano_IdSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));
  Rf_setAttrib(socket, nano_ProtocolSymbol, Rf_mkString(pname));
  Rf_setAttrib(socket, nano_StateSymbol, Rf_mkString("opened"));

  if (dial != R_NilValue)
    rnng_dial(socket, dial, tls, autostart, Rf_ScalarLogical(1));

  if (listen != R_NilValue)
    rnng_listen(socket, listen, tls, autostart, Rf_ScalarLogical(1));

  UNPROTECT(1);
  return socket;

}

SEXP rnng_close(SEXP socket) {

  if (NANO_PTR_CHECK(socket, nano_SocketSymbol))
    Rf_error("'socket' is not a valid Socket");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  const int xc = nng_close(*sock);
  if (xc)
    ERROR_RET(xc);

  Rf_setAttrib(socket, nano_StateSymbol, Rf_mkString("closed"));
  return nano_success;

}

SEXP rnng_reap(SEXP con) {

  int xc;

  if (!NANO_PTR_CHECK(con, nano_ContextSymbol)) {
    xc = nng_ctx_close(*(nng_ctx *) NANO_PTR(con));

  } else if (!NANO_PTR_CHECK(con, nano_SocketSymbol)) {
    xc = nng_close(*(nng_socket *) NANO_PTR(con));

  } else if (!NANO_PTR_CHECK(con, nano_ListenerSymbol)) {
    xc = nng_listener_close(*(nng_listener *) NANO_PTR(con));

  } else if (!NANO_PTR_CHECK(con, nano_DialerSymbol)) {
    xc = nng_dialer_close(*(nng_dialer *) NANO_PTR(con));

  } else {
    xc = 3;
  }

  if (xc)
    return mk_error(xc);

  return nano_success;

}

// streams ---------------------------------------------------------------------

static SEXP nano_stream_dial(SEXP url, SEXP textframes, SEXP tls) {

  const char *add = CHAR(STRING_ELT(url, 0));
  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("'tls' is not a valid TLS Configuration");
  nano_stream *nst = calloc(1, sizeof(nano_stream));
  NANO_ENSURE_ALLOC(nst);
  nst->mode = NANO_STREAM_DIALER;
  nst->textframes = NANO_INTEGER(textframes) != 0;
  nng_url *up;
  nng_aio *aiop;
  int xc;
  SEXP sd;

  if ((xc = nng_url_parse(&up, add)))
    goto exitlevel1;

  xc = nng_stream_dialer_alloc_url(&nst->endpoint.dial, up);
  if (xc)
    goto exitlevel2;

  if (!strcmp(up->u_scheme, "ws") || !strcmp(up->u_scheme, "wss")) {
    if (nst->textframes &&
        ((xc = nng_stream_dialer_set_bool(nst->endpoint.dial, "ws:recv-text", 1)) ||
        (xc = nng_stream_dialer_set_bool(nst->endpoint.dial, "ws:send-text", 1))))
      goto exitlevel3;
  }

  if (!strcmp(up->u_scheme, "wss")) {

    if (tls == R_NilValue) {
      if ((xc = nng_tls_config_alloc(&nst->tls, NNG_TLS_MODE_CLIENT)))
        goto exitlevel3;

      if ((xc = nng_tls_config_server_name(nst->tls, up->u_hostname)) ||
          (xc = nng_tls_config_auth_mode(nst->tls, NNG_TLS_AUTH_MODE_NONE)) ||
          (xc = nng_stream_dialer_set_ptr(nst->endpoint.dial, NNG_OPT_TLS_CONFIG, nst->tls)))
        goto exitlevel4;
    } else {

      nst->tls = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(nst->tls);

      if ((xc = nng_tls_config_server_name(nst->tls, up->u_hostname)) ||
          (xc = nng_stream_dialer_set_ptr(nst->endpoint.dial, NNG_OPT_TLS_CONFIG, nst->tls)))
        goto exitlevel4;
    }

  }

  if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
    goto exitlevel4;

  nng_stream_dialer_dial(nst->endpoint.dial, aiop);
  nng_aio_wait(aiop);
  if ((xc = nng_aio_result(aiop)))
    goto exitlevel5;

  nst->stream = nng_aio_get_output(aiop, 0);

  nng_aio_free(aiop);
  nng_url_free(up);

  PROTECT(sd = R_MakeExternalPtr(nst, nano_StreamSymbol, R_NilValue));
  R_RegisterCFinalizerEx(sd, stream_finalizer, TRUE);

  NANO_CLASS2(sd, "nanoStream", "nano");
  Rf_setAttrib(sd, R_ModeSymbol, Rf_mkString(nst->textframes ? "dialer text frames" : "dialer"));
  Rf_setAttrib(sd, nano_StateSymbol, Rf_mkString("opened"));
  Rf_setAttrib(sd, nano_UrlSymbol, url);

  UNPROTECT(1);
  return sd;

  exitlevel5:
  nng_aio_free(aiop);
  exitlevel4:
  if (nst->tls != NULL)
    nng_tls_config_free(nst->tls);
  exitlevel3:
  nng_stream_dialer_free(nst->endpoint.dial);
  exitlevel2:
  nng_url_free(up);
  exitlevel1:
  free(nst);
  ERROR_OUT(xc);

}

static SEXP nano_stream_listen(SEXP url, SEXP textframes, SEXP tls) {

  const char *add = CHAR(STRING_ELT(url, 0));
  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("'tls' is not a valid TLS Configuration");
  nano_stream *nst = calloc(1, sizeof(nano_stream));
  NANO_ENSURE_ALLOC(nst);
  nst->mode = NANO_STREAM_LISTENER;
  nst->textframes = NANO_INTEGER(textframes) != 0;
  nng_url *up;
  nng_aio *aiop;
  int xc;
  SEXP sl;

  if ((xc = nng_url_parse(&up, add)))
    goto exitlevel1;

  xc = nng_stream_listener_alloc_url(&nst->endpoint.list, up);
  if (xc)
    goto exitlevel2;

  if (!strcmp(up->u_scheme, "ws") || !strcmp(up->u_scheme, "wss")) {
    if (nst->textframes &&
        ((xc = nng_stream_listener_set_bool(nst->endpoint.list, "ws:recv-text", 1)) ||
        (xc = nng_stream_listener_set_bool(nst->endpoint.list, "ws:send-text", 1))))
      goto exitlevel3;
  }

  if (!strcmp(up->u_scheme, "wss")) {

    if (tls == R_NilValue) {
      if ((xc = nng_tls_config_alloc(&nst->tls, NNG_TLS_MODE_SERVER)))
        goto exitlevel3;

      if ((xc = nng_tls_config_auth_mode(nst->tls, NNG_TLS_AUTH_MODE_NONE)) ||
          (xc = nng_stream_listener_set_ptr(nst->endpoint.list, NNG_OPT_TLS_CONFIG, nst->tls)))
        goto exitlevel4;
    } else {

      nst->tls = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(nst->tls);

      if ((xc = nng_tls_config_server_name(nst->tls, up->u_hostname)) ||
          (xc = nng_stream_listener_set_ptr(nst->endpoint.list, NNG_OPT_TLS_CONFIG, nst->tls)))
        goto exitlevel4;
    }

  }

  if ((xc = nng_stream_listener_listen(nst->endpoint.list)))
    goto exitlevel4;

  if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
    goto exitlevel4;

  nng_stream_listener_accept(nst->endpoint.list, aiop);
  nng_aio_wait(aiop);
  if ((xc = nng_aio_result(aiop)))
    goto exitlevel5;

  nst->stream = nng_aio_get_output(aiop, 0);

  nng_aio_free(aiop);
  nng_url_free(up);

  PROTECT(sl = R_MakeExternalPtr(nst, nano_StreamSymbol, R_NilValue));
  R_RegisterCFinalizerEx(sl, stream_finalizer, TRUE);

  NANO_CLASS2(sl, "nanoStream", "nano");
  Rf_setAttrib(sl, R_ModeSymbol, Rf_mkString(nst->textframes ? "listener text frames" : "listener"));
  Rf_setAttrib(sl, nano_StateSymbol, Rf_mkString("opened"));
  Rf_setAttrib(sl, nano_UrlSymbol, url);

  UNPROTECT(1);
  return sl;

  exitlevel5:
  nng_aio_free(aiop);
  exitlevel4:
  if (nst->tls != NULL)
    nng_tls_config_free(nst->tls);
  exitlevel3:
  nng_stream_listener_free(nst->endpoint.list);
  exitlevel2:
  nng_url_free(up);
  exitlevel1:
  free(nst);
  ERROR_OUT(xc);

}

SEXP rnng_stream_open(SEXP dial, SEXP listen, SEXP textframes, SEXP tls) {

  if (dial != R_NilValue) {
    return nano_stream_dial(dial, textframes, tls);
  } else if (listen != R_NilValue) {
    return nano_stream_listen(listen, textframes, tls);
  } else {
    NANO_ERROR("specify a URL for either 'dial' or 'listen'");
  }

}

SEXP rnng_stream_close(SEXP stream) {

  if (NANO_PTR_CHECK(stream, nano_StreamSymbol))
    Rf_error("'stream' is not a valid Stream");

  stream_finalizer(stream);
  R_ClearExternalPtr(stream);
  Rf_setAttrib(stream, nano_StateSymbol, Rf_mkString("closed"));

  return nano_success;

}
