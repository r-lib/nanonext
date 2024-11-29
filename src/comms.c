// Copyright (C) 2022-2024 Hibiki AI Limited <info@hibiki-ai.com>
//
// This file is part of nanonext.
//
// nanonext is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// nanonext is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// nanonext. If not, see <https://www.gnu.org/licenses/>.

// nanonext - C level - Communications Functions -------------------------------

#include "nanonext.h"

// finalizers ------------------------------------------------------------------

static void context_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_ctx *xp = (nng_ctx *) NANO_PTR(xptr);
  nng_ctx_close(*xp);
  R_Free(xp);

}

// contexts --------------------------------------------------------------------

SEXP rnng_ctx_open(SEXP socket) {

  if (NANO_TAG(socket) != nano_SocketSymbol)
    Rf_error("'socket' is not a valid Socket");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  nng_ctx *ctx = R_Calloc(1, nng_ctx);
  SEXP context;

  const int xc = nng_ctx_open(ctx, *sock);
  if (xc) {
    R_Free(ctx);
    ERROR_OUT(xc);
  }

  PROTECT(context = R_MakeExternalPtr(ctx, nano_ContextSymbol, NANO_PROT(socket)));
  R_RegisterCFinalizerEx(context, context_finalizer, TRUE);

  NANO_CLASS2(context, "nanoContext", "nano");
  Rf_setAttrib(context, nano_IdSymbol, Rf_ScalarInteger(nng_ctx_id(*ctx)));
  Rf_setAttrib(context, nano_StateSymbol, Rf_mkString("opened"));
  Rf_setAttrib(context, nano_ProtocolSymbol, Rf_getAttrib(socket, nano_ProtocolSymbol));
  Rf_setAttrib(context, nano_SocketSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));

  UNPROTECT(1);
  return context;

}

SEXP rnng_ctx_create(SEXP socket) {

  if (NANO_TAG(socket) != nano_SocketSymbol)
    Rf_error("'socket' is not a valid Socket");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  nng_ctx *ctx = R_Calloc(1, nng_ctx);
  SEXP context;

  const int xc = nng_ctx_open(ctx, *sock);
  if (xc) {
    R_Free(ctx);
    ERROR_OUT(xc);
  }

  PROTECT(context = R_MakeExternalPtr(ctx, nano_ContextSymbol, NANO_PROT(socket)));
  R_RegisterCFinalizerEx(context, context_finalizer, TRUE);
  UNPROTECT(1);
  return context;

}

SEXP rnng_ctx_close(SEXP context) {

  if (NANO_TAG(context) != nano_ContextSymbol)
    Rf_error("'context' is not a valid Context");
  nng_ctx *ctx = (nng_ctx *) NANO_PTR(context);

  const int xc = nng_ctx_close(*ctx);
  if (xc)
    ERROR_RET(xc);

  Rf_setAttrib(context, nano_StateSymbol, Rf_mkString("closed"));
  return nano_success;

}

// dialers and listeners -------------------------------------------------------

SEXP rnng_dial(SEXP socket, SEXP url, SEXP tls, SEXP autostart, SEXP error) {

  if (NANO_TAG(socket) != nano_SocketSymbol)
    Rf_error("'socket' is not a valid Socket");

  const uint8_t sec = tls != R_NilValue;

  if (sec && NANO_TAG(tls) != nano_TlsSymbol)
    Rf_error("'tls' is not a valid TLS Configuration");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  const int start = NANO_INTEGER(autostart);
  const char *ur = CHAR(STRING_ELT(url, 0));
  nng_dialer *dp = R_Calloc(1, nng_dialer);
  SEXP dialer, attr, newattr, xp;
  nng_tls_config *cfg;
  nng_url *up;
  int xc;

  if (sec) {
    if ((xc = nng_dialer_create(dp, *sock, ur)) ||
        (xc = nng_url_parse(&up, ur)))
      goto exitlevel1;
    cfg = (nng_tls_config *) NANO_PTR(tls);
    if ((xc = nng_tls_config_server_name(cfg, up->u_hostname)) ||
        (xc = nng_dialer_set_ptr(*dp, NNG_OPT_TLS_CONFIG, cfg)))
      goto exitlevel2;
    nng_url_free(up);
    if (start && (xc = nng_dialer_start(*dp, start == 1 ? NNG_FLAG_NONBLOCK : 0)))
        goto exitlevel1;
    nng_tls_config_hold(cfg);

    PROTECT_INDEX pxi;
    PROTECT_WITH_INDEX(xp = R_MakeExternalPtr(cfg, nano_TlsSymbol, R_NilValue), &pxi);
    R_RegisterCFinalizerEx(xp, tls_finalizer, TRUE);
    REPROTECT(dialer = R_MakeExternalPtr(dp, nano_DialerSymbol, xp), pxi);

  } else {

    if ((xc = start ? nng_dial(*sock, ur, dp, start == 1 ? NNG_FLAG_NONBLOCK : 0) : nng_dialer_create(dp, *sock, ur)))
      goto exitlevel1;

    PROTECT(dialer = R_MakeExternalPtr(dp, nano_DialerSymbol, R_NilValue));

  }
  R_RegisterCFinalizerEx(dialer, dialer_finalizer, TRUE);

  NANO_CLASS2(dialer, "nanoDialer", "nano");
  Rf_setAttrib(dialer, nano_IdSymbol, Rf_ScalarInteger(nng_dialer_id(*dp)));
  Rf_setAttrib(dialer, nano_UrlSymbol, url);
  Rf_setAttrib(dialer, nano_StateSymbol, Rf_mkString(start ? "started" : "not started"));
  Rf_setAttrib(dialer, nano_SocketSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));

  attr = Rf_getAttrib(socket, nano_DialerSymbol);
  R_xlen_t xlen = Rf_xlength(attr);
  PROTECT(newattr = Rf_allocVector(VECSXP, xlen + 1));
  for (R_xlen_t i = 0; i < xlen; i++) {
    SET_VECTOR_ELT(newattr, i, VECTOR_ELT(attr, i));
  }
  SET_VECTOR_ELT(newattr, xlen, dialer);
  Rf_setAttrib(socket, nano_DialerSymbol, newattr);

  UNPROTECT(2);
  return nano_success;

  exitlevel2:
  nng_url_free(up);
  exitlevel1:
  R_Free(dp);
  if (NANO_INTEGER(error)) ERROR_OUT(xc);
  ERROR_RET(xc);

}

SEXP rnng_listen(SEXP socket, SEXP url, SEXP tls, SEXP autostart, SEXP error) {

  if (NANO_TAG(socket) != nano_SocketSymbol)
    Rf_error("'socket' is not a valid Socket");

  const uint8_t sec = tls != R_NilValue;

  if (sec && NANO_TAG(tls) != nano_TlsSymbol)
    Rf_error("'tls' is not a valid TLS Configuration");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  const int start = NANO_INTEGER(autostart);
  const char *ur = CHAR(STRING_ELT(url, 0));
  nng_listener *lp = R_Calloc(1, nng_listener);
  SEXP listener, attr, newattr, xp;
  nng_tls_config *cfg;
  nng_url *up;
  int xc;

  if (sec) {
    if ((xc = nng_listener_create(lp, *sock, ur)) ||
        (xc = nng_url_parse(&up, ur)))
      goto exitlevel1;
    cfg = (nng_tls_config *) NANO_PTR(tls);
    if ((xc = nng_tls_config_server_name(cfg, up->u_hostname)) ||
        (xc = nng_listener_set_ptr(*lp, NNG_OPT_TLS_CONFIG, cfg)))
      goto exitlevel2;
    nng_url_free(up);
    if (start && (xc = nng_listener_start(*lp, 0)))
      goto exitlevel1;
    nng_tls_config_hold(cfg);

    PROTECT_INDEX pxi;
    PROTECT_WITH_INDEX(xp = R_MakeExternalPtr(cfg, nano_TlsSymbol, R_NilValue), &pxi);
    R_RegisterCFinalizerEx(xp, tls_finalizer, TRUE);
    REPROTECT(listener = R_MakeExternalPtr(lp, nano_ListenerSymbol, xp), pxi);

  } else {

    if ((xc = start ? nng_listen(*sock, ur, lp, 0) : nng_listener_create(lp, *sock, ur)))
      goto exitlevel1;

    PROTECT(listener = R_MakeExternalPtr(lp, nano_ListenerSymbol, R_NilValue));

  }

  R_RegisterCFinalizerEx(listener, listener_finalizer, TRUE);

  NANO_CLASS2(listener, "nanoListener", "nano");
  Rf_setAttrib(listener, nano_IdSymbol, Rf_ScalarInteger(nng_listener_id(*lp)));
  Rf_setAttrib(listener, nano_UrlSymbol, url);
  Rf_setAttrib(listener, nano_StateSymbol, Rf_mkString(start ? "started" : "not started"));
  Rf_setAttrib(listener, nano_SocketSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));

  attr = Rf_getAttrib(socket, nano_ListenerSymbol);
  R_xlen_t xlen = Rf_xlength(attr);
  PROTECT(newattr = Rf_allocVector(VECSXP, xlen + 1));
  for (R_xlen_t i = 0; i < xlen; i++) {
    SET_VECTOR_ELT(newattr, i, VECTOR_ELT(attr, i));
  }
  SET_VECTOR_ELT(newattr, xlen, listener);
  Rf_setAttrib(socket, nano_ListenerSymbol, newattr);

  UNPROTECT(2);
  return nano_success;

  exitlevel2:
  nng_url_free(up);
  exitlevel1:
  R_Free(lp);
  if (NANO_INTEGER(error)) ERROR_OUT(xc);
  ERROR_RET(xc);

}

SEXP rnng_dialer_start(SEXP dialer, SEXP async) {

  if (NANO_TAG(dialer) != nano_DialerSymbol)
    Rf_error("'dialer' is not a valid Dialer");
  nng_dialer *dial = (nng_dialer *) NANO_PTR(dialer);
  const int flags = (NANO_INTEGER(async) == 1) * NNG_FLAG_NONBLOCK;
  const int xc = nng_dialer_start(*dial, flags);
  if (xc)
    ERROR_RET(xc);

  Rf_setAttrib(dialer, nano_StateSymbol, Rf_mkString("started"));
  return nano_success;

}

SEXP rnng_listener_start(SEXP listener) {

  if (NANO_TAG(listener) != nano_ListenerSymbol)
    Rf_error("'listener' is not a valid Listener");
  nng_listener *list = (nng_listener *) NANO_PTR(listener);
  const int xc = nng_listener_start(*list, 0);
  if (xc)
    ERROR_RET(xc);

  Rf_setAttrib(listener, nano_StateSymbol, Rf_mkString("started"));
  return nano_success;

}

SEXP rnng_dialer_close(SEXP dialer) {

  if (NANO_TAG(dialer) != nano_DialerSymbol)
    Rf_error("'dialer' is not a valid Dialer");
  nng_dialer *dial = (nng_dialer *) NANO_PTR(dialer);
  const int xc = nng_dialer_close(*dial);
  if (xc)
    ERROR_RET(xc);
  Rf_setAttrib(dialer, nano_StateSymbol, Rf_mkString("closed"));
  return nano_success;

}

SEXP rnng_listener_close(SEXP listener) {

  if (NANO_TAG(listener) != nano_ListenerSymbol)
    Rf_error("'listener' is not a valid Listener");
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
  nano_buf buf;
  int sock, xc;

  const SEXP ptrtag = NANO_TAG(con);
  if ((sock = ptrtag == nano_SocketSymbol) || ptrtag == nano_ContextSymbol) {

    const int pipeid = nano_integer(pipe);
    nano_encodes(mode) == 2 ? nano_encode(&buf, data) : nano_serialize(&buf, data, NANO_PROT(con));
    nng_msg *msgp;

    if (flags <= 0) {

      if ((xc = nng_msg_alloc(&msgp, 0)))
        goto exitlevel1;

      if (pipeid) {
        nng_pipe p;
        p.id = (uint32_t) pipeid;
        nng_msg_set_pipe(msgp, p);
      }

      if ((xc = nng_msg_append(msgp, buf.buf, buf.cur)) ||
          (xc = sock ? nng_sendmsg(*(nng_socket *) NANO_PTR(con), msgp, flags ? NNG_FLAG_NONBLOCK : (NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK) :
                       nng_ctx_sendmsg(*(nng_ctx *) NANO_PTR(con), msgp, flags ? NNG_FLAG_NONBLOCK : (NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK))) {
        nng_msg_free(msgp);
        goto exitlevel1;
      }

      NANO_FREE(buf);

    } else {

      nng_aio *aiop;

      if ((xc = nng_msg_alloc(&msgp, 0)))
        goto exitlevel1;

      if (pipeid) {
        nng_pipe p;
        p.id = (uint32_t) pipeid;
        nng_msg_set_pipe(msgp, p);
      }

      if ((xc = nng_msg_append(msgp, buf.buf, buf.cur)) ||
          (xc = nng_aio_alloc(&aiop, NULL, NULL))) {
        nng_msg_free(msgp);
        goto exitlevel1;
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

  } else if (ptrtag == nano_StreamSymbol) {

    nano_encode(&buf, data);

    nano_stream *nst = (nano_stream *) NANO_PTR(con);
    nng_stream *sp = nst->stream;
    nng_aio *aiop;
    nng_iov iov;

    iov.iov_len = buf.cur - nst->textframes;
    iov.iov_buf = buf.buf;

    if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
      goto exitlevel1;

    if ((xc = nng_aio_set_iov(aiop, 1u, &iov))) {
      nng_aio_free(aiop);
      goto exitlevel1;
    }

    nng_aio_set_timeout(aiop, flags ? flags : (NANO_INTEGER(block) != 0) * NNG_DURATION_DEFAULT);
    nng_stream_send(sp, aiop);
    NANO_FREE(buf);
    nng_aio_wait(aiop);
    xc = nng_aio_result(aiop);
    nng_aio_free(aiop);

  } else {
    Rf_error("'con' is not a valid Socket, Context or Stream");
  }

  if (xc)
    return mk_error(xc);

  return nano_success;

  exitlevel1:
  NANO_FREE(buf);
  return mk_error(xc);

}

SEXP rnng_recv(SEXP con, SEXP mode, SEXP block, SEXP bytes) {

  const int flags = block == R_NilValue ? NNG_DURATION_DEFAULT : TYPEOF(block) == LGLSXP ? 0 : nano_integer(block);
  int xc;
  unsigned char *buf;
  size_t sz;
  SEXP res;

  const SEXP ptrtag = NANO_TAG(con);
  if (ptrtag == nano_SocketSymbol) {

    const int mod = nano_matcharg(mode);
    nng_socket *sock = (nng_socket *) NANO_PTR(con);

    if (flags <= 0) {

      xc = nng_recv(*sock, &buf, &sz, NNG_FLAG_ALLOC + (flags < 0 || NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK);
      if (xc)
        goto exitlevel1;

      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      nng_free(buf, sz);

    } else {

      nng_aio *aiop;
      if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
        goto exitlevel1;
      nng_aio_set_timeout(aiop, flags);
      nng_recv_aio(*sock, aiop);
      nng_aio_wait(aiop);
      if ((xc = nng_aio_result(aiop))) {
        nng_aio_free(aiop);
        goto exitlevel1;
      }
      nng_msg *msgp = nng_aio_get_msg(aiop);
      nng_aio_free(aiop);
      buf = nng_msg_body(msgp);
      sz = nng_msg_len(msgp);
      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      nng_msg_free(msgp);
    }

  } else if (ptrtag == nano_ContextSymbol) {

    const int mod = nano_matcharg(mode);
    nng_ctx *ctxp = (nng_ctx *) NANO_PTR(con);
    nng_msg *msgp;

    if (flags <= 0) {

      xc = nng_ctx_recvmsg(*ctxp, &msgp, (flags < 0 || NANO_INTEGER(block) != 1) * NNG_FLAG_NONBLOCK);
      if (xc)
        goto exitlevel1;

      buf = nng_msg_body(msgp);
      sz = nng_msg_len(msgp);
      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      nng_msg_free(msgp);

    } else {

      nng_aio *aiop;

      if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
        goto exitlevel1;
      nng_aio_set_timeout(aiop, flags);
      nng_ctx_recv(*ctxp, aiop);

      nng_aio_wait(aiop);
      if ((xc = nng_aio_result(aiop))) {
        nng_aio_free(aiop);
        goto exitlevel1;
      }

      msgp = nng_aio_get_msg(aiop);
      nng_aio_free(aiop);
      buf = nng_msg_body(msgp);
      sz = nng_msg_len(msgp);
      res = nano_decode(buf, sz, mod, NANO_PROT(con));
      nng_msg_free(msgp);

    }

  } else if (ptrtag == nano_StreamSymbol) {

    const int mod = nano_matchargs(mode);
    const size_t xlen = (size_t) nano_integer(bytes);
    nng_stream **sp = (nng_stream **) NANO_PTR(con);
    nng_iov iov;
    nng_aio *aiop;

    buf = R_Calloc(xlen, unsigned char);
    iov.iov_len = xlen;
    iov.iov_buf = buf;

    if ((xc = nng_aio_alloc(&aiop, NULL, NULL)))
      goto exitlevel2;

    if ((xc = nng_aio_set_iov(aiop, 1u, &iov))) {
      nng_aio_free(aiop);
      goto exitlevel2;
    }

    nng_aio_set_timeout(aiop, flags ? flags : (NANO_INTEGER(block) != 0) * NNG_DURATION_DEFAULT);
    nng_stream_recv(*sp, aiop);

    nng_aio_wait(aiop);
    if ((xc = nng_aio_result(aiop))) {
      nng_aio_free(aiop);
      goto exitlevel2;
    }

    sz = nng_aio_count(aiop);
    nng_aio_free(aiop);
    res = nano_decode(buf, sz, mod, NANO_PROT(con));
    R_Free(buf);

  } else {
    Rf_error("'con' is not a valid Socket, Context or Stream");
  }

  return res;

  exitlevel2:
  R_Free(buf);
  exitlevel1:
  return mk_error(xc);

}
