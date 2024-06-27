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

// nanonext - C level - Async Functions ----------------------------------------

#define NANONEXT_SUPPLEMENTALS
#define NANONEXT_SIGNALS
#include "nanonext.h"

// R backports -----------------------------------------------------------------

#if R_VERSION < R_Version(4, 5, 0)

static inline SEXP R_mkClosure(SEXP formals, SEXP body, SEXP env) {
  SEXP fun = Rf_allocSExp(CLOSXP);
  SET_FORMALS(fun, formals);
  SET_BODY(fun, body);
  SET_CLOENV(fun, env);
  return fun;
}

#endif

inline int nano_integer(SEXP x) {
  int out;
  switch (TYPEOF(x)) {
  case INTSXP:
  case LGLSXP:
    out = NANO_INTEGER(x);
    break;
  default:
    out = Rf_asInteger(x);
  }
  return out;
}

// internals -------------------------------------------------------------------

static SEXP mk_error_aio(const int xc, SEXP env) {

  SEXP err = PROTECT(Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(nano_AioSymbol, R_NilValue, env);
  UNPROTECT(1);
  return err;

}

static SEXP mk_error_data(const int xc) {

  SEXP env, err;
  PROTECT(env = Rf_allocSExp(ENVSXP));
  Rf_classgets(env, xc < 0 ? nano_sendAio : nano_recvAio);
  PROTECT(err = Rf_ScalarInteger(abs(xc)));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(xc < 0 ? nano_ResultSymbol : nano_DataSymbol, err, env);
  UNPROTECT(2);
  return env;

}

static SEXP mk_error_haio(const int xc, SEXP env) {

  SEXP err = PROTECT(Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ResultSymbol, err, env);
  Rf_defineVar(nano_ProtocolSymbol, err, env);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(nano_AioSymbol, R_NilValue, env);
  UNPROTECT(1);
  return err;

}

static SEXP mk_error_ncurlaio(const int xc) {

  SEXP env, err;
  PROTECT(env = Rf_allocSExp(ENVSXP));
  NANO_CLASS2(env, "ncurlAio", "recvAio");
  PROTECT(err = Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ResultSymbol, err, env);
  Rf_defineVar(nano_StatusSymbol, err, env);
  Rf_defineVar(nano_ProtocolSymbol, err, env);
  Rf_defineVar(nano_HeadersSymbol, err, env);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(nano_DataSymbol, err, env);
  UNPROTECT(2);
  return env;

}

// aio completion callbacks ----------------------------------------------------

static void pipe_cb_signal(nng_pipe p, nng_pipe_ev ev, void *arg) {

  int sig;
  nano_cv *ncv = (nano_cv *) arg;
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  nng_mtx_lock(mtx);
  sig = ncv->flag;
  if (sig > 0) ncv->flag = -1;
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);
  if (sig > 1) {
#ifdef _WIN32
    raise(sig);
#else
    kill(getpid(), sig);
#endif

  }

}

static void pipe_cb_signal_duo(nng_pipe p, nng_pipe_ev ev, void *arg) {

  int sig;
  nano_cv_duo *duo = (nano_cv_duo *) arg;
  nano_cv *ncv = duo->cv;
  nano_cv *ncv2 = duo->cv2;

  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;
  nng_cv *cv2 = ncv2->cv;
  nng_mtx *mtx2 = ncv2->mtx;

  nng_mtx_lock(mtx);
  sig = ncv->flag;
  if (sig > 0) ncv->flag = -1;
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);
  nng_mtx_lock(mtx2);
  if (sig > 0) ncv2->flag = -1;
  ncv2->condition++;
  nng_cv_wake(cv2);
  nng_mtx_unlock(mtx2);
  if (sig > 1) {
#ifdef _WIN32
    raise(sig);
#else
    kill(getpid(), sig);
#endif
  }

}

static void pipe_cb_dropcon(nng_pipe p, nng_pipe_ev ev, void *arg) {

  if (arg != NULL) {
    nano_cv *ncv = (nano_cv *) arg;
    nng_mtx *mtx = ncv->mtx;
    int cond;
    nng_mtx_lock(mtx);
    if ((cond = ncv->condition % 2))
      ncv->condition--;
    nng_mtx_unlock(mtx);
    if (cond)
      nng_pipe_close(p);
  } else {
    nng_pipe_close(p);
  }

}

static void saio_complete(void *arg) {

  nano_aio *saio = (nano_aio *) arg;
  const int res = nng_aio_result(saio->aio);
  if (res)
    nng_msg_free(nng_aio_get_msg(saio->aio));
  saio->result = res - !res;

}

static void sendaio_complete(void *arg) {

  nng_aio *aio = (nng_aio *) arg;
  if (nng_aio_result(aio))
    nng_msg_free(nng_aio_get_msg(aio));

}

static void isaio_complete(void *arg) {

  nano_aio *iaio = (nano_aio *) arg;
  const int res = nng_aio_result(iaio->aio);
  if (iaio->data != NULL)
    R_Free(iaio->data);
  iaio->result = res - !res;

}

static void raio_complete(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  const int res = nng_aio_result(raio->aio);
  if (res == 0)
    raio->data = nng_aio_get_msg(raio->aio);

  raio->result = res - !res;

}

static void raio_complete_signal(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  nano_cv *ncv = (nano_cv *) raio->next;
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  const int res = nng_aio_result(raio->aio);
  if (res == 0)
    raio->data = nng_aio_get_msg(raio->aio);

  nng_mtx_lock(mtx);
  raio->result = res - !res;
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);

}

static void raio_invoke_cb(void *arg) {

  SEXP call, context, data, ctx = TAG((SEXP) arg);
  context = Rf_findVarInFrame(ctx, nano_ContextSymbol);
  if (context == R_UnboundValue) return;
  PROTECT(context);
  data = rnng_aio_get_msg(context);
  PROTECT(call = Rf_lcons(nano_ResolveSymbol, Rf_cons(data, R_NilValue)));
  Rf_eval(call, ctx);
  UNPROTECT(2);
}

static void request_complete(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  nano_aio *saio = (nano_aio *) raio->next;
  const int res = nng_aio_result(raio->aio);
  if (res == 0)
    raio->data = nng_aio_get_msg(raio->aio);
  raio->result = res - !res;

  if (saio->data != NULL)
    later2(raio_invoke_cb, saio->data);

}

static void request_complete_dropcon(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  nano_aio *saio = (nano_aio *) raio->next;
  const int res = nng_aio_result(raio->aio);
  if (res == 0) {
    nng_msg *msg = nng_aio_get_msg(raio->aio);
    raio->data = msg;
    nng_pipe_close(nng_msg_get_pipe(msg));
  }

  raio->result = res - !res;

  if (saio->data != NULL)
    later2(raio_invoke_cb, saio->data);

}

static void request_complete_signal(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  nano_aio *saio = (nano_aio *) raio->next;
  nano_cv *ncv = (nano_cv *) saio->next;
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  const int res = nng_aio_result(raio->aio);
  if (res == 0)
    raio->data = nng_aio_get_msg(raio->aio);

  nng_mtx_lock(mtx);
  raio->result = res - !res;
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);

  if (saio->data != NULL)
    later2(raio_invoke_cb, saio->data);

}

static void haio_invoke_cb(void *arg) {

  SEXP call, context, status, ctx = TAG((SEXP) arg);
  context = Rf_findVarInFrame(ctx, nano_ContextSymbol);
  if (context == R_UnboundValue) return;
  PROTECT(context);
  status = rnng_aio_http_status(context);
  PROTECT(call = Rf_lcons(nano_ResolveSymbol, Rf_cons(status, R_NilValue)));
  Rf_eval(call, ctx);
  UNPROTECT(2);
}

static void haio_complete(void *arg) {

  nano_aio *haio = (nano_aio *) arg;
  const int res = nng_aio_result(haio->aio);
  haio->result = res - !res;

  if (haio->data != NULL)
    later2(haio_invoke_cb, haio->data);

}

static void iraio_complete(void *arg) {

  nano_aio *iaio = (nano_aio *) arg;
  const int res = nng_aio_result(iaio->aio);
  iaio->result = res - !res;

}

static void iraio_complete_signal(void *arg) {

  nano_aio *iaio = (nano_aio *) arg;
  nano_cv *ncv = (nano_cv *) iaio->next;
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  const int res = nng_aio_result(iaio->aio);

  nng_mtx_lock(mtx);
  iaio->result = res - !res;
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);

}

// finalisers ------------------------------------------------------------------

static void saio_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nng_aio_free(xp->aio);
  R_Free(xp);

}

static void raio_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nng_aio_free(xp->aio);
  if (xp->data != NULL)
    nng_msg_free((nng_msg *) xp->data);
  R_Free(xp);

}

static void request_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nano_aio *saio = (nano_aio *) xp->next;
  nng_aio_free(saio->aio);
  nng_aio_free(xp->aio);
  if (xp->data != NULL)
    nng_msg_free((nng_msg *) xp->data);
  if (saio->data != NULL)
    nano_ReleaseObject((SEXP) saio->data);
  R_Free(saio);
  R_Free(xp);

}

static void cv_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_cv *xp = (nano_cv *) NANO_PTR(xptr);
  nng_cv_free(xp->cv);
  nng_mtx_free(xp->mtx);
  R_Free(xp);

}

static void cv_duo_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_cv_duo *xp = (nano_cv_duo *) NANO_PTR(xptr);
  R_Free(xp);

}

static void iaio_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nng_aio_free(xp->aio);
  if (xp->data != NULL)
    R_Free(xp->data);
  R_Free(xp);

}

static void haio_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nano_handle *handle = (nano_handle *) xp->next;
  nng_aio_free(xp->aio);
  if (xp->data != NULL)
    nano_ReleaseObject((SEXP) xp->data);
  if (handle->cfg != NULL)
    nng_tls_config_free(handle->cfg);
  nng_http_res_free(handle->res);
  nng_http_req_free(handle->req);
  nng_http_client_free(handle->cli);
  nng_url_free(handle->url);
  R_Free(handle);
  R_Free(xp);

}

static void session_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_http_conn *xp = (nng_http_conn *) NANO_PTR(xptr);
  nng_http_conn_close(xp);

}

// core aio --------------------------------------------------------------------

SEXP rnng_aio_result(SEXP env) {

  const SEXP exist = Rf_findVarInFrame(env, nano_ValueSymbol);
  if (exist != R_UnboundValue)
    return exist;

  const SEXP aio = Rf_findVarInFrame(env, nano_AioSymbol);

  nano_aio *saio = (nano_aio *) NANO_PTR(aio);

  if (nng_aio_busy(saio->aio))
    return nano_unresolved;

  if (saio->result > 0)
    return mk_error_aio(saio->result, env);

  Rf_defineVar(nano_ValueSymbol, nano_success, env);
  Rf_defineVar(nano_AioSymbol, R_NilValue, env);
  return nano_success;

}

SEXP rnng_aio_get_msg(SEXP env) {

  const SEXP exist = Rf_findVarInFrame(env, nano_ValueSymbol);
  if (exist != R_UnboundValue)
    return exist;

  const SEXP aio = Rf_findVarInFrame(env, nano_AioSymbol);

  nano_aio *raio = (nano_aio *) NANO_PTR(aio);

  int res;
  switch (raio->type) {
  case RECVAIO:
  case REQAIO:
  case IOV_RECVAIO:
    if (nng_aio_busy(raio->aio))
      return nano_unresolved;

    res = raio->result;
    if (res > 0)
      return mk_error_aio(res, env);

    break;
  case RECVAIOS:
  case REQAIOS:
  case IOV_RECVAIOS: ;
    nano_cv *ncv;
    if (raio->type == REQAIOS) {
      nano_aio *saio = (nano_aio *) raio->next;
      ncv = (nano_cv *) saio->next;
    } else {
      ncv = (nano_cv *) raio->next;
    }

    nng_mtx *mtx = ncv->mtx;
    nng_mtx_lock(mtx);
    res = raio->result;
    nng_mtx_unlock(mtx);

    if (res == 0)
      return nano_unresolved;

    if (res > 0)
      return mk_error_aio(res, env);

    break;
  default:
    break;
  }

  SEXP out;
  unsigned char *buf;
  size_t sz;

  if (raio->type == IOV_RECVAIO || raio->type == IOV_RECVAIOS) {
    buf = raio->data;
    sz = nng_aio_count(raio->aio);
  } else {
    nng_msg *msg = (nng_msg *) raio->data;
    buf = nng_msg_body(msg);
    sz = nng_msg_len(msg);
  }

  PROTECT(out = nano_decode(buf, sz, raio->mode));
  Rf_defineVar(nano_ValueSymbol, out, env);
  Rf_defineVar(nano_AioSymbol, R_NilValue, env);

  UNPROTECT(1);
  return out;

}

SEXP rnng_aio_call(SEXP x) {

  switch (TYPEOF(x)) {
  case ENVSXP: ;
    const SEXP coreaio = Rf_findVarInFrame(x, nano_AioSymbol);
    if (NANO_TAG(coreaio) != nano_AioSymbol)
      return x;

    nano_aio *aiop = (nano_aio *) NANO_PTR(coreaio);
    nng_aio_wait(aiop->aio);
    switch (aiop->type) {
    case RECVAIO:
    case REQAIO:
    case IOV_RECVAIO:
    case RECVAIOS:
    case REQAIOS:
    case IOV_RECVAIOS:
      rnng_aio_get_msg(x);
      break;
    case SENDAIO:
    case IOV_SENDAIO:
      rnng_aio_result(x);
      break;
    case HTTP_AIO:
      rnng_aio_http_status(x);
      break;
    }
    break;
  case VECSXP: ;
    const R_xlen_t xlen = Rf_xlength(x);
    for (R_xlen_t i = 0; i < xlen; i++) {
      rnng_aio_call(NANO_VECTOR(x)[i]);
    }
    break;
  }

  return x;

}

static SEXP rnng_aio_collect_impl(SEXP x, SEXP (*const func)(SEXP)) {

  SEXP out;

  switch (TYPEOF(x)) {
  case ENVSXP: ;
    out = Rf_findVarInFrame(func(x), nano_ValueSymbol);
    if (out == R_UnboundValue) break;
    goto resume;
  case VECSXP: ;
    SEXP env;
    const R_xlen_t xlen = Rf_xlength(x);
    PROTECT(out = Rf_allocVector(VECSXP, xlen));
    for (R_xlen_t i = 0; i < xlen; i++) {
      env = func(NANO_VECTOR(x)[i]);
      if (TYPEOF(env) != ENVSXP) goto exit;
      env = Rf_findVarInFrame(env, nano_ValueSymbol);
      if (env == R_UnboundValue) goto exit;
      SET_VECTOR_ELT(out, i, env);
    }
    out = Rf_namesgets(out, Rf_getAttrib(x, R_NamesSymbol));
    UNPROTECT(1);
    goto resume;
  }

  exit:
  Rf_error("object is not an Aio or list of Aios");

  resume:
  return out;

}

SEXP rnng_aio_collect(SEXP x) {

  return rnng_aio_collect_impl(x, rnng_aio_call);

}

SEXP rnng_aio_collect_safe(SEXP x) {

  return rnng_aio_collect_impl(x, rnng_wait_thread_create);

}

SEXP rnng_aio_stop(SEXP x) {

  switch (TYPEOF(x)) {
  case ENVSXP: ;
    const SEXP coreaio = Rf_findVarInFrame(x, nano_AioSymbol);
    if (NANO_TAG(coreaio) != nano_AioSymbol) break;
    nano_aio *aiop = (nano_aio *) NANO_PTR(coreaio);
    nng_aio_stop(aiop->aio);
    break;
  case VECSXP: ;
    const R_xlen_t xlen = Rf_xlength(x);
    for (R_xlen_t i = 0; i < xlen; i++) {
      rnng_aio_stop(NANO_VECTOR(x)[i]);
    }
    break;
  }

  return R_NilValue;

}

static int rnng_unresolved_impl(SEXP x) {

  int xc;
  switch (TYPEOF(x)) {
  case ENVSXP: ;
    const SEXP coreaio = Rf_findVarInFrame(x, nano_AioSymbol);
    if (NANO_TAG(coreaio) != nano_AioSymbol) {
      xc = 0; break;
    }
    SEXP value;
    nano_aio *aio = (nano_aio *) NANO_PTR(coreaio);
    switch (aio->type) {
    case SENDAIO:
    case IOV_SENDAIO:
      value = rnng_aio_result(x);
      break;
    case HTTP_AIO:
      value = rnng_aio_http_status(x);
      break;
    default:
      value = rnng_aio_get_msg(x);
    break;
    }
    xc = value == nano_unresolved;
    break;
  case LGLSXP:
    xc = x == nano_unresolved;
    break;
  default:
    xc = 0;
  }

  return xc;

}

SEXP rnng_unresolved(SEXP x) {

  switch (TYPEOF(x)) {
  case ENVSXP:
  case LGLSXP:
    return Rf_ScalarLogical(rnng_unresolved_impl(x));
  case VECSXP: ;
    const R_xlen_t xlen = Rf_xlength(x);
    for (R_xlen_t i = 0; i < xlen; i++) {
      if (rnng_unresolved_impl(NANO_VECTOR(x)[i]))
        return Rf_ScalarLogical(1);
    }
  }

  return Rf_ScalarLogical(0);

}

static int rnng_unresolved2_impl(SEXP x) {

  if (TYPEOF(x) == ENVSXP) {
    const SEXP coreaio = Rf_findVarInFrame(x, nano_AioSymbol);
    if (NANO_TAG(coreaio) != nano_AioSymbol)
      return 0;
    nano_aio *aiop = (nano_aio *) NANO_PTR(coreaio);
    return nng_aio_busy(aiop->aio);
  }

  return 0;

}

SEXP rnng_unresolved2(SEXP x) {

  switch (TYPEOF(x)) {
  case ENVSXP:
    return Rf_ScalarLogical(rnng_unresolved2_impl(x));
  case VECSXP: ;
    int xc = 0;
    const R_xlen_t xlen = Rf_xlength(x);
    for (R_xlen_t i = 0; i < xlen; i++) {
      xc += rnng_unresolved2_impl(NANO_VECTOR(x)[i]);
    }
    return Rf_ScalarInteger(xc);
  }

  return Rf_ScalarLogical(0);

}

// send recv aio functions -----------------------------------------------------

SEXP rnng_send_aio(SEXP con, SEXP data, SEXP mode, SEXP timeout, SEXP clo) {

  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  nano_aio *saio;
  SEXP aio;
  nano_buf buf;
  int sock, xc;

  const SEXP ptrtag = NANO_TAG(con);
  if ((sock = ptrtag == nano_SocketSymbol) || ptrtag == nano_ContextSymbol) {

    switch (nano_encodes(mode)) {
    case 1:
      nano_serialize(&buf, data); break;
    case 2:
      nano_encode(&buf, data); break;
    default:
      nano_serialize_next(&buf, data); break;
    }

    nng_msg *msg;
    saio = R_Calloc(1, nano_aio);
    saio->type = SENDAIO;

    if ((xc = nng_msg_alloc(&msg, 0)))
      goto exitlevel1;

    if ((xc = nng_msg_append(msg, buf.buf, buf.cur)) ||
        (xc = nng_aio_alloc(&saio->aio, saio_complete, saio))) {
      nng_msg_free(msg);
      goto exitlevel1;
    }

    nng_aio_set_msg(saio->aio, msg);
    nng_aio_set_timeout(saio->aio, dur);
    sock ? nng_send_aio(*(nng_socket *) NANO_PTR(con), saio->aio) :
           nng_ctx_send(*(nng_ctx *) NANO_PTR(con), saio->aio);
    NANO_FREE(buf);

    PROTECT(aio = R_MakeExternalPtr(saio, nano_AioSymbol, R_NilValue));
    R_RegisterCFinalizerEx(aio, saio_finalizer, TRUE);

  } else if (ptrtag == nano_StreamSymbol) {

    nano_encode(&buf, data);

    nano_stream *nst = (nano_stream *) NANO_PTR(con);
    nng_stream *sp = nst->stream;
    nng_iov iov;

    saio = R_Calloc(1, nano_aio);
    saio->type = IOV_SENDAIO;
    saio->data = R_Calloc(buf.cur, unsigned char);
    memcpy(saio->data, buf.buf, buf.cur);
    iov.iov_len = buf.cur - nst->textframes;
    iov.iov_buf = saio->data;

    if ((xc = nng_aio_alloc(&saio->aio, isaio_complete, saio)))
      goto exitlevel2;

    if ((xc = nng_aio_set_iov(saio->aio, 1u, &iov)))
      goto exitlevel3;

    nng_aio_set_timeout(saio->aio, dur);
    nng_stream_send(sp, saio->aio);
    NANO_FREE(buf);

    PROTECT(aio = R_MakeExternalPtr(saio, nano_AioSymbol, R_NilValue));
    R_RegisterCFinalizerEx(aio, iaio_finalizer, TRUE);

  } else {
    NANO_ERROR("'con' is not a valid Socket, Context or Stream");
  }

  SEXP env, fun;
  PROTECT(env = Rf_allocSExp(ENVSXP));
  Rf_classgets(env, nano_sendAio);
  Rf_defineVar(nano_AioSymbol, aio, env);

  PROTECT(fun = R_mkClosure(R_NilValue, nano_aioFuncRes, clo));
  R_MakeActiveBinding(nano_ResultSymbol, fun, env);

  UNPROTECT(3);
  return env;

  exitlevel3:
  nng_aio_free(saio->aio);
  exitlevel2:
  R_Free(saio->data);
  exitlevel1:
  R_Free(saio);
  NANO_FREE(buf);
  return mk_error_data(-xc);

}

SEXP rnng_recv_aio(SEXP con, SEXP mode, SEXP timeout, SEXP cvar, SEXP bytes, SEXP clo) {

  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  const int signal = NANO_TAG(cvar) == nano_CvSymbol;
  nano_cv *ncv = signal ? (nano_cv *) NANO_PTR(cvar) : NULL;
  nano_aio *raio;
  SEXP aio;
  int mod, sock, xc;

  const SEXP ptrtag = NANO_TAG(con);
  if ((sock = ptrtag == nano_SocketSymbol) || ptrtag == nano_ContextSymbol) {

    mod = nano_matcharg(mode);
    raio = R_Calloc(1, nano_aio);
    raio->next = ncv;
    raio->type = signal ? RECVAIOS : RECVAIO;
    raio->mode = mod;

    if ((xc = nng_aio_alloc(&raio->aio, signal ? raio_complete_signal : raio_complete, raio)))
      goto exitlevel1;

    nng_aio_set_timeout(raio->aio, dur);
    sock ? nng_recv_aio(*(nng_socket *) NANO_PTR(con), raio->aio) :
      nng_ctx_recv(*(nng_ctx *) NANO_PTR(con), raio->aio);

    PROTECT(aio = R_MakeExternalPtr(raio, nano_AioSymbol, R_NilValue));
    R_RegisterCFinalizerEx(aio, raio_finalizer, TRUE);

  } else if (ptrtag == nano_StreamSymbol) {

    mod = nano_matchargs(mode);
    const size_t xlen = (size_t) nano_integer(bytes);
    nng_stream **sp = (nng_stream **) NANO_PTR(con);
    nng_iov iov;

    raio = R_Calloc(1, nano_aio);
    raio->next = ncv;
    raio->type = signal ? IOV_RECVAIOS : IOV_RECVAIO;
    raio->mode = mod;
    raio->data = R_Calloc(xlen, unsigned char);
    iov.iov_len = xlen;
    iov.iov_buf = raio->data;

    if ((xc = nng_aio_alloc(&raio->aio, signal ? iraio_complete_signal : iraio_complete, raio)))
      goto exitlevel2;

    if ((xc = nng_aio_set_iov(raio->aio, 1u, &iov)))
      goto exitlevel3;

    nng_aio_set_timeout(raio->aio, dur);
    nng_stream_recv(*sp, raio->aio);

    PROTECT(aio = R_MakeExternalPtr(raio, nano_AioSymbol, R_NilValue));
    R_RegisterCFinalizerEx(aio, iaio_finalizer, TRUE);

  } else {
    NANO_ERROR("'con' is not a valid Socket, Context or Stream");
  }

  SEXP env, fun;
  PROTECT(env = Rf_allocSExp(ENVSXP));
  Rf_classgets(env, nano_recvAio);
  Rf_defineVar(nano_AioSymbol, aio, env);

  PROTECT(fun = R_mkClosure(R_NilValue, nano_aioFuncMsg, clo));
  R_MakeActiveBinding(nano_DataSymbol, fun, env);

  UNPROTECT(3);
  return env;

  exitlevel3:
  nng_aio_free(raio->aio);
  exitlevel2:
  R_Free(raio->data);
  exitlevel1:
  R_Free(raio);
  return mk_error_data(xc);

}

// ncurl aio -------------------------------------------------------------------

SEXP rnng_ncurl_aio(SEXP http, SEXP convert, SEXP method, SEXP headers, SEXP data,
                    SEXP response, SEXP timeout, SEXP tls, SEXP clo) {

  const char *httr = NANO_STRING(http);
  const char *mthd = method != R_NilValue ? NANO_STRING(method) : NULL;
  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  if (tls != R_NilValue && NANO_TAG(tls) != nano_TlsSymbol)
    Rf_error("'tls' is not a valid TLS Configuration");
  nano_aio *haio = R_Calloc(1, nano_aio);
  nano_handle *handle = R_Calloc(1, nano_handle);
  int xc;
  SEXP aio;

  haio->type = HTTP_AIO;
  haio->mode = NANO_INTEGER(convert);
  haio->next = handle;
  haio->data = NULL;
  handle->cfg = NULL;

  if ((xc = nng_url_parse(&handle->url, httr)))
    goto exitlevel1;
  if ((xc = nng_http_client_alloc(&handle->cli, handle->url)))
    goto exitlevel2;
  if ((xc = nng_http_req_alloc(&handle->req, handle->url)))
    goto exitlevel3;
  if (mthd != NULL && (xc = nng_http_req_set_method(handle->req, mthd)))
    goto exitlevel4;
  if (headers != R_NilValue && TYPEOF(headers) == STRSXP) {
    const R_xlen_t hlen = XLENGTH(headers);
    SEXP hnames = Rf_getAttrib(headers, R_NamesSymbol);
    if (TYPEOF(hnames) == STRSXP && XLENGTH(hnames) == hlen) {
      for (R_xlen_t i = 0; i < hlen; i++) {
        if ((xc = nng_http_req_set_header(handle->req,
                                          CHAR(STRING_ELT(hnames, i)),
                                          CHAR(STRING_ELT(headers, i)))))
          goto exitlevel4;
      }
    }
  }
  if (data != R_NilValue && TYPEOF(data) == STRSXP) {
    nano_buf enc = nano_char_buf(data);
    if ((xc = nng_http_req_set_data(handle->req, enc.buf, enc.cur)))
      goto exitlevel4;
  }

  if ((xc = nng_http_res_alloc(&handle->res)))
    goto exitlevel4;

  if ((xc = nng_aio_alloc(&haio->aio, haio_complete, haio)))
    goto exitlevel5;

  if (!strcmp(handle->url->u_scheme, "https")) {

    if (tls == R_NilValue) {
      if ((xc = nng_tls_config_alloc(&handle->cfg, NNG_TLS_MODE_CLIENT)))
        goto exitlevel6;

      if ((xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_tls_config_auth_mode(handle->cfg, NNG_TLS_AUTH_MODE_NONE)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto exitlevel7;

    } else {

      handle->cfg = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(handle->cfg);

      if ((xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto exitlevel7;
    }

  }

  nng_aio_set_timeout(haio->aio, dur);
  nng_http_client_transact(handle->cli, handle->req, handle->res, haio->aio);

  PROTECT(aio = R_MakeExternalPtr(haio, nano_AioSymbol, R_NilValue));
  R_RegisterCFinalizerEx(aio, haio_finalizer, TRUE);

  SEXP env, fun;
  PROTECT(env = Rf_allocSExp(ENVSXP));
  NANO_CLASS2(env, "ncurlAio", "recvAio");
  Rf_defineVar(nano_AioSymbol, aio, env);
  Rf_defineVar(nano_ResponseSymbol, response, env);

  int i = 0;
  for (SEXP fnlist = nano_aioNFuncs; fnlist != R_NilValue; fnlist = CDR(fnlist)) {
    PROTECT(fun = R_mkClosure(R_NilValue, CAR(fnlist), clo));
    switch (++i) {
    case 1: R_MakeActiveBinding(nano_StatusSymbol, fun, env);
    case 2: R_MakeActiveBinding(nano_HeadersSymbol, fun, env);
    case 3: R_MakeActiveBinding(nano_DataSymbol, fun, env);
    }
    UNPROTECT(1);
  }

  UNPROTECT(2);
  return env;

  exitlevel7:
  nng_tls_config_free(handle->cfg);
  exitlevel6:
  nng_aio_free(haio->aio);
  exitlevel5:
  nng_http_res_free(handle->res);
  exitlevel4:
  nng_http_req_free(handle->req);
  exitlevel3:
  nng_http_client_free(handle->cli);
  exitlevel2:
  nng_url_free(handle->url);
  exitlevel1:
  R_Free(handle);
  R_Free(haio);
  return mk_error_ncurlaio(xc);

}

static SEXP rnng_aio_http_impl(SEXP env, const int typ) {

  SEXP exist;
  switch (typ) {
  case 0: exist = Rf_findVarInFrame(env, nano_ResultSymbol); break;
  case 1: exist = Rf_findVarInFrame(env, nano_ProtocolSymbol); break;
  default: exist = Rf_findVarInFrame(env, nano_ValueSymbol); break;
  }
  if (exist != R_UnboundValue)
    return exist;

  const SEXP aio = Rf_findVarInFrame(env, nano_AioSymbol);

  nano_aio *haio = (nano_aio *) NANO_PTR(aio);

  if (nng_aio_busy(haio->aio))
    return nano_unresolved;

  if (haio->result > 0)
    return mk_error_haio(haio->result, env);

  void *dat;
  size_t sz;
  SEXP out, vec, rvec, response;
  nano_handle *handle = (nano_handle *) haio->next;

  PROTECT(response = Rf_findVarInFrame(env, nano_ResponseSymbol));
  int chk_resp = response != R_NilValue && TYPEOF(response) == STRSXP;
  const uint16_t code = nng_http_res_get_status(handle->res), relo = code >= 300 && code < 400;
  Rf_defineVar(nano_ResultSymbol, Rf_ScalarInteger(code), env);

  if (relo) {
    if (chk_resp) {
      const R_xlen_t rlen = XLENGTH(response);
      PROTECT(response = Rf_xlengthgets(response, rlen + 1));
      SET_STRING_ELT(response, rlen, Rf_mkChar("Location"));
    } else {
      PROTECT(response = Rf_mkString("Location"));
      chk_resp = 1;
    }
  }

  if (chk_resp) {
    const R_xlen_t rlen = XLENGTH(response);
    PROTECT(rvec = Rf_allocVector(VECSXP, rlen));
    Rf_namesgets(rvec, response);
    for (R_xlen_t i = 0; i < rlen; i++) {
      const char *r = nng_http_res_get_header(handle->res, CHAR(STRING_ELT(response, i)));
      SET_VECTOR_ELT(rvec, i, r == NULL ? R_NilValue : Rf_mkString(r));
    }
    UNPROTECT(1);
  } else {
    rvec = R_NilValue;
  }
  if (relo) UNPROTECT(1);
  UNPROTECT(1);
  Rf_defineVar(nano_ProtocolSymbol, rvec, env);

  nng_http_res_get_data(handle->res, &dat, &sz);

  if (haio->mode) {
    vec = rawToChar(dat, sz);
  } else {
    vec = Rf_allocVector(RAWSXP, sz);
    if (dat != NULL)
      memcpy(NANO_DATAPTR(vec), dat, sz);
  }
  Rf_defineVar(nano_ValueSymbol, vec, env);

  Rf_defineVar(nano_AioSymbol, R_NilValue, env);

  switch (typ) {
  case 0: out = Rf_findVarInFrame(env, nano_ResultSymbol); break;
  case 1: out = Rf_findVarInFrame(env, nano_ProtocolSymbol); break;
  default: out = Rf_findVarInFrame(env, nano_ValueSymbol); break;
  }
  return out;

}

SEXP rnng_aio_http_status(SEXP env) {
  return rnng_aio_http_impl(env, 0);
}

SEXP rnng_aio_http_headers(SEXP env) {
  return rnng_aio_http_impl(env, 1);
}

SEXP rnng_aio_http_data(SEXP env) {
  return rnng_aio_http_impl(env, 2);
}

// ncurl session ---------------------------------------------------------------

SEXP rnng_ncurl_session(SEXP http, SEXP convert, SEXP method, SEXP headers, SEXP data,
                        SEXP response, SEXP timeout, SEXP tls) {

  const char *httr = NANO_STRING(http);
  const char *mthd = method != R_NilValue ? NANO_STRING(method) : NULL;
  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  if (tls != R_NilValue && NANO_TAG(tls) != nano_TlsSymbol)
    Rf_error("'tls' is not a valid TLS Configuration");

  nano_aio *haio = R_Calloc(1, nano_aio);
  nano_handle *handle = R_Calloc(1, nano_handle);
  int xc;
  SEXP sess, aio;

  haio->type = HTTP_AIO;
  haio->mode = NANO_INTEGER(convert);
  haio->next = handle;
  haio->data = NULL;
  handle->cfg = NULL;

  if ((xc = nng_url_parse(&handle->url, httr)))
    goto exitlevel1;
  if ((xc = nng_http_client_alloc(&handle->cli, handle->url)))
    goto exitlevel2;
  if ((xc = nng_http_req_alloc(&handle->req, handle->url)))
    goto exitlevel3;
  if (mthd != NULL && (xc = nng_http_req_set_method(handle->req, mthd)))
    goto exitlevel4;
  if (headers != R_NilValue && TYPEOF(headers) == STRSXP) {
    const R_xlen_t hlen = XLENGTH(headers);
    SEXP hnames = Rf_getAttrib(headers, R_NamesSymbol);
    if (TYPEOF(hnames) == STRSXP && XLENGTH(hnames) == hlen) {
      for (R_xlen_t i = 0; i < hlen; i++) {
        if ((xc = nng_http_req_set_header(handle->req,
                                          CHAR(STRING_ELT(hnames, i)),
                                          CHAR(STRING_ELT(headers, i)))))
          goto exitlevel4;
      }
    }
  }
  if (data != R_NilValue && TYPEOF(data) == STRSXP) {
    nano_buf enc = nano_char_buf(data);
    if ((xc = nng_http_req_set_data(handle->req, enc.buf, enc.cur)))
      goto exitlevel4;
  }

  if ((xc = nng_http_res_alloc(&handle->res)))
    goto exitlevel4;

  if ((xc = nng_aio_alloc(&haio->aio, haio_complete, haio)))
    goto exitlevel5;

  if (!strcmp(handle->url->u_scheme, "https")) {

    if (tls == R_NilValue) {
      if ((xc = nng_tls_config_alloc(&handle->cfg, NNG_TLS_MODE_CLIENT)))
        goto exitlevel6;

      if ((xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_tls_config_auth_mode(handle->cfg, NNG_TLS_AUTH_MODE_NONE)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto exitlevel7;

    } else {

      handle->cfg = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(handle->cfg);

      if ((xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto exitlevel7;
    }

  }

  nng_aio_set_timeout(haio->aio, dur);
  nng_http_client_connect(handle->cli, haio->aio);
  nng_aio_wait(haio->aio);
  if ((xc = haio->result) > 0)
    goto exitlevel7;

  nng_http_conn *conn;
  conn = nng_aio_get_output(haio->aio, 0);

  PROTECT(sess = R_MakeExternalPtr(conn, nano_StatusSymbol, (response != R_NilValue && TYPEOF(response) == STRSXP) ? response : R_NilValue));
  R_RegisterCFinalizerEx(sess, session_finalizer, TRUE);
  Rf_classgets(sess, Rf_mkString("ncurlSession"));

  PROTECT(aio = R_MakeExternalPtr(haio, nano_AioSymbol, R_NilValue));
  R_RegisterCFinalizerEx(aio, haio_finalizer, TRUE);
  Rf_setAttrib(sess, nano_AioSymbol, aio);

  UNPROTECT(2);
  return sess;

  exitlevel7:
  if (handle->cfg != NULL)
    nng_tls_config_free(handle->cfg);
  exitlevel6:
  nng_aio_free(haio->aio);
  exitlevel5:
  nng_http_res_free(handle->res);
  exitlevel4:
  nng_http_req_free(handle->req);
  exitlevel3:
  nng_http_client_free(handle->cli);
  exitlevel2:
  nng_url_free(handle->url);
  exitlevel1:
  R_Free(handle);
  R_Free(haio);
  ERROR_RET(xc);

}

SEXP rnng_ncurl_transact(SEXP session) {

  if (NANO_TAG(session) != nano_StatusSymbol)
    Rf_error("'session' is not a valid or active ncurlSession");

  nng_http_conn *conn = (nng_http_conn *) NANO_PTR(session);
  SEXP aio = Rf_getAttrib(session, nano_AioSymbol);
  nano_aio *haio = (nano_aio *) NANO_PTR(aio);
  nano_handle *handle = (nano_handle *) haio->next;

  nng_http_conn_transact(conn, handle->req, handle->res, haio->aio);
  nng_aio_wait(haio->aio);
  if (haio->result > 0)
    return mk_error_ncurlaio(haio->result);

  SEXP out, vec, rvec, response;
  void *dat;
  size_t sz;
  const char *names[] = {"status", "headers", "data", ""};

  PROTECT(out = Rf_mkNamed(VECSXP, names));

  const uint16_t code = nng_http_res_get_status(handle->res);
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(code));

  response = NANO_PROT(session);
  if (response != R_NilValue) {
    const R_xlen_t rlen = XLENGTH(response);
    rvec = Rf_allocVector(VECSXP, rlen);
    SET_VECTOR_ELT(out, 1, rvec);
    Rf_namesgets(rvec, response);
    for (R_xlen_t i = 0; i < rlen; i++) {
      const char *r = nng_http_res_get_header(handle->res, CHAR(STRING_ELT(response, i)));
      SET_VECTOR_ELT(rvec, i, r == NULL ? R_NilValue : Rf_mkString(r));
    }
  } else {
    rvec = R_NilValue;
    SET_VECTOR_ELT(out, 1, rvec);
  }

  nng_http_res_get_data(handle->res, &dat, &sz);

  if (haio->mode) {
    vec = rawToChar(dat, sz);
  } else {
    vec = Rf_allocVector(RAWSXP, sz);
    if (dat != NULL)
      memcpy(NANO_DATAPTR(vec), dat, sz);
  }
  SET_VECTOR_ELT(out, 2, vec);

  UNPROTECT(1);
  return out;

}

SEXP rnng_ncurl_session_close(SEXP session) {

  if (NANO_TAG(session) != nano_StatusSymbol)
    Rf_error("'session' is not a valid or active ncurlSession");

  nng_http_conn *sp = (nng_http_conn *) NANO_PTR(session);
  nng_http_conn_close(sp);
  NANO_SET_TAG(session, R_NilValue);
  NANO_SET_PROT(session, R_NilValue);
  R_ClearExternalPtr(session);
  Rf_setAttrib(session, nano_AioSymbol, R_NilValue);

  return nano_success;

}

// request ---------------------------------------------------------------------

SEXP rnng_request(SEXP con, SEXP data, SEXP sendmode, SEXP recvmode, SEXP timeout, SEXP cvar, SEXP clo) {

  if (NANO_TAG(con) != nano_ContextSymbol)
    Rf_error("'con' is not a valid Context");

  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  const int mod = nano_matcharg(recvmode);
  int signal, drop;
  if (cvar == R_NilValue) {
    signal = 0;
    drop = 0;
  } else {
    signal = NANO_TAG(cvar) == nano_CvSymbol;
    drop = 1 - signal;
  }
  nng_ctx *ctx = (nng_ctx *) NANO_PTR(con);
  nano_cv *ncv = signal ? (nano_cv *) NANO_PTR(cvar) : NULL;

  SEXP aio, env, fun;
  nano_buf buf;
  nano_aio *saio, *raio;
  nng_msg *msg;
  int xc;

  switch (nano_encodes(sendmode)) {
  case 1:
    nano_serialize(&buf, data); break;
  case 2:
    nano_encode(&buf, data); break;
  default:
    nano_serialize_next(&buf, data); break;
  }

  saio = R_Calloc(1, nano_aio);
  saio->data = NULL;
  saio->next = ncv;

  if ((xc = nng_msg_alloc(&msg, 0)))
    goto exitlevel1;

  if ((xc = nng_msg_append(msg, buf.buf, buf.cur)) ||
      (xc = nng_aio_alloc(&saio->aio, sendaio_complete, &saio->aio))) {
    nng_msg_free(msg);
    goto exitlevel1;
  }

  nng_aio_set_msg(saio->aio, msg);
  nng_ctx_send(*ctx, saio->aio);

  raio = R_Calloc(1, nano_aio);
  raio->type = signal ? REQAIOS : REQAIO;
  raio->mode = mod;
  raio->next = saio;

  if ((xc = nng_aio_alloc(&raio->aio, signal ? request_complete_signal : drop ? request_complete_dropcon : request_complete, raio)))
    goto exitlevel2;

  nng_aio_set_timeout(raio->aio, dur);
  nng_ctx_recv(*ctx, raio->aio);
  NANO_FREE(buf);

  PROTECT(aio = R_MakeExternalPtr(raio, nano_AioSymbol, R_NilValue));
  R_RegisterCFinalizerEx(aio, request_finalizer, TRUE);

  PROTECT(env = Rf_allocSExp(ENVSXP));
  Rf_classgets(env, nano_reqAio);
  Rf_defineVar(nano_AioSymbol, aio, env);

  PROTECT(fun = R_mkClosure(R_NilValue, nano_aioFuncMsg, clo));
  R_MakeActiveBinding(nano_DataSymbol, fun, env);

  UNPROTECT(3);
  return env;

  exitlevel2:
    R_Free(raio);
  nng_aio_free(saio->aio);
  exitlevel1:
    R_Free(saio);
  NANO_FREE(buf);
  return mk_error_data(xc);

}

SEXP rnng_set_promise_context(SEXP x, SEXP ctx) {

  if (TYPEOF(x) != ENVSXP || TYPEOF(ctx) != ENVSXP)
    return x;

  SEXP aio = Rf_findVarInFrame(x, nano_AioSymbol);
  if (NANO_TAG(aio) != nano_AioSymbol)
    return x;

  nano_aio *raio = (nano_aio *) NANO_PTR(aio);

  if (eln2 == eln2dummy) {
    SEXP str, call;
    PROTECT(str = Rf_mkString("later"));
    PROTECT(call = Rf_lang2(Rf_install("loadNamespace"), str));
    Rf_eval(call, R_GlobalEnv);
    UNPROTECT(2);
    eln2 = (void (*)(void (*)(void *), void *, double, int)) R_GetCCallable("later", "execLaterNative2");
  }

  switch (raio->type) {
  case REQAIO:
  case REQAIOS:
    ((nano_aio *) raio->next)->data = nano_PreserveObject(ctx);
    break;
  case HTTP_AIO:
    raio->data = nano_PreserveObject(ctx);
    break;
  default:
    break;
  }

  return x;

}

// cv specials -----------------------------------------------------------------

SEXP rnng_cv_alloc(void) {

  nano_cv *cvp = R_Calloc(1, nano_cv);
  SEXP xp;
  int xc;

  if ((xc = nng_mtx_alloc(&cvp->mtx)))
    goto exitlevel1;

  if ((xc = nng_cv_alloc(&cvp->cv, cvp->mtx)))
    goto exitlevel2;

  PROTECT(xp = R_MakeExternalPtr(cvp, nano_CvSymbol, R_NilValue));
  R_RegisterCFinalizerEx(xp, cv_finalizer, TRUE);
  Rf_classgets(xp, Rf_mkString("conditionVariable"));

  UNPROTECT(1);
  return xp;

  exitlevel2:
  nng_mtx_free(cvp->mtx);
  exitlevel1:
  R_Free(cvp);
  ERROR_OUT(xc);

}

SEXP rnng_cv_wait(SEXP cvar) {

  if (NANO_TAG(cvar) != nano_CvSymbol)
    Rf_error("'cv' is not a valid Condition Variable");

  nano_cv *ncv = (nano_cv *) NANO_PTR(cvar);
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;
  int flag;

  nng_mtx_lock(mtx);
  while (ncv->condition == 0)
    nng_cv_wait(cv);
  ncv->condition--;
  flag = ncv->flag;
  nng_mtx_unlock(mtx);

  return Rf_ScalarLogical(flag >= 0);

}

SEXP rnng_cv_until(SEXP cvar, SEXP msec) {

  if (NANO_TAG(cvar) != nano_CvSymbol)
    Rf_error("'cv' is not a valid Condition Variable");

  nano_cv *ncv = (nano_cv *) NANO_PTR(cvar);
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  int signalled = 1;
  nng_time time = nng_clock();
  switch (TYPEOF(msec)) {
  case INTSXP:
    time = time + (nng_time) NANO_INTEGER(msec);
    break;
  case REALSXP:
    time = time + (nng_time) Rf_asInteger(msec);
    break;
  }

  nng_mtx_lock(mtx);
  while (ncv->condition == 0) {
    if (nng_cv_until(cv, time) == NNG_ETIMEDOUT) {
      signalled = 0;
      break;
    }
  }
  if (signalled) {
    ncv->condition--;
    nng_mtx_unlock(mtx);
  } else {
    nng_mtx_unlock(mtx);
    R_CheckUserInterrupt();
  }

  return Rf_ScalarLogical(signalled);

}

SEXP rnng_cv_wait_safe(SEXP cvar) {

  if (NANO_TAG(cvar) != nano_CvSymbol)
    Rf_error("'cv' is not a valid Condition Variable");

  nano_cv *ncv = (nano_cv *) NANO_PTR(cvar);
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;
  int signalled;
  int flag;
  nng_time time = nng_clock();

  while (1) {
    time = time + 400;
    signalled = 1;
    nng_mtx_lock(mtx);
    while (ncv->condition == 0) {
      if (nng_cv_until(cv, time) == NNG_ETIMEDOUT) {
        signalled = 0;
        break;
      }
    }
    if (signalled) break;
    nng_mtx_unlock(mtx);
    R_CheckUserInterrupt();
  }

  ncv->condition--;
  flag = ncv->flag;
  nng_mtx_unlock(mtx);

  return Rf_ScalarLogical(flag >= 0);

}

SEXP rnng_cv_until_safe(SEXP cvar, SEXP msec) {

  if (NANO_TAG(cvar) != nano_CvSymbol)
    Rf_error("'cv' is not a valid Condition Variable");

  nano_cv *ncv = (nano_cv *) NANO_PTR(cvar);
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;
  int signalled;

  nng_time time, period, now;
  switch (TYPEOF(msec)) {
  case INTSXP:
    period = (nng_time) NANO_INTEGER(msec);
    break;
  case REALSXP:
    period = (nng_time) Rf_asInteger(msec);
    break;
  default:
    period = 0;
  }

  now = nng_clock();

  do {
    time = period > 400 ? now + 400 : now + period;
    period = period > 400 ? period - 400 : 0;
    signalled = 1;
    nng_mtx_lock(mtx);
    while (ncv->condition == 0) {
      if (nng_cv_until(cv, time) == NNG_ETIMEDOUT) {
        signalled = 0;
        break;
      }
    }
    if (signalled) {
      ncv->condition--;
      nng_mtx_unlock(mtx);
      break;
    }
    nng_mtx_unlock(mtx);
    R_CheckUserInterrupt();
    now += 400;
  } while (period > 0);

  return Rf_ScalarLogical(signalled);

}

SEXP rnng_cv_reset(SEXP cvar) {

  if (NANO_TAG(cvar) != nano_CvSymbol)
    Rf_error("'cv' is not a valid Condition Variable");

  nano_cv *ncv = (nano_cv *) NANO_PTR(cvar);
  nng_mtx *mtx = ncv->mtx;

  nng_mtx_lock(mtx);
  ncv->flag = 0;
  ncv->condition = 0;
  nng_mtx_unlock(mtx);

  return nano_success;

}

SEXP rnng_cv_value(SEXP cvar) {

  if (NANO_TAG(cvar) != nano_CvSymbol)
    Rf_error("'cv' is not a valid Condition Variable");
  nano_cv *ncv = (nano_cv *) NANO_PTR(cvar);
  nng_mtx *mtx = ncv->mtx;
  int cond;
  nng_mtx_lock(mtx);
  cond = ncv->condition;
  nng_mtx_unlock(mtx);

  return Rf_ScalarInteger(cond);

}

SEXP rnng_cv_signal(SEXP cvar) {

  if (NANO_TAG(cvar) != nano_CvSymbol)
    Rf_error("'cv' is not a valid Condition Variable");

  nano_cv *ncv = (nano_cv *) NANO_PTR(cvar);
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  nng_mtx_lock(mtx);
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);

  return nano_success;

}

// pipes -----------------------------------------------------------------------

SEXP rnng_pipe_notify(SEXP socket, SEXP cv, SEXP cv2, SEXP add, SEXP remove, SEXP flag) {

  if (NANO_TAG(socket) != nano_SocketSymbol)
    Rf_error("'socket' is not a valid Socket");

  int xc;
  nng_socket *sock;

  if (cv == R_NilValue) {

    sock = (nng_socket *) NANO_PTR(socket);
    if (NANO_INTEGER(add) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_POST, NULL, NULL)))
      ERROR_OUT(xc);

    if (NANO_INTEGER(remove) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_REM_POST, NULL, NULL)))
      ERROR_OUT(xc);

    return nano_success;

  } else if (NANO_TAG(cv) != nano_CvSymbol) {
    Rf_error("'cv' is not a valid Condition Variable");
  }

  sock = (nng_socket *) NANO_PTR(socket);
  nano_cv *cvp = (nano_cv *) NANO_PTR(cv);
  const int flg = NANO_INTEGER(flag);

  if (cv2 != R_NilValue) {

    if (TAG(cv2) != nano_CvSymbol)
      Rf_error("'cv2' is not a valid Condition Variable");

    cvp->flag = flg < 0 ? 1 : flg;
    nano_cv_duo *duo = R_Calloc(1, nano_cv_duo);
    duo->cv = cvp;
    duo->cv2 = (nano_cv *) NANO_PTR(cv2);

    if (NANO_INTEGER(add) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_POST, pipe_cb_signal_duo, duo)))
      ERROR_OUT(xc);

    if (NANO_INTEGER(remove) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_REM_POST, pipe_cb_signal_duo, duo)))
      ERROR_OUT(xc);

    SEXP xptr = R_MakeExternalPtr(duo, R_NilValue, R_NilValue);
    NANO_SET_PROT(cv, xptr);
    R_RegisterCFinalizerEx(xptr, cv_duo_finalizer, TRUE);

  } else {

    cvp->flag = flg < 0 ? 1 : flg;

    if (NANO_INTEGER(add) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_POST, pipe_cb_signal, cvp)))
      ERROR_OUT(xc);

    if (NANO_INTEGER(remove) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_REM_POST, pipe_cb_signal, cvp)))
      ERROR_OUT(xc);

  }

  return nano_success;

}

SEXP rnng_socket_lock(SEXP socket, SEXP cv) {

  if (NANO_TAG(socket) != nano_SocketSymbol)
    Rf_error("'socket' is not a valid Socket");
  nng_socket *sock = (nng_socket *) NANO_PTR(socket);

  int xc;
  if (cv != R_NilValue) {
    if (NANO_TAG(cv) != nano_CvSymbol)
      Rf_error("'cv' is not a valid Condition Variable");
    nano_cv *ncv = (nano_cv *) NANO_PTR(cv);
    xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_PRE, pipe_cb_dropcon, ncv);
  } else {
    xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_PRE, pipe_cb_dropcon, NULL);
  }

  if (xc)
    ERROR_OUT(xc);

  return nano_success;

}

SEXP rnng_socket_unlock(SEXP socket) {

  if (NANO_TAG(socket) != nano_SocketSymbol)
    Rf_error("'socket' is not a valid Socket");

  nng_socket *sock = (nng_socket *) NANO_PTR(socket);

  const int xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_PRE, NULL, NULL);
  if (xc)
    ERROR_OUT(xc);

  return nano_success;

}
