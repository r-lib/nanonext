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

// nanonext - C level - Synchronization Primitives and Signals -----------------

#define NANONEXT_SIGNALS
#include "nanonext.h"

// aio completion callbacks ----------------------------------------------------

static void request_complete(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  int res = nng_aio_result(raio->aio);
  if (res == 0) {
    nng_msg *msg = nng_aio_get_msg(raio->aio);
    raio->data = msg;
    nng_pipe p = nng_msg_get_pipe(msg);
    res = - (int) p.id;
  }
  raio->result = res;

  nano_saio *saio = (nano_saio *) raio->cb;
  if (saio->cb != NULL)
    later2(raio_invoke_cb, saio->cb);

}

static void request_complete_dropcon(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  int res = nng_aio_result(raio->aio);
  if (res == 0) {
    nng_msg *msg = nng_aio_get_msg(raio->aio);
    raio->data = msg;
    nng_pipe p = nng_msg_get_pipe(msg);
    res = - (int) p.id;
    nng_pipe_close(p);
  }
  raio->result = res;

  nano_saio *saio = (nano_saio *) raio->cb;
  if (saio->cb != NULL)
    later2(raio_invoke_cb, saio->cb);

}

static void request_complete_signal(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  nano_cv *ncv = (nano_cv *) raio->next;
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  int res = nng_aio_result(raio->aio);
  if (res == 0) {
    nng_msg *msg = nng_aio_get_msg(raio->aio);
    raio->data = msg;
    nng_pipe p = nng_msg_get_pipe(msg);
    res = - (int) p.id;
  }

  nng_mtx_lock(mtx);
  raio->result = res;
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);

  nano_saio *saio = (nano_saio *) raio->cb;
  if (saio->cb != NULL)
    later2(raio_invoke_cb, saio->cb);

}

void pipe_cb_signal(nng_pipe p, nng_pipe_ev ev, void *arg) {

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

// finalizers ------------------------------------------------------------------

static void cv_duo_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_cv_duo *xp = (nano_cv_duo *) NANO_PTR(xptr);
  R_Free(xp);

}

static void request_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nano_saio *saio = (nano_saio *) xp->cb;
  nng_aio_free(saio->aio);
  nng_aio_free(xp->aio);
  if (xp->data != NULL)
    nng_msg_free((nng_msg *) xp->data);
  R_Free(saio);
  R_Free(xp);

}

// synchronization primitives --------------------------------------------------

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

// request ---------------------------------------------------------------------

SEXP rnng_request(SEXP con, SEXP data, SEXP sendmode, SEXP recvmode, SEXP timeout, SEXP cvar, SEXP clo) {

  if (NANO_TAG(con) != nano_ContextSymbol)
    Rf_error("'con' is not a valid Context");

  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  const uint8_t mod = (uint8_t) nano_matcharg(recvmode);
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
  nano_saio *saio;
  nano_aio *raio;
  nng_msg *msg;
  int xc;

  nano_encodes(sendmode) == 2 ? nano_encode(&buf, data) : nano_serialize(&buf, data, NANO_PROT(con));
  saio = R_Calloc(1, nano_saio);
  saio->cb = NULL;

  if ((xc = nng_msg_alloc(&msg, 0)))
    goto exitlevel1;

  if ((xc = nng_msg_append(msg, buf.buf, buf.cur)) ||
      (xc = nng_aio_alloc(&saio->aio, sendaio_complete, saio))) {
    nng_msg_free(msg);
    goto exitlevel1;
  }

  nng_aio_set_msg(saio->aio, msg);
  nng_ctx_send(*ctx, saio->aio);

  raio = R_Calloc(1, nano_aio);
  raio->type = signal ? REQAIOS : REQAIO;
  raio->mode = mod;
  raio->cb = saio;
  raio->next = ncv;

  if ((xc = nng_aio_alloc(&raio->aio, signal ? request_complete_signal : drop ? request_complete_dropcon : request_complete, raio)))
    goto exitlevel2;

  nng_aio_set_timeout(raio->aio, dur);
  nng_ctx_recv(*ctx, raio->aio);
  NANO_FREE(buf);

  PROTECT(aio = R_MakeExternalPtr(raio, nano_AioSymbol, NANO_PROT(con)));
  R_RegisterCFinalizerEx(aio, request_finalizer, TRUE);

  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
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

  if (TYPEOF(x) != ENVSXP)
    return R_NilValue;

  SEXP aio = nano_findVarInFrame(x, nano_AioSymbol);
  if (NANO_TAG(aio) != nano_AioSymbol)
    return R_NilValue;

  nano_aio *raio = (nano_aio *) NANO_PTR(aio);

  if (eln2 == NULL) {
    SEXP str, call;
    PROTECT(str = Rf_mkString("later"));
    PROTECT(call = Rf_lang2(Rf_install("loadNamespace"), str));
    Rf_eval(call, R_BaseEnv);
    UNPROTECT(2);
    eln2 = (void (*)(void (*)(void *), void *, double, int)) R_GetCCallable("later", "execLaterNative2");
  }

  switch (raio->type) {
  case REQAIO:
  case REQAIOS:
    NANO_SET_ENCLOS(x, ctx);
    nano_saio *saio = (nano_saio *) raio->cb;
    saio->cb = nano_PreserveObject(x);
    break;
  case RECVAIO:
  case RECVAIOS:
  case IOV_RECVAIO:
  case IOV_RECVAIOS:
  case HTTP_AIO:
    NANO_SET_ENCLOS(x, ctx);
    raio->cb = nano_PreserveObject(x);
    break;
  case SENDAIO:
  case IOV_SENDAIO:
    break;
  }

  return R_NilValue;

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

    if (NANO_TAG(cv2) != nano_CvSymbol)
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

SEXP rnng_interrupt_switch(void) {

  nano_interrupt = nano_interrupt ? 0 : 1;
  return R_NilValue;

}
