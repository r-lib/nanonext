// nanonext - C level - Synchronization Primitives and Signals -----------------

#define NANONEXT_SIGNALS
#include "nanonext.h"

// aio completion callbacks ----------------------------------------------------

static void sendaio_complete(void *arg) {

  nng_aio *aio = ((nano_saio *) arg)->aio;
  if (nng_aio_result(aio))
    nng_msg_free(nng_aio_get_msg(aio));

}

static void request_complete(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  nano_saio *saio = (nano_saio *) raio->cb;
  int res = nng_aio_result(raio->aio);
  if (res == 0) {
    nng_msg *msg = nng_aio_get_msg(raio->aio);
    raio->data = msg;
    nng_pipe p = nng_msg_get_pipe(msg);
    res = - (int) p.id;
  } else if (res == 5) {
    const int id = saio->msgid;
    if (id) {
      nng_msg *msg;
      if (nng_msg_alloc(&msg, 0) == 0) {
        if (nng_msg_append_u32(msg, 0) ||
            nng_msg_append(msg, &id, sizeof(id)) ||
            nng_ctx_sendmsg(*saio->ctx, msg, 0)) {
          nng_msg_free(msg);
        }
      }
    }
  }

  if (raio->next != NULL) {
    nano_cv *ncv = (nano_cv *) raio->next;
    nng_cv *cv = ncv->cv;
    nng_mtx *mtx = ncv->mtx;

    nng_mtx_lock(mtx);
    raio->result = res;
    ncv->condition++;
    nng_cv_wake(cv);
    nng_mtx_unlock(mtx);
  } else {
    raio->result = res;
  }

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
    if (sig == SIGINT)
      R_interrupts_pending = 1;
    kill(getpid(), sig);
#endif

  }

}

static void pipe_cb_monitor(nng_pipe p, nng_pipe_ev ev, void *arg) {

  nano_monitor *monitor = (nano_monitor *) arg;

  nano_cv *ncv = monitor->cv;
  nng_cv *cv = ncv->cv;
  nng_mtx *mtx = ncv->mtx;

  const int id = (int) p.id;
  if (!id)
    return;

  nng_mtx_lock(mtx);
  if (monitor->updates >= monitor->size) {
    monitor->size += 8;
    monitor->ids = R_Realloc(monitor->ids, monitor->size, int);
  }
  monitor->ids[monitor->updates] = ev == NNG_PIPE_EV_ADD_POST ? id : -id;
  monitor->updates++;
  ncv->condition++;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);

}

// finalizers ------------------------------------------------------------------

static void cv_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_cv *xp = (nano_cv *) NANO_PTR(xptr);
  nng_cv_free(xp->cv);
  nng_mtx_free(xp->mtx);
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

static void monitor_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_monitor *xp = (nano_monitor *) NANO_PTR(xptr);
  R_Free(xp->ids);
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

  if (NANO_PTR_CHECK(cvar, nano_CvSymbol))
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

  if (NANO_PTR_CHECK(cvar, nano_CvSymbol))
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

  if (NANO_PTR_CHECK(cvar, nano_CvSymbol))
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

  if (NANO_PTR_CHECK(cvar, nano_CvSymbol))
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

  if (NANO_PTR_CHECK(cvar, nano_CvSymbol))
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

  if (NANO_PTR_CHECK(cvar, nano_CvSymbol))
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

  if (NANO_PTR_CHECK(cvar, nano_CvSymbol))
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

SEXP rnng_request(SEXP con, SEXP data, SEXP sendmode, SEXP recvmode, SEXP timeout, SEXP cvar, SEXP msgid, SEXP clo) {

  const int sock = !NANO_PTR_CHECK(con, nano_SocketSymbol);
  if (!sock && NANO_PTR_CHECK(con, nano_ContextSymbol))
    Rf_error("'con' is not a valid Socket or Context");

  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  const uint8_t mod = (uint8_t) nano_matcharg(recvmode);
  const int id = msgid != R_NilValue ? NANO_INTEGER(msgid) : 0;
  int signal, drop, xc;
  SEXP context;
  if (cvar == R_NilValue) {
    signal = 0;
    drop = 0;
  } else {
    signal = !NANO_PTR_CHECK(cvar, nano_CvSymbol);
    drop = 1 - signal;
  }
  nng_ctx *ctx;
  if (sock) {
    nng_socket *sock = (nng_socket *) NANO_PTR(con);
    ctx = R_Calloc(1, nng_ctx);
    if ((xc = nng_ctx_open(ctx, *sock))) {
      R_Free(ctx);
      goto exitlevel1;
    }
    PROTECT(context = R_MakeExternalPtr(ctx, nano_ContextSymbol, R_NilValue));
    R_RegisterCFinalizerEx(context, context_finalizer, TRUE);
  } else {
    ctx = (nng_ctx *) NANO_PTR(con);
  }
  nano_cv *ncv = signal ? (nano_cv *) NANO_PTR(cvar) : NULL;

  SEXP aio, env, fun;
  nano_buf buf;
  nano_saio *saio;
  nano_aio *raio;
  nng_msg *msg;

  nano_encodes(sendmode) == 2 ? nano_encode(&buf, data) : nano_serialize(&buf, data, NANO_PROT(con));
  saio = R_Calloc(1, nano_saio);
  saio->cb = NULL;
  saio->ctx = ctx;
  saio->msgid = id;

  if ((xc = nng_msg_alloc(&msg, 0)))
    goto exitlevel2;

  if ((xc = nng_msg_append(msg, buf.buf, buf.cur)) ||
      (xc = nng_aio_alloc(&saio->aio, sendaio_complete, saio))) {
    nng_msg_free(msg);
    goto exitlevel2;
  }

  nng_aio_set_msg(saio->aio, msg);
  nng_ctx_send(*ctx, saio->aio);

  raio = R_Calloc(1, nano_aio);
  raio->type = signal ? REQAIOS : REQAIO;
  raio->mode = mod;
  raio->cb = saio;
  raio->next = ncv;

  if ((xc = nng_aio_alloc(&raio->aio, drop ? request_complete_dropcon : request_complete, raio)))
    goto exitlevel3;

  nng_aio_set_timeout(raio->aio, dur);
  nng_ctx_recv(*ctx, raio->aio);
  NANO_FREE(buf);

  PROTECT(aio = R_MakeExternalPtr(raio, nano_AioSymbol, NANO_PROT(con)));
  R_RegisterCFinalizerEx(aio, request_finalizer, TRUE);
  Rf_setAttrib(aio, nano_SocketSymbol, con);
  if (sock) {
    Rf_setAttrib(aio, nano_ContextSymbol, context);
    Rf_setAttrib(aio, nano_MsgidSymbol, Rf_ScalarInteger(id));
  }

  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  Rf_classgets(env, nano_reqAio);
  Rf_defineVar(nano_AioSymbol, aio, env);

  PROTECT(fun = R_mkClosure(R_NilValue, nano_aioFuncMsg, clo));
  R_MakeActiveBinding(nano_DataSymbol, fun, env);

  UNPROTECT(sock ? 4 : 3);
  return env;

  exitlevel3:
  R_Free(raio);
  nng_aio_free(saio->aio);
  exitlevel2:
  R_Free(saio);
  NANO_FREE(buf);
  exitlevel1:
  return mk_error_data(xc);

}

SEXP rnng_set_promise_context(SEXP x, SEXP ctx) {

  if (TYPEOF(x) != ENVSXP)
    return R_NilValue;

  SEXP aio = Rf_findVarInFrame(x, nano_AioSymbol);
  if (NANO_PTR_CHECK(aio, nano_AioSymbol))
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

SEXP rnng_pipe_notify(SEXP socket, SEXP cv, SEXP add, SEXP remove, SEXP flag) {

  if (NANO_PTR_CHECK(socket, nano_SocketSymbol))
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

  } else if (NANO_PTR_CHECK(cv, nano_CvSymbol)) {
    Rf_error("'cv' is not a valid Condition Variable");
  }

  sock = (nng_socket *) NANO_PTR(socket);
  nano_cv *cvp = (nano_cv *) NANO_PTR(cv);
  const int flg = nano_integer(flag);

  cvp->flag = flg < 0 ? 1 : flg;

  if (NANO_INTEGER(add) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_POST, pipe_cb_signal, cvp)))
    ERROR_OUT(xc);

  if (NANO_INTEGER(remove) && (xc = nng_pipe_notify(*sock, NNG_PIPE_EV_REM_POST, pipe_cb_signal, cvp)))
    ERROR_OUT(xc);

  return nano_success;

}

// monitors --------------------------------------------------------------------

SEXP rnng_monitor_create(SEXP socket, SEXP cv) {

  if (NANO_PTR_CHECK(socket, nano_SocketSymbol))
    Rf_error("'socket' is not a valid Socket");

  if (NANO_PTR_CHECK(cv, nano_CvSymbol))
    Rf_error("'cv' is not a valid Condition Variable");

  const int n = 8;
  nano_monitor *monitor = R_Calloc(1, nano_monitor);
  monitor->ids = R_Calloc(n, int);
  monitor->size = n;
  monitor->cv = (nano_cv *) NANO_PTR(cv);
  nng_socket *sock = (nng_socket *) NANO_PTR(socket);

  SEXP xptr;
  int xc;

  if ((xc = nng_pipe_notify(*sock, NNG_PIPE_EV_ADD_POST, pipe_cb_monitor, monitor)))
    ERROR_OUT(xc);

  if ((xc = nng_pipe_notify(*sock, NNG_PIPE_EV_REM_POST, pipe_cb_monitor, monitor)))
    ERROR_OUT(xc);

  PROTECT(xptr = R_MakeExternalPtr(monitor, nano_MonitorSymbol, R_NilValue));
  R_RegisterCFinalizerEx(xptr, monitor_finalizer, TRUE);
  NANO_CLASS2(xptr, "nanoMonitor", "nano");
  Rf_setAttrib(xptr, nano_SocketSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));
  UNPROTECT(1);

  return xptr;

}

SEXP rnng_monitor_read(SEXP x) {

  if (NANO_PTR_CHECK(x, nano_MonitorSymbol))
    Rf_error("'x' is not a valid Monitor");

  nano_monitor *monitor = (nano_monitor *) NANO_PTR(x);

  nano_cv *ncv = monitor->cv;
  nng_mtx *mtx = ncv->mtx;

  SEXP out;
  nng_mtx_lock(mtx);
  const int updates = monitor->updates;
  if (updates) {
    out = Rf_allocVector(INTSXP, updates);
    memcpy(NANO_DATAPTR(out), monitor->ids, updates * sizeof(int));
    monitor->updates = 0;
  }
  nng_mtx_unlock(mtx);

  if (!updates)
    out = R_NilValue;

  return out;

}
