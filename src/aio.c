// nanonext - C level - Async Functions ----------------------------------------

#define NANONEXT_SIGNALS
#include "nanonext.h"

// internals -------------------------------------------------------------------

static int nano_interrupt = 0;

static SEXP mk_error_aio(const int xc, SEXP env) {

  SEXP err = PROTECT(Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(nano_AioSymbol, nano_success, env);
  UNPROTECT(1);
  return err;

}

// aio completion callbacks ----------------------------------------------------

void nano_list_op(int add, void *data) {

  static nano_node *free_list = NULL;

  if (add) {
    nano_node *new_node = malloc(sizeof(nano_node));
    new_node->data = data;
    new_node->next = free_list;
    free_list = new_node;
  } else {
    while (free_list != NULL) {
      nano_node *current = free_list;
      free_list = free_list->next;
      nano_aio *aio = (nano_aio *) current->data;
      nng_aio_free(aio->aio);
      R_Free(aio);
      free(current);
    }
  }

}

static void saio_complete(void *arg) {

  nano_aio *saio = (nano_aio *) arg;
  const int res = nng_aio_result(saio->aio);
  if (res)
    nng_msg_free(nng_aio_get_msg(saio->aio));
  saio->result = res - !res;

  nano_list_op(1, saio);

}

static void isaio_complete(void *arg) {

  nano_aio *iaio = (nano_aio *) arg;
  const int res = nng_aio_result(iaio->aio);
  if (iaio->data != NULL)
    R_Free(iaio->data);
  iaio->result = res - !res;

  nano_list_op(1, iaio);

}

static void raio_complete(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  int res = nng_aio_result(raio->aio);
  if (res == 0) {
    nng_msg *msg = nng_aio_get_msg(raio->aio);
    raio->data = msg;
    nng_pipe p = nng_msg_get_pipe(msg);
    res = - (int) p.id;
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

  if (raio->cb != NULL)
    later2(raio_invoke_cb, raio->cb);

}

static void raio_complete_interrupt(void *arg) {

  nano_aio *raio = (nano_aio *) arg;
  int res = nng_aio_result(raio->aio);
  if (res == 0) {
    nng_msg *msg = nng_aio_get_msg(raio->aio);
    raio->data = msg;
    nng_pipe p = nng_msg_get_pipe(msg);
    res = - (int) p.id;
  }

  raio->result = res;

  if (raio->cb != NULL)
    later2(raio_invoke_cb, raio->cb);

  if (nano_interrupt) {
#ifdef _WIN32
    UserBreak = 1;
#else
    R_interrupts_pending = 1;
    kill(getpid(), SIGINT);
#endif
  }

}

static void iraio_complete(void *arg) {

  nano_aio *iaio = (nano_aio *) arg;
  const int res = nng_aio_result(iaio->aio);

  if (iaio->next != NULL) {
    nano_cv *ncv = (nano_cv *) iaio->next;
    nng_cv *cv = ncv->cv;
    nng_mtx *mtx = ncv->mtx;

    nng_mtx_lock(mtx);
    iaio->result = res - !res;
    ncv->condition++;
    nng_cv_wake(cv);
    nng_mtx_unlock(mtx);
  } else {
    iaio->result = res - !res;
  }

  if (iaio->cb != NULL)
    later2(raio_invoke_cb, iaio->cb);

}

// finalisers ------------------------------------------------------------------
static void iaio_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nng_aio_free(xp->aio);
  if (xp->data != NULL)
    R_Free(xp->data);
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

// core aio --------------------------------------------------------------------

SEXP rnng_aio_result(SEXP env) {

  const SEXP exist = Rf_findVarInFrame(env, nano_ValueSymbol);
  if (exist != R_UnboundValue)
    return exist;

  const SEXP aio = Rf_findVarInFrame(env, nano_AioSymbol);
  if (NANO_PTR_CHECK(aio, nano_AioSymbol))
    Rf_error("object is not a valid Aio");

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
  if (NANO_PTR_CHECK(aio, nano_AioSymbol))
    Rf_error("object is not a valid Aio");

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
    nng_mtx *mtx = ((nano_cv *) raio->next)->mtx;
    nng_mtx_lock(mtx);
    res = raio->result;
    nng_mtx_unlock(mtx);

    if (res == 0)
      return nano_unresolved;

    if (res > 0)
      return mk_error_aio(res, env);

    break;
  default:
    res = 0;
    return mk_error_aio(res, env);
  }

  SEXP out, pipe;
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

  PROTECT(out = nano_decode(buf, sz, raio->mode, NANO_PROT(aio)));
  PROTECT(pipe = Rf_ScalarInteger(-res));
  Rf_defineVar(nano_ValueSymbol, out, env);
  Rf_defineVar(nano_AioSymbol, pipe, env);

  UNPROTECT(2);
  return out;

}

SEXP rnng_aio_call(SEXP x) {

  switch (TYPEOF(x)) {
  case ENVSXP: ;
    const SEXP coreaio = Rf_findVarInFrame(x, nano_AioSymbol);
    if (NANO_PTR_CHECK(coreaio, nano_AioSymbol))
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
    SEXP env, names;
    const R_xlen_t xlen = Rf_xlength(x);
    PROTECT(out = Rf_allocVector(VECSXP, xlen));
    for (R_xlen_t i = 0; i < xlen; i++) {
      env = func(NANO_VECTOR(x)[i]);
      if (TYPEOF(env) != ENVSXP) goto exit;
      env = Rf_findVarInFrame(env, nano_ValueSymbol);
      if (env == R_UnboundValue) goto exit;
      SET_VECTOR_ELT(out, i, env);
    }
    names = Rf_getAttrib(x, R_NamesSymbol);
    if (names != R_NilValue)
      out = Rf_namesgets(out, names);
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
    if (NANO_PTR_CHECK(coreaio, nano_AioSymbol)) break;
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
    if (NANO_PTR_CHECK(coreaio, nano_AioSymbol)) {
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
    if (NANO_PTR_CHECK(coreaio, nano_AioSymbol))
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

SEXP rnng_send_aio(SEXP con, SEXP data, SEXP mode, SEXP timeout, SEXP pipe, SEXP clo) {

  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  nano_aio *saio;
  SEXP aio, env, fun;
  nano_buf buf;
  int sock, xc;

  if ((sock = !NANO_PTR_CHECK(con, nano_SocketSymbol)) || !NANO_PTR_CHECK(con, nano_ContextSymbol)) {

    const int pipeid = sock ? nano_integer(pipe) : 0;
    nano_encodes(mode) == 2 ? nano_encode(&buf, data) : nano_serialize(&buf, data, NANO_PROT(con));
    nng_msg *msg;
    saio = R_Calloc(1, nano_aio);
    saio->type = SENDAIO;

    if ((xc = nng_msg_alloc(&msg, 0)))
      goto exitlevel1;

    if (pipeid) {
      nng_pipe p;
      p.id = (uint32_t) pipeid;
      nng_msg_set_pipe(msg, p);
    }

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

  } else if (!NANO_PTR_CHECK(con, nano_StreamSymbol)) {

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

  } else {
    NANO_ERROR("'con' is not a valid Socket, Context, or Stream");
  }

  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  Rf_classgets(env, nano_sendAio);
  Rf_defineVar(nano_AioSymbol, aio, env);

  PROTECT(fun = R_mkClosure(R_NilValue, nano_aioFuncRes, clo));
  R_MakeActiveBinding(nano_ResultSymbol, fun, env);

  nano_list_op(0, NULL);

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
  int signal, interrupt;
  if (cvar == R_NilValue) {
    signal = 0;
    interrupt = 0;
  } else {
    signal = !NANO_PTR_CHECK(cvar, nano_CvSymbol);
    interrupt = 1 - signal;
  }
  nano_cv *ncv = signal ? (nano_cv *) NANO_PTR(cvar) : NULL;
  nano_aio *raio;
  SEXP aio, env, fun;
  int sock, xc;

  if ((sock = !NANO_PTR_CHECK(con, nano_SocketSymbol)) || !NANO_PTR_CHECK(con, nano_ContextSymbol)) {

    const uint8_t mod = (uint8_t) nano_matcharg(mode);
    raio = R_Calloc(1, nano_aio);
    raio->next = ncv;
    raio->type = signal ? RECVAIOS : RECVAIO;
    raio->mode = mod;
    raio->cb = NULL;

    if ((xc = nng_aio_alloc(&raio->aio, interrupt ? raio_complete_interrupt : raio_complete, raio)))
      goto exitlevel1;

    nng_aio_set_timeout(raio->aio, dur);
    sock ? nng_recv_aio(*(nng_socket *) NANO_PTR(con), raio->aio) :
      nng_ctx_recv(*(nng_ctx *) NANO_PTR(con), raio->aio);

    PROTECT(aio = R_MakeExternalPtr(raio, nano_AioSymbol, NANO_PROT(con)));
    R_RegisterCFinalizerEx(aio, raio_finalizer, TRUE);

  } else if (!NANO_PTR_CHECK(con, nano_StreamSymbol)) {

    const uint8_t mod = (uint8_t) nano_matchargs(mode);
    const size_t xlen = (size_t) nano_integer(bytes);
    nng_stream **sp = (nng_stream **) NANO_PTR(con);
    nng_iov iov;

    raio = R_Calloc(1, nano_aio);
    raio->next = ncv;
    raio->type = signal ? IOV_RECVAIOS : IOV_RECVAIO;
    raio->mode = mod;
    raio->cb = NULL;
    raio->data = R_Calloc(xlen, unsigned char);
    iov.iov_len = xlen;
    iov.iov_buf = raio->data;

    if ((xc = nng_aio_alloc(&raio->aio, iraio_complete, raio)))
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

  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
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

SEXP rnng_interrupt_switch(SEXP x) {

  nano_interrupt = NANO_INTEGER(x);
  return x;

}
