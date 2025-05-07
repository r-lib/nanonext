// nanonext - C level - Threaded Applications ----------------------------------

#define NANONEXT_PROTOCOLS
#define NANONEXT_IO
#include "nanonext.h"

// threads callable and messenger ----------------------------------------------

static nng_mtx *nano_wait_mtx = NULL;
static nng_cv *nano_wait_cv = NULL;
static nng_thread *nano_wait_thr = NULL;
static nng_aio *nano_shared_aio = NULL;
static int nano_wait_condition = 0;

void nano_thread_shutdown(void) {
  if (nano_wait_thr == NULL)
    return;
  if (nano_shared_aio != NULL)
    nng_aio_stop(nano_shared_aio);
  nng_mtx_lock(nano_wait_mtx);
  nano_wait_condition = -1;
  nng_cv_wake(nano_wait_cv);
  nng_mtx_unlock(nano_wait_mtx);
  nng_thread_destroy(nano_wait_thr);
  nng_cv_free(nano_wait_cv);
  nng_mtx_free(nano_wait_mtx);
  nano_wait_thr = NULL;
}

// # nocov start
// tested interactively

static void thread_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_thread *xp = (nng_thread *) NANO_PTR(xptr);
  nng_thread_destroy(xp);

}

static SEXP rnng_thread_create(void (*func)(void *), void *arg) {

  nng_thread *thr;
  int xc;

  if ((xc = nng_thread_create(&thr, func, arg)))
    ERROR_OUT(xc);

  SEXP xptr = R_MakeExternalPtr(thr, R_NilValue, R_NilValue);
  R_RegisterCFinalizerEx(xptr, thread_finalizer, TRUE);

  return xptr;

}

static void nano_printf(const int err, const char *fmt, ...) {

  char buf[NANONEXT_INIT_BUFSIZE];
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  int bytes = vsnprintf(buf, NANONEXT_INIT_BUFSIZE, fmt, arg_ptr);
  va_end(arg_ptr);

  if (write(err ? STDERR_FILENO : STDOUT_FILENO, buf, (size_t) bytes)) {};

}

static void rnng_messenger_thread(void *args) {

  SEXP plist = (SEXP) args;
  SEXP socket = CADR(plist);
  SEXP key = CADDR(plist);
  nng_socket *sock = (nng_socket *) NANO_PTR(socket);
  unsigned char *buf;
  size_t sz;
  time_t now;
  struct tm *tms;
  int xc;

  while (1) {
    xc = nng_recv(*sock, &buf, &sz, NNG_FLAG_ALLOC);
    time(&now);
    tms = localtime(&now);

    if (xc) {
      nano_printf(1,
                  "| messenger session ended: %d-%02d-%02d %02d:%02d:%02d\n",
                  tms->tm_year + 1900, tms->tm_mon + 1, tms->tm_mday,
                  tms->tm_hour, tms->tm_min, tms->tm_sec);
      break;
    }

    if (!strncmp((char *) buf, ":", 1)) {
      if (!strncmp((char *) buf, ":c ", 3)) {
        nano_printf(1,
                    "| <- peer connected: %d-%02d-%02d %02d:%02d:%02d\n",
                    tms->tm_year + 1900, tms->tm_mon + 1, tms->tm_mday,
                    tms->tm_hour, tms->tm_min, tms->tm_sec);
        nng_free(buf, sz);
        nano_buf enc;
        nano_encode(&enc, key);
        xc = nng_send(*sock, enc.buf, enc.cur, NNG_FLAG_NONBLOCK);
        if (xc) {
          nano_printf(1,
                      "| messenger session ended: %d-%02d-%02d %02d:%02d:%02d\n",
                      tms->tm_year + 1900, tms->tm_mon + 1, tms->tm_mday,
                      tms->tm_hour, tms->tm_min, tms->tm_sec);
          break;
        }
        continue;
      }
      if (!strncmp((char *) buf, ":d ", 3)) {
        nano_printf(1,
                    "| -> peer disconnected: %d-%02d-%02d %02d:%02d:%02d\n",
                    tms->tm_year + 1900, tms->tm_mon + 1, tms->tm_mday,
                    tms->tm_hour, tms->tm_min, tms->tm_sec);
        nng_free(buf, sz);
        continue;
      }
    }

    nano_printf(0,
                "%s\n%*s< %d-%02d-%02d %02d:%02d:%02d\n",
                (char *) buf, (int) sz, "",
                tms->tm_year + 1900, tms->tm_mon + 1, tms->tm_mday,
                tms->tm_hour, tms->tm_min, tms->tm_sec);
    nng_free(buf, sz);

  }

}

SEXP rnng_messenger(SEXP url) {

  const char *up = CHAR(STRING_ELT(url, 0));
  nng_listener *lp = NULL;
  nng_dialer *dp = NULL;
  int xc, dialer = 0;
  SEXP socket, con;

  nng_socket *sock = malloc(sizeof(nng_socket));
  NANO_ENSURE_ALLOC(sock);

  if ((xc = nng_pair0_open(sock)))
    goto fail;
  lp = malloc(sizeof(nng_listener));
  NANO_ENSURE_ALLOC(lp);
  if ((xc = nng_listen(*sock, up, lp, 0))) {
    if (xc != 10 && xc != 15)
      goto fail;
    free(lp);
    lp = NULL;
    dp = malloc(sizeof(nng_dialer));
    NANO_ENSURE_ALLOC(dp);
    if ((xc = nng_dial(*sock, up, dp, 0)))
      goto fail;
    dialer = 1;
  }

  if (dialer) {
    PROTECT(con = R_MakeExternalPtr(dp, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(con, dialer_finalizer, TRUE);
  } else {
    PROTECT(con = R_MakeExternalPtr(lp, R_NilValue, R_NilValue));
    R_RegisterCFinalizerEx(con, listener_finalizer, TRUE);
  }
  PROTECT(socket = R_MakeExternalPtr(sock, nano_SocketSymbol, con));
  R_RegisterCFinalizerEx(socket, socket_finalizer, TRUE);
  if (dialer) Rf_setAttrib(socket, nano_DialerSymbol, R_MissingArg);

  UNPROTECT(2);
  return socket;

  fail:
  failmem:
  free(dp);
  free(lp);
  if (sock != NULL)
    nng_close(*sock);
  free(sock);
  ERROR_OUT(xc);

}

SEXP rnng_messenger_thread_create(SEXP args) {

  SEXP socket = CADR(args);
  NANO_SET_PROT(socket, rnng_thread_create(rnng_messenger_thread, args));

  return socket;

}

// # nocov end

// threaded functions ----------------------------------------------------------

// # nocov start
// tested interactively

static void thread_aio_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_thread_aio *xp = (nano_thread_aio *) NANO_PTR(xptr);
  nano_cv *ncv = xp->cv;
  nng_mtx *mtx = ncv->mtx;
  nng_cv *cv = ncv->cv;
  nng_aio_stop(xp->aio);
  nng_thread_destroy(xp->thr);
  nng_cv_free(cv);
  nng_mtx_free(mtx);
  free(ncv);
  free(xp);

}


static void rnng_wait_thread_single(void *args) {

  nano_thread_aio *taio = (nano_thread_aio *) args;
  nano_cv *ncv = taio->cv;
  nng_mtx *mtx = ncv->mtx;
  nng_cv *cv = ncv->cv;

  nng_aio_wait(taio->aio);

  nng_mtx_lock(mtx);
  ncv->condition = 1;
  nng_cv_wake(cv);
  nng_mtx_unlock(mtx);

}

void single_wait_thread_create(SEXP x) {

  nano_aio *aiop = (nano_aio *) NANO_PTR(x);

  int xc, signalled;
  nano_thread_aio *taio = NULL;
  nano_cv *ncv = NULL;

  taio = malloc(sizeof(nano_thread_aio));
  NANO_ENSURE_ALLOC(taio);
  ncv = malloc(sizeof(nano_cv));
  NANO_ENSURE_ALLOC(ncv);
  taio->aio = aiop->aio;
  taio->cv = ncv;
  nng_mtx *mtx = NULL;
  nng_cv *cv = NULL;

  if ((xc = nng_mtx_alloc(&mtx)) ||
      (xc = nng_cv_alloc(&cv, mtx)))
    goto fail;

  ncv->mtx = mtx;
  ncv->cv = cv;

  if ((xc = nng_thread_create(&taio->thr, rnng_wait_thread_single, taio)))
    goto fail;

  SEXP xptr;
  PROTECT(xptr = R_MakeExternalPtr(taio, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(xptr, thread_aio_finalizer, TRUE);
  R_MakeWeakRef(x, xptr, R_NilValue, TRUE);
  UNPROTECT(1);

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
    nng_mtx_unlock(mtx);
    if (signalled) break;
    R_CheckUserInterrupt();
  }

  return;

  fail:
  nng_cv_free(cv);
  nng_mtx_free(mtx);
  failmem:
  free(ncv);
  free(taio);
  ERROR_OUT(xc);

}

// # nocov end

static void thread_duo_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_thread_duo *xp = (nano_thread_duo *) NANO_PTR(xptr);
  nano_cv *ncv = xp->cv;
  if (ncv != NULL) {
    nng_mtx *mtx = ncv->mtx;
    nng_cv *cv = ncv->cv;
    nng_mtx_lock(mtx);
    ncv->condition = -1;
    nng_cv_wake(cv);
    nng_mtx_unlock(mtx);
  }
  nng_thread_destroy(xp->thr);
  free(xp);

}

static void rnng_wait_thread(void *args) {

  while (1) {
    nng_mtx_lock(nano_wait_mtx);
    while (nano_wait_condition == 0)
      nng_cv_wait(nano_wait_cv);
    if (nano_wait_condition == -1) {
      nng_mtx_unlock(nano_wait_mtx);
      break;
    }
    nng_mtx_unlock(nano_wait_mtx);

    nng_aio_wait(nano_shared_aio);

    nng_mtx_lock(nano_wait_mtx);
    nano_shared_aio = NULL;
    nano_wait_condition = 0;
    nng_cv_wake(nano_wait_cv);
    nng_mtx_unlock(nano_wait_mtx);
  }

}

SEXP rnng_wait_thread_create(SEXP x) {

  const SEXPTYPE typ = TYPEOF(x);
  if (typ == ENVSXP) {

    const SEXP coreaio = Rf_findVarInFrame(x, nano_AioSymbol);
    if (NANO_PTR_CHECK(coreaio, nano_AioSymbol))
      return x;

    nano_aio *aiop = (nano_aio *) NANO_PTR(coreaio);

    int xc, signalled;

    if (nano_wait_thr == NULL) {
      if ((xc = nng_mtx_alloc(&nano_wait_mtx)) ||
          (xc = nng_cv_alloc(&nano_wait_cv, nano_wait_mtx)) ||
          (xc = nng_thread_create(&nano_wait_thr, rnng_wait_thread, NULL)))
        goto fail;
    }

    int thread_required = 0;
    nng_mtx_lock(nano_wait_mtx);
    if (nano_wait_condition == 0) {
      nano_shared_aio = aiop->aio;
      nano_wait_condition = 1;
      nng_cv_wake(nano_wait_cv);
    } else {
      thread_required = nano_shared_aio != aiop->aio;
    }
    nng_mtx_unlock(nano_wait_mtx);

    if (thread_required) {

      PROTECT(coreaio);
      single_wait_thread_create(coreaio);
      UNPROTECT(1);

    } else {

      nng_time time = nng_clock();

      while (1) {
        time = time + 400;
        signalled = 1;
        nng_mtx_lock(nano_wait_mtx);
        while (nano_wait_condition == 1) {
          if (nng_cv_until(nano_wait_cv, time) == NNG_ETIMEDOUT) {
            signalled = 0;
            break;
          }
        }
        nng_mtx_unlock(nano_wait_mtx);
        if (signalled) break;
        R_CheckUserInterrupt();
      }

    }

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

    return x;

    fail:
    nng_cv_free(nano_wait_cv);
    nng_mtx_free(nano_wait_mtx);
    ERROR_OUT(xc);

  } else if (typ == VECSXP) {

    const R_xlen_t xlen = Rf_xlength(x);
    for (R_xlen_t i = 0; i < xlen; i++) {
      rnng_wait_thread_create(NANO_VECTOR(x)[i]);
    }

  }

  return x;

}

static void rnng_signal_thread(void *args) {

  nano_thread_duo *duo = (nano_thread_duo *) args;
  nano_cv *ncv = duo->cv;
  nng_mtx *mtx = ncv->mtx;
  nng_cv *cv = ncv->cv;
  nano_cv *ncv2 = duo->cv2;
  nng_mtx *mtx2 = ncv2->mtx;
  nng_cv *cv2 = ncv2->cv;

  int incr, cond = 0;

  nng_mtx_lock(mtx);
  while (ncv->condition == cond)
    nng_cv_wait(cv);
  if (ncv->condition < 0) {
    ncv->condition = cond;
    nng_mtx_unlock(mtx);
    return;
  }
  incr = ncv->condition - cond;
  cond = cond + incr;
  nng_mtx_unlock(mtx);

  while (1) {

    nng_mtx_lock(mtx2);
    ncv2->condition = ncv2->condition + incr;
    nng_cv_wake(cv2);
    nng_mtx_unlock(mtx2);

    nng_mtx_lock(mtx);
    while (ncv->condition == cond)
      nng_cv_wait(cv);
    if (ncv->condition < 0) {
      ncv->condition = cond;
      nng_mtx_unlock(mtx);
      break;
    }
    incr = ncv->condition - cond;
    cond = cond + incr;
    nng_mtx_unlock(mtx);

  }

}

SEXP rnng_signal_thread_create(SEXP cv, SEXP cv2) {

  if (NANO_PTR_CHECK(cv, nano_CvSymbol))
    Rf_error("'cv' is not a valid Condition Variable");

  if (NANO_PTR_CHECK(cv2, nano_CvSymbol))
    Rf_error("'cv2' is not a valid Condition Variable");

  int xc;
  nano_thread_duo *duo = malloc(sizeof(nano_thread_duo));
  NANO_ENSURE_ALLOC(duo);

  SEXP existing = Rf_getAttrib(cv, R_MissingArg);
  if (existing != R_NilValue) {
    thread_duo_finalizer(existing);
    R_ClearExternalPtr(existing);
  }

  nano_cv *ncv = (nano_cv *) NANO_PTR(cv);
  nano_cv *ncv2 = (nano_cv *) NANO_PTR(cv2);
  duo->cv = ncv;
  duo->cv2 = ncv2;

  nng_mtx *dmtx = ncv->mtx;
  nng_mtx_lock(dmtx);
  ncv->condition = 0;
  nng_mtx_unlock(dmtx);

  if ((xc = nng_thread_create(&duo->thr, rnng_signal_thread, duo)))
    goto fail;

  SEXP xptr = R_MakeExternalPtr(duo, R_NilValue, R_NilValue);
  Rf_setAttrib(cv, R_MissingArg, xptr);
  R_RegisterCFinalizerEx(xptr, thread_duo_finalizer, TRUE);

  return cv2;

  fail:
  free(duo);
  Rf_setAttrib(cv, R_MissingArg, R_NilValue);
  failmem:
  ERROR_OUT(xc);

}

char *nano_readline(void) {

  size_t sz = NANONEXT_INIT_BUFSIZE;
  size_t cur = 0;
  char *buf = malloc(sz);
  if (buf == NULL) {
    return NULL;
  }

  int c;
  while ((c = fgetc(stdin)) != EOF) {
    if (cur + 1 >= sz) {
      sz += sz;
      char *nbuf = realloc(buf, sz);
      if (nbuf == NULL)
        break;
      buf = nbuf;
    }

    buf[cur++] = (char) c;
    if (c == '\n')
      break;
  }

  if (cur == 0 && c == EOF) {
    free(buf);
    return NULL;
  }

  buf[cur] = '\0';
  return buf;

}

void nano_read_thread(void *arg) {

  int xc = 0;
  nng_socket sock = {0};
  nng_dialer dp = {0};
  if ((xc = nng_push0_open(&sock)) ||
      (xc = nng_dialer_create(&dp, sock, "inproc://nanonext-reserved-reader")) ||
      (xc = nng_dialer_start(dp, 0)))
    goto cleanup;

  char *buf = NULL;
  while (1) {
    buf = nano_readline();
    if (buf == NULL)
      break;
    xc = nng_send(sock, buf, strlen(buf) + 1, 0);
    free(buf);
    if (xc)
      break;
  }

  cleanup:
  nng_close(sock);

}

SEXP rnng_read_stdin(SEXP interactive) {

  if (NANO_INTEGER(interactive))
    Rf_error("can only be used in non-interactive sessions");

  int xc;
  nng_socket *sock = NULL;
  nng_listener *lp = NULL;
  sock = malloc(sizeof(nng_socket));
  NANO_ENSURE_ALLOC(sock);
  lp = calloc(1, sizeof(nng_listener));
  NANO_ENSURE_ALLOC(lp);

  if ((xc = nng_pull0_open(sock)) ||
      (xc = nng_listener_create(lp, *sock, "inproc://nanonext-reserved-reader")) ||
      (xc = nng_listener_start(*lp, 0)))
    goto fail;

  nng_thread *thr;

  if ((xc = nng_thread_create(&thr, nano_read_thread, NULL)))
    ERROR_OUT(xc);

  SEXP socket, con, thread;
  PROTECT(thread = R_MakeExternalPtr(thr, R_NilValue, R_NilValue));
  R_RegisterCFinalizerEx(thread, thread_finalizer, TRUE);
  PROTECT(con = R_MakeExternalPtr(lp, R_NilValue, thread));
  R_RegisterCFinalizerEx(con, listener_finalizer, TRUE);
  PROTECT(socket = R_MakeExternalPtr(sock, nano_SocketSymbol, con));
  R_RegisterCFinalizerEx(socket, socket_finalizer, TRUE);

  NANO_CLASS2(socket, "nanoSocket", "nano");
  Rf_setAttrib(socket, nano_IdSymbol, Rf_ScalarInteger(nng_socket_id(*sock)));
  Rf_setAttrib(socket, nano_ProtocolSymbol, Rf_mkString("pull"));
  Rf_setAttrib(socket, nano_StateSymbol, Rf_mkString("opened"));

  UNPROTECT(3);
  return socket;

  fail:
  nng_close(*sock);
  failmem:
  free(lp);
  free(sock);
  ERROR_OUT(xc);

}
