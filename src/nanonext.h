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

// nanonext - header file ------------------------------------------------------

#ifndef NANONEXT_H
#define NANONEXT_H

#include <nng/nng.h>
#include <nng/supplemental/util/platform.h>
#include <nng/supplemental/tls/tls.h>

#ifdef NANONEXT_PROTOCOLS
#include <nng/protocol/bus0/bus.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/protocol/pair1/pair.h>
#include <nng/protocol/pubsub0/pub.h>
#include <nng/protocol/pubsub0/sub.h>
#include <nng/protocol/pipeline0/pull.h>
#include <nng/protocol/pipeline0/push.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/survey0/survey.h>
#include <nng/protocol/survey0/respond.h>
#endif

#ifdef NANONEXT_HTTP
#include <nng/supplemental/http/http.h>

typedef struct nano_handle_s {
  nng_url *url;
  nng_http_client *cli;
  nng_http_req *req;
  nng_http_res *res;
  nng_tls_config *cfg;
} nano_handle;

#endif

#ifdef NANONEXT_SIGNALS
#ifndef _WIN32
#include <unistd.h>
#endif
#include <signal.h>
#endif

#ifdef NANONEXT_IO
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#endif

#ifdef NANONEXT_TLS
#include <mbedtls/version.h>
#if MBEDTLS_VERSION_MAJOR < 3
#include <mbedtls/config.h>
#endif
#include <mbedtls/platform.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <errno.h>
#endif

#ifndef R_NO_REMAP
#define R_NO_REMAP
#endif
#ifndef STRICT_R_HEADERS
#define STRICT_R_HEADERS
#endif
#include <R.h>
#include <Rinternals.h>
#include <Rversion.h>
#include <R_ext/Visibility.h>
#if defined(NANONEXT_SIGNALS) && defined(_WIN32)
#include <Rembedded.h>
#endif

#define NANO_TAG(x) TAG(x)
#define NANO_PTR(x) (void *) CAR(x)
#define NANO_PROT(x) CDR(x)
#define NANO_ENCLOS(x) CDR(x)
#define NANO_SET_TAG(x, v) SET_TAG(x, v)
#define NANO_SET_PROT(x, v) SETCDR(x, v)
#define NANO_SET_ENCLOS(x, v) SETCDR(x, v)
#define NANO_DATAPTR(x) (void *) DATAPTR_RO(x)
#define NANO_VECTOR(x) ((const SEXP *) DATAPTR_RO(x))
#define NANO_STRING(x) CHAR(*((const SEXP *) DATAPTR_RO(x)))
#define NANO_STR_N(x, n) CHAR(((const SEXP *) DATAPTR_RO(x))[n])
#define NANO_INTEGER(x) *(int *) DATAPTR_RO(x)
#define NANO_ERROR(x) { Rf_error(x); return R_NilValue; }

#define ERROR_OUT(xc) Rf_error("%d | %s", xc, nng_strerror(xc))
#define ERROR_RET(xc) { Rf_warning("%d | %s", xc, nng_strerror(xc)); return mk_error(xc); }
#define NANONEXT_INIT_BUFSIZE 4096
#define NANONEXT_SERIAL_VER 3
#define NANONEXT_SERIAL_THR 134217728
#define NANONEXT_ERR_STRLEN 40
#define NANONEXT_LD_STRLEN 21
#define NANO_ALLOC(x, sz)                                      \
  (x)->buf = R_Calloc(sz, unsigned char);                      \
  (x)->len = sz;                                               \
  (x)->cur = 0
#define NANO_INIT(x, ptr, sz)                                  \
  (x)->buf = ptr;                                              \
  (x)->len = 0;                                                \
  (x)->cur = sz
#define NANO_FREE(x) if (x.len) R_Free(x.buf)
#define NANO_CLASS2(x, cls1, cls2)                             \
  SEXP klass = Rf_allocVector(STRSXP, 2);                      \
  Rf_classgets(x, klass);                                      \
  SET_STRING_ELT(klass, 0, Rf_mkChar(cls1));                   \
  SET_STRING_ELT(klass, 1, Rf_mkChar(cls2))

typedef union nano_opt_u {
  char *str;
  bool b;
  nng_duration d;
  int i;
  size_t s;
  uint64_t u;
} nano_opt;

typedef struct nano_stream_s {
  nng_stream *stream;
  union {
    nng_stream_dialer *dial;
    nng_stream_listener *list;
  } endpoint;
  nng_tls_config *tls;
  int textframes;
  enum {
    NANO_STREAM_DIALER,
    NANO_STREAM_LISTENER
  } mode;
} nano_stream;

typedef enum nano_aio_typ {
  SENDAIO,
  RECVAIO,
  REQAIO,
  IOV_SENDAIO,
  IOV_RECVAIO,
  HTTP_AIO,
  RECVAIOS,
  REQAIOS,
  IOV_RECVAIOS
} nano_aio_typ;

typedef struct nano_aio_s {
  nng_aio *aio;
  void *data;
  void *cb;
  void *next;
  int result;
  uint8_t mode;
  nano_aio_typ type;
} nano_aio;

typedef struct nano_saio_s {
  nng_aio *aio;
  void *cb;
} nano_saio;

typedef struct nano_cv_s {
  int condition;
  int flag;
  nng_mtx *mtx;
  nng_cv *cv;
} nano_cv;

typedef struct nano_cv_duo_s {
  nano_cv *cv;
  nano_cv *cv2;
} nano_cv_duo;

typedef struct nano_monitor_s {
  nano_cv *cv;
  int *ids;
  int size;
  int updates;
} nano_monitor;

typedef struct nano_thread_aio_s {
  nng_thread *thr;
  nano_cv *cv;
  nng_aio *aio;
} nano_thread_aio;

typedef struct nano_thread_duo_s {
  nng_thread *thr;
  nano_cv *cv;
  nano_cv *cv2;
} nano_thread_duo;

typedef struct nano_signal_s {
  nano_cv *cv;
  int *online;
} nano_signal;

typedef struct nano_buf_s {
  unsigned char *buf;
  size_t len;
  size_t cur;
} nano_buf;

extern void (*eln2)(void (*)(void *), void *, double, int);
extern uint8_t special_bit;
extern int nano_interrupt;

extern SEXP nano_AioSymbol;
extern SEXP nano_ContextSymbol;
extern SEXP nano_CvSymbol;
extern SEXP nano_DataSymbol;
extern SEXP nano_DialerSymbol;
extern SEXP nano_DotcallSymbol;
extern SEXP nano_HeadersSymbol;
extern SEXP nano_IdSymbol;
extern SEXP nano_ListenerSymbol;
extern SEXP nano_MonitorSymbol;
extern SEXP nano_ProtocolSymbol;
extern SEXP nano_ResolveSymbol;
extern SEXP nano_ResponseSymbol;
extern SEXP nano_ResultSymbol;
extern SEXP nano_SocketSymbol;
extern SEXP nano_StateSymbol;
extern SEXP nano_StatusSymbol;
extern SEXP nano_StreamSymbol;
extern SEXP nano_TlsSymbol;
extern SEXP nano_UrlSymbol;
extern SEXP nano_ValueSymbol;

extern SEXP nano_aioFuncMsg;
extern SEXP nano_aioFuncRes;
extern SEXP nano_aioNFuncs;
extern SEXP nano_error;
extern SEXP nano_precious;
extern SEXP nano_recvAio;
extern SEXP nano_reqAio;
extern SEXP nano_sendAio;
extern SEXP nano_success;
extern SEXP nano_unresolved;

#if R_VERSION < R_Version(4, 1, 0)
SEXP R_NewEnv(SEXP, int, int);
#endif
#if R_VERSION < R_Version(4, 5, 0)
SEXP R_mkClosure(SEXP, SEXP, SEXP);
#endif
SEXP nano_findVarInFrame(const SEXP, const SEXP);
SEXP nano_PreserveObject(const SEXP);
void nano_ReleaseObject(SEXP);
void raio_complete_interrupt(void *);
void raio_complete_signal(void *);
void sendaio_complete(void *);
void cv_finalizer(SEXP);
void dialer_finalizer(SEXP);
void listener_finalizer(SEXP);
void socket_finalizer(SEXP);
void later2(void (*)(void *), void *);
void raio_invoke_cb(void *);
int nano_integer(const SEXP);
SEXP mk_error(const int);
SEXP mk_error_data(const int);
SEXP rawToChar(const unsigned char *, const size_t);
void nano_serialize(nano_buf *, const SEXP, SEXP);
SEXP nano_unserialize(unsigned char *, const size_t, SEXP);
SEXP nano_decode(unsigned char *, const size_t, const uint8_t, SEXP);
void nano_encode(nano_buf *, const SEXP);
int nano_encodes(const SEXP);
int nano_matcharg(const SEXP);
int nano_matchargs(const SEXP);

void pipe_cb_signal(nng_pipe, nng_pipe_ev, void *);
void tls_finalizer(SEXP);

SEXP rnng_advance_rng_state(void);
SEXP rnng_aio_call(SEXP);
SEXP rnng_aio_collect(SEXP);
SEXP rnng_aio_collect_safe(SEXP);
SEXP rnng_aio_get_msg(SEXP);
SEXP rnng_aio_http_data(SEXP);
SEXP rnng_aio_http_headers(SEXP);
SEXP rnng_aio_http_status(SEXP);
SEXP rnng_aio_result(SEXP);
SEXP rnng_aio_stop(SEXP);
SEXP rnng_clock(void);
SEXP rnng_close(SEXP);
SEXP rnng_ctx_close(SEXP);
SEXP rnng_ctx_create(SEXP);
SEXP rnng_ctx_open(SEXP);
SEXP rnng_cv_alloc(void);
SEXP rnng_cv_reset(SEXP);
SEXP rnng_cv_signal(SEXP);
SEXP rnng_cv_until(SEXP, SEXP);
SEXP rnng_cv_until_safe(SEXP, SEXP);
SEXP rnng_cv_value(SEXP);
SEXP rnng_cv_wait(SEXP);
SEXP rnng_cv_wait_safe(SEXP);
SEXP rnng_dial(SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_dialer_close(SEXP);
SEXP rnng_dialer_start(SEXP, SEXP);
SEXP rnng_eval_safe(SEXP);
SEXP rnng_fini(void);
SEXP rnng_get_opt(SEXP, SEXP);
SEXP rnng_interrupt_switch(SEXP);
SEXP rnng_is_error_value(SEXP);
SEXP rnng_is_nul_byte(SEXP);
SEXP rnng_listen(SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_listener_close(SEXP);
SEXP rnng_listener_start(SEXP);
SEXP rnng_messenger(SEXP);
SEXP rnng_messenger_thread_create(SEXP);
SEXP rnng_monitor_create(SEXP, SEXP);
SEXP rnng_monitor_read(SEXP);
SEXP rnng_ncurl(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_ncurl_aio(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_ncurl_session(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_ncurl_session_close(SEXP);
SEXP rnng_ncurl_transact(SEXP);
SEXP rnng_pipe_notify(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_protocol_open(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_random(SEXP, SEXP);
SEXP rnng_reap(SEXP);
SEXP rnng_recv(SEXP, SEXP, SEXP, SEXP);
SEXP rnng_recv_aio(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_request(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_send(SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_send_aio(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_serial_config(SEXP, SEXP, SEXP, SEXP);
SEXP rnng_set_marker(SEXP);
SEXP rnng_set_opt(SEXP, SEXP, SEXP);
SEXP rnng_set_promise_context(SEXP, SEXP);
SEXP rnng_signal_thread_create(SEXP, SEXP);
SEXP rnng_sleep(SEXP);
SEXP rnng_socket_lock(SEXP, SEXP);
SEXP rnng_socket_unlock(SEXP);
SEXP rnng_stats_get(SEXP, SEXP);
SEXP rnng_status_code(SEXP);
SEXP rnng_stream_close(SEXP);
SEXP rnng_stream_dial(SEXP, SEXP, SEXP);
SEXP rnng_stream_listen(SEXP, SEXP, SEXP);
SEXP rnng_strerror(SEXP);
SEXP rnng_subscribe(SEXP, SEXP, SEXP);
SEXP rnng_thread_shutdown(void);
SEXP rnng_tls_config(SEXP, SEXP, SEXP, SEXP);
SEXP rnng_traverse_precious(void);
SEXP rnng_unresolved(SEXP);
SEXP rnng_unresolved2(SEXP);
SEXP rnng_url_parse(SEXP);
SEXP rnng_version(void);
SEXP rnng_wait_thread_create(SEXP);
SEXP rnng_write_cert(SEXP, SEXP, SEXP);

#endif
