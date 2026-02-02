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
#include "nng_structs.h"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

typedef struct nano_handle_s {
  nng_url *url;
  nng_http_client *cli;
  nng_http_req *req;
  nng_http_res *res;
  nng_tls_config *cfg;
} nano_handle;

#endif

#ifdef NANONEXT_IO
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#endif

#ifdef NANONEXT_NET
#ifdef _WIN32
#if !defined(_WIN32_WINNT) || (defined(_WIN32_WINNT) && (_WIN32_WINNT < 0x0600))
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <sys/uio.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#endif
#endif

#ifdef NANONEXT_SIGNALS
#ifndef _WIN32
#include <unistd.h>
#endif
#include <signal.h>
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
#ifdef MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#endif
#include <errno.h>
#endif

#include <inttypes.h>
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
#if defined(NANONEXT_SIGNALS)
#ifdef _WIN32
#include <Rembedded.h>
#else
extern int R_interrupts_pending;
#endif
#endif

#define NANO_PTR(x) (void *) CAR(x)
#define NANO_PTR_CHECK(x, tag) (TAG(x) != tag || NANO_PTR(x) == NULL)
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

#define ERROR_OUT(xc) Rf_error("%d | %s", xc, nng_strerror(xc))
#define ERROR_RET(xc) { Rf_warning("%d | %s", xc, nng_strerror(xc)); return mk_error(xc); }
#define NANONEXT_INIT_BUFSIZE 4096
#define NANONEXT_SERIAL_VER 3
#define NANONEXT_SERIAL_THR 67108864
#define NANONEXT_CHUNK_SIZE 67108864 // must be <= INT_MAX
#define NANONEXT_STR_SIZE 40
#define NANONEXT_WAIT_DUR 1000
#define NANONEXT_SLEEP_DUR 200
#define NANO_ALLOC(x, sz)                                      \
  (x)->buf = malloc(sz);                                       \
  if ((x)->buf == NULL) Rf_error("memory allocation failed");  \
  (x)->len = sz;                                               \
  (x)->cur = 0
#define NANO_INIT(x, ptr, sz)                                  \
  (x)->buf = ptr;                                              \
  (x)->len = 0;                                                \
  (x)->cur = sz
#define NANO_FREE(x) if (x.len) free(x.buf)
#define NANO_CLASS2(x, cls1, cls2)                             \
  SEXP klass = Rf_allocVector(STRSXP, 2);                      \
  Rf_classgets(x, klass);                                      \
  SET_STRING_ELT(klass, 0, Rf_mkChar(cls1));                   \
  SET_STRING_ELT(klass, 1, Rf_mkChar(cls2))
#define NANO_ENSURE_ALLOC(x) if (x == NULL) { xc = 2; goto failmem; }
#define NANO_URL_MAX 8192

typedef union nano_opt_u {
  char *str;
  uint64_t u;
  size_t s;
  nng_duration d;
  int i;
  bool b;
} nano_opt;

typedef struct nano_stream_s {
  nng_stream *stream;
  union {
    nng_stream_dialer *dial;
    nng_stream_listener *list;
  } endpoint;
  nng_tls_config *tls;
  int textframes;
  int msgmode;
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
  nng_ctx *ctx;
  nng_aio *aio;
  void *cb;
  int id;
} nano_saio;

typedef struct nano_cv_s {
  int condition;
  int flag;
  nng_mtx *mtx;
  nng_cv *cv;
} nano_cv;

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

typedef struct nano_buf_s {
  unsigned char *buf;
  size_t len;
  size_t cur;
} nano_buf;

typedef struct nano_serial_bundle_s {
  R_outpstream_t outpstream;
  R_inpstream_t inpstream;
  SEXP klass;
} nano_serial_bundle;

typedef enum nano_list_op {
  INIT,
  FINALIZE,
  COMPLETE,
  FREE,
  SHUTDOWN
} nano_list_op;

#ifdef NANONEXT_HTTP

typedef struct nano_ws_conn_s nano_ws_conn;
typedef struct nano_http_server_s nano_http_server;
typedef struct nano_http_handler_info_s nano_http_handler_info;
typedef struct nano_http_request_s nano_http_request;

typedef enum {
  WS_STATE_OPEN,      // Connection active, can send/receive
  WS_STATE_CLOSING,   // Close initiated, waiting for cleanup
  WS_STATE_CLOSED     // Fully closed, safe to free
} ws_conn_state;

typedef struct nano_ws_conn_s {
  nng_stream *stream;               // WebSocket stream (framing automatic)
  nng_aio *recv_aio;                // For async receive (msg mode)
  nng_aio *send_aio;                // For async send (msg mode)
  nano_http_handler_info *handler;  // Back-reference to handler
  nano_ws_conn *next;               // Linked list
  nano_ws_conn *prev;               // Doubly-linked for O(1) removal
  SEXP xptr;                        // R external pointer (nanoWsConn object)
  int id;                           // Unique connection ID
  ws_conn_state state;              // Connection state (protected by server->mtx)
  int onclose_scheduled;            // Prevents duplicate on_close callbacks
} nano_ws_conn;

typedef struct nano_http_handler_info_s {
  nng_http_handler *handler;        // NNG HTTP handler (NULL for WS)
  SEXP callback;                    // HTTP callback or WS on_message
  nano_http_server *server;         // Back-reference
  // WebSocket handler fields (all NULL/0 for non-WS handlers):
  nng_stream_listener *ws_listener; // WebSocket listener
  nng_aio *ws_accept_aio;           // Accept AIO for this WS handler
  nano_ws_conn *ws_conns;           // Linked list of connections
  SEXP on_open;                     // R callback for connection open
  SEXP on_close;                    // R callback for connection close
  int textframes;                   // Text frame mode
} nano_http_handler_info;

typedef struct nano_http_request_s {
  nng_aio *aio;                     // The HTTP AIO to complete
  nng_http_req *req;                // The HTTP request (valid until aio finished)
  SEXP callback;                    // R callback function
  nano_http_server *server;         // Back-reference to server
  nano_http_request *next;          // Linked list for tracking
  nano_http_request *prev;
  int cancelled;                    // Set when server stops (protected by server->mtx)
} nano_http_request;

typedef enum {
  SERVER_CREATED,   // Server created but not started
  SERVER_STARTED,   // Server running
  SERVER_STOPPED    // Server stopped
} nano_server_state;

typedef struct nano_http_server_s {
  nng_http_server *server;          // NNG HTTP server
  nng_tls_config *tls;              // TLS configuration
  nano_http_handler_info *handlers; // Array of handler info
  int handler_count;                // Number of handlers
  nano_http_request *pending_reqs;  // Linked list of pending HTTP requests
  nng_mtx *mtx;                     // Mutex for thread safety
  int ws_conn_counter;              // Server-wide unique connection ID counter
  nano_server_state state;          // Server lifecycle state
  SEXP xptr;                        // R external pointer for this server
  SEXP prot;                        // Pairlist for GC protection of callbacks
} nano_http_server;

typedef struct ws_message_s {
  nano_ws_conn *conn;
  nng_msg *msg;
} ws_message;

#endif

extern void (*eln2)(void (*)(void *), void *, double, int);

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
extern SEXP nano_HttpServerSymbol;
extern SEXP nano_WsConnSymbol;

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

static inline SEXP R_NewEnv(SEXP parent, int hash, int size) {
  (void) parent;
  (void) hash;
  (void) size;
  return Rf_allocSExp(ENVSXP);
}

#endif

#if R_VERSION < R_Version(4, 5, 0)

static inline SEXP R_mkClosure(SEXP formals, SEXP body, SEXP env) {
  SEXP fun = Rf_allocSExp(CLOSXP);
  SET_FORMALS(fun, formals);
  SET_BODY(fun, body);
  SET_CLOENV(fun, env);
  return fun;
}

#endif

static inline int nano_integer(const SEXP x) {
  return (TYPEOF(x) == INTSXP || TYPEOF(x) == LGLSXP) ? NANO_INTEGER(x) : Rf_asInteger(x);
}

static inline void later2(void (*fun)(void *), void *data) {
  eln2(fun, data, 0, 0);
}

void dialer_finalizer(SEXP);
void listener_finalizer(SEXP);
void socket_finalizer(SEXP);
void raio_invoke_cb(void *);
void haio_invoke_cb(void *);
SEXP mk_error(const int);
SEXP mk_error_data(const int);
SEXP nano_raw_char(const unsigned char *, const size_t);
void nano_serialize(nano_buf *, const SEXP, SEXP, int);
SEXP nano_unserialize(unsigned char *, const size_t, SEXP);
SEXP nano_decode(unsigned char *, const size_t, const uint8_t, SEXP);
void nano_encode(nano_buf *, const SEXP);
int nano_encode_mode(const SEXP);
int nano_matcharg(const SEXP);
SEXP nano_aio_result(SEXP);
SEXP nano_aio_get_msg(SEXP);
SEXP nano_aio_http_status(SEXP);

void pipe_cb_signal(nng_pipe, nng_pipe_ev, void *);
void tls_finalizer(SEXP);

void nano_load_later(void);
SEXP nano_PreserveObject(const SEXP);
void nano_ReleaseObject(SEXP);

void nano_list_do(nano_list_op, nano_aio *);
void nano_thread_shutdown(void);

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
SEXP rnng_dispatcher_run(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_eval_safe(SEXP);
SEXP rnng_fini(void);
SEXP rnng_fini_priors(void);
SEXP rnng_get_opt(SEXP, SEXP);
SEXP rnng_header_read(SEXP);
SEXP rnng_http_server_close(SEXP);
SEXP rnng_http_server_create(SEXP, SEXP, SEXP);
SEXP rnng_http_server_start(SEXP);
SEXP rnng_ip_addr(void);
SEXP rnng_is_error_value(SEXP);
SEXP rnng_is_nul_byte(SEXP);
SEXP rnng_listen(SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_listener_close(SEXP);
SEXP rnng_listener_start(SEXP);
SEXP rnng_marker_read(SEXP);
SEXP rnng_marker_set(SEXP);
SEXP rnng_messenger(SEXP);
SEXP rnng_messenger_thread_create(SEXP);
SEXP rnng_monitor_create(SEXP, SEXP);
SEXP rnng_monitor_read(SEXP);
SEXP rnng_ncurl(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_ncurl_aio(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_ncurl_session(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_ncurl_session_close(SEXP);
SEXP rnng_ncurl_transact(SEXP);
SEXP rnng_pipe_notify(SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_protocol_open(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_random(SEXP, SEXP);
SEXP rnng_read_stdin(SEXP);
SEXP rnng_reap(SEXP);
SEXP rnng_recv(SEXP, SEXP, SEXP, SEXP);
SEXP rnng_recv_aio(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_request(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_request_stop(SEXP);
SEXP rnng_send(SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_send_aio(SEXP, SEXP, SEXP, SEXP, SEXP, SEXP);
SEXP rnng_serial_config(SEXP, SEXP, SEXP);
SEXP rnng_set_opt(SEXP, SEXP, SEXP);
SEXP rnng_set_promise_context(SEXP, SEXP);
SEXP rnng_signal_thread_create(SEXP, SEXP);
SEXP rnng_sleep(SEXP);
SEXP rnng_stats_get(SEXP, SEXP);
SEXP rnng_status_code(SEXP);
SEXP rnng_stream_close(SEXP);
SEXP rnng_stream_open(SEXP, SEXP, SEXP, SEXP);
SEXP rnng_strerror(SEXP);
SEXP rnng_subscribe(SEXP, SEXP, SEXP);
SEXP rnng_tls_config(SEXP, SEXP, SEXP, SEXP);
SEXP rnng_traverse_precious(void);
SEXP rnng_unresolved(SEXP);
SEXP rnng_unresolved2(SEXP);
SEXP rnng_race_aio(SEXP, SEXP);
SEXP rnng_url_parse(SEXP);
SEXP rnng_version(void);
SEXP rnng_wait_thread_create(SEXP);
SEXP rnng_write_cert(SEXP, SEXP);
SEXP rnng_write_stdout(SEXP);
SEXP rnng_ws_close(SEXP);
SEXP rnng_ws_send(SEXP, SEXP);

#endif
