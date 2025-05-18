//praveen 🍉

#include <Rinternals.h>
#include <nng/nng.h>
#include <nng/protocol/pair0/pair.h>
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/util/platform.h>
#include <stdlib.h>
#include <string.h>

// A simple condition variable struct for demo purposes
typedef struct {
  int signaled;
} conditionVariable;

SEXP rnng_http_echo_server(SEXP s_port) {
  int port = INTEGER(s_port)[0];
  nng_http_server *server = NULL;
  nng_http_handler *handler = NULL;
  nng_url *url = NULL;
  char urlstr[128];
  int rv;

  snprintf(urlstr, sizeof(urlstr), "http://127.0.0.1:%d", port);

  if ((rv = nng_url_parse(&url, urlstr)) != 0)
    Rf_error("Failed to parse URL");

  if ((rv = nng_http_server_new(&server, url)) != 0)
    Rf_error("Failed to create HTTP server");

  // Handler echoes the request body back in the response
  if ((rv = nng_http_handler_alloc(&handler, "/", [](nng_http_request *req, nng_http_response *res, void *arg) {
    const void *body;
    size_t len;
    nng_http_req_get_data(req, &body, &len);
    nng_http_res_set_data(res, body, len);
    nng_http_res_set_status(res, NNG_HTTP_STATUS_OK);
    return 0;
  }, NULL)) != 0)
    Rf_error("Failed to create HTTP handler");

  if ((rv = nng_http_server_add_handler(server, handler)) != 0)
    Rf_error("Failed to add handler");

  if ((rv = nng_http_server_start(server)) != 0)
    Rf_error("Failed to start HTTP server");

  // Allocate and return a dummy conditionVariable for demo
  SEXP cv = PROTECT(R_MakeExternalPtr(malloc(sizeof(conditionVariable)), R_NilValue, R_NilValue));
  UNPROTECT(1);
  return cv;
}