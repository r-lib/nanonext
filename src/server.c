// nanonext - HTTP REST Sever --------------------------------------------------

#include <time.h>
#define NANONEXT_HTTP
#define NANONEXT_IO
#include "nanonext.h"

// Echo server -----------------------------------------------------------------

static void nano_printf(const int err, const char *fmt, ...) {

  char buf[NANONEXT_INIT_BUFSIZE];
  va_list arg_ptr;

  va_start(arg_ptr, fmt);
  int bytes = vsnprintf(buf, NANONEXT_INIT_BUFSIZE, fmt, arg_ptr);
  va_end(arg_ptr);

  if (write(err ? STDERR_FILENO : STDOUT_FILENO, buf, (size_t) bytes)) {};

}

static void fatal(const char *reason, int xc) {
  nano_printf(1, "%s: %s\n", reason, nng_strerror(xc));
}

void echo_handle(nng_aio *aio) {
  
  nng_http_req *req = nng_aio_get_input(aio, 0);
  nng_http_res *res;
  const char *method, *uri, *version;
  void *data;
  size_t sz;
  char *response_json;
  size_t response_len;
  int xc;
  
  if ((xc = nng_http_res_alloc(&res))) {
    nng_aio_finish(aio, xc);
    return;
  }
  
  // Get request information
  method = nng_http_req_get_method(req);
  uri = nng_http_req_get_uri(req);
  version = nng_http_req_get_version(req);
  nng_http_req_get_data(req, &data, &sz);
  
  // Start building JSON response
  response_len = 4096; // Start with reasonable buffer size
  response_json = malloc(response_len);
  if (!response_json) {
    nng_http_res_free(res);
    nng_aio_finish(aio, NNG_ENOMEM);
    return;
  }
  
  // Build JSON response with escaped strings
  int written = snprintf(response_json, response_len,
    "{\n"
    "  \"method\": \"%s\",\n"
    "  \"uri\": \"%s\",\n"
    "  \"version\": \"%s\",\n"
    "  \"headers\": {\n",
    method ? method : "UNKNOWN",
    uri ? uri : "/",
    version ? version : "HTTP/1.1"
  );
  
  // Add headers (simplified - would need more robust header enumeration)
  const char *content_type = nng_http_req_get_header(req, "Content-Type");
  const char *user_agent = nng_http_req_get_header(req, "User-Agent");
  const char *host = nng_http_req_get_header(req, "Host");
  const char *authorization = nng_http_req_get_header(req, "Authorization");
  
  if (content_type || user_agent || host || authorization) {
    if (content_type) {
      written += snprintf(response_json + written, response_len - written,
        "    \"Content-Type\": \"%s\"", content_type);
      if (user_agent || host || authorization) written += snprintf(response_json + written, response_len - written, ",\n");
      else written += snprintf(response_json + written, response_len - written, "\n");
    }
    if (user_agent) {
      written += snprintf(response_json + written, response_len - written,
        "    \"User-Agent\": \"%s\"", user_agent);
      if (host || authorization) written += snprintf(response_json + written, response_len - written, ",\n");
      else written += snprintf(response_json + written, response_len - written, "\n");
    }
    if (host) {
      written += snprintf(response_json + written, response_len - written,
        "    \"Host\": \"%s\"", host);
      if (authorization) written += snprintf(response_json + written, response_len - written, ",\n");
      else written += snprintf(response_json + written, response_len - written, "\n");
    }
    if (authorization) {
      written += snprintf(response_json + written, response_len - written,
        "    \"Authorization\": \"%s\"\n", authorization);
    }
  }
  
  written += snprintf(response_json + written, response_len - written,
    "  },\n"
    "  \"data_size\": %zu,\n",
    sz
  );
  
  // Add data if present (limit size for safety)
  if (data && sz > 0) {
    written += snprintf(response_json + written, response_len - written,
      "  \"data\": \"");
    
    // Add data content (escape and truncate if needed)
    size_t data_limit = (sz < 1000) ? sz : 1000;  // Limit to 1000 bytes
    for (size_t i = 0; i < data_limit && written < response_len - 100; i++) {
      char c = ((char*)data)[i];
      if (c == '"') {
        written += snprintf(response_json + written, response_len - written, "\\\"");
      } else if (c == '\\') {
        written += snprintf(response_json + written, response_len - written, "\\\\");
      } else if (c == '\n') {
        written += snprintf(response_json + written, response_len - written, "\\n");
      } else if (c == '\r') {
        written += snprintf(response_json + written, response_len - written, "\\r");
      } else if (c == '\t') {
        written += snprintf(response_json + written, response_len - written, "\\t");
      } else if (c >= 32 && c < 127) {
        response_json[written++] = c;
      } else {
        written += snprintf(response_json + written, response_len - written, "\\u%04x", (unsigned char)c);
      }
    }
    
    if (sz > data_limit) {
      written += snprintf(response_json + written, response_len - written,
        "... (truncated, showing %zu of %zu bytes)", data_limit, sz);
    }
    
    written += snprintf(response_json + written, response_len - written, "\",\n");
  } else {
    written += snprintf(response_json + written, response_len - written,
      "  \"data\": null,\n");
  }
  
  // Add timestamp
  time_t now;
  time(&now);
  written += snprintf(response_json + written, response_len - written,
    "  \"timestamp\": \"%s\",\n"
    "  \"server\": \"nanonext echo server\"\n"
    "}", 
    ctime(&now)
  );
  
  // Remove newline from ctime
  char *newline = strchr(response_json + written - 50, '\n');
  if (newline) *newline = ' ';
  
  // Set response headers
  nng_http_res_set_status(res, NNG_HTTP_STATUS_OK);
  nng_http_res_set_header(res, "Content-Type", "application/json");
  nng_http_res_set_header(res, "Server", "nanonext-echo/1.0");
  
  // Set response body
  if ((xc = nng_http_res_copy_data(res, response_json, strlen(response_json)))) {
    free(response_json);
    nng_http_res_free(res);
    nng_aio_finish(aio, xc);
    return;
  }
  
  free(response_json);
  nng_aio_set_output(aio, 0, res);
  nng_aio_finish(aio, 0);
}

void echo_start(void *arg) {
  
  const char *addr = (const char *) arg;
  nng_http_server *server;
  nng_http_handler *handler;
  nng_url *url;
  int xc;
  
  if ((xc = nng_url_parse(&url, addr)))
    fatal("nng_url_parse", xc);
  
  if ((xc = nng_http_server_hold(&server, url)))
    fatal("nng_http_server_hold", xc);
  
  if ((xc = nng_http_handler_alloc(&handler, url->u_path, echo_handle)))
    fatal("nng_http_handler_alloc", xc);
  
  // Accept all HTTP methods
  if ((xc = nng_http_handler_set_method(handler, NULL)))
    fatal("nng_http_handler_set_method", xc);
  
  if ((xc = nng_http_handler_collect_body(handler, true, 1024 * 128)))
    fatal("nng_http_handler_collect_body", xc);
  
  if ((xc = nng_http_server_add_handler(server, handler)))
    fatal("nng_http_handler_add_handler", xc);
  
  if ((xc = nng_http_server_start(server)))
    fatal("nng_http_server_start", xc);
  
  nng_url_free(url);
}

static void echo_thread_finalizer(SEXP xptr) {
  if (NANO_PTR(xptr) == NULL) return;
  nng_thread *thr = (nng_thread *) NANO_PTR(xptr);
  nng_thread_destroy(thr);
}

SEXP rnng_echo_server(SEXP url) {
  
  const char *addr = CHAR(STRING_ELT(url, 0));
  nng_thread *thr;
  int xc;
  
  if ((xc = nng_thread_create(&thr, echo_start, (void *) addr)))
    ERROR_OUT(xc);
  
  SEXP xptr = R_MakeExternalPtr(thr, R_NilValue, R_NilValue);
  R_RegisterCFinalizerEx(xptr, echo_thread_finalizer, TRUE);
  
  return xptr;
}
