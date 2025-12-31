//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2020 Dirac Research <robert.bielik@dirac.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_H
#define NNG_SUPPLEMENTAL_HTTP_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct nng_tls_config;

enum nng_http_status {
	NNG_HTTP_STATUS_CONTINUE                 = 100,
	NNG_HTTP_STATUS_SWITCHING                = 101,
	NNG_HTTP_STATUS_PROCESSING               = 102,
	NNG_HTTP_STATUS_OK                       = 200,
	NNG_HTTP_STATUS_CREATED                  = 201,
	NNG_HTTP_STATUS_ACCEPTED                 = 202,
	NNG_HTTP_STATUS_NOT_AUTHORITATIVE        = 203,
	NNG_HTTP_STATUS_NO_CONTENT               = 204,
	NNG_HTTP_STATUS_RESET_CONTENT            = 205,
	NNG_HTTP_STATUS_PARTIAL_CONTENT          = 206,
	NNG_HTTP_STATUS_MULTI_STATUS             = 207,
	NNG_HTTP_STATUS_ALREADY_REPORTED         = 208,
	NNG_HTTP_STATUS_IM_USED                  = 226,
	NNG_HTTP_STATUS_MULTIPLE_CHOICES         = 300,
	NNG_HTTP_STATUS_STATUS_MOVED_PERMANENTLY = 301,
	NNG_HTTP_STATUS_FOUND                    = 302,
	NNG_HTTP_STATUS_SEE_OTHER                = 303,
	NNG_HTTP_STATUS_NOT_MODIFIED             = 304,
	NNG_HTTP_STATUS_USE_PROXY                = 305,
	NNG_HTTP_STATUS_TEMPORARY_REDIRECT       = 307,
	NNG_HTTP_STATUS_PERMANENT_REDIRECT       = 308,
	NNG_HTTP_STATUS_BAD_REQUEST              = 400,
	NNG_HTTP_STATUS_UNAUTHORIZED             = 401,
	NNG_HTTP_STATUS_PAYMENT_REQUIRED         = 402,
	NNG_HTTP_STATUS_FORBIDDEN                = 403,
	NNG_HTTP_STATUS_NOT_FOUND                = 404,
	NNG_HTTP_STATUS_METHOD_NOT_ALLOWED       = 405,
	NNG_HTTP_STATUS_NOT_ACCEPTABLE           = 406,
	NNG_HTTP_STATUS_PROXY_AUTH_REQUIRED      = 407,
	NNG_HTTP_STATUS_REQUEST_TIMEOUT          = 408,
	NNG_HTTP_STATUS_CONFLICT                 = 409,
	NNG_HTTP_STATUS_GONE                     = 410,
	NNG_HTTP_STATUS_LENGTH_REQUIRED          = 411,
	NNG_HTTP_STATUS_PRECONDITION_FAILED      = 412,
	NNG_HTTP_STATUS_PAYLOAD_TOO_LARGE        = 413,
	NNG_HTTP_STATUS_ENTITY_TOO_LONG          = 414,
	NNG_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE   = 415,
	NNG_HTTP_STATUS_RANGE_NOT_SATISFIABLE    = 416,
	NNG_HTTP_STATUS_EXPECTATION_FAILED       = 417,
	NNG_HTTP_STATUS_TEAPOT                   = 418,
	NNG_HTTP_STATUS_UNPROCESSABLE_ENTITY     = 422,
	NNG_HTTP_STATUS_LOCKED                   = 423,
	NNG_HTTP_STATUS_FAILED_DEPENDENCY        = 424,
	NNG_HTTP_STATUS_UPGRADE_REQUIRED         = 426,
	NNG_HTTP_STATUS_PRECONDITION_REQUIRED    = 428,
	NNG_HTTP_STATUS_TOO_MANY_REQUESTS        = 429,
	NNG_HTTP_STATUS_HEADERS_TOO_LARGE        = 431,
	NNG_HTTP_STATUS_UNAVAIL_LEGAL_REASONS    = 451,
	NNG_HTTP_STATUS_INTERNAL_SERVER_ERROR    = 500,
	NNG_HTTP_STATUS_NOT_IMPLEMENTED          = 501,
	NNG_HTTP_STATUS_BAD_GATEWAY              = 502,
	NNG_HTTP_STATUS_SERVICE_UNAVAILABLE      = 503,
	NNG_HTTP_STATUS_GATEWAY_TIMEOUT          = 504,
	NNG_HTTP_STATUS_HTTP_VERSION_NOT_SUPP    = 505,
	NNG_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES  = 506,
	NNG_HTTP_STATUS_INSUFFICIENT_STORAGE     = 507,
	NNG_HTTP_STATUS_LOOP_DETECTED            = 508,
	NNG_HTTP_STATUS_NOT_EXTENDED             = 510,
	NNG_HTTP_STATUS_NETWORK_AUTH_REQUIRED    = 511,
};

typedef struct nng_http_req nng_http_req;

NNG_DECL int nng_http_req_alloc(nng_http_req **, const nng_url *);

NNG_DECL void nng_http_req_free(nng_http_req *);

NNG_DECL const char *nng_http_req_get_method(nng_http_req *);

NNG_DECL const char *nng_http_req_get_version(nng_http_req *);

NNG_DECL const char *nng_http_req_get_uri(nng_http_req *);

NNG_DECL int nng_http_req_set_header(
    nng_http_req *, const char *, const char *);

NNG_DECL int nng_http_req_add_header(
    nng_http_req *, const char *, const char *);

NNG_DECL int nng_http_req_del_header(nng_http_req *, const char *);

NNG_DECL const char *nng_http_req_get_header(nng_http_req *, const char *);

NNG_DECL int nng_http_req_set_method(nng_http_req *, const char *);

NNG_DECL int nng_http_req_set_version(nng_http_req *, const char *);

NNG_DECL int nng_http_req_set_uri(nng_http_req *, const char *);

NNG_DECL int nng_http_req_set_data(nng_http_req *, const void *, size_t);

NNG_DECL int nng_http_req_copy_data(nng_http_req *, const void *, size_t);

NNG_DECL void nng_http_req_get_data(nng_http_req *, void **, size_t *);

typedef struct nng_http_res nng_http_res;

NNG_DECL int nng_http_res_alloc(nng_http_res **);

NNG_DECL int nng_http_res_alloc_error(nng_http_res **, uint16_t);

NNG_DECL void nng_http_res_free(nng_http_res *);

NNG_DECL uint16_t nng_http_res_get_status(nng_http_res *);

NNG_DECL int nng_http_res_set_status(nng_http_res *, uint16_t);

NNG_DECL const char *nng_http_res_get_reason(nng_http_res *);

NNG_DECL int nng_http_res_set_reason(nng_http_res *, const char *);

NNG_DECL int nng_http_res_set_header(
    nng_http_res *, const char *, const char *);

NNG_DECL int nng_http_res_add_header(
    nng_http_res *, const char *, const char *);

NNG_DECL int nng_http_res_del_header(nng_http_res *, const char *);

NNG_DECL const char *nng_http_res_get_header(nng_http_res *, const char *);

NNG_DECL int nng_http_res_set_version(nng_http_res *, const char *);

NNG_DECL const char *nng_http_res_get_version(nng_http_res *);

NNG_DECL void nng_http_res_get_data(nng_http_res *, void **, size_t *);

NNG_DECL int nng_http_res_set_data(nng_http_res *, const void *, size_t);

NNG_DECL int nng_http_res_copy_data(nng_http_res *, const void *, size_t);

typedef struct nng_http_conn nng_http_conn;

NNG_DECL void nng_http_conn_close(nng_http_conn *);

NNG_DECL void nng_http_conn_read(nng_http_conn *, nng_aio *);

NNG_DECL void nng_http_conn_read_all(nng_http_conn *, nng_aio *);

NNG_DECL void nng_http_conn_write(nng_http_conn *, nng_aio *);

NNG_DECL void nng_http_conn_write_all(nng_http_conn *, nng_aio *);

NNG_DECL void nng_http_conn_write_req(
    nng_http_conn *, nng_http_req *, nng_aio *);

NNG_DECL void nng_http_conn_write_res(
    nng_http_conn *, nng_http_res *, nng_aio *);

NNG_DECL void nng_http_conn_read_req(
    nng_http_conn *, nng_http_req *, nng_aio *);

NNG_DECL void nng_http_conn_read_res(
    nng_http_conn *, nng_http_res *, nng_aio *);

NNG_DECL void nng_http_req_reset(nng_http_req *);

NNG_DECL void nng_http_res_reset(nng_http_res *);

typedef struct nng_http_handler nng_http_handler;

NNG_DECL int nng_http_handler_alloc(
    nng_http_handler **, const char *, void (*)(nng_aio *));

NNG_DECL void nng_http_handler_free(nng_http_handler *);

NNG_DECL int nng_http_handler_alloc_file(
    nng_http_handler **, const char *, const char *);

NNG_DECL int nng_http_handler_alloc_static(
    nng_http_handler **, const char *, const void *, size_t, const char *);

NNG_DECL int nng_http_handler_alloc_redirect(
    nng_http_handler **, const char *, uint16_t, const char *);

NNG_DECL int nng_http_handler_alloc_directory(
    nng_http_handler **, const char *, const char *);

NNG_DECL int nng_http_handler_set_method(nng_http_handler *, const char *);

NNG_DECL int nng_http_handler_set_host(nng_http_handler *, const char *);

NNG_DECL int nng_http_handler_collect_body(nng_http_handler *, bool, size_t);

NNG_DECL int nng_http_handler_set_tree(nng_http_handler *);

NNG_DECL int nng_http_handler_set_tree_exclusive(nng_http_handler *);

NNG_DECL int nng_http_handler_set_data(
    nng_http_handler *, void *, void (*)(void *));

NNG_DECL void *nng_http_handler_get_data(nng_http_handler *);

typedef struct nng_http_server nng_http_server;

NNG_DECL int nng_http_server_hold(nng_http_server **, const nng_url *);

NNG_DECL void nng_http_server_release(nng_http_server *);

NNG_DECL int nng_http_server_start(nng_http_server *);

NNG_DECL void nng_http_server_stop(nng_http_server *);

NNG_DECL int nng_http_server_add_handler(
    nng_http_server *, nng_http_handler *);

NNG_DECL int nng_http_server_del_handler(
    nng_http_server *, nng_http_handler *);

NNG_DECL int nng_http_server_set_tls(
    nng_http_server *, struct nng_tls_config *);

NNG_DECL int nng_http_server_get_tls(
    nng_http_server *, struct nng_tls_config **);

NNG_DECL int nng_http_server_get_addr(nng_http_server *, nng_sockaddr *);

NNG_DECL int nng_http_server_set_error_page(
    nng_http_server *, uint16_t, const char *);

NNG_DECL int nng_http_server_set_error_file(
    nng_http_server *, uint16_t, const char *);

NNG_DECL int nng_http_server_res_error(nng_http_server *, nng_http_res *);

NNG_DECL int nng_http_hijack(nng_http_conn *);

typedef struct nng_http_client nng_http_client;

NNG_DECL int nng_http_client_alloc(nng_http_client **, const nng_url *);

NNG_DECL void nng_http_client_free(nng_http_client *);

NNG_DECL int nng_http_client_set_tls(
    nng_http_client *, struct nng_tls_config *);

NNG_DECL int nng_http_client_get_tls(
    nng_http_client *, struct nng_tls_config **);

NNG_DECL void nng_http_client_connect(nng_http_client *, nng_aio *);

NNG_DECL void nng_http_conn_transact(
    nng_http_conn *, nng_http_req *, nng_http_res *, nng_aio *);

NNG_DECL void nng_http_client_transact(
    nng_http_client *, nng_http_req *, nng_http_res *, nng_aio *);

#ifdef __cplusplus
}
#endif

#endif
