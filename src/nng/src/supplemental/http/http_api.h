//
// Copyright 2023 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
// Copyright 2019 Devolutions <info@devolutions.net>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_HTTP_HTTP_API_H
#define NNG_SUPPLEMENTAL_HTTP_HTTP_API_H

#include "core/nng_impl.h"
#include <nng/supplemental/http/http.h>
#include <nng/supplemental/tls/tls.h>

#include <stdbool.h>

typedef struct nng_http_req     nni_http_req;
typedef struct nng_http_res     nni_http_res;
typedef struct nng_http_conn    nni_http_conn;
typedef struct nng_http_handler nni_http_handler;
typedef struct nng_http_server  nni_http_server;
typedef struct nng_http_client  nni_http_client;
typedef struct nng_http_chunk   nni_http_chunk;
typedef struct nng_http_chunks  nni_http_chunks;

extern const char *nni_http_reason(uint16_t);

extern int   nni_http_req_init(nni_http_req **);
extern void  nni_http_req_reset(nni_http_req *);
extern int   nni_http_req_get_buf(nni_http_req *, void **, size_t *);
extern int   nni_http_req_parse(nni_http_req *, void *, size_t, size_t *);
extern char *nni_http_req_headers(nni_http_req *);
extern void  nni_http_req_get_data(nni_http_req *, void **, size_t *);

extern void  nni_http_res_reset(nni_http_res *);
extern int   nni_http_res_get_buf(nni_http_res *, void **, size_t *);
extern int   nni_http_res_parse(nni_http_res *, void *, size_t, size_t *);
extern void  nni_http_res_get_data(nni_http_res *, void **, size_t *);
extern char *nni_http_res_headers(nni_http_res *);

extern int nni_http_chunks_init(nni_http_chunks **, size_t);

extern void nni_http_chunks_free(nni_http_chunks *);

extern nni_http_chunk *nni_http_chunks_iter(
    nni_http_chunks *, nni_http_chunk *);

extern size_t nni_http_chunks_size(nni_http_chunks *);

extern size_t nni_http_chunk_size(nni_http_chunk *);

extern void *nni_http_chunk_data(nni_http_chunk *);

extern int nni_http_chunks_parse(nni_http_chunks *, void *, size_t, size_t *);

extern void nni_http_read_chunks(
    nni_http_conn *, nni_http_chunks *, nni_aio *);

extern void  nni_http_conn_set_ctx(nni_http_conn *, void *);
extern void *nni_http_conn_get_ctx(nni_http_conn *);

extern int nni_http_conn_init(nni_http_conn **, nng_stream *);

extern void nni_http_conn_close(nni_http_conn *);
extern void nni_http_conn_fini(nni_http_conn *);
extern int  nni_http_conn_getopt(
     nni_http_conn *, const char *, void *, size_t *, nni_type);
extern int nni_http_conn_setopt(
    nni_http_conn *, const char *, const void *, size_t, nni_type);

extern int  nni_http_req_alloc(nni_http_req **, const nni_url *);
extern int  nni_http_res_alloc(nni_http_res **);
extern int  nni_http_res_alloc_error(nni_http_res **, uint16_t);
extern void nni_http_req_free(nni_http_req *);
extern void nni_http_res_free(nni_http_res *);
extern void nni_http_write_req(nni_http_conn *, nni_http_req *, nni_aio *);
extern void nni_http_write_res(nni_http_conn *, nni_http_res *, nni_aio *);
extern void nni_http_read_req(nni_http_conn *, nni_http_req *, nni_aio *);
extern void nni_http_read_res(nni_http_conn *, nni_http_res *, nni_aio *);

extern const char *nni_http_req_get_header(nni_http_req *, const char *);
extern const char *nni_http_res_get_header(nni_http_res *, const char *);
extern int nni_http_req_add_header(nni_http_req *, const char *, const char *);
extern int nni_http_res_add_header(nni_http_res *, const char *, const char *);
extern int nni_http_req_set_header(nni_http_req *, const char *, const char *);
extern int nni_http_res_set_header(nni_http_res *, const char *, const char *);
extern int nni_http_req_del_header(nni_http_req *, const char *);
extern int nni_http_res_del_header(nni_http_res *, const char *);
extern int nni_http_req_copy_data(nni_http_req *, const void *, size_t);
extern int nni_http_res_copy_data(nni_http_res *, const void *, size_t);
extern int nni_http_req_set_data(nni_http_req *, const void *, size_t);
extern int nni_http_res_set_data(nni_http_res *, const void *, size_t);
extern int nni_http_req_alloc_data(nni_http_req *, size_t);
extern int nni_http_res_alloc_data(nni_http_res *, size_t);
extern const char *nni_http_req_get_method(nni_http_req *);
extern const char *nni_http_req_get_version(nni_http_req *);
extern const char *nni_http_req_get_uri(nni_http_req *);
extern int         nni_http_req_set_method(nni_http_req *, const char *);
extern int         nni_http_req_set_version(nni_http_req *, const char *);
extern int         nni_http_req_set_uri(nni_http_req *, const char *);
extern uint16_t    nni_http_res_get_status(nni_http_res *);
extern int         nni_http_res_set_status(nni_http_res *, uint16_t);
extern const char *nni_http_res_get_version(nni_http_res *);
extern int         nni_http_res_set_version(nni_http_res *, const char *);
extern const char *nni_http_res_get_reason(nni_http_res *);
extern int         nni_http_res_set_reason(nni_http_res *, const char *);

extern bool nni_http_res_is_error(nni_http_res *);

extern int nni_http_alloc_html_error(char **, uint16_t, const char *);

extern void nni_http_read(nni_http_conn *, nni_aio *);
extern void nni_http_read_full(nni_http_conn *, nni_aio *);
extern void nni_http_write(nni_http_conn *, nni_aio *);
extern void nni_http_write_full(nni_http_conn *, nni_aio *);

extern int nni_http_server_init(nni_http_server **, const nni_url *);

extern void nni_http_server_fini(nni_http_server *);

extern int nni_http_server_add_handler(nni_http_server *, nni_http_handler *);

extern int nni_http_server_del_handler(nni_http_server *, nni_http_handler *);

extern int nni_http_server_set_tls(nni_http_server *, struct nng_tls_config *);

extern int nni_http_server_get_tls(
    nni_http_server *, struct nng_tls_config **);

extern int nni_http_server_set(
    nni_http_server *, const char *, const void *, size_t, nni_type);
extern int nni_http_server_get(
    nni_http_server *, const char *, void *, size_t *, nni_type);

extern int nni_http_server_start(nni_http_server *);

extern void nni_http_server_stop(nni_http_server *);

extern void nni_http_server_close(nni_http_server *);

extern int nni_http_server_set_error_page(
    nni_http_server *, uint16_t, const char *);

extern int nni_http_server_set_error_file(
    nni_http_server *, uint16_t, const char *);

extern int nni_http_server_res_error(nni_http_server *, nni_http_res *);

extern int nni_http_hijack(nni_http_conn *);

extern int nni_http_handler_init(
    nni_http_handler **, const char *, void (*)(nni_aio *));

extern int nni_http_handler_init_file(
    nni_http_handler **, const char *, const char *);

extern int nni_http_handler_init_file_ctype(
    nni_http_handler **, const char *, const char *, const char *);

extern int nni_http_handler_init_directory(
    nni_http_handler **, const char *, const char *);

extern int nni_http_handler_init_static(
    nni_http_handler **, const char *, const void *, size_t, const char *);

extern int nni_http_handler_init_redirect(
    nni_http_handler **, const char *, uint16_t, const char *);

extern void nni_http_handler_fini(nni_http_handler *);

extern void nni_http_handler_collect_body(nni_http_handler *, bool, size_t);

extern int nni_http_handler_set_tree(nni_http_handler *);

extern int nni_http_handler_set_tree_exclusive(nni_http_handler *);

extern int nni_http_handler_set_host(nni_http_handler *, const char *);

extern int nni_http_handler_set_method(nni_http_handler *, const char *);

extern int nni_http_handler_set_data(nni_http_handler *, void *, nni_cb);

extern void *nni_http_handler_get_data(nni_http_handler *);

extern const char *nni_http_handler_get_uri(nni_http_handler *);

extern int  nni_http_client_init(nni_http_client **, const nni_url *);
extern void nni_http_client_fini(nni_http_client *);

extern int nni_http_client_set_tls(nni_http_client *, struct nng_tls_config *);

extern int nni_http_client_get_tls(
    nni_http_client *, struct nng_tls_config **);

extern int nni_http_client_set(
    nni_http_client *, const char *, const void *buf, size_t, nni_type);
extern int nni_http_client_get(
    nni_http_client *, const char *, void *, size_t *, nni_type);

extern void nni_http_client_connect(nni_http_client *, nni_aio *);

extern void nni_http_transact_conn(
    nni_http_conn *, nni_http_req *, nni_http_res *, nni_aio *);

extern void nni_http_transact(
    nni_http_client *, nni_http_req *, nni_http_res *, nni_aio *);

extern const char *nni_http_stream_scheme(const char *);

#endif
