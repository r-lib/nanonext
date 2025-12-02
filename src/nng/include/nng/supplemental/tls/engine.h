//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_ENGINE_H
#define NNG_SUPPLEMENTAL_TLS_ENGINE_H

#include <nng/supplemental/tls/tls.h>

typedef struct nng_tls_engine_conn nng_tls_engine_conn;

typedef struct nng_tls_engine_config nng_tls_engine_config;

typedef struct nng_tls_engine_conn_ops_s {
	size_t size;

	int (*init)(nng_tls_engine_conn *, void *, nng_tls_engine_config *);

	void (*fini)(nng_tls_engine_conn *);

	void (*close)(nng_tls_engine_conn *);

	int (*handshake)(nng_tls_engine_conn *);

	int (*recv)(nng_tls_engine_conn *, uint8_t *, size_t *);

	int (*send)(nng_tls_engine_conn *, const uint8_t *, size_t *);

	bool (*verified)(nng_tls_engine_conn *);

	char *(*peer_cn)(nng_tls_engine_conn *);

	char **(*peer_alt_names)(nng_tls_engine_conn *);
} nng_tls_engine_conn_ops;

typedef struct nng_tls_engine_config_ops_s {
	size_t size;

	int (*init)(nng_tls_engine_config *, nng_tls_mode);

	void (*fini)(nng_tls_engine_config *);

	int (*server)(nng_tls_engine_config *, const char *);

	int (*auth)(nng_tls_engine_config *, nng_tls_auth_mode);

	int (*ca_chain)(nng_tls_engine_config *, const char *, const char *);

	int (*own_cert)(
	    nng_tls_engine_config *, const char *, const char *, const char *);

	int (*version)(
	    nng_tls_engine_config *, nng_tls_version, nng_tls_version);
} nng_tls_engine_config_ops;

typedef enum nng_tls_engine_version_e {
	NNG_TLS_ENGINE_V0      = 0,
	NNG_TLS_ENGINE_V1      = 1,
	NNG_TLS_ENGINE_VERSION = NNG_TLS_ENGINE_V1,
} nng_tls_engine_version;

typedef struct nng_tls_engine_s {
	nng_tls_engine_version version;

	nng_tls_engine_config_ops *config_ops;

	nng_tls_engine_conn_ops *conn_ops;

	const char *name;

	const char *description;

	bool fips_mode;
} nng_tls_engine;

NNG_DECL int nng_tls_engine_register(const nng_tls_engine *);

NNG_DECL int nng_tls_engine_send(void *, const uint8_t *, size_t *);

NNG_DECL int nng_tls_engine_recv(void *, uint8_t *, size_t *);

#endif // NNG_SUPPLEMENTAL_TLS_ENGINE_H
