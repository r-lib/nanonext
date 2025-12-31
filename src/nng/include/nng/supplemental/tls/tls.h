//
// Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
// Copyright 2018 Capitar IT Group BV <info@capitar.com>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#ifndef NNG_SUPPLEMENTAL_TLS_TLS_H
#define NNG_SUPPLEMENTAL_TLS_TLS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct nng_tls_config nng_tls_config;

typedef enum nng_tls_mode {
	NNG_TLS_MODE_CLIENT = 0,
	NNG_TLS_MODE_SERVER = 1,
} nng_tls_mode;

typedef enum nng_tls_auth_mode {
	NNG_TLS_AUTH_MODE_NONE     = 0,
	NNG_TLS_AUTH_MODE_OPTIONAL = 1,
	NNG_TLS_AUTH_MODE_REQUIRED = 2,
} nng_tls_auth_mode;

typedef enum nng_tls_version {
	NNG_TLS_1_0 = 0x301,
	NNG_TLS_1_1 = 0x302,
	NNG_TLS_1_2 = 0x303,
	NNG_TLS_1_3 = 0x304
} nng_tls_version;

NNG_DECL int nng_tls_config_alloc(nng_tls_config **, nng_tls_mode);

NNG_DECL void nng_tls_config_hold(nng_tls_config *);

NNG_DECL void nng_tls_config_free(nng_tls_config *);

NNG_DECL int nng_tls_config_server_name(nng_tls_config *, const char *);

NNG_DECL int nng_tls_config_ca_chain(
    nng_tls_config *, const char *, const char *);

NNG_DECL int nng_tls_config_own_cert(
    nng_tls_config *, const char *, const char *, const char *);

NNG_DECL int nng_tls_config_key(nng_tls_config *, const uint8_t *, size_t);

NNG_DECL int nng_tls_config_pass(nng_tls_config *, const char *);

NNG_DECL int nng_tls_config_auth_mode(nng_tls_config *, nng_tls_auth_mode);

NNG_DECL int nng_tls_config_ca_file(nng_tls_config *, const char *);

NNG_DECL int nng_tls_config_cert_key_file(
    nng_tls_config *, const char *, const char *);

NNG_DECL int nng_tls_config_version(
    nng_tls_config *, nng_tls_version, nng_tls_version);

NNG_DECL const char *nng_tls_engine_name(void);

NNG_DECL const char *nng_tls_engine_description(void);

NNG_DECL bool nng_tls_engine_fips_mode(void);

#ifdef __cplusplus
}
#endif

#endif
