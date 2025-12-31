/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_TICKET_H
#define MBEDTLS_SSL_TICKET_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/ssl.h"
#include "mbedtls/cipher.h"

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_SSL_TICKET_MAX_KEY_BYTES 32
#define MBEDTLS_SSL_TICKET_KEY_NAME_BYTES 4

typedef struct mbedtls_ssl_ticket_key {
    unsigned char MBEDTLS_PRIVATE(name)[MBEDTLS_SSL_TICKET_KEY_NAME_BYTES];

#if defined(MBEDTLS_HAVE_TIME)
    mbedtls_time_t MBEDTLS_PRIVATE(generation_time);
#endif

    uint32_t MBEDTLS_PRIVATE(lifetime);
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_cipher_context_t MBEDTLS_PRIVATE(ctx);
#else
    mbedtls_svc_key_id_t MBEDTLS_PRIVATE(key);
    psa_algorithm_t MBEDTLS_PRIVATE(alg);
    psa_key_type_t MBEDTLS_PRIVATE(key_type);
    size_t MBEDTLS_PRIVATE(key_bits);
#endif
}
mbedtls_ssl_ticket_key;

typedef struct mbedtls_ssl_ticket_context {
    mbedtls_ssl_ticket_key MBEDTLS_PRIVATE(keys)[2];
    unsigned char MBEDTLS_PRIVATE(active);

    uint32_t MBEDTLS_PRIVATE(ticket_lifetime);

    int(*MBEDTLS_PRIVATE(f_rng))(void *, unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_rng);

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
}
mbedtls_ssl_ticket_context;

void mbedtls_ssl_ticket_init(mbedtls_ssl_ticket_context *ctx);

int mbedtls_ssl_ticket_setup(mbedtls_ssl_ticket_context *ctx,
                             mbedtls_f_rng_t *f_rng, void *p_rng,
                             mbedtls_cipher_type_t cipher,
                             uint32_t lifetime);

int mbedtls_ssl_ticket_rotate(mbedtls_ssl_ticket_context *ctx,
                              const unsigned char *name, size_t nlength,
                              const unsigned char *k, size_t klength,
                              uint32_t lifetime);

mbedtls_ssl_ticket_write_t mbedtls_ssl_ticket_write;

mbedtls_ssl_ticket_parse_t mbedtls_ssl_ticket_parse;

void mbedtls_ssl_ticket_free(mbedtls_ssl_ticket_context *ctx);

#ifdef __cplusplus
}
#endif

#endif
