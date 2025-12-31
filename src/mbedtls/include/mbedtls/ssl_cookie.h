/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_COOKIE_H
#define MBEDTLS_SSL_COOKIE_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/ssl.h"

#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif
#endif

#ifndef MBEDTLS_SSL_COOKIE_TIMEOUT
#define MBEDTLS_SSL_COOKIE_TIMEOUT     60
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_ssl_cookie_ctx {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t    MBEDTLS_PRIVATE(psa_hmac_key);
    psa_algorithm_t         MBEDTLS_PRIVATE(psa_hmac_alg);
#else
    mbedtls_md_context_t    MBEDTLS_PRIVATE(hmac_ctx);
#endif
#if !defined(MBEDTLS_HAVE_TIME)
    unsigned long   MBEDTLS_PRIVATE(serial);
#endif
    unsigned long   MBEDTLS_PRIVATE(timeout);

#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
#endif
} mbedtls_ssl_cookie_ctx;

void mbedtls_ssl_cookie_init(mbedtls_ssl_cookie_ctx *ctx);

int mbedtls_ssl_cookie_setup(mbedtls_ssl_cookie_ctx *ctx,
                             mbedtls_f_rng_t *f_rng,
                             void *p_rng);

void mbedtls_ssl_cookie_set_timeout(mbedtls_ssl_cookie_ctx *ctx, unsigned long delay);

void mbedtls_ssl_cookie_free(mbedtls_ssl_cookie_ctx *ctx);

mbedtls_ssl_cookie_write_t mbedtls_ssl_cookie_write;

mbedtls_ssl_cookie_check_t mbedtls_ssl_cookie_check;

#ifdef __cplusplus
}
#endif

#endif
