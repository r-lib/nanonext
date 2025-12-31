/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_POLY1305_H
#define MBEDTLS_POLY1305_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stdint.h>
#include <stddef.h>

#define MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA         -0x0057

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_POLY1305_ALT)

typedef struct mbedtls_poly1305_context {
    uint32_t MBEDTLS_PRIVATE(r)[4];
    uint32_t MBEDTLS_PRIVATE(s)[4];
    uint32_t MBEDTLS_PRIVATE(acc)[5];
    uint8_t MBEDTLS_PRIVATE(queue)[16];
    size_t MBEDTLS_PRIVATE(queue_len);
}
mbedtls_poly1305_context;

#else
#include "poly1305_alt.h"
#endif

void mbedtls_poly1305_init(mbedtls_poly1305_context *ctx);

void mbedtls_poly1305_free(mbedtls_poly1305_context *ctx);

int mbedtls_poly1305_starts(mbedtls_poly1305_context *ctx,
                            const unsigned char key[32]);

int mbedtls_poly1305_update(mbedtls_poly1305_context *ctx,
                            const unsigned char *input,
                            size_t ilen);

int mbedtls_poly1305_finish(mbedtls_poly1305_context *ctx,
                            unsigned char mac[16]);

int mbedtls_poly1305_mac(const unsigned char key[32],
                         const unsigned char *input,
                         size_t ilen,
                         unsigned char mac[16]);

#if defined(MBEDTLS_SELF_TEST)

int mbedtls_poly1305_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif
