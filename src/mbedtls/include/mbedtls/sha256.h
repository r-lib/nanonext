/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SHA256_H
#define MBEDTLS_SHA256_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_SHA256_BAD_INPUT_DATA                 -0x0074

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_SHA256_ALT)

typedef struct mbedtls_sha256_context {
    unsigned char MBEDTLS_PRIVATE(buffer)[64];
    uint32_t MBEDTLS_PRIVATE(total)[2];
    uint32_t MBEDTLS_PRIVATE(state)[8];
#if defined(MBEDTLS_SHA224_C)
    int MBEDTLS_PRIVATE(is224);
#endif
}
mbedtls_sha256_context;

#else
#include "sha256_alt.h"
#endif

void mbedtls_sha256_init(mbedtls_sha256_context *ctx);

void mbedtls_sha256_free(mbedtls_sha256_context *ctx);

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src);

int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224);

int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen);

int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char *output);

int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx,
                                    const unsigned char data[64]);

int mbedtls_sha256(const unsigned char *input,
                   size_t ilen,
                   unsigned char *output,
                   int is224);

#if defined(MBEDTLS_SELF_TEST)

#if defined(MBEDTLS_SHA224_C)

int mbedtls_sha224_self_test(int verbose);
#endif

#if defined(MBEDTLS_SHA256_C)

int mbedtls_sha256_self_test(int verbose);
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
