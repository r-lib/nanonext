/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SHA512_H
#define MBEDTLS_SHA512_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_SHA512_BAD_INPUT_DATA                 -0x0075

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_SHA512_ALT)

typedef struct mbedtls_sha512_context {
    uint64_t MBEDTLS_PRIVATE(total)[2];
    uint64_t MBEDTLS_PRIVATE(state)[8];
    unsigned char MBEDTLS_PRIVATE(buffer)[128];
#if defined(MBEDTLS_SHA384_C)
    int MBEDTLS_PRIVATE(is384);
#endif
}
mbedtls_sha512_context;

#else
#include "sha512_alt.h"
#endif

void mbedtls_sha512_init(mbedtls_sha512_context *ctx);

void mbedtls_sha512_free(mbedtls_sha512_context *ctx);

void mbedtls_sha512_clone(mbedtls_sha512_context *dst,
                          const mbedtls_sha512_context *src);

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384);

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen);

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output);

int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx,
                                    const unsigned char data[128]);

int mbedtls_sha512(const unsigned char *input,
                   size_t ilen,
                   unsigned char *output,
                   int is384);

#if defined(MBEDTLS_SELF_TEST)

#if defined(MBEDTLS_SHA384_C)

int mbedtls_sha384_self_test(int verbose);
#endif

#if defined(MBEDTLS_SHA512_C)

int mbedtls_sha512_self_test(int verbose);
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
