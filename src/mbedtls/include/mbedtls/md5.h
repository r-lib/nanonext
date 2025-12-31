/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_MD5_H
#define MBEDTLS_MD5_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_MD5_ALT)

typedef struct mbedtls_md5_context {
    uint32_t MBEDTLS_PRIVATE(total)[2];
    uint32_t MBEDTLS_PRIVATE(state)[4];
    unsigned char MBEDTLS_PRIVATE(buffer)[64];
}
mbedtls_md5_context;

#else
#include "md5_alt.h"
#endif

void mbedtls_md5_init(mbedtls_md5_context *ctx);

void mbedtls_md5_free(mbedtls_md5_context *ctx);

void mbedtls_md5_clone(mbedtls_md5_context *dst,
                       const mbedtls_md5_context *src);

int mbedtls_md5_starts(mbedtls_md5_context *ctx);

int mbedtls_md5_update(mbedtls_md5_context *ctx,
                       const unsigned char *input,
                       size_t ilen);

int mbedtls_md5_finish(mbedtls_md5_context *ctx,
                       unsigned char output[16]);

int mbedtls_internal_md5_process(mbedtls_md5_context *ctx,
                                 const unsigned char data[64]);

int mbedtls_md5(const unsigned char *input,
                size_t ilen,
                unsigned char output[16]);

#if defined(MBEDTLS_SELF_TEST)

int mbedtls_md5_self_test(int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif
