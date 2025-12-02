/**
 * \file sha1.h
 *
 * \brief This file contains SHA-1 definitions and functions.
 *
 * The Secure Hash Algorithm 1 (SHA-1) cryptographic hash function is defined in
 * <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
 *
 * \warning   SHA-1 is considered a weak message digest and its use constitutes
 *            a security risk. We recommend considering stronger message
 *            digests instead.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SHA1_H
#define MBEDTLS_SHA1_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_SHA1_BAD_INPUT_DATA                   -0x0073

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_SHA1_ALT)
typedef struct mbedtls_sha1_context {
    uint32_t MBEDTLS_PRIVATE(total)[2];
    uint32_t MBEDTLS_PRIVATE(state)[5];
    unsigned char MBEDTLS_PRIVATE(buffer)[64];
}
mbedtls_sha1_context;

#else  /* MBEDTLS_SHA1_ALT */
#include "sha1_alt.h"
#endif /* MBEDTLS_SHA1_ALT */

void mbedtls_sha1_init(mbedtls_sha1_context *ctx);

void mbedtls_sha1_free(mbedtls_sha1_context *ctx);

void mbedtls_sha1_clone(mbedtls_sha1_context *dst,
                        const mbedtls_sha1_context *src);

int mbedtls_sha1_starts(mbedtls_sha1_context *ctx);

int mbedtls_sha1_update(mbedtls_sha1_context *ctx,
                        const unsigned char *input,
                        size_t ilen);

int mbedtls_sha1_finish(mbedtls_sha1_context *ctx,
                        unsigned char output[20]);

int mbedtls_internal_sha1_process(mbedtls_sha1_context *ctx,
                                  const unsigned char data[64]);

int mbedtls_sha1(const unsigned char *input,
                 size_t ilen,
                 unsigned char output[20]);

#ifdef __cplusplus
}
#endif

#endif
