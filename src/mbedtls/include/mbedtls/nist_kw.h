/**
 * \file nist_kw.h
 *
 * \brief This file provides an API for key wrapping (KW) and key wrapping with
 *        padding (KWP) as defined in NIST SP 800-38F.
 *        https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
 *
 *        Key wrapping specifies a deterministic authenticated-encryption mode
 *        of operation, according to <em>NIST SP 800-38F: Recommendation for
 *        Block Cipher Modes of Operation: Methods for Key Wrapping</em>. Its
 *        purpose is to protect cryptographic keys.
 *
 *        Its equivalent is RFC 3394 for KW, and RFC 5649 for KWP.
 *        https://tools.ietf.org/html/rfc3394
 *        https://tools.ietf.org/html/rfc5649
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_NIST_KW_H
#define MBEDTLS_NIST_KW_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/cipher.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    MBEDTLS_KW_MODE_KW = 0,
    MBEDTLS_KW_MODE_KWP = 1
} mbedtls_nist_kw_mode_t;
#if !defined(MBEDTLS_NIST_KW_ALT)
typedef struct {
    mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher_ctx);
} mbedtls_nist_kw_context;
#else
#include "nist_kw_alt.h"
#endif
void mbedtls_nist_kw_init(mbedtls_nist_kw_context *ctx);
int mbedtls_nist_kw_setkey(mbedtls_nist_kw_context *ctx,
                           mbedtls_cipher_id_t cipher,
                           const unsigned char *key,
                           unsigned int keybits,
                           const int is_wrap);
void mbedtls_nist_kw_free(mbedtls_nist_kw_context *ctx);
int mbedtls_nist_kw_wrap(mbedtls_nist_kw_context *ctx, mbedtls_nist_kw_mode_t mode,
                         const unsigned char *input, size_t in_len,
                         unsigned char *output, size_t *out_len, size_t out_size);
int mbedtls_nist_kw_unwrap(mbedtls_nist_kw_context *ctx, mbedtls_nist_kw_mode_t mode,
                           const unsigned char *input, size_t in_len,
                           unsigned char *output, size_t *out_len, size_t out_size);
#ifdef __cplusplus
}
#endif
#endif
