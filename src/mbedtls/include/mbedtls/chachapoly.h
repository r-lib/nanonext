/**
 * \file chachapoly.h
 *
 * \brief   This file contains the AEAD-ChaCha20-Poly1305 definitions and
 *          functions.
 *
 *          ChaCha20-Poly1305 is an algorithm for Authenticated Encryption
 *          with Associated Data (AEAD) that can be used to encrypt and
 *          authenticate data. It is based on ChaCha20 and Poly1305 by Daniel
 *          Bernstein and was standardized in RFC 7539.
 *
 * \author Daniel King <damaki.gh@gmail.com>
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_CHACHAPOLY_H
#define MBEDTLS_CHACHAPOLY_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/poly1305.h"
#define MBEDTLS_ERR_CHACHAPOLY_BAD_STATE -0x0054
#define MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED -0x0056
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    MBEDTLS_CHACHAPOLY_ENCRYPT,
    MBEDTLS_CHACHAPOLY_DECRYPT
}
mbedtls_chachapoly_mode_t;
#if !defined(MBEDTLS_CHACHAPOLY_ALT)
#include "mbedtls/chacha20.h"
typedef struct mbedtls_chachapoly_context {
    mbedtls_chacha20_context MBEDTLS_PRIVATE(chacha20_ctx);
    mbedtls_poly1305_context MBEDTLS_PRIVATE(poly1305_ctx);
    uint64_t MBEDTLS_PRIVATE(aad_len);
    uint64_t MBEDTLS_PRIVATE(ciphertext_len);
    int MBEDTLS_PRIVATE(state);
    mbedtls_chachapoly_mode_t MBEDTLS_PRIVATE(mode);
}
mbedtls_chachapoly_context;
#else
#include "chachapoly_alt.h"
#endif
void mbedtls_chachapoly_init(mbedtls_chachapoly_context *ctx);
void mbedtls_chachapoly_free(mbedtls_chachapoly_context *ctx);
int mbedtls_chachapoly_setkey(mbedtls_chachapoly_context *ctx,
                              const unsigned char key[32]);
int mbedtls_chachapoly_starts(mbedtls_chachapoly_context *ctx,
                              const unsigned char nonce[12],
                              mbedtls_chachapoly_mode_t mode);
int mbedtls_chachapoly_update_aad(mbedtls_chachapoly_context *ctx,
                                  const unsigned char *aad,
                                  size_t aad_len);
int mbedtls_chachapoly_update(mbedtls_chachapoly_context *ctx,
                              size_t len,
                              const unsigned char *input,
                              unsigned char *output);
int mbedtls_chachapoly_finish(mbedtls_chachapoly_context *ctx,
                              unsigned char mac[16]);
int mbedtls_chachapoly_encrypt_and_tag(mbedtls_chachapoly_context *ctx,
                                       size_t length,
                                       const unsigned char nonce[12],
                                       const unsigned char *aad,
                                       size_t aad_len,
                                       const unsigned char *input,
                                       unsigned char *output,
                                       unsigned char tag[16]);
int mbedtls_chachapoly_auth_decrypt(mbedtls_chachapoly_context *ctx,
                                    size_t length,
                                    const unsigned char nonce[12],
                                    const unsigned char *aad,
                                    size_t aad_len,
                                    const unsigned char tag[16],
                                    const unsigned char *input,
                                    unsigned char *output);
#ifdef __cplusplus
}
#endif
#endif
