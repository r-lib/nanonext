/**
 * \file gcm.h
 *
 * \brief This file contains GCM definitions and functions.
 *
 * The Galois/Counter Mode (GCM) for 128-bit block ciphers is defined
 * in <em>D. McGrew, J. Viega, The Galois/Counter Mode of Operation
 * (GCM), Natl. Inst. Stand. Technol.</em>
 *
 * For more information on GCM, see <em>NIST SP 800-38D: Recommendation for
 * Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</em>.
 *
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_GCM_H
#define MBEDTLS_GCM_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/cipher.h"
#if defined(MBEDTLS_BLOCK_CIPHER_C)
#include "mbedtls/block_cipher.h"
#endif
#include <stdint.h>
#define MBEDTLS_GCM_ENCRYPT 1
#define MBEDTLS_GCM_DECRYPT 0
#define MBEDTLS_ERR_GCM_AUTH_FAILED -0x0012
#define MBEDTLS_ERR_GCM_BAD_INPUT -0x0014
#define MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL -0x0016
#ifdef __cplusplus
extern "C" {
#endif
#if !defined(MBEDTLS_GCM_ALT)
#if defined(MBEDTLS_GCM_LARGE_TABLE)
#define MBEDTLS_GCM_HTABLE_SIZE 256
#else
#define MBEDTLS_GCM_HTABLE_SIZE 16
#endif
typedef struct mbedtls_gcm_context {
#if defined(MBEDTLS_BLOCK_CIPHER_C)
    mbedtls_block_cipher_context_t MBEDTLS_PRIVATE(block_cipher_ctx);
#else
    mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher_ctx);
#endif
    uint64_t MBEDTLS_PRIVATE(H)[MBEDTLS_GCM_HTABLE_SIZE][2];
    uint64_t MBEDTLS_PRIVATE(len);
    uint64_t MBEDTLS_PRIVATE(add_len);
    unsigned char MBEDTLS_PRIVATE(base_ectr)[16];
    unsigned char MBEDTLS_PRIVATE(y)[16];
    unsigned char MBEDTLS_PRIVATE(buf)[16];
    unsigned char MBEDTLS_PRIVATE(mode);
    unsigned char MBEDTLS_PRIVATE(acceleration);
}
mbedtls_gcm_context;
#else
#include "gcm_alt.h"
#endif
void mbedtls_gcm_init(mbedtls_gcm_context *ctx);
int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits);
int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx,
                              int mode,
                              size_t length,
                              const unsigned char *iv,
                              size_t iv_len,
                              const unsigned char *add,
                              size_t add_len,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t tag_len,
                              unsigned char *tag);
int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx,
                             size_t length,
                             const unsigned char *iv,
                             size_t iv_len,
                             const unsigned char *add,
                             size_t add_len,
                             const unsigned char *tag,
                             size_t tag_len,
                             const unsigned char *input,
                             unsigned char *output);
int mbedtls_gcm_starts(mbedtls_gcm_context *ctx,
                       int mode,
                       const unsigned char *iv,
                       size_t iv_len);
int mbedtls_gcm_update_ad(mbedtls_gcm_context *ctx,
                          const unsigned char *add,
                          size_t add_len);
int mbedtls_gcm_update(mbedtls_gcm_context *ctx,
                       const unsigned char *input, size_t input_length,
                       unsigned char *output, size_t output_size,
                       size_t *output_length);
int mbedtls_gcm_finish(mbedtls_gcm_context *ctx,
                       unsigned char *output, size_t output_size,
                       size_t *output_length,
                       unsigned char *tag, size_t tag_len);
void mbedtls_gcm_free(mbedtls_gcm_context *ctx);
#ifdef __cplusplus
}
#endif
#endif
