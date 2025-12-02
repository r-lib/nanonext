/**
 * \file aes.h
 *
 * \brief   This file contains AES definitions and functions.
 *
 *          The Advanced Encryption Standard (AES) specifies a FIPS-approved
 *          cryptographic algorithm that can be used to protect electronic
 *          data.
 *
 *          The AES algorithm is a symmetric block cipher that can
 *          encrypt and decrypt information. For more information, see
 *          <em>FIPS Publication 197: Advanced Encryption Standard</em> and
 *          <em>ISO/IEC 18033-2:2006: Information technology -- Security
 *          techniques -- Encryption algorithms -- Part 2: Asymmetric
 *          ciphers</em>.
 *
 *          The AES-XTS block mode is standardized by NIST SP 800-38E
 *          <https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38e.pdf>
 *          and described in detail by IEEE P1619
 *          <https://ieeexplore.ieee.org/servlet/opac?punumber=4375278>.
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_AES_H
#define MBEDTLS_AES_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"
#include <stddef.h>
#include <stdint.h>
#define MBEDTLS_AES_ENCRYPT 1
#define MBEDTLS_AES_DECRYPT 0
#define MBEDTLS_ERR_AES_INVALID_KEY_LENGTH -0x0020
#define MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH -0x0022
#define MBEDTLS_ERR_AES_BAD_INPUT_DATA -0x0021
#ifdef __cplusplus
extern "C" {
#endif
#if !defined(MBEDTLS_AES_ALT)
typedef struct mbedtls_aes_context {
    int MBEDTLS_PRIVATE(nr);
    size_t MBEDTLS_PRIVATE(rk_offset);
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH) && !defined(MBEDTLS_PADLOCK_C)
    uint32_t MBEDTLS_PRIVATE(buf)[44];
#else
    uint32_t MBEDTLS_PRIVATE(buf)[68];
#endif
}
mbedtls_aes_context;
#if defined(MBEDTLS_CIPHER_MODE_XTS)
typedef struct mbedtls_aes_xts_context {
    mbedtls_aes_context MBEDTLS_PRIVATE(crypt);
    mbedtls_aes_context MBEDTLS_PRIVATE(tweak);
} mbedtls_aes_xts_context;
#endif
#else
#include "aes_alt.h"
#endif
void mbedtls_aes_init(mbedtls_aes_context *ctx);
void mbedtls_aes_free(mbedtls_aes_context *ctx);
#if defined(MBEDTLS_CIPHER_MODE_XTS)
void mbedtls_aes_xts_init(mbedtls_aes_xts_context *ctx);
void mbedtls_aes_xts_free(mbedtls_aes_xts_context *ctx);
#endif
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits);
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key,
                           unsigned int keybits);
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_xts_setkey_enc(mbedtls_aes_xts_context *ctx,
                               const unsigned char *key,
                               unsigned int keybits);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_xts_setkey_dec(mbedtls_aes_xts_context *ctx,
                               const unsigned char *key,
                               unsigned int keybits);
#endif
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                          int mode,
                          const unsigned char input[16],
                          unsigned char output[16]);
#if defined(MBEDTLS_CIPHER_MODE_CBC)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output);
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_xts(mbedtls_aes_xts_context *ctx,
                          int mode,
                          size_t length,
                          const unsigned char data_unit[16],
                          const unsigned char *input,
                          unsigned char *output);
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_cfb128(mbedtls_aes_context *ctx,
                             int mode,
                             size_t length,
                             size_t *iv_off,
                             unsigned char iv[16],
                             const unsigned char *input,
                             unsigned char *output);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_cfb8(mbedtls_aes_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[16],
                           const unsigned char *input,
                           unsigned char *output);
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_ofb(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *iv_off,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output);
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_aes_crypt_ctr(mbedtls_aes_context *ctx,
                          size_t length,
                          size_t *nc_off,
                          unsigned char nonce_counter[16],
                          unsigned char stream_block[16],
                          const unsigned char *input,
                          unsigned char *output);
#endif
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16]);
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16]);
#endif
#ifdef __cplusplus
}
#endif
#endif
