/**
 * \file cmac.h
 *
 * \brief This file contains CMAC definitions and functions.
 *
 * The Cipher-based Message Authentication Code (CMAC) Mode for
 * Authentication is defined in <em>RFC-4493: The AES-CMAC Algorithm</em>.
 * It is supported with AES and DES.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_CMAC_H
#define MBEDTLS_CMAC_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/cipher.h"
#ifdef __cplusplus
extern "C" {
#endif
#define MBEDTLS_AES_BLOCK_SIZE 16
#define MBEDTLS_DES3_BLOCK_SIZE 8
#if defined(MBEDTLS_AES_C)
#define MBEDTLS_CMAC_MAX_BLOCK_SIZE 16
#else
#define MBEDTLS_CMAC_MAX_BLOCK_SIZE 8
#endif
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#define MBEDTLS_CIPHER_BLKSIZE_MAX MBEDTLS_MAX_BLOCK_LENGTH
#endif
#if !defined(MBEDTLS_CMAC_ALT)
struct mbedtls_cmac_context_t {
    unsigned char MBEDTLS_PRIVATE(state)[MBEDTLS_CMAC_MAX_BLOCK_SIZE];
    unsigned char MBEDTLS_PRIVATE(unprocessed_block)[MBEDTLS_CMAC_MAX_BLOCK_SIZE];
    size_t MBEDTLS_PRIVATE(unprocessed_len);
};
#else
#include "cmac_alt.h"
#endif
int mbedtls_cipher_cmac_starts(mbedtls_cipher_context_t *ctx,
                               const unsigned char *key, size_t keybits);
int mbedtls_cipher_cmac_update(mbedtls_cipher_context_t *ctx,
                               const unsigned char *input, size_t ilen);
int mbedtls_cipher_cmac_finish(mbedtls_cipher_context_t *ctx,
                               unsigned char *output);
int mbedtls_cipher_cmac_reset(mbedtls_cipher_context_t *ctx);
int mbedtls_cipher_cmac(const mbedtls_cipher_info_t *cipher_info,
                        const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t ilen,
                        unsigned char *output);
#if defined(MBEDTLS_AES_C)
int mbedtls_aes_cmac_prf_128(const unsigned char *key, size_t key_len,
                             const unsigned char *input, size_t in_len,
                             unsigned char output[16]);
#endif
#ifdef __cplusplus
}
#endif
#endif
