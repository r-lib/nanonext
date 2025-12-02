/**
 * \file block_cipher_internal.h
 *
 * \brief Lightweight abstraction layer for block ciphers with 128 bit blocks,
 * for use by the GCM and CCM modules.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_BLOCK_CIPHER_INTERNAL_H
#define MBEDTLS_BLOCK_CIPHER_INTERNAL_H 
#include "mbedtls/build_info.h"
#include "mbedtls/cipher.h"
#include "mbedtls/block_cipher.h"
#ifdef __cplusplus
extern "C" {
#endif
static inline void mbedtls_block_cipher_init(mbedtls_block_cipher_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}
int mbedtls_block_cipher_setup(mbedtls_block_cipher_context_t *ctx,
                               mbedtls_cipher_id_t cipher_id);
int mbedtls_block_cipher_setkey(mbedtls_block_cipher_context_t *ctx,
                                const unsigned char *key,
                                unsigned key_bitlen);
int mbedtls_block_cipher_encrypt(mbedtls_block_cipher_context_t *ctx,
                                 const unsigned char input[16],
                                 unsigned char output[16]);
void mbedtls_block_cipher_free(mbedtls_block_cipher_context_t *ctx);
#ifdef __cplusplus
}
#endif
#endif
