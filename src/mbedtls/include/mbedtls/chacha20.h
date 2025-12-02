/**
 * \file chacha20.h
 *
 * \brief   This file contains ChaCha20 definitions and functions.
 *
 *          ChaCha20 is a stream cipher that can encrypt and decrypt
 *          information. ChaCha was created by Daniel Bernstein as a variant of
 *          its Salsa cipher https://cr.yp.to/chacha/chacha-20080128.pdf
 *          ChaCha20 is the variant with 20 rounds, that was also standardized
 *          in RFC 7539.
 *
 * \author Daniel King <damaki.gh@gmail.com>
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_CHACHA20_H
#define MBEDTLS_CHACHA20_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include <stdint.h>
#include <stddef.h>
#define MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA -0x0051
#ifdef __cplusplus
extern "C" {
#endif
#if !defined(MBEDTLS_CHACHA20_ALT)
typedef struct mbedtls_chacha20_context {
    uint32_t MBEDTLS_PRIVATE(state)[16];
    uint8_t MBEDTLS_PRIVATE(keystream8)[64];
    size_t MBEDTLS_PRIVATE(keystream_bytes_used);
}
mbedtls_chacha20_context;
#else
#include "chacha20_alt.h"
#endif
void mbedtls_chacha20_init(mbedtls_chacha20_context *ctx);
void mbedtls_chacha20_free(mbedtls_chacha20_context *ctx);
int mbedtls_chacha20_setkey(mbedtls_chacha20_context *ctx,
                            const unsigned char key[32]);
int mbedtls_chacha20_starts(mbedtls_chacha20_context *ctx,
                            const unsigned char nonce[12],
                            uint32_t counter);
int mbedtls_chacha20_update(mbedtls_chacha20_context *ctx,
                            size_t size,
                            const unsigned char *input,
                            unsigned char *output);
int mbedtls_chacha20_crypt(const unsigned char key[32],
                           const unsigned char nonce[12],
                           uint32_t counter,
                           size_t size,
                           const unsigned char *input,
                           unsigned char *output);
#ifdef __cplusplus
}
#endif
#endif
