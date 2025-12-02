/**
 * \file aesni.h
 *
 * \brief AES-NI for hardware AES acceleration on some Intel processors
 *
 * \warning These functions are only for internal use by other library
 *          functions; you must not call them directly.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_AESNI_H
#define MBEDTLS_AESNI_H 
#include "mbedtls/build_info.h"
#include "mbedtls/aes.h"
#define MBEDTLS_AESNI_AES 0x02000000u
#define MBEDTLS_AESNI_CLMUL 0x00000002u
#if defined(MBEDTLS_AESNI_C) && \
    (defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_X86))
#undef MBEDTLS_AESNI_HAVE_INTRINSICS
#if defined(_MSC_VER) && !defined(__clang__)
#define MBEDTLS_AESNI_HAVE_INTRINSICS 
#endif
#if (defined(__GNUC__) || defined(__clang__)) && defined(__AES__) && defined(__PCLMUL__)
#define MBEDTLS_AESNI_HAVE_INTRINSICS 
#endif
#if defined(MBEDTLS_ARCH_IS_X86) && (defined(__GNUC__) || defined(__clang__))
#define MBEDTLS_AESNI_HAVE_INTRINSICS 
#endif
#if defined(MBEDTLS_AESNI_HAVE_INTRINSICS)
#define MBEDTLS_AESNI_HAVE_CODE 2
#elif defined(MBEDTLS_HAVE_ASM) && \
    (defined(__GNUC__) || defined(__clang__)) && defined(MBEDTLS_ARCH_IS_X64)
#define MBEDTLS_AESNI_HAVE_CODE 1
#else
#error "MBEDTLS_AESNI_C defined, but neither intrinsics nor assembly available"
#endif
#if defined(MBEDTLS_AESNI_HAVE_CODE)
#ifdef __cplusplus
extern "C" {
#endif
#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
int mbedtls_aesni_has_support(unsigned int what);
#else
#define mbedtls_aesni_has_support(what) 1
#endif
int mbedtls_aesni_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16]);
void mbedtls_aesni_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16]);
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
void mbedtls_aesni_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey,
                               int nr);
#endif
int mbedtls_aesni_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits);
#ifdef __cplusplus
}
#endif
#endif
#endif
#endif
