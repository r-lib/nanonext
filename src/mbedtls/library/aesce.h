/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_AESCE_H
#define MBEDTLS_AESCE_H

#include "mbedtls/build_info.h"
#include "common.h"

#include "mbedtls/aes.h"

#if defined(MBEDTLS_AESCE_C) \
    && defined(MBEDTLS_ARCH_IS_ARMV8_A) && defined(MBEDTLS_HAVE_NEON_INTRINSICS) \
    && (defined(MBEDTLS_COMPILER_IS_GCC) || defined(__clang__) || defined(MSC_VER))

#define MBEDTLS_AESCE_HAVE_CODE

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)

extern signed char mbedtls_aesce_has_support_result;

int mbedtls_aesce_has_support_impl(void);

#define MBEDTLS_AESCE_HAS_SUPPORT() (mbedtls_aesce_has_support_result == -1 ? \
                                     mbedtls_aesce_has_support_impl() : \
                                     mbedtls_aesce_has_support_result)

#else

#define MBEDTLS_AESCE_HAS_SUPPORT() 1

#endif

int mbedtls_aesce_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16]);

void mbedtls_aesce_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16]);

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)

void mbedtls_aesce_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey,
                               int nr);
#endif

int mbedtls_aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits);

#ifdef __cplusplus
}
#endif

#else

#if defined(MBEDTLS_AES_USE_HARDWARE_ONLY) && defined(MBEDTLS_ARCH_IS_ARMV8_A)
#error "AES hardware acceleration not supported on this platform / compiler"
#endif

#endif

#endif
