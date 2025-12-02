/**
 * \file des.h
 *
 * \brief DES block cipher
 *
 * \warning   DES/3DES are considered weak ciphers and their use constitutes a
 *            security risk. We recommend considering stronger ciphers
 *            instead.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 */
#ifndef MBEDTLS_DES_H
#define MBEDTLS_DES_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_DES_ENCRYPT     1
#define MBEDTLS_DES_DECRYPT     0

#define MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH              -0x0032

#define MBEDTLS_DES_KEY_SIZE    8

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_DES_ALT)

typedef struct mbedtls_des_context {
    uint32_t MBEDTLS_PRIVATE(sk)[32];
}
mbedtls_des_context;

typedef struct mbedtls_des3_context {
    uint32_t MBEDTLS_PRIVATE(sk)[96];
}
mbedtls_des3_context;

#else  /* MBEDTLS_DES_ALT */
#include "des_alt.h"
#endif /* MBEDTLS_DES_ALT */

void mbedtls_des_init(mbedtls_des_context *ctx);

void mbedtls_des_free(mbedtls_des_context *ctx);

void mbedtls_des3_init(mbedtls_des3_context *ctx);

void mbedtls_des3_free(mbedtls_des3_context *ctx);

void mbedtls_des_key_set_parity(unsigned char key[MBEDTLS_DES_KEY_SIZE]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des_key_check_key_parity(const unsigned char key[MBEDTLS_DES_KEY_SIZE]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des_key_check_weak(const unsigned char key[MBEDTLS_DES_KEY_SIZE]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des_setkey_enc(mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des_setkey_dec(mbedtls_des_context *ctx, const unsigned char key[MBEDTLS_DES_KEY_SIZE]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des3_set2key_enc(mbedtls_des3_context *ctx,
                             const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des3_set2key_dec(mbedtls_des3_context *ctx,
                             const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des3_set3key_enc(mbedtls_des3_context *ctx,
                             const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des3_set3key_dec(mbedtls_des3_context *ctx,
                             const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3]);

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des_crypt_ecb(mbedtls_des_context *ctx,
                          const unsigned char input[8],
                          unsigned char output[8]);

#if defined(MBEDTLS_CIPHER_MODE_CBC)

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des_crypt_cbc(mbedtls_des_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[8],
                          const unsigned char *input,
                          unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CBC */

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des3_crypt_ecb(mbedtls_des3_context *ctx,
                           const unsigned char input[8],
                           unsigned char output[8]);

#if defined(MBEDTLS_CIPHER_MODE_CBC)

MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_des3_crypt_cbc(mbedtls_des3_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[8],
                           const unsigned char *input,
                           unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CBC */

void mbedtls_des_setkey(uint32_t SK[32],
                        const unsigned char key[MBEDTLS_DES_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
