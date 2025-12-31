/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CCM_H
#define MBEDTLS_CCM_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/cipher.h"

#if defined(MBEDTLS_BLOCK_CIPHER_C)
#include "mbedtls/block_cipher.h"
#endif

#define MBEDTLS_CCM_DECRYPT       0
#define MBEDTLS_CCM_ENCRYPT       1
#define MBEDTLS_CCM_STAR_DECRYPT  2
#define MBEDTLS_CCM_STAR_ENCRYPT  3

#define MBEDTLS_ERR_CCM_BAD_INPUT       -0x000D

#define MBEDTLS_ERR_CCM_AUTH_FAILED     -0x000F

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_CCM_ALT)

typedef struct mbedtls_ccm_context {
    unsigned char MBEDTLS_PRIVATE(y)[16];
    unsigned char MBEDTLS_PRIVATE(ctr)[16];
    size_t MBEDTLS_PRIVATE(plaintext_len);
    size_t MBEDTLS_PRIVATE(add_len);
    size_t MBEDTLS_PRIVATE(tag_len);
    size_t MBEDTLS_PRIVATE(processed);
    unsigned int MBEDTLS_PRIVATE(q);
    unsigned int MBEDTLS_PRIVATE(mode);
#if defined(MBEDTLS_BLOCK_CIPHER_C)
    mbedtls_block_cipher_context_t MBEDTLS_PRIVATE(block_cipher_ctx);
#else
    mbedtls_cipher_context_t MBEDTLS_PRIVATE(cipher_ctx);
#endif
    int MBEDTLS_PRIVATE(state);
}
mbedtls_ccm_context;

#else
#include "ccm_alt.h"
#endif

void mbedtls_ccm_init(mbedtls_ccm_context *ctx);

int mbedtls_ccm_setkey(mbedtls_ccm_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const unsigned char *key,
                       unsigned int keybits);

void mbedtls_ccm_free(mbedtls_ccm_context *ctx);

int mbedtls_ccm_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                const unsigned char *iv, size_t iv_len,
                                const unsigned char *ad, size_t ad_len,
                                const unsigned char *input, unsigned char *output,
                                unsigned char *tag, size_t tag_len);

int mbedtls_ccm_star_encrypt_and_tag(mbedtls_ccm_context *ctx, size_t length,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *ad, size_t ad_len,
                                     const unsigned char *input, unsigned char *output,
                                     unsigned char *tag, size_t tag_len);

int mbedtls_ccm_auth_decrypt(mbedtls_ccm_context *ctx, size_t length,
                             const unsigned char *iv, size_t iv_len,
                             const unsigned char *ad, size_t ad_len,
                             const unsigned char *input, unsigned char *output,
                             const unsigned char *tag, size_t tag_len);

int mbedtls_ccm_star_auth_decrypt(mbedtls_ccm_context *ctx, size_t length,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *ad, size_t ad_len,
                                  const unsigned char *input, unsigned char *output,
                                  const unsigned char *tag, size_t tag_len);

int mbedtls_ccm_starts(mbedtls_ccm_context *ctx,
                       int mode,
                       const unsigned char *iv,
                       size_t iv_len);

int mbedtls_ccm_set_lengths(mbedtls_ccm_context *ctx,
                            size_t total_ad_len,
                            size_t plaintext_len,
                            size_t tag_len);

int mbedtls_ccm_update_ad(mbedtls_ccm_context *ctx,
                          const unsigned char *ad,
                          size_t ad_len);

int mbedtls_ccm_update(mbedtls_ccm_context *ctx,
                       const unsigned char *input, size_t input_len,
                       unsigned char *output, size_t output_size,
                       size_t *output_len);

int mbedtls_ccm_finish(mbedtls_ccm_context *ctx,
                       unsigned char *tag, size_t tag_len);

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_CCM_GCM_CAN_AES)

int mbedtls_ccm_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif
