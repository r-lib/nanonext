/**
 * \file cmac.c
 *
 * \brief NIST SP800-38B compliant CMAC implementation for AES and 3DES
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"
#if defined(MBEDTLS_CMAC_C)
#include "mbedtls/cmac.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "constant_time_internal.h"
#include <string.h>
#if !defined(MBEDTLS_CMAC_ALT) || defined(MBEDTLS_SELF_TEST)
static int cmac_multiply_by_u(unsigned char *output,
                              const unsigned char *input,
                              size_t blocksize)
{
    const unsigned char R_128 = 0x87;
    unsigned char R_n;
    uint32_t overflow = 0x00;
    int i;
    if (blocksize == MBEDTLS_AES_BLOCK_SIZE) {
        R_n = R_128;
    }
#if defined(MBEDTLS_DES_C)
    else if (blocksize == MBEDTLS_DES3_BLOCK_SIZE) {
        const unsigned char R_64 = 0x1B;
        R_n = R_64;
    }
#endif
    else {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    for (i = (int) blocksize - 4; i >= 0; i -= 4) {
        uint32_t i32 = MBEDTLS_GET_UINT32_BE(&input[i], 0);
        uint32_t new_overflow = i32 >> 31;
        i32 = (i32 << 1) | overflow;
        MBEDTLS_PUT_UINT32_BE(i32, &output[i], 0);
        overflow = new_overflow;
    }
    R_n = (unsigned char) mbedtls_ct_uint_if_else_0(mbedtls_ct_bool(input[0] >> 7), R_n);
    output[blocksize - 1] ^= R_n;
    return 0;
}
static int cmac_generate_subkeys(mbedtls_cipher_context_t *ctx,
                                 unsigned char *K1, unsigned char *K2)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char L[MBEDTLS_CMAC_MAX_BLOCK_SIZE];
    size_t olen, block_size;
    mbedtls_platform_zeroize(L, sizeof(L));
    block_size = mbedtls_cipher_info_get_block_size(ctx->cipher_info);
    if ((ret = mbedtls_cipher_update(ctx, L, block_size, L, &olen)) != 0) {
        goto exit;
    }
    if ((ret = cmac_multiply_by_u(K1, L, block_size)) != 0) {
        goto exit;
    }
    if ((ret = cmac_multiply_by_u(K2, K1, block_size)) != 0) {
        goto exit;
    }
exit:
    mbedtls_platform_zeroize(L, sizeof(L));
    return ret;
}
#endif
#if !defined(MBEDTLS_CMAC_ALT)
static void cmac_pad(unsigned char padded_block[MBEDTLS_CMAC_MAX_BLOCK_SIZE],
                     size_t padded_block_len,
                     const unsigned char *last_block,
                     size_t last_block_len)
{
    size_t j;
    for (j = 0; j < padded_block_len; j++) {
        if (j < last_block_len) {
            padded_block[j] = last_block[j];
        } else if (j == last_block_len) {
            padded_block[j] = 0x80;
        } else {
            padded_block[j] = 0x00;
        }
    }
}
int mbedtls_cipher_cmac_starts(mbedtls_cipher_context_t *ctx,
                               const unsigned char *key, size_t keybits)
{
    mbedtls_cipher_type_t type;
    mbedtls_cmac_context_t *cmac_ctx;
    int retval;
    if (ctx == NULL || ctx->cipher_info == NULL || key == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    if ((retval = mbedtls_cipher_setkey(ctx, key, (int) keybits,
                                        MBEDTLS_ENCRYPT)) != 0) {
        return retval;
    }
    type = mbedtls_cipher_info_get_type(ctx->cipher_info);
    switch (type) {
        case MBEDTLS_CIPHER_AES_128_ECB:
        case MBEDTLS_CIPHER_AES_192_ECB:
        case MBEDTLS_CIPHER_AES_256_ECB:
        case MBEDTLS_CIPHER_DES_EDE3_ECB:
            break;
        default:
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    cmac_ctx = mbedtls_calloc(1, sizeof(mbedtls_cmac_context_t));
    if (cmac_ctx == NULL) {
        return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
    }
    ctx->cmac_ctx = cmac_ctx;
    mbedtls_platform_zeroize(cmac_ctx->state, sizeof(cmac_ctx->state));
    return 0;
}
int mbedtls_cipher_cmac_update(mbedtls_cipher_context_t *ctx,
                               const unsigned char *input, size_t ilen)
{
    mbedtls_cmac_context_t *cmac_ctx;
    unsigned char *state;
    int ret = 0;
    size_t n, j, olen, block_size;
    if (ctx == NULL || ctx->cipher_info == NULL || input == NULL ||
        ctx->cmac_ctx == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    cmac_ctx = ctx->cmac_ctx;
    block_size = mbedtls_cipher_info_get_block_size(ctx->cipher_info);
    state = ctx->cmac_ctx->state;
    MBEDTLS_ASSUME(block_size <= MBEDTLS_CMAC_MAX_BLOCK_SIZE);
    if (cmac_ctx->unprocessed_len > 0 &&
        ilen > block_size - cmac_ctx->unprocessed_len) {
        memcpy(&cmac_ctx->unprocessed_block[cmac_ctx->unprocessed_len],
               input,
               block_size - cmac_ctx->unprocessed_len);
        mbedtls_xor_no_simd(state, cmac_ctx->unprocessed_block, state, block_size);
        if ((ret = mbedtls_cipher_update(ctx, state, block_size, state,
                                         &olen)) != 0) {
            goto exit;
        }
        input += block_size - cmac_ctx->unprocessed_len;
        ilen -= block_size - cmac_ctx->unprocessed_len;
        cmac_ctx->unprocessed_len = 0;
    }
    n = (ilen + block_size - 1) / block_size;
    for (j = 1; j < n; j++) {
        mbedtls_xor_no_simd(state, input, state, block_size);
        if ((ret = mbedtls_cipher_update(ctx, state, block_size, state,
                                         &olen)) != 0) {
            goto exit;
        }
        ilen -= block_size;
        input += block_size;
    }
    if (ilen > 0) {
        memcpy(&cmac_ctx->unprocessed_block[cmac_ctx->unprocessed_len],
               input,
               ilen);
        cmac_ctx->unprocessed_len += ilen;
    }
exit:
    return ret;
}
int mbedtls_cipher_cmac_finish(mbedtls_cipher_context_t *ctx,
                               unsigned char *output)
{
    mbedtls_cmac_context_t *cmac_ctx;
    unsigned char *state, *last_block;
    unsigned char K1[MBEDTLS_CMAC_MAX_BLOCK_SIZE];
    unsigned char K2[MBEDTLS_CMAC_MAX_BLOCK_SIZE];
    unsigned char M_last[MBEDTLS_CMAC_MAX_BLOCK_SIZE];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen, block_size;
    if (ctx == NULL || ctx->cipher_info == NULL || ctx->cmac_ctx == NULL ||
        output == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    cmac_ctx = ctx->cmac_ctx;
    block_size = mbedtls_cipher_info_get_block_size(ctx->cipher_info);
    MBEDTLS_ASSUME(block_size <= MBEDTLS_CMAC_MAX_BLOCK_SIZE);
    state = cmac_ctx->state;
    mbedtls_platform_zeroize(K1, sizeof(K1));
    mbedtls_platform_zeroize(K2, sizeof(K2));
    cmac_generate_subkeys(ctx, K1, K2);
    last_block = cmac_ctx->unprocessed_block;
    if (cmac_ctx->unprocessed_len < block_size) {
        cmac_pad(M_last, block_size, last_block, cmac_ctx->unprocessed_len);
        mbedtls_xor(M_last, M_last, K2, block_size);
    } else {
        mbedtls_xor(M_last, last_block, K1, block_size);
    }
    mbedtls_xor(state, M_last, state, block_size);
    if ((ret = mbedtls_cipher_update(ctx, state, block_size, state,
                                     &olen)) != 0) {
        goto exit;
    }
    memcpy(output, state, block_size);
exit:
    mbedtls_platform_zeroize(K1, sizeof(K1));
    mbedtls_platform_zeroize(K2, sizeof(K2));
    cmac_ctx->unprocessed_len = 0;
    mbedtls_platform_zeroize(cmac_ctx->unprocessed_block,
                             sizeof(cmac_ctx->unprocessed_block));
    mbedtls_platform_zeroize(state, MBEDTLS_CMAC_MAX_BLOCK_SIZE);
    return ret;
}
int mbedtls_cipher_cmac_reset(mbedtls_cipher_context_t *ctx)
{
    mbedtls_cmac_context_t *cmac_ctx;
    if (ctx == NULL || ctx->cipher_info == NULL || ctx->cmac_ctx == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    cmac_ctx = ctx->cmac_ctx;
    cmac_ctx->unprocessed_len = 0;
    mbedtls_platform_zeroize(cmac_ctx->unprocessed_block,
                             sizeof(cmac_ctx->unprocessed_block));
    mbedtls_platform_zeroize(cmac_ctx->state,
                             sizeof(cmac_ctx->state));
    return 0;
}
int mbedtls_cipher_cmac(const mbedtls_cipher_info_t *cipher_info,
                        const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t ilen,
                        unsigned char *output)
{
    mbedtls_cipher_context_t ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (cipher_info == NULL || key == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    mbedtls_cipher_init(&ctx);
    if ((ret = mbedtls_cipher_setup(&ctx, cipher_info)) != 0) {
        goto exit;
    }
    ret = mbedtls_cipher_cmac_starts(&ctx, key, keylen);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_cipher_cmac_update(&ctx, input, ilen);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_cipher_cmac_finish(&ctx, output);
exit:
    mbedtls_cipher_free(&ctx);
    return ret;
}
#if defined(MBEDTLS_AES_C)
int mbedtls_aes_cmac_prf_128(const unsigned char *key, size_t key_length,
                             const unsigned char *input, size_t in_len,
                             unsigned char output[16])
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_cipher_info_t *cipher_info;
    unsigned char zero_key[MBEDTLS_AES_BLOCK_SIZE];
    unsigned char int_key[MBEDTLS_AES_BLOCK_SIZE];
    if (key == NULL || input == NULL || output == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (cipher_info == NULL) {
        ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        goto exit;
    }
    if (key_length == MBEDTLS_AES_BLOCK_SIZE) {
        memcpy(int_key, key, MBEDTLS_AES_BLOCK_SIZE);
    } else {
        memset(zero_key, 0, MBEDTLS_AES_BLOCK_SIZE);
        ret = mbedtls_cipher_cmac(cipher_info, zero_key, 128, key,
                                  key_length, int_key);
        if (ret != 0) {
            goto exit;
        }
    }
    ret = mbedtls_cipher_cmac(cipher_info, int_key, 128, input, in_len,
                              output);
exit:
    mbedtls_platform_zeroize(int_key, sizeof(int_key));
    return ret;
}
#endif
#endif
#endif
