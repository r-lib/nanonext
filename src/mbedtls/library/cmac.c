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

#if defined(MBEDTLS_SELF_TEST)

#define NB_CMAC_TESTS_PER_KEY 4
#define NB_PRF_TESTS 3

#if defined(MBEDTLS_AES_C) || defined(MBEDTLS_DES_C)

static const unsigned char test_message[] = {

    0x6b, 0xc1, 0xbe, 0xe2,     0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11,     0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57,     0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac,     0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46,     0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19,     0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45,     0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b,     0xe6, 0x6c, 0x37, 0x10
};
#endif

#if defined(MBEDTLS_AES_C)

static const  unsigned int  aes_message_lengths[NB_CMAC_TESTS_PER_KEY] = {

    0,
    16,
    20,
    64
};

static const unsigned char aes_128_key[16] = {
    0x2b, 0x7e, 0x15, 0x16,     0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,     0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char aes_128_subkeys[2][MBEDTLS_AES_BLOCK_SIZE] = {
    {

        0xfb, 0xee, 0xd6, 0x18,     0x35, 0x71, 0x33, 0x66,
        0x7c, 0x85, 0xe0, 0x8f,     0x72, 0x36, 0xa8, 0xde
    },
    {

        0xf7, 0xdd, 0xac, 0x30,     0x6a, 0xe2, 0x66, 0xcc,
        0xf9, 0x0b, 0xc1, 0x1e,     0xe4, 0x6d, 0x51, 0x3b
    }
};
static const unsigned char aes_128_expected_result[NB_CMAC_TESTS_PER_KEY][MBEDTLS_AES_BLOCK_SIZE] =
{
    {

        0xbb, 0x1d, 0x69, 0x29,     0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12,     0x9b, 0x75, 0x67, 0x46
    },
    {

        0x07, 0x0a, 0x16, 0xb4,     0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d,     0xd0, 0x4a, 0x28, 0x7c
    },
    {

        0x7d, 0x85, 0x44, 0x9e,     0xa6, 0xea, 0x19, 0xc8,
        0x23, 0xa7, 0xbf, 0x78,     0x83, 0x7d, 0xfa, 0xde
    },
    {

        0x51, 0xf0, 0xbe, 0xbf,     0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17,     0x79, 0x36, 0x3c, 0xfe
    }
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const unsigned char aes_192_key[24] = {
    0x8e, 0x73, 0xb0, 0xf7,     0xda, 0x0e, 0x64, 0x52,
    0xc8, 0x10, 0xf3, 0x2b,     0x80, 0x90, 0x79, 0xe5,
    0x62, 0xf8, 0xea, 0xd2,     0x52, 0x2c, 0x6b, 0x7b
};
static const unsigned char aes_192_subkeys[2][MBEDTLS_AES_BLOCK_SIZE] = {
    {

        0x44, 0x8a, 0x5b, 0x1c,     0x93, 0x51, 0x4b, 0x27,
        0x3e, 0xe6, 0x43, 0x9d,     0xd4, 0xda, 0xa2, 0x96
    },
    {

        0x89, 0x14, 0xb6, 0x39,     0x26, 0xa2, 0x96, 0x4e,
        0x7d, 0xcc, 0x87, 0x3b,     0xa9, 0xb5, 0x45, 0x2c
    }
};
static const unsigned char aes_192_expected_result[NB_CMAC_TESTS_PER_KEY][MBEDTLS_AES_BLOCK_SIZE] =
{
    {

        0xd1, 0x7d, 0xdf, 0x46,     0xad, 0xaa, 0xcd, 0xe5,
        0x31, 0xca, 0xc4, 0x83,     0xde, 0x7a, 0x93, 0x67
    },
    {

        0x9e, 0x99, 0xa7, 0xbf,     0x31, 0xe7, 0x10, 0x90,
        0x06, 0x62, 0xf6, 0x5e,     0x61, 0x7c, 0x51, 0x84
    },
    {

        0x3d, 0x75, 0xc1, 0x94,     0xed, 0x96, 0x07, 0x04,
        0x44, 0xa9, 0xfa, 0x7e,     0xc7, 0x40, 0xec, 0xf8
    },
    {

        0xa1, 0xd5, 0xdf, 0x0e,     0xed, 0x79, 0x0f, 0x79,
        0x4d, 0x77, 0x58, 0x96,     0x59, 0xf3, 0x9a, 0x11
    }
};
#endif

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const unsigned char aes_256_key[32] = {
    0x60, 0x3d, 0xeb, 0x10,     0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0,     0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07,     0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3,     0x09, 0x14, 0xdf, 0xf4
};
static const unsigned char aes_256_subkeys[2][MBEDTLS_AES_BLOCK_SIZE] = {
    {

        0xca, 0xd1, 0xed, 0x03,     0x29, 0x9e, 0xed, 0xac,
        0x2e, 0x9a, 0x99, 0x80,     0x86, 0x21, 0x50, 0x2f
    },
    {

        0x95, 0xa3, 0xda, 0x06,     0x53, 0x3d, 0xdb, 0x58,
        0x5d, 0x35, 0x33, 0x01,     0x0c, 0x42, 0xa0, 0xd9
    }
};
static const unsigned char aes_256_expected_result[NB_CMAC_TESTS_PER_KEY][MBEDTLS_AES_BLOCK_SIZE] =
{
    {

        0x02, 0x89, 0x62, 0xf6,     0x1b, 0x7b, 0xf8, 0x9e,
        0xfc, 0x6b, 0x55, 0x1f,     0x46, 0x67, 0xd9, 0x83
    },
    {

        0x28, 0xa7, 0x02, 0x3f,     0x45, 0x2e, 0x8f, 0x82,
        0xbd, 0x4b, 0xf2, 0x8d,     0x8c, 0x37, 0xc3, 0x5c
    },
    {

        0x15, 0x67, 0x27, 0xdc,     0x08, 0x78, 0x94, 0x4a,
        0x02, 0x3c, 0x1f, 0xe0,     0x3b, 0xad, 0x6d, 0x93
    },
    {

        0xe1, 0x99, 0x21, 0x90,     0x54, 0x9f, 0x6e, 0xd5,
        0x69, 0x6a, 0x2c, 0x05,     0x6c, 0x31, 0x54, 0x10
    }
};
#endif
#endif

#if defined(MBEDTLS_DES_C)

static const unsigned int des3_message_lengths[NB_CMAC_TESTS_PER_KEY] = {
    0,
    16,
    20,
    32
};

static const unsigned char des3_2key_key[24] = {

    0x01, 0x23, 0x45, 0x67,     0x89, 0xab, 0xcd, 0xef,

    0x23, 0x45, 0x67, 0x89,     0xab, 0xcd, 0xEF, 0x01,

    0x01, 0x23, 0x45, 0x67,     0x89, 0xab, 0xcd, 0xef
};
static const unsigned char des3_2key_subkeys[2][8] = {
    {

        0x0d, 0xd2, 0xcb, 0x7a,     0x3d, 0x88, 0x88, 0xd9
    },
    {

        0x1b, 0xa5, 0x96, 0xf4,     0x7b, 0x11, 0x11, 0xb2
    }
};
static const unsigned char des3_2key_expected_result[NB_CMAC_TESTS_PER_KEY][MBEDTLS_DES3_BLOCK_SIZE]
    = {
    {

        0x79, 0xce, 0x52, 0xa7,     0xf7, 0x86, 0xa9, 0x60
    },
    {

        0xcc, 0x18, 0xa0, 0xb7,     0x9a, 0xf2, 0x41, 0x3b
    },
    {

        0xc0, 0x6d, 0x37, 0x7e,     0xcd, 0x10, 0x19, 0x69
    },
    {

        0x9c, 0xd3, 0x35, 0x80,     0xf9, 0xb6, 0x4d, 0xfb
    }
    };

static const unsigned char des3_3key_key[24] = {

    0x01, 0x23, 0x45, 0x67,     0x89, 0xaa, 0xcd, 0xef,

    0x23, 0x45, 0x67, 0x89,     0xab, 0xcd, 0xef, 0x01,

    0x45, 0x67, 0x89, 0xab,     0xcd, 0xef, 0x01, 0x23
};
static const unsigned char des3_3key_subkeys[2][8] = {
    {

        0x9d, 0x74, 0xe7, 0x39,     0x33, 0x17, 0x96, 0xc0
    },
    {

        0x3a, 0xe9, 0xce, 0x72,     0x66, 0x2f, 0x2d, 0x9b
    }
};
static const unsigned char des3_3key_expected_result[NB_CMAC_TESTS_PER_KEY][MBEDTLS_DES3_BLOCK_SIZE]
    = {
    {

        0x7d, 0xb0, 0xd3, 0x7d,     0xf9, 0x36, 0xc5, 0x50
    },
    {

        0x30, 0x23, 0x9c, 0xf1,     0xf5, 0x2e, 0x66, 0x09
    },
    {

        0x6c, 0x9f, 0x3e, 0xe4,     0x92, 0x3f, 0x6b, 0xe2
    },
    {

        0x99, 0x42, 0x9b, 0xd0,     0xbF, 0x79, 0x04, 0xe5
    }
    };

#endif

#if defined(MBEDTLS_AES_C)

static const unsigned char PRFK[] = {

    0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,     0x0c, 0x0d, 0x0e, 0x0f,
    0xed, 0xcb
};

static const size_t PRFKlen[NB_PRF_TESTS] = {
    18,
    16,
    10
};

static const unsigned char PRFM[] = {
    0x00, 0x01, 0x02, 0x03,     0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,     0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
};

static const unsigned char PRFT[NB_PRF_TESTS][16] = {
    {
        0x84, 0xa3, 0x48, 0xa4,     0xa4, 0x5d, 0x23, 0x5b,
        0xab, 0xff, 0xfc, 0x0d,     0x2b, 0x4d, 0xa0, 0x9a
    },
    {
        0x98, 0x0a, 0xe8, 0x7b,     0x5f, 0x4c, 0x9c, 0x52,
        0x14, 0xf5, 0xb6, 0xa8,     0x45, 0x5e, 0x4c, 0x2d
    },
    {
        0x29, 0x0d, 0x9e, 0x11,     0x2e, 0xdb, 0x09, 0xee,
        0x14, 0x1f, 0xcf, 0x64,     0xc0, 0xb7, 0x2f, 0x3d
    }
};
#endif

static int cmac_test_subkeys(int verbose,
                             const char *testname,
                             const unsigned char *key,
                             int keybits,
                             const unsigned char *subkeys,
                             mbedtls_cipher_type_t cipher_type,
                             int block_size,
                             int num_tests)
{
    int i, ret = 0;
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *cipher_info;
    unsigned char K1[MBEDTLS_CMAC_MAX_BLOCK_SIZE];
    unsigned char K2[MBEDTLS_CMAC_MAX_BLOCK_SIZE];

    cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    if (cipher_info == NULL) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    for (i = 0; i < num_tests; i++) {
        if (verbose != 0) {
            mbedtls_printf("  %s CMAC subkey #%d: ", testname, i + 1);
        }

        mbedtls_cipher_init(&ctx);

        if ((ret = mbedtls_cipher_setup(&ctx, cipher_info)) != 0) {
            if (verbose != 0) {
                mbedtls_printf("test execution failed\n");
            }

            goto cleanup;
        }

        if ((ret = mbedtls_cipher_setkey(&ctx, key, keybits,
                                         MBEDTLS_ENCRYPT)) != 0) {

            if ((ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED ||
                 ret == MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE) &&
                cipher_type == MBEDTLS_CIPHER_AES_192_ECB) {
                if (verbose != 0) {
                    mbedtls_printf("skipped\n");
                }
                goto next_test;
            }

            if (verbose != 0) {
                mbedtls_printf("test execution failed\n");
            }

            goto cleanup;
        }

        ret = cmac_generate_subkeys(&ctx, K1, K2);
        if (ret != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }

            goto cleanup;
        }

        if ((ret = memcmp(K1, subkeys, block_size)) != 0  ||
            (ret = memcmp(K2, &subkeys[block_size], block_size)) != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }

            goto cleanup;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }

next_test:
        mbedtls_cipher_free(&ctx);
    }

    ret = 0;
    goto exit;

cleanup:
    mbedtls_cipher_free(&ctx);

exit:
    return ret;
}

static int cmac_test_wth_cipher(int verbose,
                                const char *testname,
                                const unsigned char *key,
                                int keybits,
                                const unsigned char *messages,
                                const unsigned int message_lengths[4],
                                const unsigned char *expected_result,
                                mbedtls_cipher_type_t cipher_type,
                                int block_size,
                                int num_tests)
{
    const mbedtls_cipher_info_t *cipher_info;
    int i, ret = 0;
    unsigned char output[MBEDTLS_CMAC_MAX_BLOCK_SIZE];

    cipher_info = mbedtls_cipher_info_from_type(cipher_type);
    if (cipher_info == NULL) {

        ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        goto exit;
    }

    for (i = 0; i < num_tests; i++) {
        if (verbose != 0) {
            mbedtls_printf("  %s CMAC #%d: ", testname, i + 1);
        }

        if ((ret = mbedtls_cipher_cmac(cipher_info, key, keybits, messages,
                                       message_lengths[i], output)) != 0) {

            if ((ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED ||
                 ret == MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE) &&
                (cipher_type == MBEDTLS_CIPHER_AES_192_ECB ||
                 cipher_type == MBEDTLS_CIPHER_DES_EDE3_ECB)) {
                if (verbose != 0) {
                    mbedtls_printf("skipped\n");
                }
                continue;
            }

            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            goto exit;
        }

        if ((ret = memcmp(output, &expected_result[i * block_size], block_size)) != 0) {
            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }
            goto exit;
        }

        if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }
    ret = 0;

exit:
    return ret;
}

#if defined(MBEDTLS_AES_C)
static int test_aes128_cmac_prf(int verbose)
{
    int i;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char output[MBEDTLS_AES_BLOCK_SIZE];

    for (i = 0; i < NB_PRF_TESTS; i++) {
        mbedtls_printf("  AES CMAC 128 PRF #%d: ", i);
        ret = mbedtls_aes_cmac_prf_128(PRFK, PRFKlen[i], PRFM, 20, output);
        if (ret != 0 ||
            memcmp(output, PRFT[i], MBEDTLS_AES_BLOCK_SIZE) != 0) {

            if (verbose != 0) {
                mbedtls_printf("failed\n");
            }

            return ret;
        } else if (verbose != 0) {
            mbedtls_printf("passed\n");
        }
    }
    return ret;
}
#endif

int mbedtls_cmac_self_test(int verbose)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_AES_C)

    if ((ret = cmac_test_subkeys(verbose,
                                 "AES 128",
                                 aes_128_key,
                                 128,
                                 (const unsigned char *) aes_128_subkeys,
                                 MBEDTLS_CIPHER_AES_128_ECB,
                                 MBEDTLS_AES_BLOCK_SIZE,
                                 NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }

    if ((ret = cmac_test_wth_cipher(verbose,
                                    "AES 128",
                                    aes_128_key,
                                    128,
                                    test_message,
                                    aes_message_lengths,
                                    (const unsigned char *) aes_128_expected_result,
                                    MBEDTLS_CIPHER_AES_128_ECB,
                                    MBEDTLS_AES_BLOCK_SIZE,
                                    NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    if ((ret = cmac_test_subkeys(verbose,
                                 "AES 192",
                                 aes_192_key,
                                 192,
                                 (const unsigned char *) aes_192_subkeys,
                                 MBEDTLS_CIPHER_AES_192_ECB,
                                 MBEDTLS_AES_BLOCK_SIZE,
                                 NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }

    if ((ret = cmac_test_wth_cipher(verbose,
                                    "AES 192",
                                    aes_192_key,
                                    192,
                                    test_message,
                                    aes_message_lengths,
                                    (const unsigned char *) aes_192_expected_result,
                                    MBEDTLS_CIPHER_AES_192_ECB,
                                    MBEDTLS_AES_BLOCK_SIZE,
                                    NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }
#endif

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    if ((ret = cmac_test_subkeys(verbose,
                                 "AES 256",
                                 aes_256_key,
                                 256,
                                 (const unsigned char *) aes_256_subkeys,
                                 MBEDTLS_CIPHER_AES_256_ECB,
                                 MBEDTLS_AES_BLOCK_SIZE,
                                 NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }

    if ((ret = cmac_test_wth_cipher(verbose,
                                    "AES 256",
                                    aes_256_key,
                                    256,
                                    test_message,
                                    aes_message_lengths,
                                    (const unsigned char *) aes_256_expected_result,
                                    MBEDTLS_CIPHER_AES_256_ECB,
                                    MBEDTLS_AES_BLOCK_SIZE,
                                    NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }
#endif
#endif

#if defined(MBEDTLS_DES_C)

    if ((ret = cmac_test_subkeys(verbose,
                                 "3DES 2 key",
                                 des3_2key_key,
                                 192,
                                 (const unsigned char *) des3_2key_subkeys,
                                 MBEDTLS_CIPHER_DES_EDE3_ECB,
                                 MBEDTLS_DES3_BLOCK_SIZE,
                                 NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }

    if ((ret = cmac_test_wth_cipher(verbose,
                                    "3DES 2 key",
                                    des3_2key_key,
                                    192,
                                    test_message,
                                    des3_message_lengths,
                                    (const unsigned char *) des3_2key_expected_result,
                                    MBEDTLS_CIPHER_DES_EDE3_ECB,
                                    MBEDTLS_DES3_BLOCK_SIZE,
                                    NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }

    if ((ret = cmac_test_subkeys(verbose,
                                 "3DES 3 key",
                                 des3_3key_key,
                                 192,
                                 (const unsigned char *) des3_3key_subkeys,
                                 MBEDTLS_CIPHER_DES_EDE3_ECB,
                                 MBEDTLS_DES3_BLOCK_SIZE,
                                 NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }

    if ((ret = cmac_test_wth_cipher(verbose,
                                    "3DES 3 key",
                                    des3_3key_key,
                                    192,
                                    test_message,
                                    des3_message_lengths,
                                    (const unsigned char *) des3_3key_expected_result,
                                    MBEDTLS_CIPHER_DES_EDE3_ECB,
                                    MBEDTLS_DES3_BLOCK_SIZE,
                                    NB_CMAC_TESTS_PER_KEY)) != 0) {
        return ret;
    }
#endif

#if defined(MBEDTLS_AES_C)
    if ((ret = test_aes128_cmac_prf(verbose)) != 0) {
        return ret;
    }
#endif

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return 0;
}

#endif

#endif
