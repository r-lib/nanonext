/**
 * \file chacha20.c
 *
 * \brief ChaCha20 cipher.
 *
 * \author Daniel King <damaki.gh@gmail.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_CHACHA20_C)

#include "mbedtls/chacha20.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <stddef.h>
#include <string.h>

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_CHACHA20_ALT)

#define ROTL32(value, amount) \
    ((uint32_t) ((value) << (amount)) | ((value) >> (32 - (amount))))

#define CHACHA20_CTR_INDEX (12U)

#define CHACHA20_BLOCK_SIZE_BYTES (4U * 16U)

static inline void chacha20_quarter_round(uint32_t state[16],
                                          size_t a,
                                          size_t b,
                                          size_t c,
                                          size_t d)
{
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32(state[d], 16);

    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32(state[b], 12);

    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = ROTL32(state[d], 8);

    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = ROTL32(state[b], 7);
}

static void chacha20_inner_block(uint32_t state[16])
{
    chacha20_quarter_round(state, 0, 4, 8,  12);
    chacha20_quarter_round(state, 1, 5, 9,  13);
    chacha20_quarter_round(state, 2, 6, 10, 14);
    chacha20_quarter_round(state, 3, 7, 11, 15);

    chacha20_quarter_round(state, 0, 5, 10, 15);
    chacha20_quarter_round(state, 1, 6, 11, 12);
    chacha20_quarter_round(state, 2, 7, 8,  13);
    chacha20_quarter_round(state, 3, 4, 9,  14);
}

static void chacha20_block(const uint32_t initial_state[16],
                           unsigned char keystream[64])
{
    uint32_t working_state[16];
    size_t i;

    memcpy(working_state,
           initial_state,
           CHACHA20_BLOCK_SIZE_BYTES);

    for (i = 0U; i < 10U; i++) {
        chacha20_inner_block(working_state);
    }

    working_state[0] += initial_state[0];
    working_state[1] += initial_state[1];
    working_state[2] += initial_state[2];
    working_state[3] += initial_state[3];
    working_state[4] += initial_state[4];
    working_state[5] += initial_state[5];
    working_state[6] += initial_state[6];
    working_state[7] += initial_state[7];
    working_state[8] += initial_state[8];
    working_state[9] += initial_state[9];
    working_state[10] += initial_state[10];
    working_state[11] += initial_state[11];
    working_state[12] += initial_state[12];
    working_state[13] += initial_state[13];
    working_state[14] += initial_state[14];
    working_state[15] += initial_state[15];

    for (i = 0U; i < 16; i++) {
        size_t offset = i * 4U;

        MBEDTLS_PUT_UINT32_LE(working_state[i], keystream, offset);
    }

    mbedtls_platform_zeroize(working_state, sizeof(working_state));
}

void mbedtls_chacha20_init(mbedtls_chacha20_context *ctx)
{
    mbedtls_platform_zeroize(ctx->state, sizeof(ctx->state));
    mbedtls_platform_zeroize(ctx->keystream8, sizeof(ctx->keystream8));

    ctx->keystream_bytes_used = CHACHA20_BLOCK_SIZE_BYTES;
}

void mbedtls_chacha20_free(mbedtls_chacha20_context *ctx)
{
    if (ctx != NULL) {
        mbedtls_platform_zeroize(ctx, sizeof(mbedtls_chacha20_context));
    }
}

int mbedtls_chacha20_setkey(mbedtls_chacha20_context *ctx,
                            const unsigned char key[32])
{
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;

    ctx->state[4]  = MBEDTLS_GET_UINT32_LE(key, 0);
    ctx->state[5]  = MBEDTLS_GET_UINT32_LE(key, 4);
    ctx->state[6]  = MBEDTLS_GET_UINT32_LE(key, 8);
    ctx->state[7]  = MBEDTLS_GET_UINT32_LE(key, 12);
    ctx->state[8]  = MBEDTLS_GET_UINT32_LE(key, 16);
    ctx->state[9]  = MBEDTLS_GET_UINT32_LE(key, 20);
    ctx->state[10] = MBEDTLS_GET_UINT32_LE(key, 24);
    ctx->state[11] = MBEDTLS_GET_UINT32_LE(key, 28);

    return 0;
}

int mbedtls_chacha20_starts(mbedtls_chacha20_context *ctx,
                            const unsigned char nonce[12],
                            uint32_t counter)
{
    ctx->state[12] = counter;

    ctx->state[13] = MBEDTLS_GET_UINT32_LE(nonce, 0);
    ctx->state[14] = MBEDTLS_GET_UINT32_LE(nonce, 4);
    ctx->state[15] = MBEDTLS_GET_UINT32_LE(nonce, 8);

    mbedtls_platform_zeroize(ctx->keystream8, sizeof(ctx->keystream8));

    ctx->keystream_bytes_used = CHACHA20_BLOCK_SIZE_BYTES;

    return 0;
}

int mbedtls_chacha20_update(mbedtls_chacha20_context *ctx,
                            size_t size,
                            const unsigned char *input,
                            unsigned char *output)
{
    size_t offset = 0U;

    while (size > 0U && ctx->keystream_bytes_used < CHACHA20_BLOCK_SIZE_BYTES) {
        output[offset] = input[offset]
                         ^ ctx->keystream8[ctx->keystream_bytes_used];

        ctx->keystream_bytes_used++;
        offset++;
        size--;
    }

    while (size >= CHACHA20_BLOCK_SIZE_BYTES) {
        chacha20_block(ctx->state, ctx->keystream8);
        ctx->state[CHACHA20_CTR_INDEX]++;

        mbedtls_xor(output + offset, input + offset, ctx->keystream8, 64U);

        offset += CHACHA20_BLOCK_SIZE_BYTES;
        size   -= CHACHA20_BLOCK_SIZE_BYTES;
    }

    if (size > 0U) {
        chacha20_block(ctx->state, ctx->keystream8);
        ctx->state[CHACHA20_CTR_INDEX]++;

        mbedtls_xor(output + offset, input + offset, ctx->keystream8, size);

        ctx->keystream_bytes_used = size;

    }

    return 0;
}

int mbedtls_chacha20_crypt(const unsigned char key[32],
                           const unsigned char nonce[12],
                           uint32_t counter,
                           size_t data_len,
                           const unsigned char *input,
                           unsigned char *output)
{
    mbedtls_chacha20_context ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_chacha20_init(&ctx);

    ret = mbedtls_chacha20_setkey(&ctx, key);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_chacha20_starts(&ctx, nonce, counter);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_chacha20_update(&ctx, data_len, input, output);

cleanup:
    mbedtls_chacha20_free(&ctx);
    return ret;
}

#endif

#endif
