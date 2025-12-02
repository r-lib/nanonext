/**
 * \file poly1305.c
 *
 * \brief Poly1305 authentication algorithm.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"

#if defined(MBEDTLS_POLY1305_C)

#include "mbedtls/poly1305.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_POLY1305_ALT)

#define POLY1305_BLOCK_SIZE_BYTES (16U)

#if defined(MBEDTLS_NO_64BIT_MULTIPLICATION)
static uint64_t mul64(uint32_t a, uint32_t b)
{
    const uint16_t al = (uint16_t) a;
    const uint16_t bl = (uint16_t) b;
    const uint16_t ah = a >> 16;
    const uint16_t bh = b >> 16;

    const uint32_t lo = (uint32_t) al * bl;
    const uint64_t me = (uint64_t) ((uint32_t) ah * bl) + (uint32_t) al * bh;
    const uint32_t hi = (uint32_t) ah * bh;

    return lo + (me << 16) + ((uint64_t) hi << 32);
}
#else
static inline uint64_t mul64(uint32_t a, uint32_t b)
{
    return (uint64_t) a * b;
}
#endif

static void poly1305_process(mbedtls_poly1305_context *ctx,
                             size_t nblocks,
                             const unsigned char *input,
                             uint32_t needs_padding)
{
    uint64_t d0, d1, d2, d3;
    uint32_t acc0, acc1, acc2, acc3, acc4;
    uint32_t r0, r1, r2, r3;
    uint32_t rs1, rs2, rs3;
    size_t offset  = 0U;
    size_t i;

    r0 = ctx->r[0];
    r1 = ctx->r[1];
    r2 = ctx->r[2];
    r3 = ctx->r[3];

    rs1 = r1 + (r1 >> 2U);
    rs2 = r2 + (r2 >> 2U);
    rs3 = r3 + (r3 >> 2U);

    acc0 = ctx->acc[0];
    acc1 = ctx->acc[1];
    acc2 = ctx->acc[2];
    acc3 = ctx->acc[3];
    acc4 = ctx->acc[4];

    for (i = 0U; i < nblocks; i++) {
        d0   = MBEDTLS_GET_UINT32_LE(input, offset + 0);
        d1   = MBEDTLS_GET_UINT32_LE(input, offset + 4);
        d2   = MBEDTLS_GET_UINT32_LE(input, offset + 8);
        d3   = MBEDTLS_GET_UINT32_LE(input, offset + 12);

        d0  += (uint64_t) acc0;
        d1  += (uint64_t) acc1 + (d0 >> 32U);
        d2  += (uint64_t) acc2 + (d1 >> 32U);
        d3  += (uint64_t) acc3 + (d2 >> 32U);
        acc0 = (uint32_t) d0;
        acc1 = (uint32_t) d1;
        acc2 = (uint32_t) d2;
        acc3 = (uint32_t) d3;
        acc4 += (uint32_t) (d3 >> 32U) + needs_padding;

        d0 = mul64(acc0, r0) +
             mul64(acc1, rs3) +
             mul64(acc2, rs2) +
             mul64(acc3, rs1);
        d1 = mul64(acc0, r1) +
             mul64(acc1, r0) +
             mul64(acc2, rs3) +
             mul64(acc3, rs2) +
             mul64(acc4, rs1);
        d2 = mul64(acc0, r2) +
             mul64(acc1, r1) +
             mul64(acc2, r0) +
             mul64(acc3, rs3) +
             mul64(acc4, rs2);
        d3 = mul64(acc0, r3) +
             mul64(acc1, r2) +
             mul64(acc2, r1) +
             mul64(acc3, r0) +
             mul64(acc4, rs3);
        acc4 *= r0;

        d1 += (d0 >> 32);
        d2 += (d1 >> 32);
        d3 += (d2 >> 32);
        acc0 = (uint32_t) d0;
        acc1 = (uint32_t) d1;
        acc2 = (uint32_t) d2;
        acc3 = (uint32_t) d3;
        acc4 = (uint32_t) (d3 >> 32) + acc4;

        d0 = (uint64_t) acc0 + (acc4 >> 2) + (acc4 & 0xFFFFFFFCU);
        acc4 &= 3U;
        acc0 = (uint32_t) d0;
        d0 = (uint64_t) acc1 + (d0 >> 32U);
        acc1 = (uint32_t) d0;
        d0 = (uint64_t) acc2 + (d0 >> 32U);
        acc2 = (uint32_t) d0;
        d0 = (uint64_t) acc3 + (d0 >> 32U);
        acc3 = (uint32_t) d0;
        d0 = (uint64_t) acc4 + (d0 >> 32U);
        acc4 = (uint32_t) d0;

        offset    += POLY1305_BLOCK_SIZE_BYTES;
    }

    ctx->acc[0] = acc0;
    ctx->acc[1] = acc1;
    ctx->acc[2] = acc2;
    ctx->acc[3] = acc3;
    ctx->acc[4] = acc4;
}

static void poly1305_compute_mac(const mbedtls_poly1305_context *ctx,
                                 unsigned char mac[16])
{
    uint64_t d;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t acc0, acc1, acc2, acc3, acc4;
    uint32_t mask;
    uint32_t mask_inv;

    acc0 = ctx->acc[0];
    acc1 = ctx->acc[1];
    acc2 = ctx->acc[2];
    acc3 = ctx->acc[3];
    acc4 = ctx->acc[4];

    d  = ((uint64_t) acc0 + 5U);
    g0 = (uint32_t) d;
    d  = ((uint64_t) acc1 + (d >> 32));
    g1 = (uint32_t) d;
    d  = ((uint64_t) acc2 + (d >> 32));
    g2 = (uint32_t) d;
    d  = ((uint64_t) acc3 + (d >> 32));
    g3 = (uint32_t) d;
    g4 = acc4 + (uint32_t) (d >> 32U);

    mask = (uint32_t) 0U - (g4 >> 2U);
    mask_inv = ~mask;

    acc0 = (acc0 & mask_inv) | (g0 & mask);
    acc1 = (acc1 & mask_inv) | (g1 & mask);
    acc2 = (acc2 & mask_inv) | (g2 & mask);
    acc3 = (acc3 & mask_inv) | (g3 & mask);

    d = (uint64_t) acc0 + ctx->s[0];
    acc0 = (uint32_t) d;
    d = (uint64_t) acc1 + ctx->s[1] + (d >> 32U);
    acc1 = (uint32_t) d;
    d = (uint64_t) acc2 + ctx->s[2] + (d >> 32U);
    acc2 = (uint32_t) d;
    acc3 += ctx->s[3] + (uint32_t) (d >> 32U);

    MBEDTLS_PUT_UINT32_LE(acc0, mac,  0);
    MBEDTLS_PUT_UINT32_LE(acc1, mac,  4);
    MBEDTLS_PUT_UINT32_LE(acc2, mac,  8);
    MBEDTLS_PUT_UINT32_LE(acc3, mac, 12);
}

void mbedtls_poly1305_init(mbedtls_poly1305_context *ctx)
{
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_poly1305_context));
}

void mbedtls_poly1305_free(mbedtls_poly1305_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_poly1305_context));
}

int mbedtls_poly1305_starts(mbedtls_poly1305_context *ctx,
                            const unsigned char key[32])
{
    ctx->r[0] = MBEDTLS_GET_UINT32_LE(key, 0)  & 0x0FFFFFFFU;
    ctx->r[1] = MBEDTLS_GET_UINT32_LE(key, 4)  & 0x0FFFFFFCU;
    ctx->r[2] = MBEDTLS_GET_UINT32_LE(key, 8)  & 0x0FFFFFFCU;
    ctx->r[3] = MBEDTLS_GET_UINT32_LE(key, 12) & 0x0FFFFFFCU;

    ctx->s[0] = MBEDTLS_GET_UINT32_LE(key, 16);
    ctx->s[1] = MBEDTLS_GET_UINT32_LE(key, 20);
    ctx->s[2] = MBEDTLS_GET_UINT32_LE(key, 24);
    ctx->s[3] = MBEDTLS_GET_UINT32_LE(key, 28);

    ctx->acc[0] = 0U;
    ctx->acc[1] = 0U;
    ctx->acc[2] = 0U;
    ctx->acc[3] = 0U;
    ctx->acc[4] = 0U;

    mbedtls_platform_zeroize(ctx->queue, sizeof(ctx->queue));
    ctx->queue_len = 0U;

    return 0;
}

int mbedtls_poly1305_update(mbedtls_poly1305_context *ctx,
                            const unsigned char *input,
                            size_t ilen)
{
    size_t offset    = 0U;
    size_t remaining = ilen;
    size_t queue_free_len;
    size_t nblocks;

    if ((remaining > 0U) && (ctx->queue_len > 0U)) {
        queue_free_len = (POLY1305_BLOCK_SIZE_BYTES - ctx->queue_len);

        if (ilen < queue_free_len) {
            memcpy(&ctx->queue[ctx->queue_len],
                   input,
                   ilen);

            ctx->queue_len += ilen;

            remaining = 0U;
        } else {
            memcpy(&ctx->queue[ctx->queue_len],
                   input,
                   queue_free_len);

            ctx->queue_len = 0U;

            poly1305_process(ctx, 1U, ctx->queue, 1U);

            offset    += queue_free_len;
            remaining -= queue_free_len;
        }
    }

    if (remaining >= POLY1305_BLOCK_SIZE_BYTES) {
        nblocks = remaining / POLY1305_BLOCK_SIZE_BYTES;

        poly1305_process(ctx, nblocks, &input[offset], 1U);

        offset += nblocks * POLY1305_BLOCK_SIZE_BYTES;
        remaining %= POLY1305_BLOCK_SIZE_BYTES;
    }

    if (remaining > 0U) {
        ctx->queue_len = remaining;
        memcpy(ctx->queue, &input[offset], remaining);
    }

    return 0;
}

int mbedtls_poly1305_finish(mbedtls_poly1305_context *ctx,
                            unsigned char mac[16])
{
    if (ctx->queue_len > 0U) {
        ctx->queue[ctx->queue_len] = 1U;
        ctx->queue_len++;

        memset(&ctx->queue[ctx->queue_len],
               0,
               POLY1305_BLOCK_SIZE_BYTES - ctx->queue_len);

        poly1305_process(ctx, 1U,
                         ctx->queue, 0U);
    }

    poly1305_compute_mac(ctx, mac);

    return 0;
}

int mbedtls_poly1305_mac(const unsigned char key[32],
                         const unsigned char *input,
                         size_t ilen,
                         unsigned char mac[16])
{
    mbedtls_poly1305_context ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_poly1305_init(&ctx);

    ret = mbedtls_poly1305_starts(&ctx, key);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_poly1305_update(&ctx, input, ilen);
    if (ret != 0) {
        goto cleanup;
    }

    ret = mbedtls_poly1305_finish(&ctx, mac);

cleanup:
    mbedtls_poly1305_free(&ctx);
    return ret;
}

#endif /* MBEDTLS_POLY1305_ALT */

#endif
