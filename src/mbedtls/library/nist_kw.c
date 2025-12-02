/*
 *  Implementation of NIST SP 800-38F key wrapping, supporting KW and KWP modes
 *  only
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * Definition of Key Wrapping:
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf
 * RFC 3394 "Advanced Encryption Standard (AES) Key Wrap Algorithm"
 * RFC 5649 "Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm"
 *
 * Note: RFC 3394 defines different methodology for intermediate operations for
 * the wrapping and unwrapping operation than the definition in NIST SP 800-38F.
 */

#include "common.h"

#if defined(MBEDTLS_NIST_KW_C)

#include "mbedtls/nist_kw.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/constant_time.h"
#include "constant_time_internal.h"

#include <stdint.h>
#include <string.h>

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_NIST_KW_ALT)

#define KW_SEMIBLOCK_LENGTH    8
#define MIN_SEMIBLOCKS_COUNT   3

static const unsigned char NIST_KW_ICV1[] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
static const  unsigned char NIST_KW_ICV2[] = { 0xA6, 0x59, 0x59, 0xA6 };

void mbedtls_nist_kw_init(mbedtls_nist_kw_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_nist_kw_context));
}

int mbedtls_nist_kw_setkey(mbedtls_nist_kw_context *ctx,
                           mbedtls_cipher_id_t cipher,
                           const unsigned char *key,
                           unsigned int keybits,
                           const int is_wrap)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_cipher_info_t *cipher_info;

    cipher_info = mbedtls_cipher_info_from_values(cipher,
                                                  keybits,
                                                  MBEDTLS_MODE_ECB);
    if (cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (mbedtls_cipher_info_get_block_size(cipher_info) != 16) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (cipher != MBEDTLS_CIPHER_ID_AES) {
        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    mbedtls_cipher_free(&ctx->cipher_ctx);

    if ((ret = mbedtls_cipher_setup(&ctx->cipher_ctx, cipher_info)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_cipher_setkey(&ctx->cipher_ctx, key, keybits,
                                     is_wrap ? MBEDTLS_ENCRYPT :
                                     MBEDTLS_DECRYPT)
         ) != 0) {
        return ret;
    }

    return 0;
}

void mbedtls_nist_kw_free(mbedtls_nist_kw_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_cipher_free(&ctx->cipher_ctx);
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_nist_kw_context));
}

static void calc_a_xor_t(unsigned char A[KW_SEMIBLOCK_LENGTH], uint64_t t)
{
    size_t i = 0;
    for (i = 0; i < sizeof(t); i++) {
        A[i] ^= (t >> ((sizeof(t) - 1 - i) * 8)) & 0xff;
    }
}

int mbedtls_nist_kw_wrap(mbedtls_nist_kw_context *ctx,
                         mbedtls_nist_kw_mode_t mode,
                         const unsigned char *input, size_t in_len,
                         unsigned char *output, size_t *out_len, size_t out_size)
{
    int ret = 0;
    size_t semiblocks = 0;
    size_t s;
    size_t olen, padlen = 0;
    uint64_t t = 0;
    unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char inbuff[KW_SEMIBLOCK_LENGTH * 2];

    *out_len = 0;

    if (mode == MBEDTLS_KW_MODE_KW) {
        if (out_size < in_len + KW_SEMIBLOCK_LENGTH) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (in_len < 16 ||
#if SIZE_MAX > 0x1FFFFFFFFFFFFF8
            in_len > 0x1FFFFFFFFFFFFF8 ||
#endif
            in_len % KW_SEMIBLOCK_LENGTH != 0) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        memcpy(output, NIST_KW_ICV1, KW_SEMIBLOCK_LENGTH);
        memmove(output + KW_SEMIBLOCK_LENGTH, input, in_len);
    } else {
        if (in_len % 8 != 0) {
            padlen = (8 - (in_len % 8));
        }

        if (out_size < in_len + KW_SEMIBLOCK_LENGTH + padlen) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (in_len < 1
#if SIZE_MAX > 0xFFFFFFFF
            || in_len > 0xFFFFFFFF
#endif
            ) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        memcpy(output, NIST_KW_ICV2, KW_SEMIBLOCK_LENGTH / 2);
        MBEDTLS_PUT_UINT32_BE((in_len & 0xffffffff), output,
                              KW_SEMIBLOCK_LENGTH / 2);

        memcpy(output + KW_SEMIBLOCK_LENGTH, input, in_len);
        memset(output + KW_SEMIBLOCK_LENGTH + in_len, 0, padlen);
    }
    semiblocks = ((in_len + padlen) / KW_SEMIBLOCK_LENGTH) + 1;

    s = 6 * (semiblocks - 1);

    if (mode == MBEDTLS_KW_MODE_KWP
        && in_len <= KW_SEMIBLOCK_LENGTH) {
        memcpy(inbuff, output, 16);
        ret = mbedtls_cipher_update(&ctx->cipher_ctx,
                                    inbuff, 16, output, &olen);
        if (ret != 0) {
            goto cleanup;
        }
    } else {
        unsigned char *R2 = output + KW_SEMIBLOCK_LENGTH;
        unsigned char *A = output;

        if (semiblocks < MIN_SEMIBLOCKS_COUNT) {
            ret = MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
            goto cleanup;
        }

        for (t = 1; t <= s; t++) {
            memcpy(inbuff, A, KW_SEMIBLOCK_LENGTH);
            memcpy(inbuff + KW_SEMIBLOCK_LENGTH, R2, KW_SEMIBLOCK_LENGTH);

            ret = mbedtls_cipher_update(&ctx->cipher_ctx,
                                        inbuff, 16, outbuff, &olen);
            if (ret != 0) {
                goto cleanup;
            }

            memcpy(A, outbuff, KW_SEMIBLOCK_LENGTH);
            calc_a_xor_t(A, t);

            memcpy(R2, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH);
            R2 += KW_SEMIBLOCK_LENGTH;
            if (R2 >= output + (semiblocks * KW_SEMIBLOCK_LENGTH)) {
                R2 = output + KW_SEMIBLOCK_LENGTH;
            }
        }
    }

    *out_len = semiblocks * KW_SEMIBLOCK_LENGTH;

cleanup:

    if (ret != 0) {
        memset(output, 0, semiblocks * KW_SEMIBLOCK_LENGTH);
    }
    mbedtls_platform_zeroize(inbuff, KW_SEMIBLOCK_LENGTH * 2);
    mbedtls_platform_zeroize(outbuff, KW_SEMIBLOCK_LENGTH * 2);

    return ret;
}

static int unwrap(mbedtls_nist_kw_context *ctx,
                  const unsigned char *input, size_t semiblocks,
                  unsigned char A[KW_SEMIBLOCK_LENGTH],
                  unsigned char *output, size_t *out_len)
{
    int ret = 0;
    const size_t s = 6 * (semiblocks - 1);
    size_t olen;
    uint64_t t = 0;
    unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char inbuff[KW_SEMIBLOCK_LENGTH * 2];
    unsigned char *R = NULL;
    *out_len = 0;

    if (semiblocks < MIN_SEMIBLOCKS_COUNT) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    memcpy(A, input, KW_SEMIBLOCK_LENGTH);
    memmove(output, input + KW_SEMIBLOCK_LENGTH, (semiblocks - 1) * KW_SEMIBLOCK_LENGTH);
    R = output + (semiblocks - 2) * KW_SEMIBLOCK_LENGTH;

    for (t = s; t >= 1; t--) {
        calc_a_xor_t(A, t);

        memcpy(inbuff, A, KW_SEMIBLOCK_LENGTH);
        memcpy(inbuff + KW_SEMIBLOCK_LENGTH, R, KW_SEMIBLOCK_LENGTH);

        ret = mbedtls_cipher_update(&ctx->cipher_ctx,
                                    inbuff, 16, outbuff, &olen);
        if (ret != 0) {
            goto cleanup;
        }

        memcpy(A, outbuff, KW_SEMIBLOCK_LENGTH);

        memcpy(R, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH);

        if (R == output) {
            R = output + (semiblocks - 2) * KW_SEMIBLOCK_LENGTH;
        } else {
            R -= KW_SEMIBLOCK_LENGTH;
        }
    }

    *out_len = (semiblocks - 1) * KW_SEMIBLOCK_LENGTH;

cleanup:
    if (ret != 0) {
        memset(output, 0, (semiblocks - 1) * KW_SEMIBLOCK_LENGTH);
    }
    mbedtls_platform_zeroize(inbuff, sizeof(inbuff));
    mbedtls_platform_zeroize(outbuff, sizeof(outbuff));

    return ret;
}

int mbedtls_nist_kw_unwrap(mbedtls_nist_kw_context *ctx,
                           mbedtls_nist_kw_mode_t mode,
                           const unsigned char *input, size_t in_len,
                           unsigned char *output, size_t *out_len, size_t out_size)
{
    int ret = 0;
    size_t olen;
    unsigned char A[KW_SEMIBLOCK_LENGTH];
    int diff;

    *out_len = 0;
    if (out_size < in_len - KW_SEMIBLOCK_LENGTH) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (mode == MBEDTLS_KW_MODE_KW) {
        if (in_len < 24 ||
#if SIZE_MAX > 0x200000000000000
            in_len > 0x200000000000000 ||
#endif
            in_len % KW_SEMIBLOCK_LENGTH != 0) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        ret = unwrap(ctx, input, in_len / KW_SEMIBLOCK_LENGTH,
                     A, output, out_len);
        if (ret != 0) {
            goto cleanup;
        }

        diff = mbedtls_ct_memcmp(NIST_KW_ICV1, A, KW_SEMIBLOCK_LENGTH);

        if (diff != 0) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
            goto cleanup;
        }

    } else if (mode == MBEDTLS_KW_MODE_KWP) {
        size_t padlen = 0;
        uint32_t Plen;

        if (in_len < KW_SEMIBLOCK_LENGTH * 2 ||
#if SIZE_MAX > 0x100000000
            in_len > 0x100000000 ||
#endif
            in_len % KW_SEMIBLOCK_LENGTH != 0) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (in_len == KW_SEMIBLOCK_LENGTH * 2) {
            unsigned char outbuff[KW_SEMIBLOCK_LENGTH * 2];
            ret = mbedtls_cipher_update(&ctx->cipher_ctx,
                                        input, 16, outbuff, &olen);
            if (ret != 0) {
                goto cleanup;
            }

            memcpy(A, outbuff, KW_SEMIBLOCK_LENGTH);
            memcpy(output, outbuff + KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH);
            mbedtls_platform_zeroize(outbuff, sizeof(outbuff));
            *out_len = KW_SEMIBLOCK_LENGTH;
        } else {
            ret = unwrap(ctx, input, in_len / KW_SEMIBLOCK_LENGTH,
                         A, output, out_len);
            if (ret != 0) {
                goto cleanup;
            }
        }

        diff = mbedtls_ct_memcmp(NIST_KW_ICV2, A, KW_SEMIBLOCK_LENGTH / 2);

        if (diff != 0) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        Plen = MBEDTLS_GET_UINT32_BE(A, KW_SEMIBLOCK_LENGTH / 2);

        padlen = in_len - KW_SEMIBLOCK_LENGTH - Plen;
        ret = mbedtls_ct_error_if(mbedtls_ct_uint_gt(padlen, 7),
                                  MBEDTLS_ERR_CIPHER_AUTH_FAILED, ret);
        padlen &= 7;

        const uint8_t zero[KW_SEMIBLOCK_LENGTH] = { 0 };
        diff = mbedtls_ct_memcmp_partial(
            &output[*out_len - KW_SEMIBLOCK_LENGTH], zero,
            KW_SEMIBLOCK_LENGTH, KW_SEMIBLOCK_LENGTH - padlen, 0);

        if (diff != 0) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        if (ret != 0) {
            goto cleanup;
        }
        memset(output + Plen, 0, padlen);
        *out_len = Plen;
    } else {
        ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        goto cleanup;
    }

cleanup:
    if (ret != 0) {
        memset(output, 0, *out_len);
        *out_len = 0;
    }

    mbedtls_platform_zeroize(&diff, sizeof(diff));
    mbedtls_platform_zeroize(A, sizeof(A));

    return ret;
}

#endif /* !MBEDTLS_NIST_KW_ALT */

#endif
