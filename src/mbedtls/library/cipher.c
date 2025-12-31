/**
 * \file cipher.c
 *
 * \brief Generic cipher wrapper for Mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_CIPHER_C)

#include "mbedtls/cipher.h"
#include "cipher_invasive.h"
#include "cipher_wrap.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#include "mbedtls/constant_time.h"
#include "constant_time_internal.h"

#include <stdlib.h>
#include <string.h>

#if defined(MBEDTLS_CHACHAPOLY_C)
#include "mbedtls/chachapoly.h"
#endif

#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif

#if defined(MBEDTLS_CCM_C)
#include "mbedtls/ccm.h"
#endif

#if defined(MBEDTLS_CHACHA20_C)
#include "mbedtls/chacha20.h"
#endif

#if defined(MBEDTLS_CMAC_C)
#include "mbedtls/cmac.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_NIST_KW_C)
#include "mbedtls/nist_kw.h"
#endif

#include "mbedtls/platform.h"

static int supported_init = 0;

static inline const mbedtls_cipher_base_t *mbedtls_cipher_get_base(
    const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_base_lookup_table[info->base_idx];
}

const int *mbedtls_cipher_list(void)
{
    const mbedtls_cipher_definition_t *def;
    int *type;

    if (!supported_init) {
        def = mbedtls_cipher_definitions;
        type = mbedtls_cipher_supported;

        while (def->type != 0) {
            *type++ = (*def++).type;
        }

        *type = 0;

        supported_init = 1;
    }

    return mbedtls_cipher_supported;
}

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_type(
    const mbedtls_cipher_type_t cipher_type)
{
    const mbedtls_cipher_definition_t *def;

    for (def = mbedtls_cipher_definitions; def->info != NULL; def++) {
        if (def->type == cipher_type) {
            return def->info;
        }
    }

    return NULL;
}

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_string(
    const char *cipher_name)
{
    const mbedtls_cipher_definition_t *def;

    if (NULL == cipher_name) {
        return NULL;
    }

    for (def = mbedtls_cipher_definitions; def->info != NULL; def++) {
        if (!strcmp(def->info->name, cipher_name)) {
            return def->info;
        }
    }

    return NULL;
}

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_values(
    const mbedtls_cipher_id_t cipher_id,
    int key_bitlen,
    const mbedtls_cipher_mode_t mode)
{
    const mbedtls_cipher_definition_t *def;

    for (def = mbedtls_cipher_definitions; def->info != NULL; def++) {
        if (mbedtls_cipher_get_base(def->info)->cipher == cipher_id &&
            mbedtls_cipher_info_get_key_bitlen(def->info) == (unsigned) key_bitlen &&
            def->info->mode == mode) {
            return def->info;
        }
    }

    return NULL;
}

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
static inline psa_key_type_t mbedtls_psa_translate_cipher_type(
    mbedtls_cipher_type_t cipher)
{
    switch (cipher) {
        case MBEDTLS_CIPHER_AES_128_CCM:
        case MBEDTLS_CIPHER_AES_192_CCM:
        case MBEDTLS_CIPHER_AES_256_CCM:
        case MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG:
        case MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG:
        case MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG:
        case MBEDTLS_CIPHER_AES_128_GCM:
        case MBEDTLS_CIPHER_AES_192_GCM:
        case MBEDTLS_CIPHER_AES_256_GCM:
        case MBEDTLS_CIPHER_AES_128_CBC:
        case MBEDTLS_CIPHER_AES_192_CBC:
        case MBEDTLS_CIPHER_AES_256_CBC:
        case MBEDTLS_CIPHER_AES_128_ECB:
        case MBEDTLS_CIPHER_AES_192_ECB:
        case MBEDTLS_CIPHER_AES_256_ECB:
            return PSA_KEY_TYPE_AES;

        default:
            return 0;
    }
}

static inline psa_algorithm_t mbedtls_psa_translate_cipher_mode(
    mbedtls_cipher_mode_t mode, size_t taglen)
{
    switch (mode) {
        case MBEDTLS_MODE_ECB:
            return PSA_ALG_ECB_NO_PADDING;
        case MBEDTLS_MODE_GCM:
            return PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, taglen);
        case MBEDTLS_MODE_CCM:
            return PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen);
        case MBEDTLS_MODE_CCM_STAR_NO_TAG:
            return PSA_ALG_CCM_STAR_NO_TAG;
        case MBEDTLS_MODE_CBC:
            if (taglen == 0) {
                return PSA_ALG_CBC_NO_PADDING;
            } else {
                return 0;
            }
        default:
            return 0;
    }
}
#endif

void mbedtls_cipher_init(mbedtls_cipher_context_t *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_cipher_context_t));
}

void mbedtls_cipher_free(mbedtls_cipher_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {
        if (ctx->cipher_ctx != NULL) {
            mbedtls_cipher_context_psa * const cipher_psa =
                (mbedtls_cipher_context_psa *) ctx->cipher_ctx;

            if (cipher_psa->slot_state == MBEDTLS_CIPHER_PSA_KEY_OWNED) {

                (void) psa_destroy_key(cipher_psa->slot);
            }

            mbedtls_zeroize_and_free(cipher_psa, sizeof(*cipher_psa));
        }

        mbedtls_platform_zeroize(ctx, sizeof(mbedtls_cipher_context_t));
        return;
    }
#endif

#if defined(MBEDTLS_CMAC_C)
    if (ctx->cmac_ctx) {
        mbedtls_zeroize_and_free(ctx->cmac_ctx,
                                 sizeof(mbedtls_cmac_context_t));
    }
#endif

    if (ctx->cipher_ctx) {
        mbedtls_cipher_get_base(ctx->cipher_info)->ctx_free_func(ctx->cipher_ctx);
    }

    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_cipher_context_t));
}

int mbedtls_cipher_setup(mbedtls_cipher_context_t *ctx,
                         const mbedtls_cipher_info_t *cipher_info)
{
    if (cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    memset(ctx, 0, sizeof(mbedtls_cipher_context_t));

    if (mbedtls_cipher_get_base(cipher_info)->ctx_alloc_func != NULL) {
        ctx->cipher_ctx = mbedtls_cipher_get_base(cipher_info)->ctx_alloc_func();
        if (ctx->cipher_ctx == NULL) {
            return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
        }
    }

    ctx->cipher_info = cipher_info;

    return 0;
}

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_cipher_setup_psa(mbedtls_cipher_context_t *ctx,
                             const mbedtls_cipher_info_t *cipher_info,
                             size_t taglen)
{
    psa_algorithm_t alg;
    mbedtls_cipher_context_psa *cipher_psa;

    if (NULL == cipher_info || NULL == ctx) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    alg = mbedtls_psa_translate_cipher_mode(((mbedtls_cipher_mode_t) cipher_info->mode), taglen);
    if (alg == 0) {
        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
    if (mbedtls_psa_translate_cipher_type(((mbedtls_cipher_type_t) cipher_info->type)) == 0) {
        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    memset(ctx, 0, sizeof(mbedtls_cipher_context_t));

    cipher_psa = mbedtls_calloc(1, sizeof(mbedtls_cipher_context_psa));
    if (cipher_psa == NULL) {
        return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
    }
    cipher_psa->alg  = alg;
    ctx->cipher_ctx  = cipher_psa;
    ctx->cipher_info = cipher_info;
    ctx->psa_enabled = 1;
    return 0;
}
#endif

int mbedtls_cipher_setkey(mbedtls_cipher_context_t *ctx,
                          const unsigned char *key,
                          int key_bitlen,
                          const mbedtls_operation_t operation)
{
    if (operation != MBEDTLS_ENCRYPT && operation != MBEDTLS_DECRYPT) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
#if defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (MBEDTLS_MODE_ECB == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) &&
        MBEDTLS_DECRYPT == operation) {
        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {
        mbedtls_cipher_context_psa * const cipher_psa =
            (mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        size_t const key_bytelen = ((size_t) key_bitlen + 7) / 8;

        psa_status_t status;
        psa_key_type_t key_type;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

        if (key_bitlen % 8 != 0) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (cipher_psa->slot_state != MBEDTLS_CIPHER_PSA_KEY_UNSET) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        key_type = mbedtls_psa_translate_cipher_type(
            ((mbedtls_cipher_type_t) ctx->cipher_info->type));
        if (key_type == 0) {
            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }
        psa_set_key_type(&attributes, key_type);

        psa_set_key_usage_flags(&attributes,
                                PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attributes, cipher_psa->alg);

        status = psa_import_key(&attributes, key, key_bytelen,
                                &cipher_psa->slot);
        switch (status) {
            case PSA_SUCCESS:
                break;
            case PSA_ERROR_INSUFFICIENT_MEMORY:
                return MBEDTLS_ERR_CIPHER_ALLOC_FAILED;
            case PSA_ERROR_NOT_SUPPORTED:
                return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
            default:
                return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        cipher_psa->slot_state = MBEDTLS_CIPHER_PSA_KEY_OWNED;

        ctx->key_bitlen = key_bitlen;
        ctx->operation = operation;
        return 0;
    }
#endif

    if ((ctx->cipher_info->flags & MBEDTLS_CIPHER_VARIABLE_KEY_LEN) == 0 &&
        (int) mbedtls_cipher_info_get_key_bitlen(ctx->cipher_info) != key_bitlen) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    ctx->key_bitlen = key_bitlen;
    ctx->operation = operation;

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)

    if (MBEDTLS_ENCRYPT == operation ||
        MBEDTLS_MODE_CFB == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_OFB == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_CTR == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return mbedtls_cipher_get_base(ctx->cipher_info)->setkey_enc_func(ctx->cipher_ctx, key,
                                                                          ctx->key_bitlen);
    }

    if (MBEDTLS_DECRYPT == operation) {
        return mbedtls_cipher_get_base(ctx->cipher_info)->setkey_dec_func(ctx->cipher_ctx, key,
                                                                          ctx->key_bitlen);
    }
#else
    if (operation == MBEDTLS_ENCRYPT || operation == MBEDTLS_DECRYPT) {
        return mbedtls_cipher_get_base(ctx->cipher_info)->setkey_enc_func(ctx->cipher_ctx, key,
                                                                          ctx->key_bitlen);
    }
#endif

    return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
}

int mbedtls_cipher_set_iv(mbedtls_cipher_context_t *ctx,
                          const unsigned char *iv,
                          size_t iv_len)
{
    size_t actual_iv_size;

    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

    if (iv_len > MBEDTLS_MAX_IV_LENGTH) {
        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    if ((ctx->cipher_info->flags & MBEDTLS_CIPHER_VARIABLE_IV_LEN) != 0) {
        actual_iv_size = iv_len;
    } else {
        actual_iv_size = mbedtls_cipher_info_get_iv_size(ctx->cipher_info);

        if (actual_iv_size > iv_len) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }
    }

#if defined(MBEDTLS_CHACHA20_C)
    if (((mbedtls_cipher_type_t) ctx->cipher_info->type) == MBEDTLS_CIPHER_CHACHA20) {

        if (iv_len != 12) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (0 != mbedtls_chacha20_starts((mbedtls_chacha20_context *) ctx->cipher_ctx,
                                         iv,
                                         0U)) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }
    }
#if defined(MBEDTLS_CHACHAPOLY_C)
    if (((mbedtls_cipher_type_t) ctx->cipher_info->type) == MBEDTLS_CIPHER_CHACHA20_POLY1305 &&
        iv_len != 12) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }
#endif
#endif

#if defined(MBEDTLS_GCM_C)
    if (MBEDTLS_MODE_GCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return mbedtls_gcm_starts((mbedtls_gcm_context *) ctx->cipher_ctx,
                                  ctx->operation,
                                  iv, iv_len);
    }
#endif

#if defined(MBEDTLS_CCM_C)
    if (MBEDTLS_MODE_CCM_STAR_NO_TAG == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int set_lengths_result;
        int ccm_star_mode;

        set_lengths_result = mbedtls_ccm_set_lengths(
            (mbedtls_ccm_context *) ctx->cipher_ctx,
            0, 0, 0);
        if (set_lengths_result != 0) {
            return set_lengths_result;
        }

        if (ctx->operation == MBEDTLS_DECRYPT) {
            ccm_star_mode = MBEDTLS_CCM_STAR_DECRYPT;
        } else if (ctx->operation == MBEDTLS_ENCRYPT) {
            ccm_star_mode = MBEDTLS_CCM_STAR_ENCRYPT;
        } else {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        return mbedtls_ccm_starts((mbedtls_ccm_context *) ctx->cipher_ctx,
                                  ccm_star_mode,
                                  iv, iv_len);
    }
#endif

    if (actual_iv_size != 0) {
        memcpy(ctx->iv, iv, actual_iv_size);
        ctx->iv_size = actual_iv_size;
    }

    return 0;
}

int mbedtls_cipher_reset(mbedtls_cipher_context_t *ctx)
{
    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

    ctx->unprocessed_len = 0;

    return 0;
}

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
int mbedtls_cipher_update_ad(mbedtls_cipher_context_t *ctx,
                             const unsigned char *ad, size_t ad_len)
{
    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

#if defined(MBEDTLS_GCM_C)
    if (MBEDTLS_MODE_GCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return mbedtls_gcm_update_ad((mbedtls_gcm_context *) ctx->cipher_ctx,
                                     ad, ad_len);
    }
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
    if (MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((mbedtls_cipher_type_t) ctx->cipher_info->type)) {
        int result;
        mbedtls_chachapoly_mode_t mode;

        mode = (ctx->operation == MBEDTLS_ENCRYPT)
                ? MBEDTLS_CHACHAPOLY_ENCRYPT
                : MBEDTLS_CHACHAPOLY_DECRYPT;

        result = mbedtls_chachapoly_starts((mbedtls_chachapoly_context *) ctx->cipher_ctx,
                                           ctx->iv,
                                           mode);
        if (result != 0) {
            return result;
        }

        return mbedtls_chachapoly_update_aad((mbedtls_chachapoly_context *) ctx->cipher_ctx,
                                             ad, ad_len);
    }
#endif

    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}
#endif

int mbedtls_cipher_update(mbedtls_cipher_context_t *ctx, const unsigned char *input,
                          size_t ilen, unsigned char *output, size_t *olen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t block_size;

    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

    *olen = 0;
    block_size = mbedtls_cipher_get_block_size(ctx);
    if (0 == block_size) {
        return MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }

    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_ECB) {
        if (ilen != block_size) {
            return MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        *olen = ilen;

        if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->ecb_func(ctx->cipher_ctx,
                                                                            ctx->operation, input,
                                                                            output))) {
            return ret;
        }

        return 0;
    }

#if defined(MBEDTLS_GCM_C)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_GCM) {
        return mbedtls_gcm_update((mbedtls_gcm_context *) ctx->cipher_ctx,
                                  input, ilen,
                                  output, ilen, olen);
    }
#endif

#if defined(MBEDTLS_CCM_C)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_CCM_STAR_NO_TAG) {
        return mbedtls_ccm_update((mbedtls_ccm_context *) ctx->cipher_ctx,
                                  input, ilen,
                                  output, ilen, olen);
    }
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
    if (((mbedtls_cipher_type_t) ctx->cipher_info->type) == MBEDTLS_CIPHER_CHACHA20_POLY1305) {
        *olen = ilen;
        return mbedtls_chachapoly_update((mbedtls_chachapoly_context *) ctx->cipher_ctx,
                                         ilen, input, output);
    }
#endif

    if (input == output &&
        (ctx->unprocessed_len != 0 || ilen % block_size)) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_CBC) {
        size_t copy_len = 0;

        if ((ctx->operation == MBEDTLS_DECRYPT && NULL != ctx->add_padding &&
             ilen <= block_size - ctx->unprocessed_len) ||
            (ctx->operation == MBEDTLS_DECRYPT && NULL == ctx->add_padding &&
             ilen < block_size - ctx->unprocessed_len) ||
            (ctx->operation == MBEDTLS_ENCRYPT &&
             ilen < block_size - ctx->unprocessed_len)) {
            memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]), input,
                   ilen);

            ctx->unprocessed_len += ilen;
            return 0;
        }

        if (0 != ctx->unprocessed_len) {
            copy_len = block_size - ctx->unprocessed_len;

            memcpy(&(ctx->unprocessed_data[ctx->unprocessed_len]), input,
                   copy_len);

            if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                                ctx->operation,
                                                                                block_size, ctx->iv,
                                                                                ctx->
                                                                                unprocessed_data,
                                                                                output))) {
                return ret;
            }

            *olen += block_size;
            output += block_size;
            ctx->unprocessed_len = 0;

            input += copy_len;
            ilen -= copy_len;
        }

        if (0 != ilen) {

            copy_len = ilen % block_size;
            if (copy_len == 0 &&
                ctx->operation == MBEDTLS_DECRYPT &&
                NULL != ctx->add_padding) {
                copy_len = block_size;
            }

            memcpy(ctx->unprocessed_data, &(input[ilen - copy_len]),
                   copy_len);

            ctx->unprocessed_len += copy_len;
            ilen -= copy_len;
        }

        if (ilen) {
            if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                                ctx->operation,
                                                                                ilen, ctx->iv,
                                                                                input,
                                                                                output))) {
                return ret;
            }

            *olen += ilen;
        }

        return 0;
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_CFB)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_CFB) {
        if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->cfb_func(ctx->cipher_ctx,
                                                                            ctx->operation, ilen,
                                                                            &ctx->unprocessed_len,
                                                                            ctx->iv,
                                                                            input, output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_OFB)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_OFB) {
        if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->ofb_func(ctx->cipher_ctx,
                                                                            ilen,
                                                                            &ctx->unprocessed_len,
                                                                            ctx->iv,
                                                                            input, output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_CTR)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_CTR) {
        if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->ctr_func(ctx->cipher_ctx,
                                                                            ilen,
                                                                            &ctx->unprocessed_len,
                                                                            ctx->iv,
                                                                            ctx->unprocessed_data,
                                                                            input, output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_XTS)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_XTS) {
        if (ctx->unprocessed_len > 0) {

            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        ret = mbedtls_cipher_get_base(ctx->cipher_info)->xts_func(ctx->cipher_ctx,
                                                                  ctx->operation,
                                                                  ilen,
                                                                  ctx->iv,
                                                                  input,
                                                                  output);
        if (ret != 0) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) == MBEDTLS_MODE_STREAM) {
        if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->stream_func(ctx->cipher_ctx,
                                                                               ilen, input,
                                                                               output))) {
            return ret;
        }

        *olen = ilen;

        return 0;
    }
#endif

    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)

static void add_pkcs_padding(unsigned char *output, size_t output_len,
                             size_t data_len)
{
    size_t padding_len = output_len - data_len;
    unsigned char i;

    for (i = 0; i < padding_len; i++) {
        output[data_len + i] = (unsigned char) padding_len;
    }
}

MBEDTLS_STATIC_TESTABLE int mbedtls_get_pkcs_padding(unsigned char *input,
                                                     size_t input_len,
                                                     size_t *data_len,
                                                     size_t *invalid_padding)
{
    size_t i, pad_idx;
    unsigned char padding_len;

    if (NULL == input || NULL == data_len) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    padding_len = input[input_len - 1];

    mbedtls_ct_condition_t bad = mbedtls_ct_uint_gt(padding_len, input_len);
    bad = mbedtls_ct_bool_or(bad, mbedtls_ct_uint_eq(padding_len, 0));

    pad_idx = input_len - padding_len;
    for (i = 0; i < input_len; i++) {
        mbedtls_ct_condition_t in_padding = mbedtls_ct_uint_ge(i, pad_idx);
        mbedtls_ct_condition_t different  = mbedtls_ct_uint_ne(input[i], padding_len);
        bad = mbedtls_ct_bool_or(bad, mbedtls_ct_bool_and(in_padding, different));
    }

    *data_len = mbedtls_ct_if(bad, 0, input_len - padding_len);

    *invalid_padding = mbedtls_ct_size_if_else_0(bad, SIZE_MAX);
    return 0;
}
#endif

#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)

static void add_one_and_zeros_padding(unsigned char *output,
                                      size_t output_len, size_t data_len)
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    output[data_len] = 0x80;
    for (i = 1; i < padding_len; i++) {
        output[data_len + i] = 0x00;
    }
}

static int get_one_and_zeros_padding(unsigned char *input, size_t input_len,
                                     size_t *data_len, size_t *invalid_padding)
{
    if (NULL == input || NULL == data_len) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    mbedtls_ct_condition_t in_padding = MBEDTLS_CT_TRUE;
    mbedtls_ct_condition_t bad = MBEDTLS_CT_TRUE;

    *data_len = 0;

    for (ptrdiff_t i = (ptrdiff_t) (input_len) - 1; i >= 0; i--) {
        mbedtls_ct_condition_t is_nonzero = mbedtls_ct_bool(input[i]);

        mbedtls_ct_condition_t hit_first_nonzero = mbedtls_ct_bool_and(is_nonzero, in_padding);

        *data_len = mbedtls_ct_size_if(hit_first_nonzero, i, *data_len);

        bad = mbedtls_ct_bool_if(hit_first_nonzero, mbedtls_ct_uint_ne(input[i], 0x80), bad);

        in_padding = mbedtls_ct_bool_and(in_padding, mbedtls_ct_bool_not(is_nonzero));
    }

    *invalid_padding = mbedtls_ct_size_if_else_0(bad, SIZE_MAX);
    return 0;
}
#endif

#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)

static void add_zeros_and_len_padding(unsigned char *output,
                                      size_t output_len, size_t data_len)
{
    size_t padding_len = output_len - data_len;
    unsigned char i = 0;

    for (i = 1; i < padding_len; i++) {
        output[data_len + i - 1] = 0x00;
    }
    output[output_len - 1] = (unsigned char) padding_len;
}

static int get_zeros_and_len_padding(unsigned char *input, size_t input_len,
                                     size_t *data_len, size_t *invalid_padding)
{
    size_t i, pad_idx;
    unsigned char padding_len;
    mbedtls_ct_condition_t bad;

    if (NULL == input || NULL == data_len) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    bad = mbedtls_ct_uint_gt(padding_len, input_len);
    bad = mbedtls_ct_bool_or(bad, mbedtls_ct_uint_eq(padding_len, 0));

    pad_idx = input_len - padding_len;
    for (i = 0; i < input_len - 1; i++) {
        mbedtls_ct_condition_t is_padding = mbedtls_ct_uint_ge(i, pad_idx);
        mbedtls_ct_condition_t nonzero_pad_byte;
        nonzero_pad_byte = mbedtls_ct_bool_if_else_0(is_padding, mbedtls_ct_bool(input[i]));
        bad = mbedtls_ct_bool_or(bad, nonzero_pad_byte);
    }

    *invalid_padding = mbedtls_ct_size_if_else_0(bad, SIZE_MAX);
    return 0;
}
#endif

#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)

static void add_zeros_padding(unsigned char *output,
                              size_t output_len, size_t data_len)
{
    memset(output + data_len, 0, output_len - data_len);
}

static int get_zeros_padding(unsigned char *input, size_t input_len,
                             size_t *data_len, size_t *invalid_padding)
{
    size_t i;
    mbedtls_ct_condition_t done = MBEDTLS_CT_FALSE, prev_done;

    if (NULL == input || NULL == data_len) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    *data_len = 0;
    for (i = input_len; i > 0; i--) {
        prev_done = done;
        done = mbedtls_ct_bool_or(done, mbedtls_ct_uint_ne(input[i-1], 0));
        *data_len = mbedtls_ct_size_if(mbedtls_ct_bool_ne(done, prev_done), i, *data_len);
    }

    *invalid_padding = 0;
    return 0;
}
#endif

static int get_no_padding(unsigned char *input, size_t input_len,
                          size_t *data_len, size_t *invalid_padding)
{
    if (NULL == input || NULL == data_len) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    *data_len = input_len;
    *invalid_padding = 0;
    return 0;
}
#endif

int mbedtls_cipher_finish_padded(mbedtls_cipher_context_t *ctx,
                                 unsigned char *output, size_t *olen,
                                 size_t *invalid_padding)
{
    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

    *olen = 0;
    *invalid_padding = 0;

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)

    if (MBEDTLS_MODE_CBC == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        if (ctx->get_padding == NULL) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }
    }
#endif

    if (MBEDTLS_MODE_CFB == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_OFB == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_CTR == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_GCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_CCM_STAR_NO_TAG == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_XTS == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
        MBEDTLS_MODE_STREAM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return 0;
    }

    if ((MBEDTLS_CIPHER_CHACHA20          == ((mbedtls_cipher_type_t) ctx->cipher_info->type)) ||
        (MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((mbedtls_cipher_type_t) ctx->cipher_info->type))) {
        return 0;
    }

    if (MBEDTLS_MODE_ECB == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        if (ctx->unprocessed_len != 0) {
            return MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        return 0;
    }

#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if (MBEDTLS_MODE_CBC == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int ret = 0;

        if (MBEDTLS_ENCRYPT == ctx->operation) {

            if (NULL == ctx->add_padding) {
                if (0 != ctx->unprocessed_len) {
                    return MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
                }

                return 0;
            }

            ctx->add_padding(ctx->unprocessed_data, mbedtls_cipher_get_iv_size(ctx),
                             ctx->unprocessed_len);
        } else if (mbedtls_cipher_get_block_size(ctx) != ctx->unprocessed_len) {

            if (NULL == ctx->add_padding && 0 == ctx->unprocessed_len) {
                return 0;
            }

            return MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED;
        }

        if (0 != (ret = mbedtls_cipher_get_base(ctx->cipher_info)->cbc_func(ctx->cipher_ctx,
                                                                            ctx->operation,
                                                                            mbedtls_cipher_get_block_size(
                                                                                ctx),
                                                                            ctx->iv,
                                                                            ctx->unprocessed_data,
                                                                            output))) {
            return ret;
        }

        if (MBEDTLS_DECRYPT == ctx->operation) {
            return ctx->get_padding(output, mbedtls_cipher_get_block_size(ctx),
                                    olen, invalid_padding);
        }

        *olen = mbedtls_cipher_get_block_size(ctx);
        return 0;
    }
#else
    ((void) output);
#endif

    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

int mbedtls_cipher_finish(mbedtls_cipher_context_t *ctx,
                          unsigned char *output, size_t *olen)
{
    size_t invalid_padding = 0;
    int ret = mbedtls_cipher_finish_padded(ctx, output, olen,
                                           &invalid_padding);
    if (ret == 0) {
        ret = mbedtls_ct_error_if_else_0(invalid_padding,
                                         MBEDTLS_ERR_CIPHER_INVALID_PADDING);
    }
    return ret;
}

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
int mbedtls_cipher_set_padding_mode(mbedtls_cipher_context_t *ctx,
                                    mbedtls_cipher_padding_t mode)
{
    if (NULL == ctx->cipher_info ||
        MBEDTLS_MODE_CBC != ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        if (mode != MBEDTLS_PADDING_NONE) {
            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        return 0;
    }
#endif

    switch (mode) {
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
        case MBEDTLS_PADDING_PKCS7:
            ctx->add_padding = add_pkcs_padding;
            ctx->get_padding = mbedtls_get_pkcs_padding;
            break;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
        case MBEDTLS_PADDING_ONE_AND_ZEROS:
            ctx->add_padding = add_one_and_zeros_padding;
            ctx->get_padding = get_one_and_zeros_padding;
            break;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
        case MBEDTLS_PADDING_ZEROS_AND_LEN:
            ctx->add_padding = add_zeros_and_len_padding;
            ctx->get_padding = get_zeros_and_len_padding;
            break;
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)
        case MBEDTLS_PADDING_ZEROS:
            ctx->add_padding = add_zeros_padding;
            ctx->get_padding = get_zeros_padding;
            break;
#endif
        case MBEDTLS_PADDING_NONE:
            ctx->add_padding = NULL;
            ctx->get_padding = get_no_padding;
            break;

        default:
            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }

    return 0;
}
#endif

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
int mbedtls_cipher_write_tag(mbedtls_cipher_context_t *ctx,
                             unsigned char *tag, size_t tag_len)
{
    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (MBEDTLS_ENCRYPT != ctx->operation) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

#if defined(MBEDTLS_GCM_C)
    if (MBEDTLS_MODE_GCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        size_t output_length;

        return mbedtls_gcm_finish((mbedtls_gcm_context *) ctx->cipher_ctx,
                                  NULL, 0, &output_length,
                                  tag, tag_len);
    }
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
    if (MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((mbedtls_cipher_type_t) ctx->cipher_info->type)) {

        if (tag_len != 16U) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        return mbedtls_chachapoly_finish(
            (mbedtls_chachapoly_context *) ctx->cipher_ctx, tag);
    }
#endif

    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

int mbedtls_cipher_check_tag(mbedtls_cipher_context_t *ctx,
                             const unsigned char *tag, size_t tag_len)
{
    unsigned char check_tag[16];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ctx->cipher_info == NULL) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (MBEDTLS_DECRYPT != ctx->operation) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
    }
#endif

    ret = MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;

#if defined(MBEDTLS_GCM_C)
    if (MBEDTLS_MODE_GCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        size_t output_length;

        if (tag_len > sizeof(check_tag)) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (0 != (ret = mbedtls_gcm_finish(
                      (mbedtls_gcm_context *) ctx->cipher_ctx,
                      NULL, 0, &output_length,
                      check_tag, tag_len))) {
            return ret;
        }

        if (mbedtls_ct_memcmp(tag, check_tag, tag_len) != 0) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
            goto exit;
        }
    }
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
    if (MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((mbedtls_cipher_type_t) ctx->cipher_info->type)) {

        if (tag_len != sizeof(check_tag)) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        ret = mbedtls_chachapoly_finish(
            (mbedtls_chachapoly_context *) ctx->cipher_ctx, check_tag);
        if (ret != 0) {
            return ret;
        }

        if (mbedtls_ct_memcmp(tag, check_tag, tag_len) != 0) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
            goto exit;
        }
    }
#endif

exit:
    mbedtls_platform_zeroize(check_tag, tag_len);
    return ret;
}
#endif

int mbedtls_cipher_crypt(mbedtls_cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t finish_olen;

#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        mbedtls_cipher_context_psa * const cipher_psa =
            (mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        psa_status_t status;
        psa_cipher_operation_t cipher_op = PSA_CIPHER_OPERATION_INIT;
        size_t part_len;

        if (ctx->operation == MBEDTLS_DECRYPT) {
            status = psa_cipher_decrypt_setup(&cipher_op,
                                              cipher_psa->slot,
                                              cipher_psa->alg);
        } else if (ctx->operation == MBEDTLS_ENCRYPT) {
            status = psa_cipher_encrypt_setup(&cipher_op,
                                              cipher_psa->slot,
                                              cipher_psa->alg);
        } else {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        if (status != PSA_SUCCESS) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        if (((mbedtls_cipher_mode_t) ctx->cipher_info->mode) != MBEDTLS_MODE_ECB) {
            status = psa_cipher_set_iv(&cipher_op, iv, iv_len);
            if (status != PSA_SUCCESS) {
                return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
            }
        }

        status = psa_cipher_update(&cipher_op,
                                   input, ilen,
                                   output, ilen, olen);
        if (status != PSA_SUCCESS) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        status = psa_cipher_finish(&cipher_op,
                                   output + *olen, ilen - *olen,
                                   &part_len);
        if (status != PSA_SUCCESS) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        *olen += part_len;
        return 0;
    }
#endif

    if ((ret = mbedtls_cipher_set_iv(ctx, iv, iv_len)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_cipher_reset(ctx)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_cipher_update(ctx, input, ilen,
                                     output, olen)) != 0) {
        return ret;
    }

    size_t invalid_padding = 0;
    if ((ret = mbedtls_cipher_finish_padded(ctx, output + *olen,
                                            &finish_olen,
                                            &invalid_padding)) != 0) {
        return ret;
    }
    *olen += finish_olen;

    ret = mbedtls_ct_error_if_else_0(invalid_padding,
                                     MBEDTLS_ERR_CIPHER_INVALID_PADDING);
    return ret;
}

#if defined(MBEDTLS_CIPHER_MODE_AEAD)

static int mbedtls_cipher_aead_encrypt(mbedtls_cipher_context_t *ctx,
                                       const unsigned char *iv, size_t iv_len,
                                       const unsigned char *ad, size_t ad_len,
                                       const unsigned char *input, size_t ilen,
                                       unsigned char *output, size_t *olen,
                                       unsigned char *tag, size_t tag_len)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        mbedtls_cipher_context_psa * const cipher_psa =
            (mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        psa_status_t status;

        if (output == NULL || tag != output + ilen) {
            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        status = psa_aead_encrypt(cipher_psa->slot,
                                  cipher_psa->alg,
                                  iv, iv_len,
                                  ad, ad_len,
                                  input, ilen,
                                  output, ilen + tag_len, olen);
        if (status != PSA_SUCCESS) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        *olen -= tag_len;
        return 0;
    }
#endif

#if defined(MBEDTLS_GCM_C)
    if (MBEDTLS_MODE_GCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        *olen = ilen;
        return mbedtls_gcm_crypt_and_tag(ctx->cipher_ctx, MBEDTLS_GCM_ENCRYPT,
                                         ilen, iv, iv_len, ad, ad_len,
                                         input, output, tag_len, tag);
    }
#endif
#if defined(MBEDTLS_CCM_C)
    if (MBEDTLS_MODE_CCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        *olen = ilen;
        return mbedtls_ccm_encrypt_and_tag(ctx->cipher_ctx, ilen,
                                           iv, iv_len, ad, ad_len, input, output,
                                           tag, tag_len);
    }
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    if (MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((mbedtls_cipher_type_t) ctx->cipher_info->type)) {

        if ((iv_len != mbedtls_cipher_info_get_iv_size(ctx->cipher_info)) ||
            (tag_len != 16U)) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        *olen = ilen;
        return mbedtls_chachapoly_encrypt_and_tag(ctx->cipher_ctx,
                                                  ilen, iv, ad, ad_len, input, output, tag);
    }
#endif

    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}

static int mbedtls_cipher_aead_decrypt(mbedtls_cipher_context_t *ctx,
                                       const unsigned char *iv, size_t iv_len,
                                       const unsigned char *ad, size_t ad_len,
                                       const unsigned char *input, size_t ilen,
                                       unsigned char *output, size_t *olen,
                                       const unsigned char *tag, size_t tag_len)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ctx->psa_enabled == 1) {

        mbedtls_cipher_context_psa * const cipher_psa =
            (mbedtls_cipher_context_psa *) ctx->cipher_ctx;

        psa_status_t status;

        if (input == NULL || tag != input + ilen) {
            return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
        }

        status = psa_aead_decrypt(cipher_psa->slot,
                                  cipher_psa->alg,
                                  iv, iv_len,
                                  ad, ad_len,
                                  input, ilen + tag_len,
                                  output, ilen, olen);
        if (status == PSA_ERROR_INVALID_SIGNATURE) {
            return MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        } else if (status != PSA_SUCCESS) {
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }

        return 0;
    }
#endif

#if defined(MBEDTLS_GCM_C)
    if (MBEDTLS_MODE_GCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        *olen = ilen;
        ret = mbedtls_gcm_auth_decrypt(ctx->cipher_ctx, ilen,
                                       iv, iv_len, ad, ad_len,
                                       tag, tag_len, input, output);

        if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        return ret;
    }
#endif
#if defined(MBEDTLS_CCM_C)
    if (MBEDTLS_MODE_CCM == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        *olen = ilen;
        ret = mbedtls_ccm_auth_decrypt(ctx->cipher_ctx, ilen,
                                       iv, iv_len, ad, ad_len,
                                       input, output, tag, tag_len);

        if (ret == MBEDTLS_ERR_CCM_AUTH_FAILED) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        return ret;
    }
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    if (MBEDTLS_CIPHER_CHACHA20_POLY1305 == ((mbedtls_cipher_type_t) ctx->cipher_info->type)) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

        if ((iv_len != mbedtls_cipher_info_get_iv_size(ctx->cipher_info)) ||
            (tag_len != 16U)) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        *olen = ilen;
        ret = mbedtls_chachapoly_auth_decrypt(ctx->cipher_ctx, ilen,
                                              iv, ad, ad_len, tag, input, output);

        if (ret == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED) {
            ret = MBEDTLS_ERR_CIPHER_AUTH_FAILED;
        }

        return ret;
    }
#endif

    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
}
#endif

#if defined(MBEDTLS_CIPHER_MODE_AEAD) || defined(MBEDTLS_NIST_KW_C)

int mbedtls_cipher_auth_encrypt_ext(mbedtls_cipher_context_t *ctx,
                                    const unsigned char *iv, size_t iv_len,
                                    const unsigned char *ad, size_t ad_len,
                                    const unsigned char *input, size_t ilen,
                                    unsigned char *output, size_t output_len,
                                    size_t *olen, size_t tag_len)
{
#if defined(MBEDTLS_NIST_KW_C)
    if (
#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
        ctx->psa_enabled == 0 &&
#endif
        (MBEDTLS_MODE_KW == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
         MBEDTLS_MODE_KWP == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode))) {
        mbedtls_nist_kw_mode_t mode =
            (MBEDTLS_MODE_KW == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) ?
            MBEDTLS_KW_MODE_KW : MBEDTLS_KW_MODE_KWP;

        if (iv_len != 0 || tag_len != 0 || ad_len != 0) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        (void) iv;
        (void) ad;

        return mbedtls_nist_kw_wrap(ctx->cipher_ctx, mode, input, ilen,
                                    output, olen, output_len);
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_AEAD)

    if (output_len < ilen + tag_len) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    int ret = mbedtls_cipher_aead_encrypt(ctx, iv, iv_len, ad, ad_len,
                                          input, ilen, output, olen,
                                          output + ilen, tag_len);
    *olen += tag_len;
    return ret;
#else
    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
#endif
}

int mbedtls_cipher_auth_decrypt_ext(mbedtls_cipher_context_t *ctx,
                                    const unsigned char *iv, size_t iv_len,
                                    const unsigned char *ad, size_t ad_len,
                                    const unsigned char *input, size_t ilen,
                                    unsigned char *output, size_t output_len,
                                    size_t *olen, size_t tag_len)
{
#if defined(MBEDTLS_NIST_KW_C)
    if (
#if defined(MBEDTLS_USE_PSA_CRYPTO) && !defined(MBEDTLS_DEPRECATED_REMOVED)
        ctx->psa_enabled == 0 &&
#endif
        (MBEDTLS_MODE_KW == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode) ||
         MBEDTLS_MODE_KWP == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode))) {
        mbedtls_nist_kw_mode_t mode =
            (MBEDTLS_MODE_KW == ((mbedtls_cipher_mode_t) ctx->cipher_info->mode)) ?
            MBEDTLS_KW_MODE_KW : MBEDTLS_KW_MODE_KWP;

        if (iv_len != 0 || tag_len != 0 || ad_len != 0) {
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
        }

        (void) iv;
        (void) ad;

        return mbedtls_nist_kw_unwrap(ctx->cipher_ctx, mode, input, ilen,
                                      output, olen, output_len);
    }
#endif

#if defined(MBEDTLS_CIPHER_MODE_AEAD)

    if (ilen < tag_len || output_len < ilen - tag_len) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return mbedtls_cipher_aead_decrypt(ctx, iv, iv_len, ad, ad_len,
                                       input, ilen - tag_len, output, olen,
                                       input + ilen - tag_len, tag_len);
#else
    return MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE;
#endif
}
#endif

#endif
