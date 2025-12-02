/**
 * \file pkcs5.c
 *
 * \brief PKCS#5 functions
 *
 * \author Mathias Olsson <mathias@kompetensum.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * PKCS#5 includes PBKDF2 and more
 *
 * http://tools.ietf.org/html/rfc2898 (Specification)
 * http://tools.ietf.org/html/rfc6070 (Test vectors)
 */

#include "common.h"

#if defined(MBEDTLS_PKCS5_C)

#include "mbedtls/pkcs5.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_ASN1_PARSE_C)
#include "mbedtls/asn1.h"
#if defined(MBEDTLS_CIPHER_C)
#include "mbedtls/cipher.h"
#endif /* MBEDTLS_CIPHER_C */
#include "mbedtls/oid.h"
#endif /* MBEDTLS_ASN1_PARSE_C */

#include <string.h>

#include "mbedtls/platform.h"

#if defined(MBEDTLS_ASN1_PARSE_C) && defined(MBEDTLS_CIPHER_C)
static int pkcs5_parse_pbkdf2_params(const mbedtls_asn1_buf *params,
                                     mbedtls_asn1_buf *salt, int *iterations,
                                     int *keylen, mbedtls_md_type_t *md_type)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_asn1_buf prf_alg_oid;
    unsigned char *p = params->p;
    const unsigned char *end = params->p + params->len;

    if (params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }
    if ((ret = mbedtls_asn1_get_tag(&p, end, &salt->len,
                                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    salt->p = p;
    p += salt->len;

    if ((ret = mbedtls_asn1_get_int(&p, end, iterations)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    if (p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_int(&p, end, keylen)) != 0) {
        if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
        }
    }

    if (p == end) {
        return 0;
    }

    if ((ret = mbedtls_asn1_get_alg_null(&p, end, &prf_alg_oid)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    if (mbedtls_oid_get_md_hmac(&prf_alg_oid, md_type) != 0) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }

    if (p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

#if !defined(MBEDTLS_CIPHER_PADDING_PKCS7)
int mbedtls_pkcs5_pbes2_ext(const mbedtls_asn1_buf *pbe_params, int mode,
                            const unsigned char *pwd,  size_t pwdlen,
                            const unsigned char *data, size_t datalen,
                            unsigned char *output, size_t output_size,
                            size_t *output_len);
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_pkcs5_pbes2(const mbedtls_asn1_buf *pbe_params, int mode,
                        const unsigned char *pwd,  size_t pwdlen,
                        const unsigned char *data, size_t datalen,
                        unsigned char *output)
{
    size_t output_len = 0;

    return mbedtls_pkcs5_pbes2_ext(pbe_params, mode, pwd, pwdlen, data,
                                   datalen, output, SIZE_MAX, &output_len);
}
#endif

int mbedtls_pkcs5_pbes2_ext(const mbedtls_asn1_buf *pbe_params, int mode,
                            const unsigned char *pwd,  size_t pwdlen,
                            const unsigned char *data, size_t datalen,
                            unsigned char *output, size_t output_size,
                            size_t *output_len)
{
    int ret, iterations = 0, keylen = 0;
    unsigned char *p, *end;
    mbedtls_asn1_buf kdf_alg_oid, enc_scheme_oid, kdf_alg_params, enc_scheme_params;
    mbedtls_asn1_buf salt;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
    unsigned char key[32], iv[32];
    const mbedtls_cipher_info_t *cipher_info;
    mbedtls_cipher_type_t cipher_alg;
    mbedtls_cipher_context_t cipher_ctx;
    unsigned int padlen = 0;

    p = pbe_params->p;
    end = p + pbe_params->len;

    if (pbe_params->tag != (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    if ((ret = mbedtls_asn1_get_alg(&p, end, &kdf_alg_oid,
                                    &kdf_alg_params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS5_PBKDF2, &kdf_alg_oid) != 0) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }

    if ((ret = pkcs5_parse_pbkdf2_params(&kdf_alg_params,
                                         &salt, &iterations, &keylen,
                                         &md_type)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_asn1_get_alg(&p, end, &enc_scheme_oid,
                                    &enc_scheme_params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PKCS5_INVALID_FORMAT, ret);
    }

    if (mbedtls_oid_get_cipher_alg(&enc_scheme_oid, &cipher_alg) != 0) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }

    cipher_info = mbedtls_cipher_info_from_type(cipher_alg);
    if (cipher_info == NULL) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }

    keylen = (int) mbedtls_cipher_info_get_key_bitlen(cipher_info) / 8;

    if (enc_scheme_params.tag != MBEDTLS_ASN1_OCTET_STRING ||
        enc_scheme_params.len != mbedtls_cipher_info_get_iv_size(cipher_info)) {
        return MBEDTLS_ERR_PKCS5_INVALID_FORMAT;
    }

    if (mode == MBEDTLS_PKCS5_DECRYPT) {
        if (output_size < datalen) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
    }

    if (mode == MBEDTLS_PKCS5_ENCRYPT) {
        padlen = cipher_info->block_size - (datalen % cipher_info->block_size);
        if (output_size < (datalen + padlen)) {
            return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
        }
    }

    mbedtls_cipher_init(&cipher_ctx);

    memcpy(iv, enc_scheme_params.p, enc_scheme_params.len);

    if ((ret = mbedtls_pkcs5_pbkdf2_hmac_ext(md_type, pwd, pwdlen, salt.p,
                                             salt.len, iterations, keylen,
                                             key)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_cipher_setkey(&cipher_ctx, key, 8 * keylen,
                                     (mbedtls_operation_t) mode)) != 0) {
        goto exit;
    }

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    {
        mbedtls_cipher_padding_t padding = MBEDTLS_PADDING_PKCS7;
#if !defined(MBEDTLS_CIPHER_PADDING_PKCS7)
        if (mode == MBEDTLS_DECRYPT) {
            padding = MBEDTLS_PADDING_NONE;
        }
#endif
        if ((ret = mbedtls_cipher_set_padding_mode(&cipher_ctx, padding)) != 0) {
            goto exit;
        }
    }
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */
    if ((ret = mbedtls_cipher_crypt(&cipher_ctx, iv, enc_scheme_params.len,
                                    data, datalen, output, output_len)) != 0) {
        ret = MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH;
    }

exit:
    mbedtls_cipher_free(&cipher_ctx);

    return ret;
}
#endif /* MBEDTLS_ASN1_PARSE_C && MBEDTLS_CIPHER_C */

static int pkcs5_pbkdf2_hmac(mbedtls_md_context_t *ctx,
                             const unsigned char *password,
                             size_t plen, const unsigned char *salt, size_t slen,
                             unsigned int iteration_count,
                             uint32_t key_length, unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned int i;
    unsigned char md1[MBEDTLS_MD_MAX_SIZE];
    unsigned char work[MBEDTLS_MD_MAX_SIZE];
    unsigned char md_size = mbedtls_md_get_size(ctx->md_info);
    size_t use_len;
    unsigned char *out_p = output;
    unsigned char counter[4];

    memset(counter, 0, 4);
    counter[3] = 1;

#if UINT_MAX > 0xFFFFFFFF
    if (iteration_count > 0xFFFFFFFF) {
        return MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA;
    }
#endif

    if ((ret = mbedtls_md_hmac_starts(ctx, password, plen)) != 0) {
        return ret;
    }
    while (key_length) {
        if ((ret = mbedtls_md_hmac_update(ctx, salt, slen)) != 0) {
            goto cleanup;
        }

        if ((ret = mbedtls_md_hmac_update(ctx, counter, 4)) != 0) {
            goto cleanup;
        }

        if ((ret = mbedtls_md_hmac_finish(ctx, work)) != 0) {
            goto cleanup;
        }

        if ((ret = mbedtls_md_hmac_reset(ctx)) != 0) {
            goto cleanup;
        }

        memcpy(md1, work, md_size);

        for (i = 1; i < iteration_count; i++) {
            if ((ret = mbedtls_md_hmac_update(ctx, md1, md_size)) != 0) {
                goto cleanup;
            }

            if ((ret = mbedtls_md_hmac_finish(ctx, md1)) != 0) {
                goto cleanup;
            }

            if ((ret = mbedtls_md_hmac_reset(ctx)) != 0) {
                goto cleanup;
            }
            mbedtls_xor(work, work, md1, md_size);
        }

        use_len = (key_length < md_size) ? key_length : md_size;
        memcpy(out_p, work, use_len);

        key_length -= (uint32_t) use_len;
        out_p += use_len;

        for (i = 4; i > 0; i--) {
            if (++counter[i - 1] != 0) {
                break;
            }
        }
    }

cleanup:
    mbedtls_platform_zeroize(work, MBEDTLS_MD_MAX_SIZE);
    mbedtls_platform_zeroize(md1, MBEDTLS_MD_MAX_SIZE);

    return ret;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_pkcs5_pbkdf2_hmac(mbedtls_md_context_t *ctx,
                              const unsigned char *password,
                              size_t plen, const unsigned char *salt, size_t slen,
                              unsigned int iteration_count,
                              uint32_t key_length, unsigned char *output)
{
    return pkcs5_pbkdf2_hmac(ctx, password, plen, salt, slen, iteration_count,
                             key_length, output);
}
#endif

int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_alg,
                                  const unsigned char *password,
                                  size_t plen, const unsigned char *salt, size_t slen,
                                  unsigned int iteration_count,
                                  uint32_t key_length, unsigned char *output)
{
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t *md_info = NULL;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    md_info = mbedtls_md_info_from_type(md_alg);
    if (md_info == NULL) {
        return MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE;
    }

    mbedtls_md_init(&md_ctx);

    if ((ret = mbedtls_md_setup(&md_ctx, md_info, 1)) != 0) {
        goto exit;
    }
    ret = pkcs5_pbkdf2_hmac(&md_ctx, password, plen, salt, slen,
                            iteration_count, key_length, output);
exit:
    mbedtls_md_free(&md_ctx);
    return ret;
}

#endif
