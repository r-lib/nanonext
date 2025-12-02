/*
 *  CTR_DRBG implementation based on AES-256 (NIST SP 800-90)
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *  The NIST SP 800-90 DRBGs are described in the following publication.
 *
 *  https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-90r.pdf
 */

#include "common.h"

#if defined(MBEDTLS_CTR_DRBG_C)

#include "ctr.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#endif

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
#include "psa_util_internal.h"
#endif

#include "mbedtls/platform.h"

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
static psa_status_t ctr_drbg_setup_psa_context(mbedtls_ctr_drbg_psa_context *psa_ctx,
                                               unsigned char *key, size_t key_len)
{
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;

    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&key_attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_type(&key_attr, PSA_KEY_TYPE_AES);
    status = psa_import_key(&key_attr, key, key_len, &psa_ctx->key_id);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

    status = psa_cipher_encrypt_setup(&psa_ctx->operation, psa_ctx->key_id, PSA_ALG_ECB_NO_PADDING);
    if (status != PSA_SUCCESS) {
        goto exit;
    }

exit:
    psa_reset_key_attributes(&key_attr);
    return status;
}

static void ctr_drbg_destroy_psa_contex(mbedtls_ctr_drbg_psa_context *psa_ctx)
{
    psa_cipher_abort(&psa_ctx->operation);
    psa_destroy_key(psa_ctx->key_id);

    psa_ctx->operation = psa_cipher_operation_init();
    psa_ctx->key_id = MBEDTLS_SVC_KEY_ID_INIT;
}
#endif

void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_ctr_drbg_context));
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    ctx->psa_ctx.key_id = MBEDTLS_SVC_KEY_ID_INIT;
    ctx->psa_ctx.operation = psa_cipher_operation_init();
#else
    mbedtls_aes_init(&ctx->aes_ctx);
#endif
    ctx->reseed_counter = -1;

    ctx->reseed_interval = MBEDTLS_CTR_DRBG_RESEED_INTERVAL;
}

void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(MBEDTLS_THREADING_C)
    if (ctx->f_entropy != NULL) {
        mbedtls_mutex_free(&ctx->mutex);
    }
#endif
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    ctr_drbg_destroy_psa_contex(&ctx->psa_ctx);
#else
    mbedtls_aes_free(&ctx->aes_ctx);
#endif
    mbedtls_platform_zeroize(ctx, sizeof(mbedtls_ctr_drbg_context));
    ctx->reseed_interval = MBEDTLS_CTR_DRBG_RESEED_INTERVAL;
    ctx->reseed_counter = -1;
}

void mbedtls_ctr_drbg_set_prediction_resistance(mbedtls_ctr_drbg_context *ctx,
                                                int resistance)
{
    ctx->prediction_resistance = resistance;
}

void mbedtls_ctr_drbg_set_entropy_len(mbedtls_ctr_drbg_context *ctx,
                                      size_t len)
{
    ctx->entropy_len = len;
}

int mbedtls_ctr_drbg_set_nonce_len(mbedtls_ctr_drbg_context *ctx,
                                   size_t len)
{
    if (ctx->f_entropy != NULL) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }

    if (len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }

    if (len > INT_MAX) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }

    ctx->reseed_counter = (int) len;
    return 0;
}

void mbedtls_ctr_drbg_set_reseed_interval(mbedtls_ctr_drbg_context *ctx,
                                          int interval)
{
    ctx->reseed_interval = interval;
}

static int block_cipher_df(unsigned char *output,
                           const unsigned char *data, size_t data_len)
{
    unsigned char buf[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT +
                      MBEDTLS_CTR_DRBG_BLOCKSIZE + 16];
    unsigned char tmp[MBEDTLS_CTR_DRBG_SEEDLEN];
    unsigned char key[MBEDTLS_CTR_DRBG_KEYSIZE];
    unsigned char chain[MBEDTLS_CTR_DRBG_BLOCKSIZE];
    unsigned char *p, *iv;
    int ret = 0;
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    psa_status_t status;
    size_t tmp_len;
    mbedtls_ctr_drbg_psa_context psa_ctx;

    psa_ctx.key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_ctx.operation = psa_cipher_operation_init();
#else
    mbedtls_aes_context aes_ctx;
#endif

    int i, j;
    size_t buf_len, use_len;

    if (data_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }

    memset(buf, 0, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT +
           MBEDTLS_CTR_DRBG_BLOCKSIZE + 16);

    p = buf + MBEDTLS_CTR_DRBG_BLOCKSIZE;
    MBEDTLS_PUT_UINT32_BE(data_len, p, 0);
    p += 4 + 3;
    *p++ = MBEDTLS_CTR_DRBG_SEEDLEN;
    memcpy(p, data, data_len);
    p[data_len] = 0x80;

    buf_len = MBEDTLS_CTR_DRBG_BLOCKSIZE + 8 + data_len + 1;

    for (i = 0; i < MBEDTLS_CTR_DRBG_KEYSIZE; i++) {
        key[i] = i;
    }

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    status = ctr_drbg_setup_psa_context(&psa_ctx, key, sizeof(key));
    if (status != PSA_SUCCESS) {
        ret = psa_generic_status_to_mbedtls(status);
        goto exit;
    }
#else
    mbedtls_aes_init(&aes_ctx);

    if ((ret = mbedtls_aes_setkey_enc(&aes_ctx, key,
                                      MBEDTLS_CTR_DRBG_KEYBITS)) != 0) {
        goto exit;
    }
#endif

    for (j = 0; j < MBEDTLS_CTR_DRBG_SEEDLEN; j += MBEDTLS_CTR_DRBG_BLOCKSIZE) {
        p = buf;
        memset(chain, 0, MBEDTLS_CTR_DRBG_BLOCKSIZE);
        use_len = buf_len;

        while (use_len > 0) {
            mbedtls_xor(chain, chain, p, MBEDTLS_CTR_DRBG_BLOCKSIZE);
            p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
            use_len -= (use_len >= MBEDTLS_CTR_DRBG_BLOCKSIZE) ?
                       MBEDTLS_CTR_DRBG_BLOCKSIZE : use_len;

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
            status = psa_cipher_update(&psa_ctx.operation, chain, MBEDTLS_CTR_DRBG_BLOCKSIZE,
                                       chain, MBEDTLS_CTR_DRBG_BLOCKSIZE, &tmp_len);
            if (status != PSA_SUCCESS) {
                ret = psa_generic_status_to_mbedtls(status);
                goto exit;
            }
#else
            if ((ret = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                                             chain, chain)) != 0) {
                goto exit;
            }
#endif
        }

        memcpy(tmp + j, chain, MBEDTLS_CTR_DRBG_BLOCKSIZE);

        buf[3]++;
    }

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    ctr_drbg_destroy_psa_contex(&psa_ctx);

    status = ctr_drbg_setup_psa_context(&psa_ctx, tmp, MBEDTLS_CTR_DRBG_KEYSIZE);
    if (status != PSA_SUCCESS) {
        ret = psa_generic_status_to_mbedtls(status);
        goto exit;
    }
#else
    if ((ret = mbedtls_aes_setkey_enc(&aes_ctx, tmp,
                                      MBEDTLS_CTR_DRBG_KEYBITS)) != 0) {
        goto exit;
    }
#endif
    iv = tmp + MBEDTLS_CTR_DRBG_KEYSIZE;
    p = output;

    for (j = 0; j < MBEDTLS_CTR_DRBG_SEEDLEN; j += MBEDTLS_CTR_DRBG_BLOCKSIZE) {
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
        status = psa_cipher_update(&psa_ctx.operation, iv, MBEDTLS_CTR_DRBG_BLOCKSIZE,
                                   iv, MBEDTLS_CTR_DRBG_BLOCKSIZE, &tmp_len);
        if (status != PSA_SUCCESS) {
            ret = psa_generic_status_to_mbedtls(status);
            goto exit;
        }
#else
        if ((ret = mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                                         iv, iv)) != 0) {
            goto exit;
        }
#endif
        memcpy(p, iv, MBEDTLS_CTR_DRBG_BLOCKSIZE);
        p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
    }
exit:
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    ctr_drbg_destroy_psa_contex(&psa_ctx);
#else
    mbedtls_aes_free(&aes_ctx);
#endif

    mbedtls_platform_zeroize(buf, sizeof(buf));
    mbedtls_platform_zeroize(tmp, sizeof(tmp));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(chain, sizeof(chain));
    if (0 != ret) {
        mbedtls_platform_zeroize(output, MBEDTLS_CTR_DRBG_SEEDLEN);
    }

    return ret;
}

static int ctr_drbg_update_internal(mbedtls_ctr_drbg_context *ctx,
                                    const unsigned char data[MBEDTLS_CTR_DRBG_SEEDLEN])
{
    unsigned char tmp[MBEDTLS_CTR_DRBG_SEEDLEN];
    unsigned char *p = tmp;
    int j;
    int ret = 0;
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    psa_status_t status;
    size_t tmp_len;
#endif

    memset(tmp, 0, MBEDTLS_CTR_DRBG_SEEDLEN);

    for (j = 0; j < MBEDTLS_CTR_DRBG_SEEDLEN; j += MBEDTLS_CTR_DRBG_BLOCKSIZE) {
        mbedtls_ctr_increment_counter(ctx->counter);
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
        status = psa_cipher_update(&ctx->psa_ctx.operation, ctx->counter, sizeof(ctx->counter),
                                   p, MBEDTLS_CTR_DRBG_BLOCKSIZE, &tmp_len);
        if (status != PSA_SUCCESS) {
            ret = psa_generic_status_to_mbedtls(status);
            goto exit;
        }
#else
        if ((ret = mbedtls_aes_crypt_ecb(&ctx->aes_ctx, MBEDTLS_AES_ENCRYPT,
                                         ctx->counter, p)) != 0) {
            goto exit;
        }
#endif

        p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
    }

    mbedtls_xor(tmp, tmp, data, MBEDTLS_CTR_DRBG_SEEDLEN);

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    ctr_drbg_destroy_psa_contex(&ctx->psa_ctx);

    status = ctr_drbg_setup_psa_context(&ctx->psa_ctx, tmp, MBEDTLS_CTR_DRBG_KEYSIZE);
    if (status != PSA_SUCCESS) {
        ret = psa_generic_status_to_mbedtls(status);
        goto exit;
    }
#else
    if ((ret = mbedtls_aes_setkey_enc(&ctx->aes_ctx, tmp,
                                      MBEDTLS_CTR_DRBG_KEYBITS)) != 0) {
        goto exit;
    }
#endif
    memcpy(ctx->counter, tmp + MBEDTLS_CTR_DRBG_KEYSIZE,
           MBEDTLS_CTR_DRBG_BLOCKSIZE);

exit:
    mbedtls_platform_zeroize(tmp, sizeof(tmp));
    return ret;
}

int mbedtls_ctr_drbg_update(mbedtls_ctr_drbg_context *ctx,
                            const unsigned char *additional,
                            size_t add_len)
{
    unsigned char add_input[MBEDTLS_CTR_DRBG_SEEDLEN];
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (add_len == 0) {
        return 0;
    }

    if ((ret = block_cipher_df(add_input, additional, add_len)) != 0) {
        goto exit;
    }
    if ((ret = ctr_drbg_update_internal(ctx, add_input)) != 0) {
        goto exit;
    }

exit:
    mbedtls_platform_zeroize(add_input, sizeof(add_input));
    return ret;
}

static int mbedtls_ctr_drbg_reseed_internal(mbedtls_ctr_drbg_context *ctx,
                                            const unsigned char *additional,
                                            size_t len,
                                            size_t nonce_len)
{
    unsigned char seed[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT];
    size_t seedlen = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (ctx->entropy_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }
    if (nonce_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - ctx->entropy_len) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }
    if (len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - ctx->entropy_len - nonce_len) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }

    memset(seed, 0, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT);

    if (0 != ctx->f_entropy(ctx->p_entropy, seed, ctx->entropy_len)) {
        return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
    }
    seedlen += ctx->entropy_len;

    if (nonce_len != 0) {
        if (0 != ctx->f_entropy(ctx->p_entropy, seed + seedlen, nonce_len)) {
            return MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
        }
        seedlen += nonce_len;
    }

    if (additional != NULL && len != 0) {
        memcpy(seed + seedlen, additional, len);
        seedlen += len;
    }

    if ((ret = block_cipher_df(seed, seed, seedlen)) != 0) {
        goto exit;
    }

    if ((ret = ctr_drbg_update_internal(ctx, seed)) != 0) {
        goto exit;
    }
    ctx->reseed_counter = 1;

exit:
    mbedtls_platform_zeroize(seed, sizeof(seed));
    return ret;
}

int mbedtls_ctr_drbg_reseed(mbedtls_ctr_drbg_context *ctx,
                            const unsigned char *additional, size_t len)
{
    return mbedtls_ctr_drbg_reseed_internal(ctx, additional, len, 0);
}

static size_t good_nonce_len(size_t entropy_len)
{
    if (entropy_len >= MBEDTLS_CTR_DRBG_KEYSIZE * 3 / 2) {
        return 0;
    } else {
        return (entropy_len + 1) / 2;
    }
}

int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx,
                          int (*f_entropy)(void *, unsigned char *, size_t),
                          void *p_entropy,
                          const unsigned char *custom,
                          size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char key[MBEDTLS_CTR_DRBG_KEYSIZE];
    size_t nonce_len;

    memset(key, 0, MBEDTLS_CTR_DRBG_KEYSIZE);

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init(&ctx->mutex);
#endif

    ctx->f_entropy = f_entropy;
    ctx->p_entropy = p_entropy;

    if (ctx->entropy_len == 0) {
        ctx->entropy_len = MBEDTLS_CTR_DRBG_ENTROPY_LEN;
    }

    nonce_len = (ctx->reseed_counter >= 0 ?
                 (size_t) ctx->reseed_counter :
                 good_nonce_len(ctx->entropy_len));

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    psa_status_t status;

    status = ctr_drbg_setup_psa_context(&ctx->psa_ctx, key, MBEDTLS_CTR_DRBG_KEYSIZE);
    if (status != PSA_SUCCESS) {
        ret = psa_generic_status_to_mbedtls(status);
        return status;
    }
#else
    if ((ret = mbedtls_aes_setkey_enc(&ctx->aes_ctx, key,
                                      MBEDTLS_CTR_DRBG_KEYBITS)) != 0) {
        return ret;
    }
#endif

    if ((ret = mbedtls_ctr_drbg_reseed_internal(ctx, custom, len,
                                                nonce_len)) != 0) {
        return ret;
    }
    return 0;
}

int mbedtls_ctr_drbg_random_with_add(void *p_rng,
                                     unsigned char *output, size_t output_len,
                                     const unsigned char *additional, size_t add_len)
{
    int ret = 0;
    mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *) p_rng;
    unsigned char *p = output;
    struct {
        unsigned char add_input[MBEDTLS_CTR_DRBG_SEEDLEN];
        unsigned char tmp[MBEDTLS_CTR_DRBG_BLOCKSIZE];
    } locals;
    size_t use_len;

    if (output_len > MBEDTLS_CTR_DRBG_MAX_REQUEST) {
        return MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG;
    }

    if (add_len > MBEDTLS_CTR_DRBG_MAX_INPUT) {
        return MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
    }

    memset(locals.add_input, 0, MBEDTLS_CTR_DRBG_SEEDLEN);

    if (ctx->reseed_counter > ctx->reseed_interval ||
        ctx->prediction_resistance) {
        if ((ret = mbedtls_ctr_drbg_reseed(ctx, additional, add_len)) != 0) {
            return ret;
        }
        add_len = 0;
    }

    if (add_len > 0) {
        if ((ret = block_cipher_df(locals.add_input, additional, add_len)) != 0) {
            goto exit;
        }
        if ((ret = ctr_drbg_update_internal(ctx, locals.add_input)) != 0) {
            goto exit;
        }
    }

    while (output_len > 0) {

        mbedtls_ctr_increment_counter(ctx->counter);

#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
        psa_status_t status;
        size_t tmp_len;

        status = psa_cipher_update(&ctx->psa_ctx.operation, ctx->counter, sizeof(ctx->counter),
                                   locals.tmp, MBEDTLS_CTR_DRBG_BLOCKSIZE, &tmp_len);
        if (status != PSA_SUCCESS) {
            ret = psa_generic_status_to_mbedtls(status);
            goto exit;
        }
#else
        if ((ret = mbedtls_aes_crypt_ecb(&ctx->aes_ctx, MBEDTLS_AES_ENCRYPT,
                                         ctx->counter, locals.tmp)) != 0) {
            goto exit;
        }
#endif

        use_len = (output_len > MBEDTLS_CTR_DRBG_BLOCKSIZE)
            ? MBEDTLS_CTR_DRBG_BLOCKSIZE : output_len;

        memcpy(p, locals.tmp, use_len);
        p += use_len;
        output_len -= use_len;
    }

    if ((ret = ctr_drbg_update_internal(ctx, locals.add_input)) != 0) {
        goto exit;
    }

    ctx->reseed_counter++;

exit:
    mbedtls_platform_zeroize(&locals, sizeof(locals));
    return ret;
}

int mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output,
                            size_t output_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *) p_rng;

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    ret = mbedtls_ctr_drbg_random_with_add(ctx, output, output_len, NULL, 0);

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

#if defined(MBEDTLS_FS_IO)
int mbedtls_ctr_drbg_write_seed_file(mbedtls_ctr_drbg_context *ctx,
                                     const char *path)
{
    int ret = MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
    FILE *f;
    unsigned char buf[MBEDTLS_CTR_DRBG_MAX_INPUT];

    if ((f = fopen(path, "wb")) == NULL) {
        return MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
    }

    mbedtls_setbuf(f, NULL);

    if ((ret = mbedtls_ctr_drbg_random(ctx, buf,
                                       MBEDTLS_CTR_DRBG_MAX_INPUT)) != 0) {
        goto exit;
    }

    if (fwrite(buf, 1, MBEDTLS_CTR_DRBG_MAX_INPUT, f) !=
        MBEDTLS_CTR_DRBG_MAX_INPUT) {
        ret = MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
    } else {
        ret = 0;
    }

exit:
    mbedtls_platform_zeroize(buf, sizeof(buf));

    fclose(f);
    return ret;
}

int mbedtls_ctr_drbg_update_seed_file(mbedtls_ctr_drbg_context *ctx,
                                      const char *path)
{
    int ret = 0;
    FILE *f = NULL;
    size_t n;
    unsigned char buf[MBEDTLS_CTR_DRBG_MAX_INPUT];
    unsigned char c;

    if ((f = fopen(path, "rb")) == NULL) {
        return MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
    }

    mbedtls_setbuf(f, NULL);

    n = fread(buf, 1, sizeof(buf), f);
    if (fread(&c, 1, 1, f) != 0) {
        ret = MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG;
        goto exit;
    }
    if (n == 0 || ferror(f)) {
        ret = MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR;
        goto exit;
    }
    fclose(f);
    f = NULL;

    ret = mbedtls_ctr_drbg_update(ctx, buf, n);

exit:
    mbedtls_platform_zeroize(buf, sizeof(buf));
    if (f != NULL) {
        fclose(f);
    }
    if (ret != 0) {
        return ret;
    }
    return mbedtls_ctr_drbg_write_seed_file(ctx, path);
}
#endif /* MBEDTLS_FS_IO */

#endif
