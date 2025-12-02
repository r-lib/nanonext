/**
 * \file ctr_drbg.h
 *
 * \brief    This file contains definitions and functions for the
 *           CTR_DRBG pseudorandom generator.
 *
 * CTR_DRBG is a standardized way of building a PRNG from a block-cipher
 * in counter mode operation, as defined in <em>NIST SP 800-90A:
 * Recommendation for Random Number Generation Using Deterministic Random
 * Bit Generators</em>.
 *
 * The Mbed TLS implementation of CTR_DRBG uses AES-256 (default) or AES-128
 * (if \c MBEDTLS_CTR_DRBG_USE_128_BIT_KEY is enabled at compile time)
 * as the underlying block cipher, with a derivation function.
 *
 * The security strength as defined in NIST SP 800-90A is
 * 128 bits when AES-128 is used (\c MBEDTLS_CTR_DRBG_USE_128_BIT_KEY enabled)
 * and 256 bits otherwise, provided that #MBEDTLS_CTR_DRBG_ENTROPY_LEN is
 * kept at its default value (and not overridden in mbedtls_config.h) and that the
 * DRBG instance is set up with default parameters.
 * See the documentation of mbedtls_ctr_drbg_seed() for more
 * information.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_CTR_DRBG_H
#define MBEDTLS_CTR_DRBG_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#if !defined(MBEDTLS_AES_C)
#define MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO 
#endif
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#else
#include "mbedtls/aes.h"
#endif
#include "entropy.h"
#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif
#define MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED -0x0034
#define MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG -0x0036
#define MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG -0x0038
#define MBEDTLS_ERR_CTR_DRBG_FILE_IO_ERROR -0x003A
#define MBEDTLS_CTR_DRBG_BLOCKSIZE 16
#if defined(MBEDTLS_CTR_DRBG_USE_128_BIT_KEY)
#define MBEDTLS_CTR_DRBG_KEYSIZE 16
#else
#define MBEDTLS_CTR_DRBG_KEYSIZE 32
#endif
#define MBEDTLS_CTR_DRBG_KEYBITS (MBEDTLS_CTR_DRBG_KEYSIZE * 8)
#define MBEDTLS_CTR_DRBG_SEEDLEN (MBEDTLS_CTR_DRBG_KEYSIZE + MBEDTLS_CTR_DRBG_BLOCKSIZE)
#if !defined(MBEDTLS_CTR_DRBG_ENTROPY_LEN)
#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
#define MBEDTLS_CTR_DRBG_ENTROPY_LEN 48
#else
#if !defined(MBEDTLS_CTR_DRBG_USE_128_BIT_KEY)
#endif
#define MBEDTLS_CTR_DRBG_ENTROPY_LEN 32
#endif
#endif
#if !defined(MBEDTLS_CTR_DRBG_RESEED_INTERVAL)
#define MBEDTLS_CTR_DRBG_RESEED_INTERVAL 10000
#endif
#if !defined(MBEDTLS_CTR_DRBG_MAX_INPUT)
#define MBEDTLS_CTR_DRBG_MAX_INPUT 256
#endif
#if !defined(MBEDTLS_CTR_DRBG_MAX_REQUEST)
#define MBEDTLS_CTR_DRBG_MAX_REQUEST 1024
#endif
#if !defined(MBEDTLS_CTR_DRBG_MAX_SEED_INPUT)
#define MBEDTLS_CTR_DRBG_MAX_SEED_INPUT 384
#endif
#define MBEDTLS_CTR_DRBG_PR_OFF 0
#define MBEDTLS_CTR_DRBG_PR_ON 1
#ifdef __cplusplus
extern "C" {
#endif
#if MBEDTLS_CTR_DRBG_ENTROPY_LEN >= MBEDTLS_CTR_DRBG_KEYSIZE * 3 / 2
#define MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN 0
#else
#define MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN (MBEDTLS_CTR_DRBG_ENTROPY_LEN + 1) / 2
#endif
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
typedef struct mbedtls_ctr_drbg_psa_context {
    mbedtls_svc_key_id_t key_id;
    psa_cipher_operation_t operation;
} mbedtls_ctr_drbg_psa_context;
#endif
typedef struct mbedtls_ctr_drbg_context {
    unsigned char MBEDTLS_PRIVATE(counter)[16];
    int MBEDTLS_PRIVATE(reseed_counter);
    int MBEDTLS_PRIVATE(prediction_resistance);
    size_t MBEDTLS_PRIVATE(entropy_len);
    int MBEDTLS_PRIVATE(reseed_interval);
#if defined(MBEDTLS_CTR_DRBG_USE_PSA_CRYPTO)
    mbedtls_ctr_drbg_psa_context MBEDTLS_PRIVATE(psa_ctx);
#else
    mbedtls_aes_context MBEDTLS_PRIVATE(aes_ctx);
#endif
    int(*MBEDTLS_PRIVATE(f_entropy))(void *, unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_entropy);
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
}
mbedtls_ctr_drbg_context;
void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx);
#if MBEDTLS_CTR_DRBG_ENTROPY_NONCE_LEN == 0
#else
#endif
#if defined(MBEDTLS_THREADING_C)
#endif
int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx,
                          int (*f_entropy)(void *, unsigned char *, size_t),
                          void *p_entropy,
                          const unsigned char *custom,
                          size_t len);
void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *ctx);
void mbedtls_ctr_drbg_set_prediction_resistance(mbedtls_ctr_drbg_context *ctx,
                                                int resistance);
void mbedtls_ctr_drbg_set_entropy_len(mbedtls_ctr_drbg_context *ctx,
                                      size_t len);
int mbedtls_ctr_drbg_set_nonce_len(mbedtls_ctr_drbg_context *ctx,
                                   size_t len);
void mbedtls_ctr_drbg_set_reseed_interval(mbedtls_ctr_drbg_context *ctx,
                                          int interval);
int mbedtls_ctr_drbg_reseed(mbedtls_ctr_drbg_context *ctx,
                            const unsigned char *additional, size_t len);
int mbedtls_ctr_drbg_update(mbedtls_ctr_drbg_context *ctx,
                            const unsigned char *additional,
                            size_t add_len);
int mbedtls_ctr_drbg_random_with_add(void *p_rng,
                                     unsigned char *output, size_t output_len,
                                     const unsigned char *additional, size_t add_len);
#if defined(MBEDTLS_THREADING_C)
#endif
int mbedtls_ctr_drbg_random(void *p_rng,
                            unsigned char *output, size_t output_len);
#if defined(MBEDTLS_FS_IO)
int mbedtls_ctr_drbg_write_seed_file(mbedtls_ctr_drbg_context *ctx, const char *path);
int mbedtls_ctr_drbg_update_seed_file(mbedtls_ctr_drbg_context *ctx, const char *path);
#endif
#ifdef __cplusplus
}
#endif
#endif
