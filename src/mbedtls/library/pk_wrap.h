/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_PK_WRAP_H
#define MBEDTLS_PK_WRAP_H

#include "mbedtls/build_info.h"

#include "mbedtls/pk.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#endif

struct mbedtls_pk_info_t {

    mbedtls_pk_type_t type;

    const char *name;

    size_t (*get_bitlen)(mbedtls_pk_context *pk);

    int (*can_do)(mbedtls_pk_type_t type);

    int (*verify_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                       const unsigned char *hash, size_t hash_len,
                       const unsigned char *sig, size_t sig_len);

    int (*sign_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                     const unsigned char *hash, size_t hash_len,
                     unsigned char *sig, size_t sig_size, size_t *sig_len,
                     int (*f_rng)(void *, unsigned char *, size_t),
                     void *p_rng);

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)

    int (*verify_rs_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len,
                          void *rs_ctx);

    int (*sign_rs_func)(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng, void *rs_ctx);
#endif

    int (*decrypt_func)(mbedtls_pk_context *pk, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    int (*encrypt_func)(mbedtls_pk_context *pk, const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen, size_t osize,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);

    int (*check_pair_func)(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng);

    void * (*ctx_alloc_func)(void);

    void (*ctx_free_func)(void *ctx);

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)

    void *(*rs_alloc_func)(void);

    void (*rs_free_func)(void *rs_ctx);
#endif

    void (*debug_func)(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items);

};
#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)

typedef struct {
    void *key;
    mbedtls_pk_rsa_alt_decrypt_func decrypt_func;
    mbedtls_pk_rsa_alt_sign_func sign_func;
    mbedtls_pk_rsa_alt_key_len_func key_len_func;
} mbedtls_rsa_alt_context;
#endif

#if defined(MBEDTLS_RSA_C)
extern const mbedtls_pk_info_t mbedtls_rsa_info;
#endif

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
extern const mbedtls_pk_info_t mbedtls_eckey_info;
extern const mbedtls_pk_info_t mbedtls_eckeydh_info;
#endif

#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
extern const mbedtls_pk_info_t mbedtls_ecdsa_info;
#endif

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
extern const mbedtls_pk_info_t mbedtls_rsa_alt_info;
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
extern const mbedtls_pk_info_t mbedtls_ecdsa_opaque_info;
extern const mbedtls_pk_info_t mbedtls_rsa_opaque_info;

#if defined(MBEDTLS_RSA_C)
int mbedtls_pk_psa_rsa_sign_ext(psa_algorithm_t psa_alg_md,
                                mbedtls_rsa_context *rsa_ctx,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size,
                                size_t *sig_len);
#endif

#endif

#endif
