/**
 * \file pk.h
 *
 * \brief Public Key abstraction layer
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PK_H
#define MBEDTLS_PK_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/md.h"
#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif
#if defined(MBEDTLS_PSA_CRYPTO_CLIENT)
#include "psa/crypto.h"
#endif
#define MBEDTLS_ERR_PK_ALLOC_FAILED -0x3F80
#define MBEDTLS_ERR_PK_TYPE_MISMATCH -0x3F00
#define MBEDTLS_ERR_PK_BAD_INPUT_DATA -0x3E80
#define MBEDTLS_ERR_PK_FILE_IO_ERROR -0x3E00
#define MBEDTLS_ERR_PK_KEY_INVALID_VERSION -0x3D80
#define MBEDTLS_ERR_PK_KEY_INVALID_FORMAT -0x3D00
#define MBEDTLS_ERR_PK_UNKNOWN_PK_ALG -0x3C80
#define MBEDTLS_ERR_PK_PASSWORD_REQUIRED -0x3C00
#define MBEDTLS_ERR_PK_PASSWORD_MISMATCH -0x3B80
#define MBEDTLS_ERR_PK_INVALID_PUBKEY -0x3B00
#define MBEDTLS_ERR_PK_INVALID_ALG -0x3A80
#define MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE -0x3A00
#define MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE -0x3980
#define MBEDTLS_ERR_PK_SIG_LEN_MISMATCH -0x3900
#define MBEDTLS_ERR_PK_BUFFER_TOO_SMALL -0x3880
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    MBEDTLS_PK_NONE=0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
    MBEDTLS_PK_OPAQUE,
} mbedtls_pk_type_t;
typedef struct mbedtls_pk_rsassa_pss_options {
    mbedtls_md_type_t mgf1_hash_id;
    int expected_salt_len;
} mbedtls_pk_rsassa_pss_options;
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE 0
#if (defined(MBEDTLS_RSA_C) || defined(MBEDTLS_PK_RSA_ALT_SUPPORT)) && \
    MBEDTLS_MPI_MAX_SIZE > MBEDTLS_PK_SIGNATURE_MAX_SIZE
#undef MBEDTLS_PK_SIGNATURE_MAX_SIZE
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE MBEDTLS_MPI_MAX_SIZE
#endif
#if defined(MBEDTLS_ECDSA_C) && \
    MBEDTLS_ECDSA_MAX_LEN > MBEDTLS_PK_SIGNATURE_MAX_SIZE
#undef MBEDTLS_PK_SIGNATURE_MAX_SIZE
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE MBEDTLS_ECDSA_MAX_LEN
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if PSA_SIGNATURE_MAX_SIZE > MBEDTLS_PK_SIGNATURE_MAX_SIZE
#undef MBEDTLS_PK_SIGNATURE_MAX_SIZE
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE PSA_SIGNATURE_MAX_SIZE
#endif
#if PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE + 11 > MBEDTLS_PK_SIGNATURE_MAX_SIZE
#undef MBEDTLS_PK_SIGNATURE_MAX_SIZE
#define MBEDTLS_PK_SIGNATURE_MAX_SIZE (PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE + 11)
#endif
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY) && \
    !defined(MBEDTLS_ECP_C)
#define MBEDTLS_PK_USE_PSA_EC_DATA 
#endif
typedef enum {
    MBEDTLS_PK_DEBUG_NONE = 0,
    MBEDTLS_PK_DEBUG_MPI,
    MBEDTLS_PK_DEBUG_ECP,
    MBEDTLS_PK_DEBUG_PSA_EC,
} mbedtls_pk_debug_type;
typedef struct mbedtls_pk_debug_item {
    mbedtls_pk_debug_type MBEDTLS_PRIVATE(type);
    const char *MBEDTLS_PRIVATE(name);
    void *MBEDTLS_PRIVATE(value);
} mbedtls_pk_debug_item;
#define MBEDTLS_PK_DEBUG_MAX_ITEMS 3
typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;
#define MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN \
    PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)
typedef struct mbedtls_pk_context {
    const mbedtls_pk_info_t *MBEDTLS_PRIVATE(pk_info);
    void *MBEDTLS_PRIVATE(pk_ctx);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t MBEDTLS_PRIVATE(priv_id);
#endif
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    uint8_t MBEDTLS_PRIVATE(pub_raw)[MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t MBEDTLS_PRIVATE(pub_raw_len);
    psa_ecc_family_t MBEDTLS_PRIVATE(ec_family);
    size_t MBEDTLS_PRIVATE(ec_bits);
#endif
} mbedtls_pk_context;
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
typedef struct {
    const mbedtls_pk_info_t *MBEDTLS_PRIVATE(pk_info);
    void *MBEDTLS_PRIVATE(rs_ctx);
} mbedtls_pk_restart_ctx;
#else
typedef void mbedtls_pk_restart_ctx;
#endif
#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
typedef int (*mbedtls_pk_rsa_alt_decrypt_func)(void *ctx, size_t *olen,
                                               const unsigned char *input, unsigned char *output,
                                               size_t output_max_len);
typedef int (*mbedtls_pk_rsa_alt_sign_func)(void *ctx,
                                            int (*f_rng)(void *, unsigned char *, size_t),
                                            void *p_rng,
                                            mbedtls_md_type_t md_alg, unsigned int hashlen,
                                            const unsigned char *hash, unsigned char *sig);
typedef size_t (*mbedtls_pk_rsa_alt_key_len_func)(void *ctx);
#endif
const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type);
void mbedtls_pk_init(mbedtls_pk_context *ctx);
void mbedtls_pk_free(mbedtls_pk_context *ctx);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
void mbedtls_pk_restart_init(mbedtls_pk_restart_ctx *ctx);
void mbedtls_pk_restart_free(mbedtls_pk_restart_ctx *ctx);
#endif
int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_pk_setup_opaque(mbedtls_pk_context *ctx,
                            const mbedtls_svc_key_id_t key);
#endif
#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
int mbedtls_pk_setup_rsa_alt(mbedtls_pk_context *ctx, void *key,
                             mbedtls_pk_rsa_alt_decrypt_func decrypt_func,
                             mbedtls_pk_rsa_alt_sign_func sign_func,
                             mbedtls_pk_rsa_alt_key_len_func key_len_func);
#endif
size_t mbedtls_pk_get_bitlen(const mbedtls_pk_context *ctx);
static inline size_t mbedtls_pk_get_len(const mbedtls_pk_context *ctx)
{
    return (mbedtls_pk_get_bitlen(ctx) + 7) / 8;
}
int mbedtls_pk_can_do(const mbedtls_pk_context *ctx, mbedtls_pk_type_t type);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_pk_can_do_ext(const mbedtls_pk_context *ctx, psa_algorithm_t alg,
                          psa_key_usage_t usage);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_CLIENT)
int mbedtls_pk_get_psa_attributes(const mbedtls_pk_context *pk,
                                  psa_key_usage_t usage,
                                  psa_key_attributes_t *attributes);
int mbedtls_pk_import_into_psa(const mbedtls_pk_context *pk,
                               const psa_key_attributes_t *attributes,
                               mbedtls_svc_key_id_t *key_id);
int mbedtls_pk_copy_from_psa(mbedtls_svc_key_id_t key_id, mbedtls_pk_context *pk);
int mbedtls_pk_copy_public_from_psa(mbedtls_svc_key_id_t key_id, mbedtls_pk_context *pk);
#endif
int mbedtls_pk_verify(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                      const unsigned char *hash, size_t hash_len,
                      const unsigned char *sig, size_t sig_len);
int mbedtls_pk_verify_restartable(mbedtls_pk_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  const unsigned char *sig, size_t sig_len,
                                  mbedtls_pk_restart_ctx *rs_ctx);
int mbedtls_pk_verify_ext(mbedtls_pk_type_t type, const void *options,
                          mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          const unsigned char *sig, size_t sig_len);
int mbedtls_pk_sign(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                    const unsigned char *hash, size_t hash_len,
                    unsigned char *sig, size_t sig_size, size_t *sig_len,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_sign_ext(mbedtls_pk_type_t pk_type,
                        mbedtls_pk_context *ctx,
                        mbedtls_md_type_t md_alg,
                        const unsigned char *hash, size_t hash_len,
                        unsigned char *sig, size_t sig_size, size_t *sig_len,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng);
int mbedtls_pk_sign_restartable(mbedtls_pk_context *ctx,
                                mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_pk_restart_ctx *rs_ctx);
int mbedtls_pk_decrypt(mbedtls_pk_context *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_encrypt(mbedtls_pk_context *ctx,
                       const unsigned char *input, size_t ilen,
                       unsigned char *output, size_t *olen, size_t osize,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_check_pair(const mbedtls_pk_context *pub,
                          const mbedtls_pk_context *prv,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng);
int mbedtls_pk_debug(const mbedtls_pk_context *ctx, mbedtls_pk_debug_item *items);
const char *mbedtls_pk_get_name(const mbedtls_pk_context *ctx);
mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx);
#if defined(MBEDTLS_RSA_C)
static inline mbedtls_rsa_context *mbedtls_pk_rsa(const mbedtls_pk_context pk)
{
    switch (mbedtls_pk_get_type(&pk)) {
        case MBEDTLS_PK_RSA:
            return (mbedtls_rsa_context *) (pk).MBEDTLS_PRIVATE(pk_ctx);
        default:
            return NULL;
    }
}
#endif
#if defined(MBEDTLS_ECP_C)
static inline mbedtls_ecp_keypair *mbedtls_pk_ec(const mbedtls_pk_context pk)
{
    switch (mbedtls_pk_get_type(&pk)) {
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
            return (mbedtls_ecp_keypair *) (pk).MBEDTLS_PRIVATE(pk_ctx);
        default:
            return NULL;
    }
}
#endif
#if defined(MBEDTLS_PK_PARSE_C)
int mbedtls_pk_parse_key(mbedtls_pk_context *ctx,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *pwd, size_t pwdlen,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                const unsigned char *key, size_t keylen);
#if defined(MBEDTLS_FS_IO)
int mbedtls_pk_parse_keyfile(mbedtls_pk_context *ctx,
                             const char *path, const char *password,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
int mbedtls_pk_parse_public_keyfile(mbedtls_pk_context *ctx, const char *path);
#endif
#endif
#if defined(MBEDTLS_PK_WRITE_C)
int mbedtls_pk_write_key_der(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
int mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
#if defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_pk_write_pubkey_pem(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
int mbedtls_pk_write_key_pem(const mbedtls_pk_context *ctx, unsigned char *buf, size_t size);
#endif
#endif
#if defined(MBEDTLS_PK_PARSE_C)
int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
                               mbedtls_pk_context *pk);
#endif
#if defined(MBEDTLS_PK_WRITE_C)
int mbedtls_pk_write_pubkey(unsigned char **p, unsigned char *start,
                            const mbedtls_pk_context *key);
#endif
#ifdef __cplusplus
}
#endif
#endif
