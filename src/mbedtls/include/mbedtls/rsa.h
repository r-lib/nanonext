/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_RSA_H
#define MBEDTLS_RSA_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/bignum.h"
#include "mbedtls/md.h"

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#define MBEDTLS_ERR_RSA_BAD_INPUT_DATA                    -0x4080

#define MBEDTLS_ERR_RSA_INVALID_PADDING                   -0x4100

#define MBEDTLS_ERR_RSA_KEY_GEN_FAILED                    -0x4180

#define MBEDTLS_ERR_RSA_KEY_CHECK_FAILED                  -0x4200

#define MBEDTLS_ERR_RSA_PUBLIC_FAILED                     -0x4280

#define MBEDTLS_ERR_RSA_PRIVATE_FAILED                    -0x4300

#define MBEDTLS_ERR_RSA_VERIFY_FAILED                     -0x4380

#define MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE                  -0x4400

#define MBEDTLS_ERR_RSA_RNG_FAILED                        -0x4480

#define MBEDTLS_RSA_PKCS_V15    0
#define MBEDTLS_RSA_PKCS_V21    1

#define MBEDTLS_RSA_SIGN        1
#define MBEDTLS_RSA_CRYPT       2

#define MBEDTLS_RSA_SALT_LEN_ANY    -1

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_RSA_ALT)

#if !defined(MBEDTLS_RSA_GEN_KEY_MIN_BITS)
#define MBEDTLS_RSA_GEN_KEY_MIN_BITS 1024
#elif MBEDTLS_RSA_GEN_KEY_MIN_BITS < 128
#error "MBEDTLS_RSA_GEN_KEY_MIN_BITS must be at least 128 bits"
#endif

typedef struct mbedtls_rsa_context {
    int MBEDTLS_PRIVATE(ver);
    size_t MBEDTLS_PRIVATE(len);

    mbedtls_mpi MBEDTLS_PRIVATE(N);
    mbedtls_mpi MBEDTLS_PRIVATE(E);

    mbedtls_mpi MBEDTLS_PRIVATE(D);
    mbedtls_mpi MBEDTLS_PRIVATE(P);
    mbedtls_mpi MBEDTLS_PRIVATE(Q);

    mbedtls_mpi MBEDTLS_PRIVATE(DP);
    mbedtls_mpi MBEDTLS_PRIVATE(DQ);
    mbedtls_mpi MBEDTLS_PRIVATE(QP);

    mbedtls_mpi MBEDTLS_PRIVATE(RN);

    mbedtls_mpi MBEDTLS_PRIVATE(RP);
    mbedtls_mpi MBEDTLS_PRIVATE(RQ);

    mbedtls_mpi MBEDTLS_PRIVATE(Vi);
    mbedtls_mpi MBEDTLS_PRIVATE(Vf);

    int MBEDTLS_PRIVATE(padding);
    int MBEDTLS_PRIVATE(hash_id);
#if defined(MBEDTLS_THREADING_C)

    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
}
mbedtls_rsa_context;

#else
#include "rsa_alt.h"
#endif

void mbedtls_rsa_init(mbedtls_rsa_context *ctx);

int mbedtls_rsa_set_padding(mbedtls_rsa_context *ctx, int padding,
                            mbedtls_md_type_t hash_id);

int mbedtls_rsa_get_padding_mode(const mbedtls_rsa_context *ctx);

int mbedtls_rsa_get_md_alg(const mbedtls_rsa_context *ctx);

int mbedtls_rsa_import(mbedtls_rsa_context *ctx,
                       const mbedtls_mpi *N,
                       const mbedtls_mpi *P, const mbedtls_mpi *Q,
                       const mbedtls_mpi *D, const mbedtls_mpi *E);

int mbedtls_rsa_import_raw(mbedtls_rsa_context *ctx,
                           unsigned char const *N, size_t N_len,
                           unsigned char const *P, size_t P_len,
                           unsigned char const *Q, size_t Q_len,
                           unsigned char const *D, size_t D_len,
                           unsigned char const *E, size_t E_len);

int mbedtls_rsa_complete(mbedtls_rsa_context *ctx);

int mbedtls_rsa_export(const mbedtls_rsa_context *ctx,
                       mbedtls_mpi *N, mbedtls_mpi *P, mbedtls_mpi *Q,
                       mbedtls_mpi *D, mbedtls_mpi *E);

int mbedtls_rsa_export_raw(const mbedtls_rsa_context *ctx,
                           unsigned char *N, size_t N_len,
                           unsigned char *P, size_t P_len,
                           unsigned char *Q, size_t Q_len,
                           unsigned char *D, size_t D_len,
                           unsigned char *E, size_t E_len);

int mbedtls_rsa_export_crt(const mbedtls_rsa_context *ctx,
                           mbedtls_mpi *DP, mbedtls_mpi *DQ, mbedtls_mpi *QP);

size_t mbedtls_rsa_get_bitlen(const mbedtls_rsa_context *ctx);

size_t mbedtls_rsa_get_len(const mbedtls_rsa_context *ctx);

int mbedtls_rsa_gen_key(mbedtls_rsa_context *ctx,
                        mbedtls_f_rng_t *f_rng,
                        void *p_rng,
                        unsigned int nbits, int exponent);

int mbedtls_rsa_check_pubkey(const mbedtls_rsa_context *ctx);

int mbedtls_rsa_check_privkey(const mbedtls_rsa_context *ctx);

int mbedtls_rsa_check_pub_priv(const mbedtls_rsa_context *pub,
                               const mbedtls_rsa_context *prv);

int mbedtls_rsa_public(mbedtls_rsa_context *ctx,
                       const unsigned char *input,
                       unsigned char *output);

int mbedtls_rsa_private(mbedtls_rsa_context *ctx,
                        mbedtls_f_rng_t *f_rng,
                        void *p_rng,
                        const unsigned char *input,
                        unsigned char *output);

int mbedtls_rsa_pkcs1_encrypt(mbedtls_rsa_context *ctx,
                              mbedtls_f_rng_t *f_rng,
                              void *p_rng,
                              size_t ilen,
                              const unsigned char *input,
                              unsigned char *output);

int mbedtls_rsa_rsaes_pkcs1_v15_encrypt(mbedtls_rsa_context *ctx,
                                        mbedtls_f_rng_t *f_rng,
                                        void *p_rng,
                                        size_t ilen,
                                        const unsigned char *input,
                                        unsigned char *output);

int mbedtls_rsa_rsaes_oaep_encrypt(mbedtls_rsa_context *ctx,
                                   mbedtls_f_rng_t *f_rng,
                                   void *p_rng,
                                   const unsigned char *label, size_t label_len,
                                   size_t ilen,
                                   const unsigned char *input,
                                   unsigned char *output);

int mbedtls_rsa_pkcs1_decrypt(mbedtls_rsa_context *ctx,
                              mbedtls_f_rng_t *f_rng,
                              void *p_rng,
                              size_t *olen,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t output_max_len);

int mbedtls_rsa_rsaes_pkcs1_v15_decrypt(mbedtls_rsa_context *ctx,
                                        mbedtls_f_rng_t *f_rng,
                                        void *p_rng,
                                        size_t *olen,
                                        const unsigned char *input,
                                        unsigned char *output,
                                        size_t output_max_len);

int mbedtls_rsa_rsaes_oaep_decrypt(mbedtls_rsa_context *ctx,
                                   mbedtls_f_rng_t *f_rng,
                                   void *p_rng,
                                   const unsigned char *label, size_t label_len,
                                   size_t *olen,
                                   const unsigned char *input,
                                   unsigned char *output,
                                   size_t output_max_len);

int mbedtls_rsa_pkcs1_sign(mbedtls_rsa_context *ctx,
                           mbedtls_f_rng_t *f_rng,
                           void *p_rng,
                           mbedtls_md_type_t md_alg,
                           unsigned int hashlen,
                           const unsigned char *hash,
                           unsigned char *sig);

int mbedtls_rsa_rsassa_pkcs1_v15_sign(mbedtls_rsa_context *ctx,
                                      mbedtls_f_rng_t *f_rng,
                                      void *p_rng,
                                      mbedtls_md_type_t md_alg,
                                      unsigned int hashlen,
                                      const unsigned char *hash,
                                      unsigned char *sig);

#if defined(MBEDTLS_PKCS1_V21)

int mbedtls_rsa_rsassa_pss_sign_ext(mbedtls_rsa_context *ctx,
                                    mbedtls_f_rng_t *f_rng,
                                    void *p_rng,
                                    mbedtls_md_type_t md_alg,
                                    unsigned int hashlen,
                                    const unsigned char *hash,
                                    int saltlen,
                                    unsigned char *sig);

int mbedtls_rsa_rsassa_pss_sign(mbedtls_rsa_context *ctx,
                                mbedtls_f_rng_t *f_rng,
                                void *p_rng,
                                mbedtls_md_type_t md_alg,
                                unsigned int hashlen,
                                const unsigned char *hash,
                                unsigned char *sig);
#endif

int mbedtls_rsa_pkcs1_verify(mbedtls_rsa_context *ctx,
                             mbedtls_md_type_t md_alg,
                             unsigned int hashlen,
                             const unsigned char *hash,
                             const unsigned char *sig);

int mbedtls_rsa_rsassa_pkcs1_v15_verify(mbedtls_rsa_context *ctx,
                                        mbedtls_md_type_t md_alg,
                                        unsigned int hashlen,
                                        const unsigned char *hash,
                                        const unsigned char *sig);

int mbedtls_rsa_rsassa_pss_verify(mbedtls_rsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  unsigned int hashlen,
                                  const unsigned char *hash,
                                  const unsigned char *sig);

int mbedtls_rsa_rsassa_pss_verify_ext(mbedtls_rsa_context *ctx,
                                      mbedtls_md_type_t md_alg,
                                      unsigned int hashlen,
                                      const unsigned char *hash,
                                      mbedtls_md_type_t mgf1_hash_id,
                                      int expected_salt_len,
                                      const unsigned char *sig);

int mbedtls_rsa_copy(mbedtls_rsa_context *dst, const mbedtls_rsa_context *src);

void mbedtls_rsa_free(mbedtls_rsa_context *ctx);

#if defined(MBEDTLS_SELF_TEST)

int mbedtls_rsa_self_test(int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif
