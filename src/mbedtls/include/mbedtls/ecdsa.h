/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_ECDSA_H
#define MBEDTLS_ECDSA_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"

#define MBEDTLS_ECDSA_MAX_SIG_LEN(bits)                               \
    ( ((bits) >= 61 * 8 ? 3 : 2) +              \
      2 * (((bits) >= 127 * 8 ? 3 : 2) +     \
                          ((bits) + 8) / 8))

#define MBEDTLS_ECDSA_MAX_LEN  MBEDTLS_ECDSA_MAX_SIG_LEN(MBEDTLS_ECP_MAX_BITS)

#ifdef __cplusplus
extern "C" {
#endif

typedef mbedtls_ecp_keypair mbedtls_ecdsa_context;

#if defined(MBEDTLS_ECP_RESTARTABLE)

typedef struct mbedtls_ecdsa_restart_ver mbedtls_ecdsa_restart_ver_ctx;

typedef struct mbedtls_ecdsa_restart_sig mbedtls_ecdsa_restart_sig_ctx;

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)

typedef struct mbedtls_ecdsa_restart_det mbedtls_ecdsa_restart_det_ctx;
#endif

typedef struct {
    mbedtls_ecp_restart_ctx MBEDTLS_PRIVATE(ecp);
    mbedtls_ecdsa_restart_ver_ctx *MBEDTLS_PRIVATE(ver);
    mbedtls_ecdsa_restart_sig_ctx *MBEDTLS_PRIVATE(sig);
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    mbedtls_ecdsa_restart_det_ctx *MBEDTLS_PRIVATE(det);
#endif
} mbedtls_ecdsa_restart_ctx;

#else

typedef void mbedtls_ecdsa_restart_ctx;

#endif

int mbedtls_ecdsa_can_do(mbedtls_ecp_group_id gid);

int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       mbedtls_f_rng_t *f_rng, void *p_rng);

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)

int mbedtls_ecdsa_sign_det_ext(mbedtls_ecp_group *grp, mbedtls_mpi *r,
                               mbedtls_mpi *s, const mbedtls_mpi *d,
                               const unsigned char *buf, size_t blen,
                               mbedtls_md_type_t md_alg,
                               mbedtls_f_rng_t *f_rng_blind,
                               void *p_rng_blind);
#endif

#if !defined(MBEDTLS_ECDSA_SIGN_ALT)

int mbedtls_ecdsa_sign_restartable(
    mbedtls_ecp_group *grp,
    mbedtls_mpi *r, mbedtls_mpi *s,
    const mbedtls_mpi *d,
    const unsigned char *buf, size_t blen,
    mbedtls_f_rng_t *f_rng,
    void *p_rng,
    mbedtls_f_rng_t *f_rng_blind,
    void *p_rng_blind,
    mbedtls_ecdsa_restart_ctx *rs_ctx);

#endif

#if defined(MBEDTLS_ECDSA_DETERMINISTIC)

int mbedtls_ecdsa_sign_det_restartable(
    mbedtls_ecp_group *grp,
    mbedtls_mpi *r, mbedtls_mpi *s,
    const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
    mbedtls_md_type_t md_alg,
    mbedtls_f_rng_t *f_rng_blind,
    void *p_rng_blind,
    mbedtls_ecdsa_restart_ctx *rs_ctx);

#endif

int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                         const mbedtls_mpi *s);

#if !defined(MBEDTLS_ECDSA_VERIFY_ALT)

int mbedtls_ecdsa_verify_restartable(mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r,
                                     const mbedtls_mpi *s,
                                     mbedtls_ecdsa_restart_ctx *rs_ctx);

#endif

int mbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  mbedtls_f_rng_t *f_rng,
                                  void *p_rng);

int mbedtls_ecdsa_write_signature_restartable(mbedtls_ecdsa_context *ctx,
                                              mbedtls_md_type_t md_alg,
                                              const unsigned char *hash, size_t hlen,
                                              unsigned char *sig, size_t sig_size, size_t *slen,
                                              mbedtls_f_rng_t *f_rng,
                                              void *p_rng,
                                              mbedtls_ecdsa_restart_ctx *rs_ctx);

int mbedtls_ecdsa_read_signature(mbedtls_ecdsa_context *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen);

int mbedtls_ecdsa_read_signature_restartable(mbedtls_ecdsa_context *ctx,
                                             const unsigned char *hash, size_t hlen,
                                             const unsigned char *sig, size_t slen,
                                             mbedtls_ecdsa_restart_ctx *rs_ctx);

int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                         mbedtls_f_rng_t *f_rng, void *p_rng);

int mbedtls_ecdsa_from_keypair(mbedtls_ecdsa_context *ctx,
                               const mbedtls_ecp_keypair *key);

void mbedtls_ecdsa_init(mbedtls_ecdsa_context *ctx);

void mbedtls_ecdsa_free(mbedtls_ecdsa_context *ctx);

#if defined(MBEDTLS_ECP_RESTARTABLE)

void mbedtls_ecdsa_restart_init(mbedtls_ecdsa_restart_ctx *ctx);

void mbedtls_ecdsa_restart_free(mbedtls_ecdsa_restart_ctx *ctx);
#endif

#ifdef __cplusplus
}
#endif

#endif
