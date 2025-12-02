/**
 * \file ecdh.h
 *
 * \brief This file contains ECDH definitions and functions.
 *
 * The Elliptic Curve Diffie-Hellman (ECDH) protocol is an anonymous
 * key agreement protocol allowing two parties to establish a shared
 * secret over an insecure channel. Each party must have an
 * elliptic-curve public–private key pair.
 *
 * For more information, see <em>NIST SP 800-56A Rev. 2: Recommendation for
 * Pair-Wise Key Establishment Schemes Using Discrete Logarithm
 * Cryptography</em>.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ECDH_H
#define MBEDTLS_ECDH_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ecp.h"
#if defined(MBEDTLS_ECP_RESTARTABLE)
#define MBEDTLS_ECDH_LEGACY_CONTEXT 
#else
#undef MBEDTLS_ECDH_LEGACY_CONTEXT
#endif
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
#undef MBEDTLS_ECDH_LEGACY_CONTEXT
#include "everest/everest.h"
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    MBEDTLS_ECDH_OURS,
    MBEDTLS_ECDH_THEIRS,
} mbedtls_ecdh_side;
#if !defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef enum {
    MBEDTLS_ECDH_VARIANT_NONE = 0,
    MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0,
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
    MBEDTLS_ECDH_VARIANT_EVEREST
#endif
} mbedtls_ecdh_variant;
typedef struct mbedtls_ecdh_context_mbed {
    mbedtls_ecp_group MBEDTLS_PRIVATE(grp);
    mbedtls_mpi MBEDTLS_PRIVATE(d);
    mbedtls_ecp_point MBEDTLS_PRIVATE(Q);
    mbedtls_ecp_point MBEDTLS_PRIVATE(Qp);
    mbedtls_mpi MBEDTLS_PRIVATE(z);
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx MBEDTLS_PRIVATE(rs);
#endif
} mbedtls_ecdh_context_mbed;
#endif
typedef struct mbedtls_ecdh_context {
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    mbedtls_ecp_group MBEDTLS_PRIVATE(grp);
    mbedtls_mpi MBEDTLS_PRIVATE(d);
    mbedtls_ecp_point MBEDTLS_PRIVATE(Q);
    mbedtls_ecp_point MBEDTLS_PRIVATE(Qp);
    mbedtls_mpi MBEDTLS_PRIVATE(z);
    int MBEDTLS_PRIVATE(point_format);
    mbedtls_ecp_point MBEDTLS_PRIVATE(Vi);
    mbedtls_ecp_point MBEDTLS_PRIVATE(Vf);
    mbedtls_mpi MBEDTLS_PRIVATE(_d);
#if defined(MBEDTLS_ECP_RESTARTABLE)
    int MBEDTLS_PRIVATE(restart_enabled);
    mbedtls_ecp_restart_ctx MBEDTLS_PRIVATE(rs);
#endif
#else
    uint8_t MBEDTLS_PRIVATE(point_format);
    mbedtls_ecp_group_id MBEDTLS_PRIVATE(grp_id);
    mbedtls_ecdh_variant MBEDTLS_PRIVATE(var);
    union {
        mbedtls_ecdh_context_mbed MBEDTLS_PRIVATE(mbed_ecdh);
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        mbedtls_ecdh_context_everest MBEDTLS_PRIVATE(everest_ecdh);
#endif
    } MBEDTLS_PRIVATE(ctx);
#if defined(MBEDTLS_ECP_RESTARTABLE)
    uint8_t MBEDTLS_PRIVATE(restart_enabled);
#endif
#endif
}
mbedtls_ecdh_context;
mbedtls_ecp_group_id mbedtls_ecdh_get_grp_id(mbedtls_ecdh_context *ctx);
int mbedtls_ecdh_can_do(mbedtls_ecp_group_id gid);
int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng);
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng);
void mbedtls_ecdh_init(mbedtls_ecdh_context *ctx);
int mbedtls_ecdh_setup(mbedtls_ecdh_context *ctx,
                       mbedtls_ecp_group_id grp_id);
void mbedtls_ecdh_free(mbedtls_ecdh_context *ctx);
int mbedtls_ecdh_make_params(mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);
int mbedtls_ecdh_read_params(mbedtls_ecdh_context *ctx,
                             const unsigned char **buf,
                             const unsigned char *end);
int mbedtls_ecdh_get_params(mbedtls_ecdh_context *ctx,
                            const mbedtls_ecp_keypair *key,
                            mbedtls_ecdh_side side);
int mbedtls_ecdh_make_public(mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);
int mbedtls_ecdh_read_public(mbedtls_ecdh_context *ctx,
                             const unsigned char *buf, size_t blen);
int mbedtls_ecdh_calc_secret(mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);
#if defined(MBEDTLS_ECP_RESTARTABLE)
void mbedtls_ecdh_enable_restart(mbedtls_ecdh_context *ctx);
#endif
#ifdef __cplusplus
}
#endif
#endif
