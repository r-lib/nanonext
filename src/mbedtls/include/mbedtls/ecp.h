/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_ECP_H
#define MBEDTLS_ECP_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"

#include "mbedtls/bignum.h"

#define MBEDTLS_ERR_ECP_BAD_INPUT_DATA                    -0x4F80

#define MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL                  -0x4F00

#define MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE               -0x4E80

#define MBEDTLS_ERR_ECP_VERIFY_FAILED                     -0x4E00

#define MBEDTLS_ERR_ECP_ALLOC_FAILED                      -0x4D80

#define MBEDTLS_ERR_ECP_RANDOM_FAILED                     -0x4D00

#define MBEDTLS_ERR_ECP_INVALID_KEY                       -0x4C80

#define MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH                  -0x4C00

#define MBEDTLS_ERR_ECP_IN_PROGRESS                       -0x4B00

#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_BP256R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_BP384R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_BP512R1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) || \
    defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || \
    defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define MBEDTLS_ECP_MONTGOMERY_ENABLED
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_SECP192R1,
    MBEDTLS_ECP_DP_SECP224R1,
    MBEDTLS_ECP_DP_SECP256R1,
    MBEDTLS_ECP_DP_SECP384R1,
    MBEDTLS_ECP_DP_SECP521R1,
    MBEDTLS_ECP_DP_BP256R1,
    MBEDTLS_ECP_DP_BP384R1,
    MBEDTLS_ECP_DP_BP512R1,
    MBEDTLS_ECP_DP_CURVE25519,
    MBEDTLS_ECP_DP_SECP192K1,
    MBEDTLS_ECP_DP_SECP224K1,
    MBEDTLS_ECP_DP_SECP256K1,
    MBEDTLS_ECP_DP_CURVE448,
} mbedtls_ecp_group_id;

#define MBEDTLS_ECP_DP_MAX     14

typedef enum {
    MBEDTLS_ECP_TYPE_NONE = 0,
    MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS,
    MBEDTLS_ECP_TYPE_MONTGOMERY,
} mbedtls_ecp_curve_type;

typedef struct mbedtls_ecp_curve_info {
    mbedtls_ecp_group_id grp_id;
    uint16_t tls_id;
    uint16_t bit_size;
    const char *name;
} mbedtls_ecp_curve_info;

typedef struct mbedtls_ecp_point {
    mbedtls_mpi MBEDTLS_PRIVATE(X);
    mbedtls_mpi MBEDTLS_PRIVATE(Y);
    mbedtls_mpi MBEDTLS_PRIVATE(Z);
}
mbedtls_ecp_point;

#if !defined(MBEDTLS_ECP_ALT)

typedef struct mbedtls_ecp_group {
    mbedtls_ecp_group_id id;
    mbedtls_mpi P;
    mbedtls_mpi A;
    mbedtls_mpi B;
    mbedtls_ecp_point G;
    mbedtls_mpi N;
    size_t pbits;
    size_t nbits;

    unsigned int MBEDTLS_PRIVATE(h);
    int(*MBEDTLS_PRIVATE(modp))(mbedtls_mpi *);
    int(*MBEDTLS_PRIVATE(t_pre))(mbedtls_ecp_point *, void *);
    int(*MBEDTLS_PRIVATE(t_post))(mbedtls_ecp_point *, void *);
    void *MBEDTLS_PRIVATE(t_data);
    mbedtls_ecp_point *MBEDTLS_PRIVATE(T);
    size_t MBEDTLS_PRIVATE(T_size);
}
mbedtls_ecp_group;

#if !defined(MBEDTLS_ECP_WINDOW_SIZE)

#define MBEDTLS_ECP_WINDOW_SIZE    4
#endif

#if !defined(MBEDTLS_ECP_FIXED_POINT_OPTIM)

#define MBEDTLS_ECP_FIXED_POINT_OPTIM  1
#endif

#else
#include "ecp_alt.h"
#endif

#if !defined(MBEDTLS_ECP_LIGHT)

#define MBEDTLS_ECP_MAX_BITS 1

#elif defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 521
#elif defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 512
#elif defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 448
#elif defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 384
#elif defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 384
#elif defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 256
#elif defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 256
#elif defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 256
#elif defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 255
#elif defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 225
#elif defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 224
#elif defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 192
#elif defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
#define MBEDTLS_ECP_MAX_BITS 192
#else
#error "Missing definition of MBEDTLS_ECP_MAX_BITS"
#endif

#define MBEDTLS_ECP_MAX_BYTES    ((MBEDTLS_ECP_MAX_BITS + 7) / 8)
#define MBEDTLS_ECP_MAX_PT_LEN   (2 * MBEDTLS_ECP_MAX_BYTES + 1)

#if defined(MBEDTLS_ECP_RESTARTABLE)

typedef struct mbedtls_ecp_restart_mul mbedtls_ecp_restart_mul_ctx;

typedef struct mbedtls_ecp_restart_muladd mbedtls_ecp_restart_muladd_ctx;

typedef struct {
    unsigned MBEDTLS_PRIVATE(ops_done);
    unsigned MBEDTLS_PRIVATE(depth);
    mbedtls_ecp_restart_mul_ctx *MBEDTLS_PRIVATE(rsm);
    mbedtls_ecp_restart_muladd_ctx *MBEDTLS_PRIVATE(ma);
} mbedtls_ecp_restart_ctx;

#define MBEDTLS_ECP_OPS_CHK   3
#define MBEDTLS_ECP_OPS_DBL   8
#define MBEDTLS_ECP_OPS_ADD  11
#define MBEDTLS_ECP_OPS_INV 120

int mbedtls_ecp_check_budget(const mbedtls_ecp_group *grp,
                             mbedtls_ecp_restart_ctx *rs_ctx,
                             unsigned ops);

#define MBEDTLS_ECP_BUDGET(ops)   \
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_budget(grp, rs_ctx, \
                                             (unsigned) (ops)));

#else

#define MBEDTLS_ECP_BUDGET(ops)

typedef void mbedtls_ecp_restart_ctx;

#endif

typedef struct mbedtls_ecp_keypair {
    mbedtls_ecp_group MBEDTLS_PRIVATE(grp);
    mbedtls_mpi MBEDTLS_PRIVATE(d);
    mbedtls_ecp_point MBEDTLS_PRIVATE(Q);
}
mbedtls_ecp_keypair;

#define MBEDTLS_ECP_PF_UNCOMPRESSED    0

#define MBEDTLS_ECP_PF_COMPRESSED      1

#define MBEDTLS_ECP_TLS_NAMED_CURVE    3

#if defined(MBEDTLS_ECP_RESTARTABLE)

void mbedtls_ecp_set_max_ops(unsigned max_ops);

int mbedtls_ecp_restart_is_enabled(void);
#endif

mbedtls_ecp_curve_type mbedtls_ecp_get_type(const mbedtls_ecp_group *grp);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_list(void);

const mbedtls_ecp_group_id *mbedtls_ecp_grp_id_list(void);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_grp_id(mbedtls_ecp_group_id grp_id);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_tls_id(uint16_t tls_id);

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_name(const char *name);

void mbedtls_ecp_point_init(mbedtls_ecp_point *pt);

void mbedtls_ecp_group_init(mbedtls_ecp_group *grp);

void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key);

void mbedtls_ecp_point_free(mbedtls_ecp_point *pt);

void mbedtls_ecp_group_free(mbedtls_ecp_group *grp);

void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key);

#if defined(MBEDTLS_ECP_RESTARTABLE)

void mbedtls_ecp_restart_init(mbedtls_ecp_restart_ctx *ctx);

void mbedtls_ecp_restart_free(mbedtls_ecp_restart_ctx *ctx);
#endif

int mbedtls_ecp_copy(mbedtls_ecp_point *P, const mbedtls_ecp_point *Q);

int mbedtls_ecp_group_copy(mbedtls_ecp_group *dst,
                           const mbedtls_ecp_group *src);

int mbedtls_ecp_set_zero(mbedtls_ecp_point *pt);

int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt);

int mbedtls_ecp_point_cmp(const mbedtls_ecp_point *P,
                          const mbedtls_ecp_point *Q);

int mbedtls_ecp_point_read_string(mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y);

int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen);

int mbedtls_ecp_point_read_binary(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *P,
                                  const unsigned char *buf, size_t ilen);

int mbedtls_ecp_tls_read_point(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *pt,
                               const unsigned char **buf, size_t len);

int mbedtls_ecp_tls_write_point(const mbedtls_ecp_group *grp,
                                const mbedtls_ecp_point *pt,
                                int format, size_t *olen,
                                unsigned char *buf, size_t blen);

int mbedtls_ecp_group_load(mbedtls_ecp_group *grp, mbedtls_ecp_group_id id);

int mbedtls_ecp_tls_read_group(mbedtls_ecp_group *grp,
                               const unsigned char **buf, size_t len);

int mbedtls_ecp_tls_read_group_id(mbedtls_ecp_group_id *grp,
                                  const unsigned char **buf,
                                  size_t len);

int mbedtls_ecp_tls_write_group(const mbedtls_ecp_group *grp,
                                size_t *olen,
                                unsigned char *buf, size_t blen);

int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                    mbedtls_f_rng_t *f_rng, void *p_rng);

int mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                mbedtls_f_rng_t *f_rng, void *p_rng,
                                mbedtls_ecp_restart_ctx *rs_ctx);

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

static inline int mbedtls_ecp_group_a_is_minus_3(const mbedtls_ecp_group *grp)
{
    return grp->A.MBEDTLS_PRIVATE(p) == NULL;
}

int mbedtls_ecp_muladd(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                       const mbedtls_mpi *n, const mbedtls_ecp_point *Q);

int mbedtls_ecp_muladd_restartable(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    mbedtls_ecp_restart_ctx *rs_ctx);
#endif

int mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp,
                             const mbedtls_ecp_point *pt);

int mbedtls_ecp_check_privkey(const mbedtls_ecp_group *grp,
                              const mbedtls_mpi *d);

int mbedtls_ecp_gen_privkey(const mbedtls_ecp_group *grp,
                            mbedtls_mpi *d,
                            mbedtls_f_rng_t *f_rng,
                            void *p_rng);

int mbedtls_ecp_gen_keypair_base(mbedtls_ecp_group *grp,
                                 const mbedtls_ecp_point *G,
                                 mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                 mbedtls_f_rng_t *f_rng,
                                 void *p_rng);

int mbedtls_ecp_gen_keypair(mbedtls_ecp_group *grp, mbedtls_mpi *d,
                            mbedtls_ecp_point *Q,
                            mbedtls_f_rng_t *f_rng,
                            void *p_rng);

int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                        mbedtls_f_rng_t *f_rng,
                        void *p_rng);

int mbedtls_ecp_set_public_key(mbedtls_ecp_group_id grp_id,
                               mbedtls_ecp_keypair *key,
                               const mbedtls_ecp_point *Q);

int mbedtls_ecp_read_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                         const unsigned char *buf, size_t buflen);

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

int MBEDTLS_DEPRECATED mbedtls_ecp_write_key(mbedtls_ecp_keypair *key,
                                             unsigned char *buf, size_t buflen);
#endif

int mbedtls_ecp_write_key_ext(const mbedtls_ecp_keypair *key,
                              size_t *olen, unsigned char *buf, size_t buflen);

int mbedtls_ecp_write_public_key(const mbedtls_ecp_keypair *key,
                                 int format, size_t *olen,
                                 unsigned char *buf, size_t buflen);

int mbedtls_ecp_check_pub_priv(
    const mbedtls_ecp_keypair *pub, const mbedtls_ecp_keypair *prv,
    mbedtls_f_rng_t *f_rng, void *p_rng);

int mbedtls_ecp_keypair_calc_public(
    mbedtls_ecp_keypair *key,
    mbedtls_f_rng_t *f_rng, void *p_rng);

mbedtls_ecp_group_id mbedtls_ecp_keypair_get_group_id(
    const mbedtls_ecp_keypair *key);

int mbedtls_ecp_export(const mbedtls_ecp_keypair *key, mbedtls_ecp_group *grp,
                       mbedtls_mpi *d, mbedtls_ecp_point *Q);

#if defined(MBEDTLS_SELF_TEST)

int mbedtls_ecp_self_test(int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif
