/*
 *  Elliptic curves over GF(p): generic functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
#endif

#if defined(MBEDTLS_ECP_LIGHT)

#include "mbedtls/ecp.h"
#include "mbedtls/threading.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include "bn_mul.h"
#include "bignum_internal.h"
#include "ecp_invasive.h"

#include <string.h>

#if !defined(MBEDTLS_ECP_ALT)

#include "mbedtls/platform.h"

#include "ecp_internal_alt.h"

#if defined(MBEDTLS_SELF_TEST)

#if defined(MBEDTLS_ECP_C)
static unsigned long add_count, dbl_count;
#endif
static unsigned long mul_count;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)

static unsigned ecp_max_ops = 0;

void mbedtls_ecp_set_max_ops(unsigned max_ops)
{
    ecp_max_ops = max_ops;
}

int mbedtls_ecp_restart_is_enabled(void)
{
    return ecp_max_ops != 0;
}

struct mbedtls_ecp_restart_mul {
    mbedtls_ecp_point R;
    size_t i;
    mbedtls_ecp_point *T;
    unsigned char T_size;
    enum {
        ecp_rsm_init = 0,
        ecp_rsm_pre_dbl,
        ecp_rsm_pre_norm_dbl,
        ecp_rsm_pre_add,
        ecp_rsm_pre_norm_add,
        ecp_rsm_comb_core,
        ecp_rsm_final_norm,
    } state;
};

static void ecp_restart_rsm_init(mbedtls_ecp_restart_mul_ctx *ctx)
{
    mbedtls_ecp_point_init(&ctx->R);
    ctx->i = 0;
    ctx->T = NULL;
    ctx->T_size = 0;
    ctx->state = ecp_rsm_init;
}

static void ecp_restart_rsm_free(mbedtls_ecp_restart_mul_ctx *ctx)
{
    unsigned char i;

    if (ctx == NULL) {
        return;
    }

    mbedtls_ecp_point_free(&ctx->R);

    if (ctx->T != NULL) {
        for (i = 0; i < ctx->T_size; i++) {
            mbedtls_ecp_point_free(ctx->T + i);
        }
        mbedtls_free(ctx->T);
    }

    ecp_restart_rsm_init(ctx);
}

struct mbedtls_ecp_restart_muladd {
    mbedtls_ecp_point mP;
    mbedtls_ecp_point R;
    enum {
        ecp_rsma_mul1 = 0,
        ecp_rsma_mul2,
        ecp_rsma_add,
        ecp_rsma_norm,
    } state;
};

static void ecp_restart_ma_init(mbedtls_ecp_restart_muladd_ctx *ctx)
{
    mbedtls_ecp_point_init(&ctx->mP);
    mbedtls_ecp_point_init(&ctx->R);
    ctx->state = ecp_rsma_mul1;
}

static void ecp_restart_ma_free(mbedtls_ecp_restart_muladd_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    mbedtls_ecp_point_free(&ctx->mP);
    mbedtls_ecp_point_free(&ctx->R);

    ecp_restart_ma_init(ctx);
}

void mbedtls_ecp_restart_init(mbedtls_ecp_restart_ctx *ctx)
{
    ctx->ops_done = 0;
    ctx->depth = 0;
    ctx->rsm = NULL;
    ctx->ma = NULL;
}

void mbedtls_ecp_restart_free(mbedtls_ecp_restart_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    ecp_restart_rsm_free(ctx->rsm);
    mbedtls_free(ctx->rsm);

    ecp_restart_ma_free(ctx->ma);
    mbedtls_free(ctx->ma);

    mbedtls_ecp_restart_init(ctx);
}

int mbedtls_ecp_check_budget(const mbedtls_ecp_group *grp,
                             mbedtls_ecp_restart_ctx *rs_ctx,
                             unsigned ops)
{
    if (rs_ctx != NULL && ecp_max_ops != 0) {

        if (grp->pbits >= 512) {
            ops *= 4;
        } else if (grp->pbits >= 384) {
            ops *= 2;
        }

        if ((rs_ctx->ops_done != 0) &&
            (rs_ctx->ops_done > ecp_max_ops ||
             ops > ecp_max_ops - rs_ctx->ops_done)) {
            return MBEDTLS_ERR_ECP_IN_PROGRESS;
        }

        rs_ctx->ops_done += ops;
    }

    return 0;
}

#define ECP_RS_ENTER(SUB)   do {                                      \
                            \
        if (rs_ctx != NULL && rs_ctx->depth++ == 0)                        \
        rs_ctx->ops_done = 0;                                           \
                                                                        \
                                  \
        if (mbedtls_ecp_restart_is_enabled() &&                             \
            rs_ctx != NULL && rs_ctx->SUB == NULL)                         \
        {                                                                   \
            rs_ctx->SUB = mbedtls_calloc(1, sizeof(*rs_ctx->SUB));      \
            if (rs_ctx->SUB == NULL)                                       \
            return MBEDTLS_ERR_ECP_ALLOC_FAILED;                     \
                                                                      \
            ecp_restart_## SUB ##_init(rs_ctx->SUB);                      \
        }                                                                   \
} while (0)

#define ECP_RS_LEAVE(SUB)   do {                                      \
            \
        if (rs_ctx != NULL && rs_ctx->SUB != NULL &&                        \
            ret != MBEDTLS_ERR_ECP_IN_PROGRESS)                            \
        {                                                                   \
            ecp_restart_## SUB ##_free(rs_ctx->SUB);                      \
            mbedtls_free(rs_ctx->SUB);                                    \
            rs_ctx->SUB = NULL;                                             \
        }                                                                   \
                                                                        \
        if (rs_ctx != NULL)                                                \
        rs_ctx->depth--;                                                \
} while (0)

#else

#define ECP_RS_ENTER(sub)     (void) rs_ctx;
#define ECP_RS_LEAVE(sub)     (void) rs_ctx;

#endif

#if defined(MBEDTLS_ECP_C)
static void mpi_init_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_init(arr++);
    }
}

static void mpi_free_many(mbedtls_mpi *arr, size_t size)
{
    while (size--) {
        mbedtls_mpi_free(arr++);
    }
}
#endif

static const mbedtls_ecp_curve_info ecp_supported_curves[] =
{
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP521R1,    25,     521,    "secp521r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    { MBEDTLS_ECP_DP_BP512R1,      28,     512,    "brainpoolP512r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP384R1,    24,     384,    "secp384r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    { MBEDTLS_ECP_DP_BP384R1,      27,     384,    "brainpoolP384r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP256R1,    23,     256,    "secp256r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP256K1,    22,     256,    "secp256k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    { MBEDTLS_ECP_DP_BP256R1,      26,     256,    "brainpoolP256r1"   },
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP224R1,    21,     224,    "secp224r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP224K1,    20,     224,    "secp224k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    { MBEDTLS_ECP_DP_SECP192R1,    19,     192,    "secp192r1"         },
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
    { MBEDTLS_ECP_DP_SECP192K1,    18,     192,    "secp192k1"         },
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    { MBEDTLS_ECP_DP_CURVE25519,   29,     256,    "x25519"            },
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
    { MBEDTLS_ECP_DP_CURVE448,     30,     448,    "x448"              },
#endif
    { MBEDTLS_ECP_DP_NONE,          0,     0,      NULL                },
};

#define ECP_NB_CURVES   sizeof(ecp_supported_curves) /    \
    sizeof(ecp_supported_curves[0])

static mbedtls_ecp_group_id ecp_supported_grp_id[ECP_NB_CURVES];

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_list(void)
{
    return ecp_supported_curves;
}

const mbedtls_ecp_group_id *mbedtls_ecp_grp_id_list(void)
{
    static int init_done = 0;

    if (!init_done) {
        size_t i = 0;
        const mbedtls_ecp_curve_info *curve_info;

        for (curve_info = mbedtls_ecp_curve_list();
             curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
             curve_info++) {
            ecp_supported_grp_id[i++] = curve_info->grp_id;
        }
        ecp_supported_grp_id[i] = MBEDTLS_ECP_DP_NONE;

        init_done = 1;
    }

    return ecp_supported_grp_id;
}

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_grp_id(mbedtls_ecp_group_id grp_id)
{
    const mbedtls_ecp_curve_info *curve_info;

    for (curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (curve_info->grp_id == grp_id) {
            return curve_info;
        }
    }

    return NULL;
}

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_tls_id(uint16_t tls_id)
{
    const mbedtls_ecp_curve_info *curve_info;

    for (curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (curve_info->tls_id == tls_id) {
            return curve_info;
        }
    }

    return NULL;
}

const mbedtls_ecp_curve_info *mbedtls_ecp_curve_info_from_name(const char *name)
{
    const mbedtls_ecp_curve_info *curve_info;

    if (name == NULL) {
        return NULL;
    }

    for (curve_info = mbedtls_ecp_curve_list();
         curve_info->grp_id != MBEDTLS_ECP_DP_NONE;
         curve_info++) {
        if (strcmp(curve_info->name, name) == 0) {
            return curve_info;
        }
    }

    return NULL;
}

mbedtls_ecp_curve_type mbedtls_ecp_get_type(const mbedtls_ecp_group *grp)
{
    if (grp->G.X.p == NULL) {
        return MBEDTLS_ECP_TYPE_NONE;
    }

    if (grp->G.Y.p == NULL) {
        return MBEDTLS_ECP_TYPE_MONTGOMERY;
    } else {
        return MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS;
    }
}

void mbedtls_ecp_point_init(mbedtls_ecp_point *pt)
{
    mbedtls_mpi_init(&pt->X);
    mbedtls_mpi_init(&pt->Y);
    mbedtls_mpi_init(&pt->Z);
}

void mbedtls_ecp_group_init(mbedtls_ecp_group *grp)
{
    grp->id = MBEDTLS_ECP_DP_NONE;
    mbedtls_mpi_init(&grp->P);
    mbedtls_mpi_init(&grp->A);
    mbedtls_mpi_init(&grp->B);
    mbedtls_ecp_point_init(&grp->G);
    mbedtls_mpi_init(&grp->N);
    grp->pbits = 0;
    grp->nbits = 0;
    grp->h = 0;
    grp->modp = NULL;
    grp->t_pre = NULL;
    grp->t_post = NULL;
    grp->t_data = NULL;
    grp->T = NULL;
    grp->T_size = 0;
}

void mbedtls_ecp_keypair_init(mbedtls_ecp_keypair *key)
{
    mbedtls_ecp_group_init(&key->grp);
    mbedtls_mpi_init(&key->d);
    mbedtls_ecp_point_init(&key->Q);
}

void mbedtls_ecp_point_free(mbedtls_ecp_point *pt)
{
    if (pt == NULL) {
        return;
    }

    mbedtls_mpi_free(&(pt->X));
    mbedtls_mpi_free(&(pt->Y));
    mbedtls_mpi_free(&(pt->Z));
}

static int ecp_group_is_static_comb_table(const mbedtls_ecp_group *grp)
{
#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
    return grp->T != NULL && grp->T_size == 0;
#else
    (void) grp;
    return 0;
#endif
}

void mbedtls_ecp_group_free(mbedtls_ecp_group *grp)
{
    size_t i;

    if (grp == NULL) {
        return;
    }

    if (grp->h != 1) {
        mbedtls_mpi_free(&grp->A);
        mbedtls_mpi_free(&grp->B);
        mbedtls_ecp_point_free(&grp->G);

#if !defined(MBEDTLS_ECP_WITH_MPI_UINT)
        mbedtls_mpi_free(&grp->N);
        mbedtls_mpi_free(&grp->P);
#endif
    }

    if (!ecp_group_is_static_comb_table(grp) && grp->T != NULL) {
        for (i = 0; i < grp->T_size; i++) {
            mbedtls_ecp_point_free(&grp->T[i]);
        }
        mbedtls_free(grp->T);
    }

    mbedtls_platform_zeroize(grp, sizeof(mbedtls_ecp_group));
}

void mbedtls_ecp_keypair_free(mbedtls_ecp_keypair *key)
{
    if (key == NULL) {
        return;
    }

    mbedtls_ecp_group_free(&key->grp);
    mbedtls_mpi_free(&key->d);
    mbedtls_ecp_point_free(&key->Q);
}

int mbedtls_ecp_copy(mbedtls_ecp_point *P, const mbedtls_ecp_point *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->X, &Q->X));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->Y, &Q->Y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&P->Z, &Q->Z));

cleanup:
    return ret;
}

int mbedtls_ecp_group_copy(mbedtls_ecp_group *dst, const mbedtls_ecp_group *src)
{
    return mbedtls_ecp_group_load(dst, src->id);
}

int mbedtls_ecp_set_zero(mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->X, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Y, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 0));

cleanup:
    return ret;
}

int mbedtls_ecp_is_zero(mbedtls_ecp_point *pt)
{
    return mbedtls_mpi_cmp_int(&pt->Z, 0) == 0;
}

int mbedtls_ecp_point_cmp(const mbedtls_ecp_point *P,
                          const mbedtls_ecp_point *Q)
{
    if (mbedtls_mpi_cmp_mpi(&P->X, &Q->X) == 0 &&
        mbedtls_mpi_cmp_mpi(&P->Y, &Q->Y) == 0 &&
        mbedtls_mpi_cmp_mpi(&P->Z, &Q->Z) == 0) {
        return 0;
    }

    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

int mbedtls_ecp_point_read_string(mbedtls_ecp_point *P, int radix,
                                  const char *x, const char *y)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->X, radix, x));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&P->Y, radix, y));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&P->Z, 1));

cleanup:
    return ret;
}

int mbedtls_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    if (format != MBEDTLS_ECP_PF_UNCOMPRESSED &&
        format != MBEDTLS_ECP_PF_COMPRESSED) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    plen = mbedtls_mpi_size(&grp->P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    (void) format;
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        *olen = plen;
        if (buflen < *olen) {
            return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&P->X, buf, plen));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {

        if (mbedtls_mpi_cmp_int(&P->Z, 0) == 0) {
            if (buflen < 1) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x00;
            *olen = 1;

            return 0;
        }

        if (format == MBEDTLS_ECP_PF_UNCOMPRESSED) {
            *olen = 2 * plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x04;
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->Y, buf + 1 + plen, plen));
        } else if (format == MBEDTLS_ECP_PF_COMPRESSED) {
            *olen = plen + 1;

            if (buflen < *olen) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

            buf[0] = 0x02 + mbedtls_mpi_get_bit(&P->Y, 0);
            MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&P->X, buf + 1, plen));
        }
    }
#endif

cleanup:
    return ret;
}

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
static int mbedtls_ecp_sw_derive_y(const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *X,
                                   mbedtls_mpi *Y,
                                   int parity_bit);
#endif

int mbedtls_ecp_point_read_binary(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *pt,
                                  const unsigned char *buf, size_t ilen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    if (ilen < 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    plen = mbedtls_mpi_size(&grp->P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        if (plen != ilen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&pt->X, buf, plen));
        mbedtls_mpi_free(&pt->Y);

        if (grp->id == MBEDTLS_ECP_DP_CURVE25519) {

            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&pt->X, plen * 8 - 1, 0));
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        if (buf[0] == 0x00) {
            if (ilen == 1) {
                return mbedtls_ecp_set_zero(pt);
            } else {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
        }

        if (ilen < 1 + plen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&pt->X, buf + 1, plen));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));

        if (buf[0] == 0x04) {

            if (ilen != 1 + plen * 2) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_mpi_read_binary(&pt->Y, buf + 1 + plen, plen);
        } else if (buf[0] == 0x02 || buf[0] == 0x03) {

            if (ilen != 1 + plen) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_ecp_sw_derive_y(grp, &pt->X, &pt->Y,
                                           (buf[0] & 1));
        } else {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }
#endif

cleanup:
    return ret;
}

int mbedtls_ecp_tls_read_point(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *pt,
                               const unsigned char **buf, size_t buf_len)
{
    unsigned char data_len;
    const unsigned char *buf_start;

    if (buf_len < 2) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    data_len = *(*buf)++;
    if (data_len < 1 || data_len > buf_len - 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    buf_start = *buf;
    *buf += data_len;

    return mbedtls_ecp_point_read_binary(grp, pt, buf_start, data_len);
}

int mbedtls_ecp_tls_write_point(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt,
                                int format, size_t *olen,
                                unsigned char *buf, size_t blen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (format != MBEDTLS_ECP_PF_UNCOMPRESSED &&
        format != MBEDTLS_ECP_PF_COMPRESSED) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (blen < 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ((ret = mbedtls_ecp_point_write_binary(grp, pt, format,
                                              olen, buf + 1, blen - 1)) != 0) {
        return ret;
    }

    buf[0] = (unsigned char) *olen;
    ++*olen;

    return 0;
}

int mbedtls_ecp_tls_read_group(mbedtls_ecp_group *grp,
                               const unsigned char **buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group_id grp_id;
    if ((ret = mbedtls_ecp_tls_read_group_id(&grp_id, buf, len)) != 0) {
        return ret;
    }

    return mbedtls_ecp_group_load(grp, grp_id);
}

int mbedtls_ecp_tls_read_group_id(mbedtls_ecp_group_id *grp,
                                  const unsigned char **buf, size_t len)
{
    uint16_t tls_id;
    const mbedtls_ecp_curve_info *curve_info;

    if (len < 3) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (*(*buf)++ != MBEDTLS_ECP_TLS_NAMED_CURVE) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    tls_id = MBEDTLS_GET_UINT16_BE(*buf, 0);
    *buf += 2;

    if ((curve_info = mbedtls_ecp_curve_info_from_tls_id(tls_id)) == NULL) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    *grp = curve_info->grp_id;

    return 0;
}

int mbedtls_ecp_tls_write_group(const mbedtls_ecp_group *grp, size_t *olen,
                                unsigned char *buf, size_t blen)
{
    const mbedtls_ecp_curve_info *curve_info;
    if ((curve_info = mbedtls_ecp_curve_info_from_grp_id(grp->id)) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    *olen = 3;
    if (blen < *olen) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }

    *buf++ = MBEDTLS_ECP_TLS_NAMED_CURVE;

    MBEDTLS_PUT_UINT16_BE(curve_info->tls_id, buf, 0);

    return 0;
}

static int ecp_modp(mbedtls_mpi *N, const mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (grp->modp == NULL) {
        return mbedtls_mpi_mod_mpi(N, N, &grp->P);
    }

    if ((N->s < 0 && mbedtls_mpi_cmp_int(N, 0) != 0) ||
        mbedtls_mpi_bitlen(N) > 2 * grp->pbits) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MBEDTLS_MPI_CHK(grp->modp(N));

    while (N->s < 0 && mbedtls_mpi_cmp_int(N, 0) != 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(N, N, &grp->P));
    }

    while (mbedtls_mpi_cmp_mpi(N, &grp->P) >= 0) {

        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs(N, N, &grp->P));
    }

cleanup:
    return ret;
}

#if defined(MBEDTLS_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

#define MOD_MUL(N)                                                    \
    do                                                                  \
    {                                                                   \
        MBEDTLS_MPI_CHK(ecp_modp(&(N), grp));                       \
        INC_MUL_COUNT                                                   \
    } while (0)

static inline int mbedtls_mpi_mul_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(X, A, B));
    MOD_MUL(*X);
cleanup:
    return ret;
}

#define MOD_SUB(N)                                                          \
    do {                                                                      \
        while ((N)->s < 0 && mbedtls_mpi_cmp_int((N), 0) != 0)             \
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi((N), (N), &grp->P));      \
    } while (0)

MBEDTLS_MAYBE_UNUSED
static inline int mbedtls_mpi_sub_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(X, A, B));
    MOD_SUB(X);
cleanup:
    return ret;
}

#define MOD_ADD(N)                                                   \
    while (mbedtls_mpi_cmp_mpi((N), &grp->P) >= 0)                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs((N), (N), &grp->P))

static inline int mbedtls_mpi_add_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(X, A, B));
    MOD_ADD(X);
cleanup:
    return ret;
}

MBEDTLS_MAYBE_UNUSED
static inline int mbedtls_mpi_mul_int_mod(const mbedtls_ecp_group *grp,
                                          mbedtls_mpi *X,
                                          const mbedtls_mpi *A,
                                          mbedtls_mpi_uint c)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(X, A, c));
    MOD_ADD(X);
cleanup:
    return ret;
}

MBEDTLS_MAYBE_UNUSED
static inline int mbedtls_mpi_sub_int_mod(const mbedtls_ecp_group *grp,
                                          mbedtls_mpi *X,
                                          const mbedtls_mpi *A,
                                          mbedtls_mpi_uint c)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(X, A, c));
    MOD_SUB(X);
cleanup:
    return ret;
}

#define MPI_ECP_SUB_INT(X, A, c)             \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int_mod(grp, X, A, c))

MBEDTLS_MAYBE_UNUSED
static inline int mbedtls_mpi_shift_l_mod(const mbedtls_ecp_group *grp,
                                          mbedtls_mpi *X,
                                          size_t count)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(X, count));
    MOD_ADD(X);
cleanup:
    return ret;
}

#define MPI_ECP_ADD(X, A, B)                                                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mod(grp, X, A, B))

#define MPI_ECP_SUB(X, A, B)                                                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mod(grp, X, A, B))

#define MPI_ECP_MUL(X, A, B)                                                  \
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mod(grp, X, A, B))

#define MPI_ECP_SQR(X, A)                                                     \
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mod(grp, X, A, A))

#define MPI_ECP_MUL_INT(X, A, c)                                              \
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int_mod(grp, X, A, c))

#define MPI_ECP_INV(dst, src)                                                 \
    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(NULL, (dst), (src), &grp->P))

#define MPI_ECP_MOV(X, A)                                                     \
    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X, A))

#define MPI_ECP_SHIFT_L(X, count)                                             \
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l_mod(grp, X, count))

#define MPI_ECP_LSET(X, c)                                                    \
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(X, c))

#define MPI_ECP_CMP_INT(X, c)                                                 \
    mbedtls_mpi_cmp_int(X, c)

#define MPI_ECP_CMP(X, Y)                                                     \
    mbedtls_mpi_cmp_mpi(X, Y)

#define MPI_ECP_RAND(X)                                                       \
    MBEDTLS_MPI_CHK(mbedtls_mpi_random((X), 2, &grp->P, f_rng, p_rng))

#define MPI_ECP_COND_NEG(X, cond)                                        \
    do                                                                     \
    {                                                                      \
        unsigned char nonzero = mbedtls_mpi_cmp_int((X), 0) != 0;        \
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&tmp, &grp->P, (X)));      \
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign((X), &tmp,          \
                                                     nonzero & cond)); \
    } while (0)

#define MPI_ECP_NEG(X) MPI_ECP_COND_NEG((X), 1)

#define MPI_ECP_VALID(X)                      \
    ((X)->p != NULL)

#define MPI_ECP_COND_ASSIGN(X, Y, cond)       \
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign((X), (Y), (cond)))

#define MPI_ECP_COND_SWAP(X, Y, cond)       \
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap((X), (Y), (cond)))

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

static int ecp_sw_rhs(const mbedtls_ecp_group *grp,
                      mbedtls_mpi *rhs,
                      const mbedtls_mpi *X)
{
    int ret;

    MPI_ECP_SQR(rhs, X);

    if (mbedtls_ecp_group_a_is_minus_3(grp)) {
        MPI_ECP_SUB_INT(rhs, rhs, 3);
    } else {
        MPI_ECP_ADD(rhs, rhs, &grp->A);
    }

    MPI_ECP_MUL(rhs, rhs, X);
    MPI_ECP_ADD(rhs, rhs, &grp->B);

cleanup:
    return ret;
}

static int mbedtls_ecp_sw_derive_y(const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *X,
                                   mbedtls_mpi *Y,
                                   int parity_bit)
{

    if (mbedtls_mpi_get_bit(&grp->P, 0) != 1 ||
        mbedtls_mpi_get_bit(&grp->P, 1) != 1) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    int ret;
    mbedtls_mpi exp;
    mbedtls_mpi_init(&exp);

    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, Y, X));

    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&exp, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&exp, 2));

    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(Y, Y , &exp, &grp->P, NULL));

    if (mbedtls_mpi_get_bit(Y, 0) != parity_bit) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(Y, &grp->P, Y));
    }

cleanup:

    mbedtls_mpi_free(&exp);
    return ret;
}
#endif

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

static int ecp_normalize_jac(const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt)
{
    if (MPI_ECP_CMP_INT(&pt->Z, 0) == 0) {
        return 0;
    }

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_normalize_jac(grp, pt);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi T;
    mbedtls_mpi_init(&T);

    MPI_ECP_INV(&T,       &pt->Z);
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &T);
    MPI_ECP_SQR(&T,       &T);
    MPI_ECP_MUL(&pt->X,   &pt->X,     &T);
    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &T);

    MPI_ECP_LSET(&pt->Z, 1);

cleanup:

    mbedtls_mpi_free(&T);

    return ret;
#endif
}

static int ecp_normalize_jac_many(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *T[], size_t T_size)
{
    if (T_size < 2) {
        return ecp_normalize_jac(grp, *T);
    }

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_normalize_jac_many(grp, T, T_size);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    mbedtls_mpi *c, t;

    if ((c = mbedtls_calloc(T_size, sizeof(mbedtls_mpi))) == NULL) {
        return MBEDTLS_ERR_ECP_ALLOC_FAILED;
    }

    mbedtls_mpi_init(&t);

    mpi_init_many(c, T_size);

    MPI_ECP_MOV(&c[0], &T[0]->Z);
    for (i = 1; i < T_size; i++) {
        MPI_ECP_MUL(&c[i], &c[i-1], &T[i]->Z);
    }

    MPI_ECP_INV(&c[T_size-1], &c[T_size-1]);

    for (i = T_size - 1;; i--) {

        if (i > 0) {

            MPI_ECP_MUL(&t,      &c[i], &c[i-1]);
            MPI_ECP_MUL(&c[i-1], &c[i], &T[i]->Z);
        } else {
            MPI_ECP_MOV(&t, &c[0]);
        }

        MPI_ECP_MUL(&T[i]->Y, &T[i]->Y, &t);
        MPI_ECP_SQR(&t,       &t);
        MPI_ECP_MUL(&T[i]->X, &T[i]->X, &t);
        MPI_ECP_MUL(&T[i]->Y, &T[i]->Y, &t);

        MBEDTLS_MPI_CHK(mbedtls_mpi_shrink(&T[i]->X, grp->P.n));
        MBEDTLS_MPI_CHK(mbedtls_mpi_shrink(&T[i]->Y, grp->P.n));

        MPI_ECP_LSET(&T[i]->Z, 1);

        if (i == 0) {
            break;
        }
    }

cleanup:

    mbedtls_mpi_free(&t);
    mpi_free_many(c, T_size);
    mbedtls_free(c);

    return ret;
#endif
}

static int ecp_safe_invert_jac(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point *Q,
                               unsigned char inv)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    MPI_ECP_COND_NEG(&Q->Y, inv);

cleanup:
    mbedtls_mpi_free(&tmp);
    return ret;
}

static int ecp_double_jac(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                          const mbedtls_ecp_point *P,
                          mbedtls_mpi tmp[4])
{
#if defined(MBEDTLS_SELF_TEST)
    dbl_count++;
#endif

#if defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_double_jac(grp, R, P);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (mbedtls_ecp_group_a_is_minus_3(grp)) {

        MPI_ECP_SQR(&tmp[1],  &P->Z);
        MPI_ECP_ADD(&tmp[2],  &P->X,  &tmp[1]);
        MPI_ECP_SUB(&tmp[3],  &P->X,  &tmp[1]);
        MPI_ECP_MUL(&tmp[1],  &tmp[2],     &tmp[3]);
        MPI_ECP_MUL_INT(&tmp[0],  &tmp[1],     3);
    } else {

        MPI_ECP_SQR(&tmp[1],  &P->X);
        MPI_ECP_MUL_INT(&tmp[0],  &tmp[1],  3);

        if (MPI_ECP_CMP_INT(&grp->A, 0) != 0) {

            MPI_ECP_SQR(&tmp[1],  &P->Z);
            MPI_ECP_SQR(&tmp[2],  &tmp[1]);
            MPI_ECP_MUL(&tmp[1],  &tmp[2],     &grp->A);
            MPI_ECP_ADD(&tmp[0],  &tmp[0],     &tmp[1]);
        }
    }

    MPI_ECP_SQR(&tmp[2],  &P->Y);
    MPI_ECP_SHIFT_L(&tmp[2],  1);
    MPI_ECP_MUL(&tmp[1],  &P->X, &tmp[2]);
    MPI_ECP_SHIFT_L(&tmp[1],  1);

    MPI_ECP_SQR(&tmp[3],  &tmp[2]);
    MPI_ECP_SHIFT_L(&tmp[3],  1);

    MPI_ECP_SQR(&tmp[2],  &tmp[0]);
    MPI_ECP_SUB(&tmp[2],  &tmp[2], &tmp[1]);
    MPI_ECP_SUB(&tmp[2],  &tmp[2], &tmp[1]);

    MPI_ECP_SUB(&tmp[1],  &tmp[1],     &tmp[2]);
    MPI_ECP_MUL(&tmp[1],  &tmp[1],     &tmp[0]);
    MPI_ECP_SUB(&tmp[1],  &tmp[1],     &tmp[3]);

    MPI_ECP_MUL(&tmp[3],  &P->Y,  &P->Z);
    MPI_ECP_SHIFT_L(&tmp[3],  1);

    MPI_ECP_MOV(&R->X, &tmp[2]);
    MPI_ECP_MOV(&R->Y, &tmp[1]);
    MPI_ECP_MOV(&R->Z, &tmp[3]);

cleanup:

    return ret;
#endif
}

static int ecp_add_mixed(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q,
                         mbedtls_mpi tmp[4])
{
#if defined(MBEDTLS_SELF_TEST)
    add_count++;
#endif

#if defined(MBEDTLS_ECP_ADD_MIXED_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_add_mixed(grp, R, P, Q);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_ADD_MIXED_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_mpi * const X = &R->X;
    mbedtls_mpi * const Y = &R->Y;
    mbedtls_mpi * const Z = &R->Z;

    if (!MPI_ECP_VALID(&Q->Z)) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (MPI_ECP_CMP_INT(&P->Z, 0) == 0) {
        return mbedtls_ecp_copy(R, Q);
    }

    if (MPI_ECP_CMP_INT(&Q->Z, 0) == 0) {
        return mbedtls_ecp_copy(R, P);
    }

    if (MPI_ECP_CMP_INT(&Q->Z, 1) != 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MPI_ECP_SQR(&tmp[0], &P->Z);
    MPI_ECP_MUL(&tmp[1], &tmp[0], &P->Z);
    MPI_ECP_MUL(&tmp[0], &tmp[0], &Q->X);
    MPI_ECP_MUL(&tmp[1], &tmp[1], &Q->Y);
    MPI_ECP_SUB(&tmp[0], &tmp[0], &P->X);
    MPI_ECP_SUB(&tmp[1], &tmp[1], &P->Y);

    if (MPI_ECP_CMP_INT(&tmp[0], 0) == 0) {
        if (MPI_ECP_CMP_INT(&tmp[1], 0) == 0) {
            ret = ecp_double_jac(grp, R, P, tmp);
            goto cleanup;
        } else {
            ret = mbedtls_ecp_set_zero(R);
            goto cleanup;
        }
    }

    MPI_ECP_MUL(Z,        &P->Z,    &tmp[0]);
    MPI_ECP_SQR(&tmp[2],  &tmp[0]);
    MPI_ECP_MUL(&tmp[3],  &tmp[2],  &tmp[0]);
    MPI_ECP_MUL(&tmp[2],  &tmp[2],  &P->X);

    MPI_ECP_MOV(&tmp[0], &tmp[2]);
    MPI_ECP_SHIFT_L(&tmp[0], 1);

    MPI_ECP_SQR(X,        &tmp[1]);
    MPI_ECP_SUB(X,        X,        &tmp[0]);
    MPI_ECP_SUB(X,        X,        &tmp[3]);
    MPI_ECP_SUB(&tmp[2],  &tmp[2],  X);
    MPI_ECP_MUL(&tmp[2],  &tmp[2],  &tmp[1]);
    MPI_ECP_MUL(&tmp[3],  &tmp[3],  &P->Y);

    MPI_ECP_SUB(Y,     &tmp[2],     &tmp[3]);

cleanup:

    return ret;
#endif
}

static int ecp_randomize_jac(const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
#if defined(MBEDTLS_ECP_RANDOMIZE_JAC_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_randomize_jac(grp, pt, f_rng, p_rng);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_RANDOMIZE_JAC_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l;

    mbedtls_mpi_init(&l);

    MPI_ECP_RAND(&l);

    MPI_ECP_MUL(&pt->Z,   &pt->Z,     &l);

    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &l);

    MPI_ECP_SQR(&l,       &l);
    MPI_ECP_MUL(&pt->X,   &pt->X,     &l);

    MPI_ECP_MUL(&pt->Y,   &pt->Y,     &l);

cleanup:
    mbedtls_mpi_free(&l);

    if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    return ret;
#endif
}

#if MBEDTLS_ECP_WINDOW_SIZE < 2 || MBEDTLS_ECP_WINDOW_SIZE > 7
#error "MBEDTLS_ECP_WINDOW_SIZE out of bounds"
#endif

#define COMB_MAX_D      (MBEDTLS_ECP_MAX_BITS + 1) / 2

#define COMB_MAX_PRE    (1 << (MBEDTLS_ECP_WINDOW_SIZE - 1))

static void ecp_comb_recode_core(unsigned char x[], size_t d,
                                 unsigned char w, const mbedtls_mpi *m)
{
    size_t i, j;
    unsigned char c, cc, adjust;

    memset(x, 0, d+1);

    for (i = 0; i < d; i++) {
        for (j = 0; j < w; j++) {
            x[i] |= mbedtls_mpi_get_bit(m, i + d * j) << j;
        }
    }

    c = 0;
    for (i = 1; i <= d; i++) {

        cc   = x[i] & c;
        x[i] = x[i] ^ c;
        c = cc;

        adjust = 1 - (x[i] & 0x01);
        c   |= x[i] & (x[i-1] * adjust);
        x[i] = x[i] ^ (x[i-1] * adjust);
        x[i-1] |= adjust << 7;
    }
}

static int ecp_precompute_comb(const mbedtls_ecp_group *grp,
                               mbedtls_ecp_point T[], const mbedtls_ecp_point *P,
                               unsigned char w, size_t d,
                               mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char i;
    size_t j = 0;
    const unsigned char T_size = 1U << (w - 1);
    mbedtls_ecp_point *cur, *TT[COMB_MAX_PRE - 1] = { NULL };

    mbedtls_mpi tmp[4];

    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        if (rs_ctx->rsm->state == ecp_rsm_pre_dbl) {
            goto dbl;
        }
        if (rs_ctx->rsm->state == ecp_rsm_pre_norm_dbl) {
            goto norm_dbl;
        }
        if (rs_ctx->rsm->state == ecp_rsm_pre_add) {
            goto add;
        }
        if (rs_ctx->rsm->state == ecp_rsm_pre_norm_add) {
            goto norm_add;
        }
    }
#else
    (void) rs_ctx;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        rs_ctx->rsm->state = ecp_rsm_pre_dbl;

        rs_ctx->rsm->i = 0;
    }

dbl:
#endif

    MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&T[0], P));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL && rs_ctx->rsm->i != 0) {
        j = rs_ctx->rsm->i;
    } else
#endif
    j = 0;

    for (; j < d * (w - 1); j++) {
        MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_DBL);

        i = 1U << (j / d);
        cur = T + i;

        if (j % d == 0) {
            MBEDTLS_MPI_CHK(mbedtls_ecp_copy(cur, T + (i >> 1)));
        }

        MBEDTLS_MPI_CHK(ecp_double_jac(grp, cur, cur, tmp));
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        rs_ctx->rsm->state = ecp_rsm_pre_norm_dbl;
    }

norm_dbl:
#endif

    j = 0;
    for (i = 1; i < T_size; i <<= 1) {
        TT[j++] = T + i;
    }

    MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_INV + 6 * j - 2);

    MBEDTLS_MPI_CHK(ecp_normalize_jac_many(grp, TT, j));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        rs_ctx->rsm->state = ecp_rsm_pre_add;
    }

add:
#endif

    MBEDTLS_ECP_BUDGET((T_size - 1) * MBEDTLS_ECP_OPS_ADD);

    for (i = 1; i < T_size; i <<= 1) {
        j = i;
        while (j--) {
            MBEDTLS_MPI_CHK(ecp_add_mixed(grp, &T[i + j], &T[j], &T[i], tmp));
        }
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        rs_ctx->rsm->state = ecp_rsm_pre_norm_add;
    }

norm_add:
#endif

    for (j = 0; j + 1 < T_size; j++) {
        TT[j] = T + j + 1;
    }

    MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_INV + 6 * j - 2);

    MBEDTLS_MPI_CHK(ecp_normalize_jac_many(grp, TT, j));

    for (i = 0; i < T_size; i++) {
        mbedtls_mpi_free(&T[i].Z);
    }

cleanup:

    mpi_free_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL &&
        ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
        if (rs_ctx->rsm->state == ecp_rsm_pre_dbl) {
            rs_ctx->rsm->i = j;
        }
    }
#endif

    return ret;
}

static int ecp_select_comb(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                           const mbedtls_ecp_point T[], unsigned char T_size,
                           unsigned char i)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char ii, j;

    ii =  (i & 0x7Fu) >> 1;

    for (j = 0; j < T_size; j++) {
        MPI_ECP_COND_ASSIGN(&R->X, &T[j].X, j == ii);
        MPI_ECP_COND_ASSIGN(&R->Y, &T[j].Y, j == ii);
    }

    MBEDTLS_MPI_CHK(ecp_safe_invert_jac(grp, R, i >> 7));

    MPI_ECP_LSET(&R->Z, 1);

cleanup:
    return ret;
}

static int ecp_mul_comb_core(const mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                             const mbedtls_ecp_point T[], unsigned char T_size,
                             const unsigned char x[], size_t d,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng,
                             mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point Txi;
    mbedtls_mpi tmp[4];
    size_t i;

    mbedtls_ecp_point_init(&Txi);
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

#if !defined(MBEDTLS_ECP_RESTARTABLE)
    (void) rs_ctx;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL &&
        rs_ctx->rsm->state != ecp_rsm_comb_core) {
        rs_ctx->rsm->i = 0;
        rs_ctx->rsm->state = ecp_rsm_comb_core;
    }

    if (rs_ctx != NULL && rs_ctx->rsm != NULL && rs_ctx->rsm->i != 0) {

        i = rs_ctx->rsm->i;
    } else
#endif
    {

        i = d;
        MBEDTLS_MPI_CHK(ecp_select_comb(grp, R, T, T_size, x[i]));
        if (f_rng != 0) {
            MBEDTLS_MPI_CHK(ecp_randomize_jac(grp, R, f_rng, p_rng));
        }
    }

    while (i != 0) {
        MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_DBL + MBEDTLS_ECP_OPS_ADD);
        --i;

        MBEDTLS_MPI_CHK(ecp_double_jac(grp, R, R, tmp));
        MBEDTLS_MPI_CHK(ecp_select_comb(grp, &Txi, T, T_size, x[i]));
        MBEDTLS_MPI_CHK(ecp_add_mixed(grp, R, R, &Txi, tmp));
    }

cleanup:

    mbedtls_ecp_point_free(&Txi);
    mpi_free_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL &&
        ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
        rs_ctx->rsm->i = i;

    }
#endif

    return ret;
}

static int ecp_comb_recode_scalar(const mbedtls_ecp_group *grp,
                                  const mbedtls_mpi *m,
                                  unsigned char k[COMB_MAX_D + 1],
                                  size_t d,
                                  unsigned char w,
                                  unsigned char *parity_trick)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi M, mm;

    mbedtls_mpi_init(&M);
    mbedtls_mpi_init(&mm);

    if (mbedtls_mpi_get_bit(&grp->N, 0) != 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    *parity_trick = (mbedtls_mpi_get_bit(m, 0) == 0);

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&M, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&mm, &grp->N, m));
    MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(&M, &mm, *parity_trick));

    ecp_comb_recode_core(k, d, w, &M);

cleanup:
    mbedtls_mpi_free(&mm);
    mbedtls_mpi_free(&M);

    return ret;
}

static int ecp_mul_comb_after_precomp(const mbedtls_ecp_group *grp,
                                      mbedtls_ecp_point *R,
                                      const mbedtls_mpi *m,
                                      const mbedtls_ecp_point *T,
                                      unsigned char T_size,
                                      unsigned char w,
                                      size_t d,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng,
                                      mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char parity_trick;
    unsigned char k[COMB_MAX_D + 1];
    mbedtls_ecp_point *RR = R;

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        RR = &rs_ctx->rsm->R;

        if (rs_ctx->rsm->state == ecp_rsm_final_norm) {
            goto final_norm;
        }
    }
#endif

    MBEDTLS_MPI_CHK(ecp_comb_recode_scalar(grp, m, k, d, w,
                                           &parity_trick));
    MBEDTLS_MPI_CHK(ecp_mul_comb_core(grp, RR, T, T_size, k, d,
                                      f_rng, p_rng, rs_ctx));
    MBEDTLS_MPI_CHK(ecp_safe_invert_jac(grp, RR, parity_trick));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        rs_ctx->rsm->state = ecp_rsm_final_norm;
    }

final_norm:
    MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_INV);
#endif
    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, RR));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_copy(R, RR));
    }
#endif

cleanup:
    return ret;
}

static unsigned char ecp_pick_window_size(const mbedtls_ecp_group *grp,
                                          unsigned char p_eq_g)
{
    unsigned char w;

    w = grp->nbits >= 384 ? 5 : 4;

    if (p_eq_g) {
        w++;
    }

#if (MBEDTLS_ECP_WINDOW_SIZE < 6)
    if ((!p_eq_g || !ecp_group_is_static_comb_table(grp)) && w > MBEDTLS_ECP_WINDOW_SIZE) {
        w = MBEDTLS_ECP_WINDOW_SIZE;
    }
#endif
    if (w >= grp->nbits) {
        w = 2;
    }

    return w;
}

static int ecp_mul_comb(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng,
                        mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char w, p_eq_g, i;
    size_t d;
    unsigned char T_size = 0, T_ok = 0;
    mbedtls_ecp_point *T = NULL;

    ECP_RS_ENTER(rsm);

#if MBEDTLS_ECP_FIXED_POINT_OPTIM == 1
    p_eq_g = (MPI_ECP_CMP(&P->Y, &grp->G.Y) == 0 &&
              MPI_ECP_CMP(&P->X, &grp->G.X) == 0);
#else
    p_eq_g = 0;
#endif

    w = ecp_pick_window_size(grp, p_eq_g);
    T_size = 1U << (w - 1);
    d = (grp->nbits + w - 1) / w;

    if (p_eq_g && grp->T != NULL) {

        T = grp->T;
        T_ok = 1;
    } else
#if defined(MBEDTLS_ECP_RESTARTABLE)

    if (rs_ctx != NULL && rs_ctx->rsm != NULL && rs_ctx->rsm->T != NULL) {

        T = rs_ctx->rsm->T;
        rs_ctx->rsm->T = NULL;
        rs_ctx->rsm->T_size = 0;

        T_ok = rs_ctx->rsm->state >= ecp_rsm_comb_core;
    } else
#endif

    {
        T = mbedtls_calloc(T_size, sizeof(mbedtls_ecp_point));
        if (T == NULL) {
            ret = MBEDTLS_ERR_ECP_ALLOC_FAILED;
            goto cleanup;
        }

        for (i = 0; i < T_size; i++) {
            mbedtls_ecp_point_init(&T[i]);
        }

        T_ok = 0;
    }

    if (!T_ok) {
        MBEDTLS_MPI_CHK(ecp_precompute_comb(grp, T, P, w, d, rs_ctx));

        if (p_eq_g) {

            grp->T = T;
            grp->T_size = T_size;
        }
    }

    MBEDTLS_MPI_CHK(ecp_mul_comb_after_precomp(grp, R, m,
                                               T, T_size, w, d,
                                               f_rng, p_rng, rs_ctx));

cleanup:

    if (T == grp->T) {
        T = NULL;
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->rsm != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS && T != NULL) {

        rs_ctx->rsm->T_size = T_size;
        rs_ctx->rsm->T = T;
        T = NULL;
    }
#endif

    if (T != NULL) {
        for (i = 0; i < T_size; i++) {
            mbedtls_ecp_point_free(&T[i]);
        }
        mbedtls_free(T);
    }

    int should_free_R = (ret != 0);
#if defined(MBEDTLS_ECP_RESTARTABLE)

    if (ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
        should_free_R = 0;
    }
#endif
    if (should_free_R) {
        mbedtls_ecp_point_free(R);
    }

    ECP_RS_LEAVE(rsm);

    return ret;
}

#endif

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)

static int ecp_normalize_mxz(const mbedtls_ecp_group *grp, mbedtls_ecp_point *P)
{
#if defined(MBEDTLS_ECP_NORMALIZE_MXZ_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_normalize_mxz(grp, P);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_NORMALIZE_MXZ_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MPI_ECP_INV(&P->Z, &P->Z);
    MPI_ECP_MUL(&P->X, &P->X, &P->Z);
    MPI_ECP_LSET(&P->Z, 1);

cleanup:
    return ret;
#endif
}

static int ecp_randomize_mxz(const mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
#if defined(MBEDTLS_ECP_RANDOMIZE_MXZ_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_randomize_mxz(grp, P, f_rng, p_rng);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_RANDOMIZE_MXZ_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l;
    mbedtls_mpi_init(&l);

    MPI_ECP_RAND(&l);

    MPI_ECP_MUL(&P->X, &P->X, &l);
    MPI_ECP_MUL(&P->Z, &P->Z, &l);

cleanup:
    mbedtls_mpi_free(&l);

    if (ret == MBEDTLS_ERR_MPI_NOT_ACCEPTABLE) {
        ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
    }
    return ret;
#endif
}

static int ecp_double_add_mxz(const mbedtls_ecp_group *grp,
                              mbedtls_ecp_point *R, mbedtls_ecp_point *S,
                              const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q,
                              const mbedtls_mpi *d,
                              mbedtls_mpi T[4])
{
#if defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)
    if (mbedtls_internal_ecp_grp_capable(grp)) {
        return mbedtls_internal_ecp_double_add_mxz(grp, R, S, P, Q, d);
    }
#endif

#if defined(MBEDTLS_ECP_NO_FALLBACK) && defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    MPI_ECP_ADD(&T[0], &P->X,   &P->Z);
    MPI_ECP_SUB(&T[1], &P->X,   &P->Z);
    MPI_ECP_ADD(&T[2], &Q->X,   &Q->Z);
    MPI_ECP_SUB(&T[3], &Q->X,   &Q->Z);
    MPI_ECP_MUL(&T[3], &T[3],   &T[0]);
    MPI_ECP_MUL(&T[2], &T[2],   &T[1]);
    MPI_ECP_SQR(&T[0], &T[0]);
    MPI_ECP_SQR(&T[1], &T[1]);
    MPI_ECP_MUL(&R->X, &T[0],   &T[1]);
    MPI_ECP_SUB(&T[0], &T[0],   &T[1]);
    MPI_ECP_MUL(&R->Z, &grp->A, &T[0]);
    MPI_ECP_ADD(&R->Z, &T[1],   &R->Z);
    MPI_ECP_ADD(&S->X, &T[3],   &T[2]);
    MPI_ECP_SQR(&S->X, &S->X);
    MPI_ECP_SUB(&S->Z, &T[3],   &T[2]);
    MPI_ECP_SQR(&S->Z, &S->Z);
    MPI_ECP_MUL(&S->Z, d,       &S->Z);
    MPI_ECP_MUL(&R->Z, &T[0],   &R->Z);

cleanup:

    return ret;
#endif
}

static int ecp_mul_mxz(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    unsigned char b;
    mbedtls_ecp_point RP;
    mbedtls_mpi PX;
    mbedtls_mpi tmp[4];
    mbedtls_ecp_point_init(&RP); mbedtls_mpi_init(&PX);

    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    MPI_ECP_MOV(&PX, &P->X);
    MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&RP, P));

    MPI_ECP_LSET(&R->X, 1);
    MPI_ECP_LSET(&R->Z, 0);
    mbedtls_mpi_free(&R->Y);

    MOD_ADD(&RP.X);

    MBEDTLS_MPI_CHK(ecp_randomize_mxz(grp, &RP, f_rng, p_rng));

    i = grp->nbits + 1;
    while (i-- > 0) {
        b = mbedtls_mpi_get_bit(m, i);

        MPI_ECP_COND_SWAP(&R->X, &RP.X, b);
        MPI_ECP_COND_SWAP(&R->Z, &RP.Z, b);
        MBEDTLS_MPI_CHK(ecp_double_add_mxz(grp, R, &RP, R, &RP, &PX, tmp));
        MPI_ECP_COND_SWAP(&R->X, &RP.X, b);
        MPI_ECP_COND_SWAP(&R->Z, &RP.Z, b);
    }

    MBEDTLS_MPI_CHK(ecp_normalize_mxz(grp, R));

cleanup:
    mbedtls_ecp_point_free(&RP); mbedtls_mpi_free(&PX);

    mpi_free_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));
    return ret;
}

#endif

static int ecp_mul_restartable_internal(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                        const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                        mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    char is_grp_capable = 0;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)

    if (rs_ctx != NULL && rs_ctx->depth++ == 0) {
        rs_ctx->ops_done = 0;
    }
#else
    (void) rs_ctx;
#endif

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if ((is_grp_capable = mbedtls_internal_ecp_grp_capable(grp))) {
        MBEDTLS_MPI_CHK(mbedtls_internal_ecp_init(grp));
    }
#endif

    int restarting = 0;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    restarting = (rs_ctx != NULL && rs_ctx->rsm != NULL);
#endif

    if (!restarting) {

        MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_CHK);

        MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(grp, m));
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
    }

    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        MBEDTLS_MPI_CHK(ecp_mul_mxz(grp, R, m, P, f_rng, p_rng));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        MBEDTLS_MPI_CHK(ecp_mul_comb(grp, R, m, P, f_rng, p_rng, rs_ctx));
    }
#endif

cleanup:

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if (is_grp_capable) {
        mbedtls_internal_ecp_free(grp);
    }
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL) {
        rs_ctx->depth--;
    }
#endif

    return ret;
}

int mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                mbedtls_ecp_restart_ctx *rs_ctx)
{
    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return ecp_mul_restartable_internal(grp, R, m, P, f_rng, p_rng, rs_ctx);
}

int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_ecp_mul_restartable(grp, R, m, P, f_rng, p_rng, NULL);
}
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

static int ecp_check_pubkey_sw(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi YY, RHS;

    if (mbedtls_mpi_cmp_int(&pt->X, 0) < 0 ||
        mbedtls_mpi_cmp_int(&pt->Y, 0) < 0 ||
        mbedtls_mpi_cmp_mpi(&pt->X, &grp->P) >= 0 ||
        mbedtls_mpi_cmp_mpi(&pt->Y, &grp->P) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_mpi_init(&YY); mbedtls_mpi_init(&RHS);

    MPI_ECP_SQR(&YY,  &pt->Y);
    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, &RHS, &pt->X));

    if (MPI_ECP_CMP(&YY, &RHS) != 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
    }

cleanup:

    mbedtls_mpi_free(&YY); mbedtls_mpi_free(&RHS);

    return ret;
}
#endif

#if defined(MBEDTLS_ECP_C)
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

static int mbedtls_ecp_mul_shortcuts(mbedtls_ecp_group *grp,
                                     mbedtls_ecp_point *R,
                                     const mbedtls_mpi *m,
                                     const mbedtls_ecp_point *P,
                                     mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi tmp;
    mbedtls_mpi_init(&tmp);

    if (mbedtls_mpi_cmp_int(m, 0) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
        MBEDTLS_MPI_CHK(mbedtls_ecp_set_zero(R));
    } else if (mbedtls_mpi_cmp_int(m, 1) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
        MBEDTLS_MPI_CHK(mbedtls_ecp_copy(R, P));
    } else if (mbedtls_mpi_cmp_int(m, -1) == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));
        MBEDTLS_MPI_CHK(mbedtls_ecp_copy(R, P));
        MPI_ECP_NEG(&R->Y);
    } else {
        MBEDTLS_MPI_CHK(ecp_mul_restartable_internal(grp, R, m, P,
                                                     NULL, NULL, rs_ctx));
    }

cleanup:
    mbedtls_mpi_free(&tmp);

    return ret;
}

int mbedtls_ecp_muladd_restartable(
    mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
    const mbedtls_mpi *n, const mbedtls_ecp_point *Q,
    mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point mP;
    mbedtls_ecp_point *pmP = &mP;
    mbedtls_ecp_point *pR = R;
    mbedtls_mpi tmp[4];
#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    char is_grp_capable = 0;
#endif
    if (mbedtls_ecp_get_type(grp) != MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    mbedtls_ecp_point_init(&mP);
    mpi_init_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

    ECP_RS_ENTER(ma);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ma != NULL) {

        pmP = &rs_ctx->ma->mP;
        pR  = &rs_ctx->ma->R;

        if (rs_ctx->ma->state == ecp_rsma_mul2) {
            goto mul2;
        }
        if (rs_ctx->ma->state == ecp_rsma_add) {
            goto add;
        }
        if (rs_ctx->ma->state == ecp_rsma_norm) {
            goto norm;
        }
    }
#endif

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pmP, m, P, rs_ctx));
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ma != NULL) {
        rs_ctx->ma->state = ecp_rsma_mul2;
    }

mul2:
#endif
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_shortcuts(grp, pR,  n, Q, rs_ctx));

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if ((is_grp_capable = mbedtls_internal_ecp_grp_capable(grp))) {
        MBEDTLS_MPI_CHK(mbedtls_internal_ecp_init(grp));
    }
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ma != NULL) {
        rs_ctx->ma->state = ecp_rsma_add;
    }

add:
#endif
    MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_ADD);
    MBEDTLS_MPI_CHK(ecp_add_mixed(grp, pR, pmP, pR, tmp));
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ma != NULL) {
        rs_ctx->ma->state = ecp_rsma_norm;
    }

norm:
#endif
    MBEDTLS_ECP_BUDGET(MBEDTLS_ECP_OPS_INV);
    MBEDTLS_MPI_CHK(ecp_normalize_jac(grp, pR));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ma != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_copy(R, pR));
    }
#endif

cleanup:

    mpi_free_many(tmp, sizeof(tmp) / sizeof(mbedtls_mpi));

#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    if (is_grp_capable) {
        mbedtls_internal_ecp_free(grp);
    }
#endif

    mbedtls_ecp_point_free(&mP);

    ECP_RS_LEAVE(ma);

    return ret;
}

int mbedtls_ecp_muladd(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                       const mbedtls_mpi *n, const mbedtls_ecp_point *Q)
{
    return mbedtls_ecp_muladd_restartable(grp, R, m, P, n, Q, NULL);
}
#endif
#endif

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define ECP_MPI_INIT(_p, _n) { .p = (mbedtls_mpi_uint *) (_p), .s = 1, .n = (_n) }
#define ECP_MPI_INIT_ARRAY(x)   \
    ECP_MPI_INIT(x, sizeof(x) / sizeof(mbedtls_mpi_uint))

static const mbedtls_mpi_uint x25519_bad_point_1[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae),
    MBEDTLS_BYTES_TO_T_UINT_8(0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a),
    MBEDTLS_BYTES_TO_T_UINT_8(0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd),
    MBEDTLS_BYTES_TO_T_UINT_8(0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00),
};
static const mbedtls_mpi_uint x25519_bad_point_2[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24),
    MBEDTLS_BYTES_TO_T_UINT_8(0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b),
    MBEDTLS_BYTES_TO_T_UINT_8(0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86),
    MBEDTLS_BYTES_TO_T_UINT_8(0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57),
};
static const mbedtls_mpi ecp_x25519_bad_point_1 = ECP_MPI_INIT_ARRAY(
    x25519_bad_point_1);
static const mbedtls_mpi ecp_x25519_bad_point_2 = ECP_MPI_INIT_ARRAY(
    x25519_bad_point_2);
#endif

static int ecp_check_bad_points_mx(const mbedtls_mpi *X, const mbedtls_mpi *P,
                                   const mbedtls_ecp_group_id grp_id)
{
    int ret;
    mbedtls_mpi XmP;

    mbedtls_mpi_init(&XmP);

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(&XmP, X));
    while (mbedtls_mpi_cmp_mpi(&XmP, P) >= 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&XmP, &XmP, P));
    }

    if (mbedtls_mpi_cmp_int(&XmP, 1) <= 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    if (grp_id == MBEDTLS_ECP_DP_CURVE25519) {
        if (mbedtls_mpi_cmp_mpi(&XmP, &ecp_x25519_bad_point_1) == 0) {
            ret = MBEDTLS_ERR_ECP_INVALID_KEY;
            goto cleanup;
        }

        if (mbedtls_mpi_cmp_mpi(&XmP, &ecp_x25519_bad_point_2) == 0) {
            ret = MBEDTLS_ERR_ECP_INVALID_KEY;
            goto cleanup;
        }
    }
#else
    (void) grp_id;
#endif

    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&XmP, &XmP, 1));
    if (mbedtls_mpi_cmp_mpi(&XmP, P) == 0) {
        ret = MBEDTLS_ERR_ECP_INVALID_KEY;
        goto cleanup;
    }

    ret = 0;

cleanup:
    mbedtls_mpi_free(&XmP);

    return ret;
}

static int ecp_check_pubkey_mx(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt)
{

    if (mbedtls_mpi_size(&pt->X) > (grp->nbits + 7) / 8) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    if (mbedtls_mpi_cmp_int(&pt->X, 0) < 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    return ecp_check_bad_points_mx(&pt->X, &grp->P, grp->id);
}
#endif

int mbedtls_ecp_check_pubkey(const mbedtls_ecp_group *grp,
                             const mbedtls_ecp_point *pt)
{

    if (mbedtls_mpi_cmp_int(&pt->Z, 1) != 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return ecp_check_pubkey_mx(grp, pt);
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return ecp_check_pubkey_sw(grp, pt);
    }
#endif
    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

int mbedtls_ecp_check_privkey(const mbedtls_ecp_group *grp,
                              const mbedtls_mpi *d)
{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {

        if (mbedtls_mpi_get_bit(d, 0) != 0 ||
            mbedtls_mpi_get_bit(d, 1) != 0 ||
            mbedtls_mpi_bitlen(d) != grp->nbits + 1) {
            return MBEDTLS_ERR_ECP_INVALID_KEY;
        }

        if (grp->nbits == 254 && mbedtls_mpi_get_bit(d, 2) != 0) {
            return MBEDTLS_ERR_ECP_INVALID_KEY;
        }

        return 0;
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {

        if (mbedtls_mpi_cmp_int(d, 1) < 0 ||
            mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
            return MBEDTLS_ERR_ECP_INVALID_KEY;
        } else {
            return 0;
        }
    }
#endif

    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_gen_privkey_mx(size_t high_bit,
                               mbedtls_mpi *d,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    size_t n_random_bytes = high_bit / 8 + 1;

    MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(d, n_random_bytes,
                                            f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(d, 8 * n_random_bytes - high_bit - 1));

    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, high_bit, 1));

    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, 0, 0));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, 1, 0));
    if (high_bit == 254) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(d, 2, 0));
    }

cleanup:
    return ret;
}
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
static int mbedtls_ecp_gen_privkey_sw(
    const mbedtls_mpi *N, mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = mbedtls_mpi_random(d, 1, N, f_rng, p_rng);
    switch (ret) {
        case MBEDTLS_ERR_MPI_NOT_ACCEPTABLE:
            return MBEDTLS_ERR_ECP_RANDOM_FAILED;
        default:
            return ret;
    }
}
#endif

int mbedtls_ecp_gen_privkey(const mbedtls_ecp_group *grp,
                            mbedtls_mpi *d,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return mbedtls_ecp_gen_privkey_mx(grp->nbits, d, f_rng, p_rng);
    }
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return mbedtls_ecp_gen_privkey_sw(&grp->N, d, f_rng, p_rng);
    }
#endif

    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
}

#if defined(MBEDTLS_ECP_C)

int mbedtls_ecp_gen_keypair_base(mbedtls_ecp_group *grp,
                                 const mbedtls_ecp_point *G,
                                 mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, d, f_rng, p_rng));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, Q, d, G, f_rng, p_rng));

cleanup:
    return ret;
}

int mbedtls_ecp_gen_keypair(mbedtls_ecp_group *grp,
                            mbedtls_mpi *d, mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    return mbedtls_ecp_gen_keypair_base(grp, &grp->G, d, Q, f_rng, p_rng);
}

int mbedtls_ecp_gen_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = mbedtls_ecp_group_load(&key->grp, grp_id)) != 0) {
        return ret;
    }

    return mbedtls_ecp_gen_keypair(&key->grp, &key->d, &key->Q, f_rng, p_rng);
}
#endif

int mbedtls_ecp_set_public_key(mbedtls_ecp_group_id grp_id,
                               mbedtls_ecp_keypair *key,
                               const mbedtls_ecp_point *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (key->grp.id == MBEDTLS_ECP_DP_NONE) {

        if ((ret = mbedtls_ecp_group_load(&key->grp, grp_id)) != 0) {
            return ret;
        }
    } else if (key->grp.id != grp_id) {

        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    return mbedtls_ecp_copy(&key->Q, Q);
}

#define ECP_CURVE25519_KEY_SIZE 32
#define ECP_CURVE448_KEY_SIZE   56

int mbedtls_ecp_read_key(mbedtls_ecp_group_id grp_id, mbedtls_ecp_keypair *key,
                         const unsigned char *buf, size_t buflen)
{
    int ret = 0;

    if ((ret = mbedtls_ecp_group_load(&key->grp, grp_id)) != 0) {
        return ret;
    }

    ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {

        if (grp_id == MBEDTLS_ECP_DP_CURVE25519) {
            if (buflen != ECP_CURVE25519_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_INVALID_KEY;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&key->d, buf, buflen));

            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 0, 0));
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 1, 0));
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 2, 0));

            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit(&key->d,
                                    ECP_CURVE25519_KEY_SIZE * 8 - 1, 0)
                );

            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit(&key->d,
                                    ECP_CURVE25519_KEY_SIZE * 8 - 2, 1)
                );
        } else if (grp_id == MBEDTLS_ECP_DP_CURVE448) {
            if (buflen != ECP_CURVE448_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_INVALID_KEY;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&key->d, buf, buflen));

            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 0, 0));
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&key->d, 1, 0));

            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit(&key->d,
                                    ECP_CURVE448_KEY_SIZE * 8 - 1, 1)
                );
        }
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&key->d, buf, buflen));
    }
#endif

    if (ret == 0) {
        MBEDTLS_MPI_CHK(mbedtls_ecp_check_privkey(&key->grp, &key->d));
    }

cleanup:

    if (ret != 0) {
        mbedtls_mpi_free(&key->d);
    }

    return ret;
}

#if !defined MBEDTLS_DEPRECATED_REMOVED
int mbedtls_ecp_write_key(mbedtls_ecp_keypair *key,
                          unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        if (key->grp.id == MBEDTLS_ECP_DP_CURVE25519) {
            if (buflen < ECP_CURVE25519_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }

        } else if (key->grp.id == MBEDTLS_ECP_DP_CURVE448) {
            if (buflen < ECP_CURVE448_KEY_SIZE) {
                return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
            }
        }
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&key->d, buf, buflen));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&key->d, buf, buflen));
    }

#endif
cleanup:

    return ret;
}
#endif

int mbedtls_ecp_write_key_ext(const mbedtls_ecp_keypair *key,
                              size_t *olen, unsigned char *buf, size_t buflen)
{
    size_t len = (key->grp.nbits + 7) / 8;
    if (len > buflen) {

        *olen = 0;
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    *olen = len;

    if (key->d.n == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return mbedtls_mpi_write_binary_le(&key->d, buf, len);
    }
#endif

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(&key->grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        return mbedtls_mpi_write_binary(&key->d, buf, len);
    }
#endif

    return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
}

int mbedtls_ecp_write_public_key(const mbedtls_ecp_keypair *key,
                                 int format, size_t *olen,
                                 unsigned char *buf, size_t buflen)
{
    return mbedtls_ecp_point_write_binary(&key->grp, &key->Q,
                                          format, olen, buf, buflen);
}

#if defined(MBEDTLS_ECP_C)

int mbedtls_ecp_check_pub_priv(
    const mbedtls_ecp_keypair *pub, const mbedtls_ecp_keypair *prv,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group grp;
    if (pub->grp.id == MBEDTLS_ECP_DP_NONE ||
        pub->grp.id != prv->grp.id ||
        mbedtls_mpi_cmp_mpi(&pub->Q.X, &prv->Q.X) ||
        mbedtls_mpi_cmp_mpi(&pub->Q.Y, &prv->Q.Y) ||
        mbedtls_mpi_cmp_mpi(&pub->Q.Z, &prv->Q.Z)) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_group_init(&grp);

    mbedtls_ecp_group_copy(&grp, &prv->grp);

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &Q, &prv->d, &prv->grp.G, f_rng, p_rng));

    if (mbedtls_mpi_cmp_mpi(&Q.X, &prv->Q.X) ||
        mbedtls_mpi_cmp_mpi(&Q.Y, &prv->Q.Y) ||
        mbedtls_mpi_cmp_mpi(&Q.Z, &prv->Q.Z)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);

    return ret;
}

int mbedtls_ecp_keypair_calc_public(mbedtls_ecp_keypair *key,
                                    int (*f_rng)(void *, unsigned char *, size_t),
                                    void *p_rng)
{
    return mbedtls_ecp_mul(&key->grp, &key->Q, &key->d, &key->grp.G,
                           f_rng, p_rng);
}
#endif

mbedtls_ecp_group_id mbedtls_ecp_keypair_get_group_id(
    const mbedtls_ecp_keypair *key)
{
    return key->grp.id;
}

int mbedtls_ecp_export(const mbedtls_ecp_keypair *key, mbedtls_ecp_group *grp,
                       mbedtls_mpi *d, mbedtls_ecp_point *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (grp != NULL && (ret = mbedtls_ecp_group_copy(grp, &key->grp)) != 0) {
        return ret;
    }

    if (d != NULL && (ret = mbedtls_mpi_copy(d, &key->d)) != 0) {
        return ret;
    }

    if (Q != NULL && (ret = mbedtls_ecp_copy(Q, &key->Q)) != 0) {
        return ret;
    }

    return 0;
}

#if defined(MBEDTLS_SELF_TEST)

#if defined(MBEDTLS_ECP_C)

static int self_test_rng(void *ctx, unsigned char *out, size_t len)
{
    static uint32_t state = 42;

    (void) ctx;

    for (size_t i = 0; i < len; i++) {
        state = state * 1664525u + 1013904223u;
        out[i] = (unsigned char) state;
    }

    return 0;
}

static int self_test_adjust_exponent(const mbedtls_ecp_group *grp,
                                     mbedtls_mpi *m)
{
    int ret = 0;
    switch (grp->id) {

#if !defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
        case MBEDTLS_ECP_DP_CURVE448:

            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(m, 254, 0));
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(m, grp->nbits, 1));

            MBEDTLS_MPI_CHK(
                mbedtls_mpi_set_bit(m, grp->nbits - 1,
                                    mbedtls_mpi_get_bit(m, 253)));
            break;
#endif
#endif
        default:

            (void) grp;
            (void) m;
            goto cleanup;
    }
cleanup:
    return ret;
}

static int self_test_point(int verbose,
                           mbedtls_ecp_group *grp,
                           mbedtls_ecp_point *R,
                           mbedtls_mpi *m,
                           const mbedtls_ecp_point *P,
                           const char *const *exponents,
                           size_t n_exponents)
{
    int ret = 0;
    size_t i = 0;
    unsigned long add_c_prev, dbl_c_prev, mul_c_prev;
    add_count = 0;
    dbl_count = 0;
    mul_count = 0;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(m, 16, exponents[0]));
    MBEDTLS_MPI_CHK(self_test_adjust_exponent(grp, m));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, R, m, P, self_test_rng, NULL));

    for (i = 1; i < n_exponents; i++) {
        add_c_prev = add_count;
        dbl_c_prev = dbl_count;
        mul_c_prev = mul_count;
        add_count = 0;
        dbl_count = 0;
        mul_count = 0;

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(m, 16, exponents[i]));
        MBEDTLS_MPI_CHK(self_test_adjust_exponent(grp, m));
        MBEDTLS_MPI_CHK(mbedtls_ecp_mul(grp, R, m, P, self_test_rng, NULL));

        if (add_count != add_c_prev ||
            dbl_count != dbl_c_prev ||
            mul_count != mul_c_prev) {
            ret = 1;
            break;
        }
    }

cleanup:
    if (verbose != 0) {
        if (ret != 0) {
            mbedtls_printf("failed (%u)\n", (unsigned int) i);
        } else {
            mbedtls_printf("passed\n");
        }
    }
    return ret;
}
#endif

int mbedtls_ecp_self_test(int verbose)
{
#if defined(MBEDTLS_ECP_C)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point R, P;
    mbedtls_mpi m;

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

    const char *sw_exponents[] =
    {
        "000000000000000000000000000000000000000000000001",
        "FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8C",
        "5EA6F389A38B8BC81E767753B15AA5569E1782E30ABE7D25",
        "400000000000000000000000000000000000000000000000",
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "555555555555555555555555555555555555555555555555",
    };
#endif
#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    const char *m_exponents[] =
    {

        "4000000000000000000000000000000000000000000000000000000000000000",
        "5C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C30",
        "5715ECCE24583F7A7023C24164390586842E816D7280A49EF6DF4EAE6B280BF8",
        "41A2B017516F6D254E1F002BCCBADD54BE30F8CEC737A0E912B4963B6BA74460",
        "5555555555555555555555555555555555555555555555555555555555555550",
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF8",
    };
#endif

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&m);

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP192R1));
#else
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, mbedtls_ecp_curve_list()->grp_id));
#endif

    if (verbose != 0) {
        mbedtls_printf("  ECP SW test #1 (constant op_count, base point G): ");
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&m, 2));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &P, &m, &grp.G, self_test_rng, NULL));
    ret = self_test_point(verbose,
                          &grp, &R, &m, &grp.G,
                          sw_exponents,
                          sizeof(sw_exponents) / sizeof(sw_exponents[0]));
    if (ret != 0) {
        goto cleanup;
    }

    if (verbose != 0) {
        mbedtls_printf("  ECP SW test #2 (constant op_count, other point): ");
    }

    ret = self_test_point(verbose,
                          &grp, &R, &m, &P,
                          sw_exponents,
                          sizeof(sw_exponents) / sizeof(sw_exponents[0]));
    if (ret != 0) {
        goto cleanup;
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R);
#endif

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (verbose != 0) {
        mbedtls_printf("  ECP Montgomery test (constant op_count): ");
    }
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519));
#elif defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE448));
#else
#error "MBEDTLS_ECP_MONTGOMERY_ENABLED is defined, but no curve is supported for self-test"
#endif
    ret = self_test_point(verbose,
                          &grp, &R, &m, &grp.G,
                          m_exponents,
                          sizeof(m_exponents) / sizeof(m_exponents[0]));
    if (ret != 0) {
        goto cleanup;
    }
#endif

cleanup:

    if (ret < 0 && verbose != 0) {
        mbedtls_printf("Unexpected error, return code = %08X\n", (unsigned int) ret);
    }

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_free(&m);

    if (verbose != 0) {
        mbedtls_printf("\n");
    }

    return ret;
#else
    (void) verbose;
    return 0;
#endif
}

#endif

#endif

#endif
