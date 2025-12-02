/*
 *  Elliptic curve DSA
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"
#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#include "mbedtls/asn1write.h"
#include <string.h>
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#include "mbedtls/hmac_drbg.h"
#endif
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"
#if defined(MBEDTLS_ECP_RESTARTABLE)
struct mbedtls_ecdsa_restart_ver {
    mbedtls_mpi u1, u2;
    enum {
        ecdsa_ver_init = 0,
        ecdsa_ver_muladd,
    } state;
};
static void ecdsa_restart_ver_init(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    mbedtls_mpi_init(&ctx->u1);
    mbedtls_mpi_init(&ctx->u2);
    ctx->state = ecdsa_ver_init;
}
static void ecdsa_restart_ver_free(mbedtls_ecdsa_restart_ver_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_mpi_free(&ctx->u1);
    mbedtls_mpi_free(&ctx->u2);
    ecdsa_restart_ver_init(ctx);
}
struct mbedtls_ecdsa_restart_sig {
    int sign_tries;
    int key_tries;
    mbedtls_mpi k;
    mbedtls_mpi r;
    enum {
        ecdsa_sig_init = 0,
        ecdsa_sig_mul,
        ecdsa_sig_modn,
    } state;
};
static void ecdsa_restart_sig_init(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    ctx->sign_tries = 0;
    ctx->key_tries = 0;
    mbedtls_mpi_init(&ctx->k);
    mbedtls_mpi_init(&ctx->r);
    ctx->state = ecdsa_sig_init;
}
static void ecdsa_restart_sig_free(mbedtls_ecdsa_restart_sig_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_mpi_free(&ctx->k);
    mbedtls_mpi_free(&ctx->r);
}
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
struct mbedtls_ecdsa_restart_det {
    mbedtls_hmac_drbg_context rng_ctx;
    enum {
        ecdsa_det_init = 0,
        ecdsa_det_sign,
    } state;
};
static void ecdsa_restart_det_init(mbedtls_ecdsa_restart_det_ctx *ctx)
{
    mbedtls_hmac_drbg_init(&ctx->rng_ctx);
    ctx->state = ecdsa_det_init;
}
static void ecdsa_restart_det_free(mbedtls_ecdsa_restart_det_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_hmac_drbg_free(&ctx->rng_ctx);
    ecdsa_restart_det_init(ctx);
}
#endif
#define ECDSA_RS_ECP (rs_ctx == NULL ? NULL : &rs_ctx->ecp)
#define ECDSA_BUDGET(ops) \
    MBEDTLS_MPI_CHK(mbedtls_ecp_check_budget(grp, ECDSA_RS_ECP, ops));
#define ECDSA_RS_ENTER(SUB) do { \
                                                                         \
        if (rs_ctx != NULL && rs_ctx->ecp.depth++ == 0) \
        rs_ctx->ecp.ops_done = 0; \
                                                                     \
                                                                         \
        if (mbedtls_ecp_restart_is_enabled() && \
            rs_ctx != NULL && rs_ctx->SUB == NULL) \
        { \
            rs_ctx->SUB = mbedtls_calloc(1, sizeof(*rs_ctx->SUB)); \
            if (rs_ctx->SUB == NULL) \
            return MBEDTLS_ERR_ECP_ALLOC_FAILED; \
                                                                   \
            ecdsa_restart_## SUB ##_init(rs_ctx->SUB); \
        } \
} while (0)
#define ECDSA_RS_LEAVE(SUB) do { \
                                                                         \
        if (rs_ctx != NULL && rs_ctx->SUB != NULL && \
            ret != MBEDTLS_ERR_ECP_IN_PROGRESS) \
        { \
            ecdsa_restart_## SUB ##_free(rs_ctx->SUB); \
            mbedtls_free(rs_ctx->SUB); \
            rs_ctx->SUB = NULL; \
        } \
                                                                     \
        if (rs_ctx != NULL) \
        rs_ctx->ecp.depth--; \
} while (0)
#else
#define ECDSA_RS_ECP NULL
#define ECDSA_BUDGET(ops) 
#define ECDSA_RS_ENTER(SUB) (void) rs_ctx
#define ECDSA_RS_LEAVE(SUB) (void) rs_ctx
#endif
#if defined(MBEDTLS_ECDSA_DETERMINISTIC) || \
    !defined(MBEDTLS_ECDSA_SIGN_ALT) || \
    !defined(MBEDTLS_ECDSA_VERIFY_ALT)
static int derive_mpi(const mbedtls_ecp_group *grp, mbedtls_mpi *x,
                      const unsigned char *buf, size_t blen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n_size = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(x, buf, use_size));
    if (use_size * 8 > grp->nbits) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(x, use_size * 8 - grp->nbits));
    }
    if (mbedtls_mpi_cmp_mpi(x, &grp->N) >= 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(x, x, &grp->N));
    }
cleanup:
    return ret;
}
#endif
int mbedtls_ecdsa_can_do(mbedtls_ecp_group_id gid)
{
    switch (gid) {
#ifdef MBEDTLS_ECP_DP_CURVE25519_ENABLED
        case MBEDTLS_ECP_DP_CURVE25519: return 0;
#endif
#ifdef MBEDTLS_ECP_DP_CURVE448_ENABLED
        case MBEDTLS_ECP_DP_CURVE448: return 0;
#endif
        default: return 1;
    }
}
#if !defined(MBEDTLS_ECDSA_SIGN_ALT)
int mbedtls_ecdsa_sign_restartable(mbedtls_ecp_group *grp,
                                   mbedtls_mpi *r, mbedtls_mpi *s,
                                   const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                   int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                                   int (*f_rng_blind)(void *, unsigned char *, size_t),
                                   void *p_rng_blind,
                                   mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (mbedtls_mpi_cmp_int(d, 1) < 0 || mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&k); mbedtls_mpi_init(&e); mbedtls_mpi_init(&t);
    ECDSA_RS_ENTER(sig);
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        p_sign_tries = &rs_ctx->sig->sign_tries;
        p_key_tries = &rs_ctx->sig->key_tries;
        pk = &rs_ctx->sig->k;
        pr = &rs_ctx->sig->r;
        if (rs_ctx->sig->state == ecdsa_sig_mul) {
            goto mul;
        }
        if (rs_ctx->sig->state == ecdsa_sig_modn) {
            goto modn;
        }
    }
#endif
    *p_sign_tries = 0;
    do {
        if ((*p_sign_tries)++ > 10) {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
        *p_key_tries = 0;
        do {
            if ((*p_key_tries)++ > 10) {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
            MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, pk, f_rng, p_rng));
#if defined(MBEDTLS_ECP_RESTARTABLE)
            if (rs_ctx != NULL && rs_ctx->sig != NULL) {
                rs_ctx->sig->state = ecdsa_sig_mul;
            }
mul:
#endif
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &R, pk, &grp->G,
                                                        f_rng_blind,
                                                        p_rng_blind,
                                                        ECDSA_RS_ECP));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pr, &R.X, &grp->N));
        } while (mbedtls_mpi_cmp_int(pr, 0) == 0);
#if defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && rs_ctx->sig != NULL) {
            rs_ctx->sig->state = ecdsa_sig_modn;
        }
modn:
#endif
        ECDSA_BUDGET(MBEDTLS_ECP_OPS_INV + 4);
        MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));
        MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, &t, f_rng_blind,
                                                p_rng_blind));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, pr, d));
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&e, &e, s));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&e, &e, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pk, pk, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pk, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(s, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, s, &e));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, s, &grp->N));
    } while (mbedtls_mpi_cmp_int(s, 0) == 0);
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(r, pr));
    }
#endif
cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&k); mbedtls_mpi_free(&e); mbedtls_mpi_free(&t);
    ECDSA_RS_LEAVE(sig);
    return ret;
}
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                          f_rng, p_rng, f_rng, p_rng, NULL);
}
#endif
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
int mbedtls_ecdsa_sign_det_restartable(mbedtls_ecp_group *grp,
                                       mbedtls_mpi *r, mbedtls_mpi *s,
                                       const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                                       mbedtls_md_type_t md_alg,
                                       int (*f_rng_blind)(void *, unsigned char *, size_t),
                                       void *p_rng_blind,
                                       mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_hmac_drbg_context rng_ctx;
    mbedtls_hmac_drbg_context *p_rng = &rng_ctx;
    unsigned char data[2 * MBEDTLS_ECP_MAX_BYTES];
    size_t grp_len = (grp->nbits + 7) / 8;
    const mbedtls_md_info_t *md_info;
    mbedtls_mpi h;
    if ((md_info = mbedtls_md_info_from_type(md_alg)) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    mbedtls_mpi_init(&h);
    mbedtls_hmac_drbg_init(&rng_ctx);
    ECDSA_RS_ENTER(det);
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->det != NULL) {
        p_rng = &rs_ctx->det->rng_ctx;
        if (rs_ctx->det->state == ecdsa_det_sign) {
            goto sign;
        }
    }
#endif
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(d, data, grp_len));
    MBEDTLS_MPI_CHK(derive_mpi(grp, &h, buf, blen));
    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&h, data + grp_len, grp_len));
    MBEDTLS_MPI_CHK(mbedtls_hmac_drbg_seed_buf(p_rng, md_info, data, 2 * grp_len));
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->det != NULL) {
        rs_ctx->det->state = ecdsa_det_sign;
    }
sign:
#endif
#if defined(MBEDTLS_ECDSA_SIGN_ALT)
    (void) f_rng_blind;
    (void) p_rng_blind;
    ret = mbedtls_ecdsa_sign(grp, r, s, d, buf, blen,
                             mbedtls_hmac_drbg_random, p_rng);
#else
    ret = mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen,
                                         mbedtls_hmac_drbg_random, p_rng,
                                         f_rng_blind, p_rng_blind, rs_ctx);
#endif
cleanup:
    mbedtls_hmac_drbg_free(&rng_ctx);
    mbedtls_mpi_free(&h);
    ECDSA_RS_LEAVE(det);
    return ret;
}
int mbedtls_ecdsa_sign_det_ext(mbedtls_ecp_group *grp, mbedtls_mpi *r,
                               mbedtls_mpi *s, const mbedtls_mpi *d,
                               const unsigned char *buf, size_t blen,
                               mbedtls_md_type_t md_alg,
                               int (*f_rng_blind)(void *, unsigned char *,
                                                  size_t),
                               void *p_rng_blind)
{
    return mbedtls_ecdsa_sign_det_restartable(grp, r, s, d, buf, blen, md_alg,
                                              f_rng_blind, p_rng_blind, NULL);
}
#endif
#if !defined(MBEDTLS_ECDSA_VERIFY_ALT)
int mbedtls_ecdsa_verify_restartable(mbedtls_ecp_group *grp,
                                     const unsigned char *buf, size_t blen,
                                     const mbedtls_ecp_point *Q,
                                     const mbedtls_mpi *r,
                                     const mbedtls_mpi *s,
                                     mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi e, s_inv, u1, u2;
    mbedtls_ecp_point R;
    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;
    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&e); mbedtls_mpi_init(&s_inv);
    mbedtls_mpi_init(&u1); mbedtls_mpi_init(&u2);
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    ECDSA_RS_ENTER(ver);
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        pu1 = &rs_ctx->ver->u1;
        pu2 = &rs_ctx->ver->u2;
        if (rs_ctx->ver->state == ecdsa_ver_muladd) {
            goto muladd;
        }
    }
#endif
    if (mbedtls_mpi_cmp_int(r, 1) < 0 || mbedtls_mpi_cmp_mpi(r, &grp->N) >= 0 ||
        mbedtls_mpi_cmp_int(s, 1) < 0 || mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));
    ECDSA_BUDGET(MBEDTLS_ECP_OPS_CHK + MBEDTLS_ECP_OPS_INV + 2);
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&s_inv, s, &grp->N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu1, &e, &s_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu1, pu1, &grp->N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu2, r, &s_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu2, pu2, &grp->N));
#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        rs_ctx->ver->state = ecdsa_ver_muladd;
    }
muladd:
#endif
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd_restartable(grp,
                                                   &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP));
    if (mbedtls_ecp_is_zero(&R)) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R.X, &R.X, &grp->N));
    if (mbedtls_mpi_cmp_mpi(&R.X, r) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }
cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&e); mbedtls_mpi_free(&s_inv);
    mbedtls_mpi_free(&u1); mbedtls_mpi_free(&u2);
    ECDSA_RS_LEAVE(ver);
    return ret;
}
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                         const unsigned char *buf, size_t blen,
                         const mbedtls_ecp_point *Q,
                         const mbedtls_mpi *r,
                         const mbedtls_mpi *s)
{
    return mbedtls_ecdsa_verify_restartable(grp, buf, blen, Q, r, s, NULL);
}
#endif
static int ecdsa_signature_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s,
                                   unsigned char *sig, size_t sig_size,
                                   size_t *slen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN] = { 0 };
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    if (len > sig_size) {
        return MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL;
    }
    memcpy(sig, p, len);
    *slen = len;
    return 0;
}
int mbedtls_ecdsa_write_signature_restartable(mbedtls_ecdsa_context *ctx,
                                              mbedtls_md_type_t md_alg,
                                              const unsigned char *hash, size_t hlen,
                                              unsigned char *sig, size_t sig_size, size_t *slen,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi r, s;
    if (f_rng == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_det_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                       hash, hlen, md_alg, f_rng,
                                                       p_rng, rs_ctx));
#else
    (void) md_alg;
#if defined(MBEDTLS_ECDSA_SIGN_ALT)
    (void) rs_ctx;
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign(&ctx->grp, &r, &s, &ctx->d,
                                       hash, hlen, f_rng, p_rng));
#else
    MBEDTLS_MPI_CHK(mbedtls_ecdsa_sign_restartable(&ctx->grp, &r, &s, &ctx->d,
                                                   hash, hlen, f_rng, p_rng, f_rng,
                                                   p_rng, rs_ctx));
#endif
#endif
    MBEDTLS_MPI_CHK(ecdsa_signature_to_asn1(&r, &s, sig, sig_size, slen));
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}
int mbedtls_ecdsa_write_signature(mbedtls_ecdsa_context *ctx,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hlen,
                                  unsigned char *sig, size_t sig_size, size_t *slen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    return mbedtls_ecdsa_write_signature_restartable(
        ctx, md_alg, hash, hlen, sig, sig_size, slen,
        f_rng, p_rng, NULL);
}
int mbedtls_ecdsa_read_signature(mbedtls_ecdsa_context *ctx,
                                 const unsigned char *hash, size_t hlen,
                                 const unsigned char *sig, size_t slen)
{
    return mbedtls_ecdsa_read_signature_restartable(
        ctx, hash, hlen, sig, slen, NULL);
}
int mbedtls_ecdsa_read_signature_restartable(mbedtls_ecdsa_context *ctx,
                                             const unsigned char *hash, size_t hlen,
                                             const unsigned char *sig, size_t slen,
                                             mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
    if (p + len != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        goto cleanup;
    }
    if ((ret = mbedtls_asn1_get_mpi(&p, end, &r)) != 0 ||
        (ret = mbedtls_asn1_get_mpi(&p, end, &s)) != 0) {
        ret += MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }
#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
    (void) rs_ctx;
    if ((ret = mbedtls_ecdsa_verify(&ctx->grp, hash, hlen,
                                    &ctx->Q, &r, &s)) != 0) {
        goto cleanup;
    }
#else
    if ((ret = mbedtls_ecdsa_verify_restartable(&ctx->grp, hash, hlen,
                                                &ctx->Q, &r, &s, rs_ctx)) != 0) {
        goto cleanup;
    }
#endif
    if (p != end) {
        ret = MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH;
    }
cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return ret;
}
#if !defined(MBEDTLS_ECDSA_GENKEY_ALT)
int mbedtls_ecdsa_genkey(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id gid,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = 0;
    ret = mbedtls_ecp_group_load(&ctx->grp, gid);
    if (ret != 0) {
        return ret;
    }
    return mbedtls_ecp_gen_keypair(&ctx->grp, &ctx->d,
                                   &ctx->Q, f_rng, p_rng);
}
#endif
int mbedtls_ecdsa_from_keypair(mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = mbedtls_ecp_group_copy(&ctx->grp, &key->grp)) != 0 ||
        (ret = mbedtls_mpi_copy(&ctx->d, &key->d)) != 0 ||
        (ret = mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0) {
        mbedtls_ecdsa_free(ctx);
    }
    return ret;
}
void mbedtls_ecdsa_init(mbedtls_ecdsa_context *ctx)
{
    mbedtls_ecp_keypair_init(ctx);
}
void mbedtls_ecdsa_free(mbedtls_ecdsa_context *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_ecp_keypair_free(ctx);
}
#if defined(MBEDTLS_ECP_RESTARTABLE)
void mbedtls_ecdsa_restart_init(mbedtls_ecdsa_restart_ctx *ctx)
{
    mbedtls_ecp_restart_init(&ctx->ecp);
    ctx->ver = NULL;
    ctx->sig = NULL;
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    ctx->det = NULL;
#endif
}
void mbedtls_ecdsa_restart_free(mbedtls_ecdsa_restart_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_ecp_restart_free(&ctx->ecp);
    ecdsa_restart_ver_free(ctx->ver);
    mbedtls_free(ctx->ver);
    ctx->ver = NULL;
    ecdsa_restart_sig_free(ctx->sig);
    mbedtls_free(ctx->sig);
    ctx->sig = NULL;
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    ecdsa_restart_det_free(ctx->det);
    mbedtls_free(ctx->det);
    ctx->det = NULL;
#endif
}
#endif
#endif
