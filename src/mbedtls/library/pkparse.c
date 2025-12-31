/*
 *  Public Key layer for parsing key files and structures
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_PK_PARSE_C)

#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/platform.h"
#include "mbedtls/error.h"
#include "mbedtls/ecp.h"
#include "pk_internal.h"

#include <string.h>

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "mbedtls/psa_util.h"
#include "psa/crypto.h"
#endif

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#include "rsa_internal.h"
#endif

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif
#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif
#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)

#if !defined(MBEDTLS_PK_PARSE_EC_EXTENDED)

static int pk_ecc_tag_is_specified_ec_domain(int tag)
{
    (void) tag;
    return 0;
}

static int pk_ecc_group_id_from_specified(const mbedtls_asn1_buf *params,
                                          mbedtls_ecp_group_id *grp_id)
{
    (void) params;
    (void) grp_id;
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
}
#else

static int pk_ecc_tag_is_specified_ec_domain(int tag)
{
    return tag == (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
}

static int pk_group_from_specified(const mbedtls_asn1_buf *params, mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = params->p;
    const unsigned char *const end = params->p + params->len;
    const unsigned char *end_field, *end_curve;
    size_t len;
    int ver;

    if ((ret = mbedtls_asn1_get_int(&p, end, &ver)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    if (ver < 1 || ver > 3) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    end_field = p + len;

    if ((ret = mbedtls_asn1_get_tag(&p, end_field, &len, MBEDTLS_ASN1_OID)) != 0) {
        return ret;
    }

    if (len != MBEDTLS_OID_SIZE(MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD) ||
        memcmp(p, MBEDTLS_OID_ANSI_X9_62_PRIME_FIELD, len) != 0) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    p += len;

    if ((ret = mbedtls_asn1_get_mpi(&p, end_field, &grp->P)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    if (p != end_field) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return ret;
    }

    end_curve = p + len;

    if ((ret = mbedtls_asn1_get_tag(&p, end_curve, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0 ||
        (ret = mbedtls_mpi_read_binary(&grp->A, p, len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    p += len;

    if ((ret = mbedtls_asn1_get_tag(&p, end_curve, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0 ||
        (ret = mbedtls_mpi_read_binary(&grp->B, p, len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    p += len;

    if ((ret = mbedtls_asn1_get_tag(&p, end_curve, &len, MBEDTLS_ASN1_BIT_STRING)) == 0) {
        p += len;
    }

    if (p != end_curve) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    if ((ret = mbedtls_ecp_point_read_binary(grp, &grp->G,
                                             (const unsigned char *) p, len)) != 0) {

        if (ret != MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE ||
            (p[0] != 0x02 && p[0] != 0x03) ||
            len != mbedtls_mpi_size(&grp->P) + 1 ||
            mbedtls_mpi_read_binary(&grp->G.X, p + 1, len - 1) != 0 ||
            mbedtls_mpi_lset(&grp->G.Y, p[0] - 2) != 0 ||
            mbedtls_mpi_lset(&grp->G.Z, 1) != 0) {
            return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
        }
    }

    p += len;

    if ((ret = mbedtls_asn1_get_mpi(&p, end, &grp->N)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    grp->nbits = mbedtls_mpi_bitlen(&grp->N);

    return 0;
}

static int pk_group_id_from_group(const mbedtls_ecp_group *grp, mbedtls_ecp_group_id *grp_id)
{
    int ret = 0;
    mbedtls_ecp_group ref;
    const mbedtls_ecp_group_id *id;

    mbedtls_ecp_group_init(&ref);

    for (id = mbedtls_ecp_grp_id_list(); *id != MBEDTLS_ECP_DP_NONE; id++) {

        mbedtls_ecp_group_free(&ref);
        MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&ref, *id));

        if (grp->pbits == ref.pbits && grp->nbits == ref.nbits &&
            mbedtls_mpi_cmp_mpi(&grp->P, &ref.P) == 0 &&
            mbedtls_mpi_cmp_mpi(&grp->A, &ref.A) == 0 &&
            mbedtls_mpi_cmp_mpi(&grp->B, &ref.B) == 0 &&
            mbedtls_mpi_cmp_mpi(&grp->N, &ref.N) == 0 &&
            mbedtls_mpi_cmp_mpi(&grp->G.X, &ref.G.X) == 0 &&
            mbedtls_mpi_cmp_mpi(&grp->G.Z, &ref.G.Z) == 0 &&

            mbedtls_mpi_get_bit(&grp->G.Y, 0) == mbedtls_mpi_get_bit(&ref.G.Y, 0)) {
            break;
        }
    }

cleanup:
    mbedtls_ecp_group_free(&ref);

    *grp_id = *id;

    if (ret == 0 && *id == MBEDTLS_ECP_DP_NONE) {
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    return ret;
}

static int pk_ecc_group_id_from_specified(const mbedtls_asn1_buf *params,
                                          mbedtls_ecp_group_id *grp_id)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group grp;

    mbedtls_ecp_group_init(&grp);

    if ((ret = pk_group_from_specified(params, &grp)) != 0) {
        goto cleanup;
    }

    ret = pk_group_id_from_group(&grp, grp_id);

cleanup:

    mbedtls_mpi_free(&grp.N);
    mbedtls_mpi_free(&grp.P);
    mbedtls_mpi_free(&grp.A);
    mbedtls_mpi_free(&grp.B);
    mbedtls_ecp_point_free(&grp.G);

    return ret;
}
#endif

static int pk_get_ecparams(unsigned char **p, const unsigned char *end,
                           mbedtls_asn1_buf *params)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (end - *p < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    params->tag = **p;
    if (params->tag != MBEDTLS_ASN1_OID &&
        !pk_ecc_tag_is_specified_ec_domain(params->tag)) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
    }

    if ((ret = mbedtls_asn1_get_tag(p, end, &params->len, params->tag)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    params->p = *p;
    *p += params->len;

    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

static int pk_use_ecparams(const mbedtls_asn1_buf *params, mbedtls_pk_context *pk)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group_id grp_id;

    if (params->tag == MBEDTLS_ASN1_OID) {
        if (mbedtls_oid_get_ec_grp(params, &grp_id) != 0) {
            return MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE;
        }
    } else {
        ret = pk_ecc_group_id_from_specified(params, &grp_id);
        if (ret != 0) {
            return ret;
        }
    }

    return mbedtls_pk_ecc_set_group(pk, grp_id);
}

#if defined(MBEDTLS_PK_HAVE_RFC8410_CURVES)

static int pk_use_ecparams_rfc8410(const mbedtls_asn1_buf *params,
                                   mbedtls_ecp_group_id grp_id,
                                   mbedtls_pk_context *pk)
{
    if (params->tag != 0 || params->len != 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    return mbedtls_pk_ecc_set_group(pk, grp_id);
}

static int pk_parse_key_rfc8410_der(mbedtls_pk_context *pk,
                                    unsigned char *key, size_t keylen, const unsigned char *end,
                                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;

    if ((ret = mbedtls_asn1_get_tag(&key, (key + keylen), &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    if (key + len != end) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    ret = mbedtls_pk_ecc_set_key(pk, key, len);
    if (ret != 0) {
        return ret;
    }

    if ((ret = mbedtls_pk_ecc_set_pubkey_from_prv(pk, key, len, f_rng, p_rng)) != 0) {
        return ret;
    }

    return 0;
}
#endif

#endif

static int pk_get_pk_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_pk_type_t *pk_alg, mbedtls_asn1_buf *params,
                         mbedtls_ecp_group_id *ec_grp_id)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_asn1_buf alg_oid;

    memset(params, 0, sizeof(mbedtls_asn1_buf));

    if ((ret = mbedtls_asn1_get_alg(p, end, &alg_oid, params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_ALG, ret);
    }

    ret = mbedtls_oid_get_pk_alg(&alg_oid, pk_alg);
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    if (ret == MBEDTLS_ERR_OID_NOT_FOUND) {
        ret = mbedtls_oid_get_ec_grp_algid(&alg_oid, ec_grp_id);
        if (ret == 0) {
            *pk_alg = MBEDTLS_PK_ECKEY;
        }
    }
#else
    (void) ec_grp_id;
#endif
    if (ret != 0) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if (*pk_alg == MBEDTLS_PK_RSA &&
        ((params->tag != MBEDTLS_ASN1_NULL && params->tag != 0) ||
         params->len != 0)) {
        return MBEDTLS_ERR_PK_INVALID_ALG;
    }

    return 0;
}

int mbedtls_pk_parse_subpubkey(unsigned char **p, const unsigned char *end,
                               mbedtls_pk_context *pk)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    mbedtls_asn1_buf alg_params;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    mbedtls_ecp_group_id ec_grp_id = MBEDTLS_ECP_DP_NONE;
    const mbedtls_pk_info_t *pk_info;

    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = *p + len;

    if ((ret = pk_get_pk_alg(p, end, &pk_alg, &alg_params, &ec_grp_id)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_asn1_get_bitstring_null(p, end, &len)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY, ret);
    }

    if (*p + len != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if ((pk_info = mbedtls_pk_info_from_type(pk_alg)) == NULL) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0) {
        return ret;
    }

#if defined(MBEDTLS_RSA_C)
    if (pk_alg == MBEDTLS_PK_RSA) {
        ret = mbedtls_rsa_parse_pubkey(mbedtls_pk_rsa(*pk), *p, (size_t) (end - *p));
        if (ret == 0) {

            *p += end - *p;
        } else if ((ret <= MBEDTLS_ERR_ASN1_OUT_OF_DATA) &&
                   (ret >= MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)) {

            ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY, ret);
        } else {
            ret = MBEDTLS_ERR_PK_INVALID_PUBKEY;
        }
    } else
#endif
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    if (pk_alg == MBEDTLS_PK_ECKEY_DH || pk_alg == MBEDTLS_PK_ECKEY) {
#if defined(MBEDTLS_PK_HAVE_RFC8410_CURVES)
        if (MBEDTLS_PK_IS_RFC8410_GROUP_ID(ec_grp_id)) {
            ret = pk_use_ecparams_rfc8410(&alg_params, ec_grp_id, pk);
        } else
#endif
        {
            ret = pk_use_ecparams(&alg_params, pk);
        }
        if (ret == 0) {
            ret = mbedtls_pk_ecc_set_pubkey(pk, *p, (size_t) (end - *p));
            *p += end - *p;
        }
    } else
#endif
    ret = MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;

    if (ret == 0 && *p != end) {
        ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_INVALID_PUBKEY,
                                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    if (ret != 0) {
        mbedtls_pk_free(pk);
    }

    return ret;
}

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)

static int pk_parse_key_sec1_der(mbedtls_pk_context *pk,
                                 const unsigned char *key, size_t keylen,
                                 int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int version, pubkey_done;
    size_t len, d_len;
    mbedtls_asn1_buf params = { 0, 0, NULL };
    unsigned char *p = (unsigned char *) key;
    unsigned char *d;
    unsigned char *end = p + keylen;
    unsigned char *end2;

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = p + len;

    if ((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    if (version != 1) {
        return MBEDTLS_ERR_PK_KEY_INVALID_VERSION;
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    d = p;
    d_len = len;

    p += len;

    pubkey_done = 0;
    if (p != end) {

        if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                        0)) == 0) {
            if ((ret = pk_get_ecparams(&p, p + len, &params)) != 0 ||
                (ret = pk_use_ecparams(&params, pk)) != 0) {
                return ret;
            }
        } else if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
        }
    }

    ret = mbedtls_pk_ecc_set_key(pk, d, d_len);
    if (ret != 0) {
        return ret;
    }

    if (p != end) {

        if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                        1)) == 0) {
            end2 = p + len;

            if ((ret = mbedtls_asn1_get_bitstring_null(&p, end2, &len)) != 0) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
            }

            if (p + len != end2) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                         MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
            }

            if ((ret = mbedtls_pk_ecc_set_pubkey(pk, p, (size_t) (end2 - p))) == 0) {
                pubkey_done = 1;
            } else {

                if (ret != MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE) {
                    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
                }
            }
        } else if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
        }
    }

    if (!pubkey_done) {
        if ((ret = mbedtls_pk_ecc_set_pubkey_from_prv(pk, d, d_len, f_rng, p_rng)) != 0) {
            return ret;
        }
    }

    return 0;
}
#endif

static int pk_parse_key_pkcs8_unencrypted_der(
    mbedtls_pk_context *pk,
    const unsigned char *key, size_t keylen,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret, version;
    size_t len;
    mbedtls_asn1_buf params;
    unsigned char *p = (unsigned char *) key;
    unsigned char *end = p + keylen;
    mbedtls_pk_type_t pk_alg = MBEDTLS_PK_NONE;
    mbedtls_ecp_group_id ec_grp_id = MBEDTLS_ECP_DP_NONE;
    const mbedtls_pk_info_t *pk_info;

#if !defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    (void) f_rng;
    (void) p_rng;
#endif

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = p + len;

    if ((ret = mbedtls_asn1_get_int(&p, end, &version)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    if (version != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_VERSION, ret);
    }

    if ((ret = pk_get_pk_alg(&p, end, &pk_alg, &params, &ec_grp_id)) != 0) {
        return ret;
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    if (len < 1) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_OUT_OF_DATA);
    }

    if ((pk_info = mbedtls_pk_info_from_type(pk_alg)) == NULL) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0) {
        return ret;
    }

#if defined(MBEDTLS_RSA_C)
    if (pk_alg == MBEDTLS_PK_RSA) {
        if ((ret = mbedtls_rsa_parse_key(mbedtls_pk_rsa(*pk), p, len)) != 0) {
            mbedtls_pk_free(pk);
            return ret;
        }
    } else
#endif
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    if (pk_alg == MBEDTLS_PK_ECKEY || pk_alg == MBEDTLS_PK_ECKEY_DH) {
#if defined(MBEDTLS_PK_HAVE_RFC8410_CURVES)
        if (MBEDTLS_PK_IS_RFC8410_GROUP_ID(ec_grp_id)) {
            if ((ret =
                     pk_use_ecparams_rfc8410(&params, ec_grp_id, pk)) != 0 ||
                (ret =
                     pk_parse_key_rfc8410_der(pk, p, len, end, f_rng,
                                              p_rng)) != 0) {
                mbedtls_pk_free(pk);
                return ret;
            }
        } else
#endif
        {
            if ((ret = pk_use_ecparams(&params, pk)) != 0 ||
                (ret = pk_parse_key_sec1_der(pk, p, len, f_rng, p_rng)) != 0) {
                mbedtls_pk_free(pk);
                return ret;
            }
        }
    } else
#endif
    return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;

    end = p + len;
    if (end != (key + keylen)) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }

    return 0;
}

#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
MBEDTLS_STATIC_TESTABLE int mbedtls_pk_parse_key_pkcs8_encrypted_der(
    mbedtls_pk_context *pk,
    unsigned char *key, size_t keylen,
    const unsigned char *pwd, size_t pwdlen,
    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret, decrypted = 0;
    size_t len;
    unsigned char *buf;
    unsigned char *p, *end;
    mbedtls_asn1_buf pbe_alg_oid, pbe_params;
#if defined(MBEDTLS_PKCS12_C) && defined(MBEDTLS_CIPHER_PADDING_PKCS7) && defined(MBEDTLS_CIPHER_C)
    mbedtls_cipher_type_t cipher_alg;
    mbedtls_md_type_t md_alg;
#endif
    size_t outlen = 0;

    p = key;
    end = p + keylen;

    if (pwdlen == 0) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    end = p + len;

    if ((ret = mbedtls_asn1_get_alg(&p, end, &pbe_alg_oid, &pbe_params)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    if ((ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_PK_KEY_INVALID_FORMAT, ret);
    }

    buf = p;

#if defined(MBEDTLS_PKCS12_C) && defined(MBEDTLS_CIPHER_PADDING_PKCS7) && defined(MBEDTLS_CIPHER_C)
    if (mbedtls_oid_get_pkcs12_pbe_alg(&pbe_alg_oid, &md_alg, &cipher_alg) == 0) {
        if ((ret = mbedtls_pkcs12_pbe_ext(&pbe_params, MBEDTLS_PKCS12_PBE_DECRYPT,
                                          cipher_alg, md_alg,
                                          pwd, pwdlen, p, len, buf, len, &outlen)) != 0) {
            if (ret == MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH) {
                return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
            }

            return ret;
        }

        decrypted = 1;
    } else
#endif
#if defined(MBEDTLS_PKCS5_C) && defined(MBEDTLS_CIPHER_PADDING_PKCS7) && defined(MBEDTLS_CIPHER_C)
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_PKCS5_PBES2, &pbe_alg_oid) == 0) {
        if ((ret = mbedtls_pkcs5_pbes2_ext(&pbe_params, MBEDTLS_PKCS5_DECRYPT, pwd, pwdlen,
                                           p, len, buf, len, &outlen)) != 0) {
            if (ret == MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH) {
                return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
            }

            return ret;
        }

        decrypted = 1;
    } else
#endif
    {
        ((void) pwd);
    }

    if (decrypted == 0) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }
    return pk_parse_key_pkcs8_unencrypted_der(pk, buf, outlen, f_rng, p_rng);
}
#endif

int mbedtls_pk_parse_key(mbedtls_pk_context *pk,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *pwd, size_t pwdlen,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_pk_info_t *pk_info;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;
#endif

    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_init(&pem);

#if defined(MBEDTLS_RSA_C)

    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      PEM_BEGIN_PRIVATE_KEY_RSA, PEM_END_PRIVATE_KEY_RSA,
                                      key, pwd, pwdlen, &len);
    }

    if (ret == 0) {
        pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
        if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0 ||
            (ret = mbedtls_rsa_parse_key(mbedtls_pk_rsa(*pk),
                                         pem.buf, pem.buflen)) != 0) {
            mbedtls_pk_free(pk);
        }

        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)

    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      PEM_BEGIN_PRIVATE_KEY_EC,
                                      PEM_END_PRIVATE_KEY_EC,
                                      key, pwd, pwdlen, &len);
    }
    if (ret == 0) {
        pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);

        if ((ret = mbedtls_pk_setup(pk, pk_info)) != 0 ||
            (ret = pk_parse_key_sec1_der(pk,
                                         pem.buf, pem.buflen,
                                         f_rng, p_rng)) != 0) {
            mbedtls_pk_free(pk);
        }

        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif

    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      PEM_BEGIN_PRIVATE_KEY_PKCS8, PEM_END_PRIVATE_KEY_PKCS8,
                                      key, NULL, 0, &len);
    }
    if (ret == 0) {
        if ((ret = pk_parse_key_pkcs8_unencrypted_der(pk,
                                                      pem.buf, pem.buflen, f_rng, p_rng)) != 0) {
            mbedtls_pk_free(pk);
        }

        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }

#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)

    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      PEM_BEGIN_ENCRYPTED_PRIVATE_KEY_PKCS8,
                                      PEM_END_ENCRYPTED_PRIVATE_KEY_PKCS8,
                                      key, NULL, 0, &len);
    }
    if (ret == 0) {
        if ((ret = mbedtls_pk_parse_key_pkcs8_encrypted_der(pk, pem.buf, pem.buflen,
                                                            pwd, pwdlen, f_rng, p_rng)) != 0) {
            mbedtls_pk_free(pk);
        }

        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif
#else
    ((void) pwd);
    ((void) pwdlen);
#endif

#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    if (pwdlen != 0) {
        unsigned char *key_copy;

        if ((key_copy = mbedtls_calloc(1, keylen)) == NULL) {
            return MBEDTLS_ERR_PK_ALLOC_FAILED;
        }

        memcpy(key_copy, key, keylen);

        ret = mbedtls_pk_parse_key_pkcs8_encrypted_der(pk, key_copy, keylen,
                                                       pwd, pwdlen, f_rng, p_rng);

        mbedtls_zeroize_and_free(key_copy, keylen);
    }

    if (ret == 0) {
        return 0;
    }

    mbedtls_pk_free(pk);
    mbedtls_pk_init(pk);

    if (ret == MBEDTLS_ERR_PK_PASSWORD_MISMATCH) {
        return ret;
    }
#endif

    ret = pk_parse_key_pkcs8_unencrypted_der(pk, key, keylen, f_rng, p_rng);
    if (ret == 0) {
        return 0;
    }

    mbedtls_pk_free(pk);
    mbedtls_pk_init(pk);

#if defined(MBEDTLS_RSA_C)

    pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    if (mbedtls_pk_setup(pk, pk_info) == 0 &&
        mbedtls_rsa_parse_key(mbedtls_pk_rsa(*pk), key, keylen) == 0) {
        return 0;
    }

    mbedtls_pk_free(pk);
    mbedtls_pk_init(pk);
#endif

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    if (mbedtls_pk_setup(pk, pk_info) == 0 &&
        pk_parse_key_sec1_der(pk,
                              key, keylen, f_rng, p_rng) == 0) {
        return 0;
    }
    mbedtls_pk_free(pk);
#endif

    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
}

int mbedtls_pk_parse_public_key(mbedtls_pk_context *ctx,
                                const unsigned char *key, size_t keylen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p;
#if defined(MBEDTLS_RSA_C)
    const mbedtls_pk_info_t *pk_info;
#endif
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
    mbedtls_pem_context pem;
#endif

    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_init(&pem);
#if defined(MBEDTLS_RSA_C)

    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      PEM_BEGIN_PUBLIC_KEY_RSA, PEM_END_PUBLIC_KEY_RSA,
                                      key, NULL, 0, &len);
    }

    if (ret == 0) {
        p = pem.buf;
        if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == NULL) {
            mbedtls_pem_free(&pem);
            return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
        }

        if ((ret = mbedtls_pk_setup(ctx, pk_info)) != 0) {
            mbedtls_pem_free(&pem);
            return ret;
        }

        if ((ret = mbedtls_rsa_parse_pubkey(mbedtls_pk_rsa(*ctx), p, pem.buflen)) != 0) {
            mbedtls_pk_free(ctx);
        }

        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        mbedtls_pem_free(&pem);
        return ret;
    }
#endif

    if (key[keylen - 1] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(&pem,
                                      PEM_BEGIN_PUBLIC_KEY, PEM_END_PUBLIC_KEY,
                                      key, NULL, 0, &len);
    }

    if (ret == 0) {

        p = pem.buf;

        ret = mbedtls_pk_parse_subpubkey(&p, p + pem.buflen, ctx);
        mbedtls_pem_free(&pem);
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        mbedtls_pem_free(&pem);
        return ret;
    }
    mbedtls_pem_free(&pem);
#endif

#if defined(MBEDTLS_RSA_C)
    if ((pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) == NULL) {
        return MBEDTLS_ERR_PK_UNKNOWN_PK_ALG;
    }

    if ((ret = mbedtls_pk_setup(ctx, pk_info)) != 0) {
        return ret;
    }

    p = (unsigned char *) key;
    ret = mbedtls_rsa_parse_pubkey(mbedtls_pk_rsa(*ctx), p, keylen);
    if (ret == 0) {
        return ret;
    }
    mbedtls_pk_free(ctx);
    if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        return ret;
    }
#endif
    p = (unsigned char *) key;

    ret = mbedtls_pk_parse_subpubkey(&p, p + keylen, ctx);

    return ret;
}

#if defined(MBEDTLS_FS_IO)

int mbedtls_pk_load_file(const char *path, unsigned char **buf, size_t *n)
{
    FILE *f;
    long size;

    if ((f = fopen(path, "rb")) == NULL) {
        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }

    mbedtls_setbuf(f, NULL);

    fseek(f, 0, SEEK_END);
    if ((size = ftell(f)) == -1) {
        fclose(f);
        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }
    fseek(f, 0, SEEK_SET);

    *n = (size_t) size;

    if (*n + 1 == 0 ||
        (*buf = mbedtls_calloc(1, *n + 1)) == NULL) {
        fclose(f);
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    if (fread(*buf, 1, *n, f) != *n) {
        fclose(f);

        mbedtls_zeroize_and_free(*buf, *n);

        return MBEDTLS_ERR_PK_FILE_IO_ERROR;
    }

    fclose(f);

    (*buf)[*n] = '\0';

    if (strstr((const char *) *buf, "-----BEGIN ") != NULL) {
        ++*n;
    }

    return 0;
}

int mbedtls_pk_parse_keyfile(mbedtls_pk_context *ctx,
                             const char *path, const char *pwd,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char *buf;

    if ((ret = mbedtls_pk_load_file(path, &buf, &n)) != 0) {
        return ret;
    }

    if (pwd == NULL) {
        ret = mbedtls_pk_parse_key(ctx, buf, n, NULL, 0, f_rng, p_rng);
    } else {
        ret = mbedtls_pk_parse_key(ctx, buf, n,
                                   (const unsigned char *) pwd, strlen(pwd), f_rng, p_rng);
    }

    mbedtls_zeroize_and_free(buf, n);

    return ret;
}

int mbedtls_pk_parse_public_keyfile(mbedtls_pk_context *ctx, const char *path)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char *buf;

    if ((ret = mbedtls_pk_load_file(path, &buf, &n)) != 0) {
        return ret;
    }

    ret = mbedtls_pk_parse_public_key(ctx, buf, n);

    mbedtls_zeroize_and_free(buf, n);

    return ret;
}
#endif

#endif
