/*
 *  X.509 certificate parsing and verification
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/x509_crt.h"
#include "x509_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "psa_util_internal.h"
#include "mbedtls/psa_util.h"
#endif
#include "pk_internal.h"
#include "mbedtls/platform.h"
#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif
#if defined(MBEDTLS_HAVE_TIME)
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 
#endif
#include <windows.h>
#else
#include <time.h>
#endif
#endif
#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#if !defined(_WIN32) || defined(EFIX64) || defined(EFI32)
#include <sys/types.h>
#include <sys/stat.h>
#if defined(__MBED__)
#include <platform/mbed_retarget.h>
#else
#include <dirent.h>
#endif
#include <errno.h>
#endif
#endif
typedef struct {
    mbedtls_x509_crt *crt;
    uint32_t flags;
} x509_crt_verify_chain_item;
#define X509_MAX_VERIFY_CHAIN_SIZE (MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2)
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default =
{
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
    0xFFFFFFF,
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP521R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_BP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_BP384R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_BP512R1) |
    0,
#else
    0,
#endif
    2048,
};
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next =
{
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA512),
    0xFFFFFFF,
#if defined(MBEDTLS_ECP_C)
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP521R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_BP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_BP384R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_BP512R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256K1),
#else
    0,
#endif
    2048,
};
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb =
{
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384),
    MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECDSA) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECKEY),
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1),
#else
    0,
#endif
    0,
};
const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_none =
{
    0,
    0,
    0,
    (uint32_t) -1,
};
static int x509_profile_check_md_alg(const mbedtls_x509_crt_profile *profile,
                                     mbedtls_md_type_t md_alg)
{
    if (md_alg == MBEDTLS_MD_NONE) {
        return -1;
    }
    if ((profile->allowed_mds & MBEDTLS_X509_ID_FLAG(md_alg)) != 0) {
        return 0;
    }
    return -1;
}
static int x509_profile_check_pk_alg(const mbedtls_x509_crt_profile *profile,
                                     mbedtls_pk_type_t pk_alg)
{
    if (pk_alg == MBEDTLS_PK_NONE) {
        return -1;
    }
    if ((profile->allowed_pks & MBEDTLS_X509_ID_FLAG(pk_alg)) != 0) {
        return 0;
    }
    return -1;
}
static int x509_profile_check_key(const mbedtls_x509_crt_profile *profile,
                                  const mbedtls_pk_context *pk)
{
    const mbedtls_pk_type_t pk_alg = mbedtls_pk_get_type(pk);
#if defined(MBEDTLS_RSA_C)
    if (pk_alg == MBEDTLS_PK_RSA || pk_alg == MBEDTLS_PK_RSASSA_PSS) {
        if (mbedtls_pk_get_bitlen(pk) >= profile->rsa_min_bitlen) {
            return 0;
        }
        return -1;
    }
#endif
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    if (pk_alg == MBEDTLS_PK_ECDSA ||
        pk_alg == MBEDTLS_PK_ECKEY ||
        pk_alg == MBEDTLS_PK_ECKEY_DH) {
        const mbedtls_ecp_group_id gid = mbedtls_pk_get_ec_group_id(pk);
        if (gid == MBEDTLS_ECP_DP_NONE) {
            return -1;
        }
        if ((profile->allowed_curves & MBEDTLS_X509_ID_FLAG(gid)) != 0) {
            return 0;
        }
        return -1;
    }
#endif
    return -1;
}
static int x509_memcasecmp(const void *s1, const void *s2, size_t len)
{
    size_t i;
    unsigned char diff;
    const unsigned char *n1 = s1, *n2 = s2;
    for (i = 0; i < len; i++) {
        diff = n1[i] ^ n2[i];
        if (diff == 0) {
            continue;
        }
        if (diff == 32 &&
            ((n1[i] >= 'a' && n1[i] <= 'z') ||
             (n1[i] >= 'A' && n1[i] <= 'Z'))) {
            continue;
        }
        return -1;
    }
    return 0;
}
static int x509_check_wildcard(const char *cn, const mbedtls_x509_buf *name)
{
    size_t i;
    size_t cn_idx = 0, cn_len = strlen(cn);
    if (name->len < 3 || name->p[0] != '*' || name->p[1] != '.') {
        return -1;
    }
    for (i = 0; i < cn_len; ++i) {
        if (cn[i] == '.') {
            cn_idx = i;
            break;
        }
    }
    if (cn_idx == 0) {
        return -1;
    }
    if (cn_len - cn_idx == name->len - 1 &&
        x509_memcasecmp(name->p + 1, cn + cn_idx, name->len - 1) == 0) {
        return 0;
    }
    return -1;
}
static int x509_string_cmp(const mbedtls_x509_buf *a, const mbedtls_x509_buf *b)
{
    if (a->tag == b->tag &&
        a->len == b->len &&
        memcmp(a->p, b->p, b->len) == 0) {
        return 0;
    }
    if ((a->tag == MBEDTLS_ASN1_UTF8_STRING || a->tag == MBEDTLS_ASN1_PRINTABLE_STRING) &&
        (b->tag == MBEDTLS_ASN1_UTF8_STRING || b->tag == MBEDTLS_ASN1_PRINTABLE_STRING) &&
        a->len == b->len &&
        x509_memcasecmp(a->p, b->p, b->len) == 0) {
        return 0;
    }
    return -1;
}
static int x509_name_cmp(const mbedtls_x509_name *a, const mbedtls_x509_name *b)
{
    while (a != NULL || b != NULL) {
        if (a == NULL || b == NULL) {
            return -1;
        }
        if (a->oid.tag != b->oid.tag ||
            a->oid.len != b->oid.len ||
            memcmp(a->oid.p, b->oid.p, b->oid.len) != 0) {
            return -1;
        }
        if (x509_string_cmp(&a->val, &b->val) != 0) {
            return -1;
        }
        if (a->next_merged != b->next_merged) {
            return -1;
        }
        a = a->next;
        b = b->next;
    }
    return 0;
}
static void x509_crt_verify_chain_reset(
    mbedtls_x509_crt_verify_chain *ver_chain)
{
    size_t i;
    for (i = 0; i < MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE; i++) {
        ver_chain->items[i].crt = NULL;
        ver_chain->items[i].flags = (uint32_t) -1;
    }
    ver_chain->len = 0;
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    ver_chain->trust_ca_cb_result = NULL;
#endif
}
static int x509_get_version(unsigned char **p,
                            const unsigned char *end,
                            int *ver)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                    0)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            *ver = 0;
            return 0;
        }
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    end = *p + len;
    if ((ret = mbedtls_asn1_get_int(p, end, ver)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION, ret);
    }
    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_VERSION,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    return 0;
}
static int x509_get_dates(unsigned char **p,
                          const unsigned char *end,
                          mbedtls_x509_time *from,
                          mbedtls_x509_time *to)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE, ret);
    }
    end = *p + len;
    if ((ret = mbedtls_x509_get_time(p, end, from)) != 0) {
        return ret;
    }
    if ((ret = mbedtls_x509_get_time(p, end, to)) != 0) {
        return ret;
    }
    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_DATE,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    return 0;
}
static int x509_get_uid(unsigned char **p,
                        const unsigned char *end,
                        mbedtls_x509_buf *uid, int n)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (*p == end) {
        return 0;
    }
    uid->tag = **p;
    if ((ret = mbedtls_asn1_get_tag(p, end, &uid->len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                    n)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            return 0;
        }
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    uid->p = *p;
    *p += uid->len;
    return 0;
}
static int x509_get_basic_constraints(unsigned char **p,
                                      const unsigned char *end,
                                      int *ca_istrue,
                                      int *max_pathlen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    *ca_istrue = 0;
    *max_pathlen = 0;
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    if (*p == end) {
        return 0;
    }
    if ((ret = mbedtls_asn1_get_bool(p, end, ca_istrue)) != 0) {
        if (ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
            ret = mbedtls_asn1_get_int(p, end, ca_istrue);
        }
        if (ret != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        if (*ca_istrue != 0) {
            *ca_istrue = 1;
        }
    }
    if (*p == end) {
        return 0;
    }
    if ((ret = mbedtls_asn1_get_int(p, end, max_pathlen)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    if (*max_pathlen == INT_MAX) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }
    (*max_pathlen)++;
    return 0;
}
static int x509_get_ext_key_usage(unsigned char **p,
                                  const unsigned char *end,
                                  mbedtls_x509_sequence *ext_key_usage)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = mbedtls_asn1_get_sequence_of(p, end, ext_key_usage, MBEDTLS_ASN1_OID)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    if (ext_key_usage->buf.p == NULL) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_INVALID_LENGTH);
    }
    return 0;
}
static int x509_get_subject_key_id(unsigned char **p,
                                   const unsigned char *end,
                                   mbedtls_x509_buf *subject_key_id)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0u;
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_OCTET_STRING)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    subject_key_id->len = len;
    subject_key_id->tag = MBEDTLS_ASN1_OCTET_STRING;
    subject_key_id->p = *p;
    *p += len;
    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    return 0;
}
static int x509_get_authority_key_id(unsigned char **p,
                                     unsigned char *end,
                                     mbedtls_x509_authority *authority_key_id)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0u;
    if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    if (*p + len != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    ret = mbedtls_asn1_get_tag(p, end, &len,
                               MBEDTLS_ASN1_CONTEXT_SPECIFIC);
    if (ret == 0) {
        authority_key_id->keyIdentifier.len = len;
        authority_key_id->keyIdentifier.p = *p;
        authority_key_id->keyIdentifier.tag = MBEDTLS_ASN1_OCTET_STRING;
        *p += len;
    } else if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    if (*p < end) {
        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED |
                                        1)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        ret = mbedtls_x509_get_subject_alt_name_ext(p,
                                                    (*p+len),
                                                    &authority_key_id->authorityCertIssuer);
        if (ret != 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        authority_key_id->authorityCertSerialNumber.len = len;
        authority_key_id->authorityCertSerialNumber.p = *p;
        authority_key_id->authorityCertSerialNumber.tag = MBEDTLS_ASN1_INTEGER;
        *p += len;
    }
    if (*p != end) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS +
               MBEDTLS_ERR_ASN1_LENGTH_MISMATCH;
    }
    return 0;
}
static int x509_get_certificate_policies(unsigned char **p,
                                         const unsigned char *end,
                                         mbedtls_x509_sequence *certificate_policies)
{
    int ret, parse_ret = 0;
    size_t len;
    mbedtls_asn1_buf *buf;
    mbedtls_asn1_sequence *cur = certificate_policies;
    ret = mbedtls_asn1_get_tag(p, end, &len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
    }
    if (*p + len != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    if (len == 0) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    while (*p < end) {
        mbedtls_x509_buf policy_oid;
        const unsigned char *policy_end;
        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        policy_end = *p + len;
        if ((ret = mbedtls_asn1_get_tag(p, policy_end, &len,
                                        MBEDTLS_ASN1_OID)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        policy_oid.tag = MBEDTLS_ASN1_OID;
        policy_oid.len = len;
        policy_oid.p = *p;
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_ANY_POLICY, &policy_oid) != 0) {
            parse_ret = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
        }
        if (cur->buf.p != NULL) {
            if (cur->next != NULL) {
                return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            }
            cur->next = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
            if (cur->next == NULL) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                         MBEDTLS_ERR_ASN1_ALLOC_FAILED);
            }
            cur = cur->next;
        }
        buf = &(cur->buf);
        buf->tag = policy_oid.tag;
        buf->p = policy_oid.p;
        buf->len = policy_oid.len;
        *p += len;
        if (*p < policy_end) {
            if ((ret = mbedtls_asn1_get_tag(p, policy_end, &len,
                                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) !=
                0) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
            }
            *p += len;
        }
        if (*p != policy_end) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }
    }
    cur->next = NULL;
    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    return parse_ret;
}
static int x509_get_crt_ext(unsigned char **p,
                            const unsigned char *end,
                            mbedtls_x509_crt *crt,
                            mbedtls_x509_crt_ext_cb_t cb,
                            void *p_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *end_ext_data, *start_ext_octet, *end_ext_octet;
    if (*p == end) {
        return 0;
    }
    if ((ret = mbedtls_x509_get_ext(p, end, &crt->v3_ext, 3)) != 0) {
        return ret;
    }
    end = crt->v3_ext.p + crt->v3_ext.len;
    while (*p < end) {
        mbedtls_x509_buf extn_oid = { 0, 0, NULL };
        int is_critical = 0;
        int ext_type = 0;
        if ((ret = mbedtls_asn1_get_tag(p, end, &len,
                                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        end_ext_data = *p + len;
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &extn_oid.len,
                                        MBEDTLS_ASN1_OID)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        extn_oid.tag = MBEDTLS_ASN1_OID;
        extn_oid.p = *p;
        *p += extn_oid.len;
        if ((ret = mbedtls_asn1_get_bool(p, end_ext_data, &is_critical)) != 0 &&
            (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG)) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        if ((ret = mbedtls_asn1_get_tag(p, end_ext_data, &len,
                                        MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS, ret);
        }
        start_ext_octet = *p;
        end_ext_octet = *p + len;
        if (end_ext_octet != end_ext_data) {
            return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                     MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
        }
        ret = mbedtls_oid_get_x509_ext_type(&extn_oid, &ext_type);
        if (ret != 0) {
            if (cb != NULL) {
                ret = cb(p_ctx, crt, &extn_oid, is_critical, *p, end_ext_octet);
                if (ret != 0 && is_critical) {
                    return ret;
                }
                *p = end_ext_octet;
                continue;
            }
            *p = end_ext_octet;
            if (is_critical) {
                return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                         MBEDTLS_ERR_ASN1_UNEXPECTED_TAG);
            }
            continue;
        }
        if ((crt->ext_types & ext_type) != 0) {
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        crt->ext_types |= ext_type;
        switch (ext_type) {
            case MBEDTLS_X509_EXT_BASIC_CONSTRAINTS:
                if ((ret = x509_get_basic_constraints(p, end_ext_octet,
                                                      &crt->ca_istrue, &crt->max_pathlen)) != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_X509_EXT_KEY_USAGE:
                if ((ret = mbedtls_x509_get_key_usage(p, end_ext_octet,
                                                      &crt->key_usage)) != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE:
                if ((ret = x509_get_ext_key_usage(p, end_ext_octet,
                                                  &crt->ext_key_usage)) != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER:
                if ((ret = x509_get_subject_key_id(p, end_ext_data,
                                                   &crt->subject_key_id)) != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER:
                if ((ret = x509_get_authority_key_id(p, end_ext_octet,
                                                     &crt->authority_key_id)) != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_X509_EXT_SUBJECT_ALT_NAME:
                if ((ret = mbedtls_x509_get_subject_alt_name(p, end_ext_octet,
                                                             &crt->subject_alt_names)) != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_X509_EXT_NS_CERT_TYPE:
                if ((ret = mbedtls_x509_get_ns_cert_type(p, end_ext_octet,
                                                         &crt->ns_cert_type)) != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES:
                if ((ret = x509_get_certificate_policies(p, end_ext_octet,
                                                         &crt->certificate_policies)) != 0) {
                    if (ret == MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE && cb != NULL &&
                        cb(p_ctx, crt, &extn_oid, is_critical,
                           start_ext_octet, end_ext_octet) == 0) {
                        break;
                    }
                    if (is_critical) {
                        return ret;
                    } else
                    if (ret != MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) {
                        return ret;
                    }
                }
                break;
            default:
                if (is_critical) {
                    return MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE;
                } else {
                    *p = end_ext_octet;
                }
        }
    }
    if (*p != end) {
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    return 0;
}
static int x509_crt_parse_der_core(mbedtls_x509_crt *crt,
                                   const unsigned char *buf,
                                   size_t buflen,
                                   int make_copy,
                                   mbedtls_x509_crt_ext_cb_t cb,
                                   void *p_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len;
    unsigned char *p, *end, *crt_end;
    mbedtls_x509_buf sig_params1, sig_params2, sig_oid2;
    memset(&sig_params1, 0, sizeof(mbedtls_x509_buf));
    memset(&sig_params2, 0, sizeof(mbedtls_x509_buf));
    memset(&sig_oid2, 0, sizeof(mbedtls_x509_buf));
    if (crt == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    p = (unsigned char *) buf;
    len = buflen;
    end = p + len;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    end = crt_end = p + len;
    crt->raw.len = (size_t) (crt_end - buf);
    if (make_copy != 0) {
        crt->raw.p = p = mbedtls_calloc(1, crt->raw.len);
        if (crt->raw.p == NULL) {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }
        memcpy(crt->raw.p, buf, crt->raw.len);
        crt->own_buffer = 1;
        p += crt->raw.len - len;
        end = crt_end = p + len;
    } else {
        crt->raw.p = (unsigned char *) buf;
        crt->own_buffer = 0;
    }
    crt->tbs.p = p;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    end = p + len;
    crt->tbs.len = (size_t) (end - crt->tbs.p);
    if ((ret = x509_get_version(&p, end, &crt->version)) != 0 ||
        (ret = mbedtls_x509_get_serial(&p, end, &crt->serial)) != 0 ||
        (ret = mbedtls_x509_get_alg(&p, end, &crt->sig_oid,
                                    &sig_params1)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    if (crt->version < 0 || crt->version > 2) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_UNKNOWN_VERSION;
    }
    crt->version++;
    if ((ret = mbedtls_x509_get_sig_alg(&crt->sig_oid, &sig_params1,
                                        &crt->sig_md, &crt->sig_pk,
                                        &crt->sig_opts)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    crt->issuer_raw.p = p;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    if ((ret = mbedtls_x509_get_name(&p, p + len, &crt->issuer)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    crt->issuer_raw.len = (size_t) (p - crt->issuer_raw.p);
    if ((ret = x509_get_dates(&p, end, &crt->valid_from,
                              &crt->valid_to)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    crt->subject_raw.p = p;
    if ((ret = mbedtls_asn1_get_tag(&p, end, &len,
                                    MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT, ret);
    }
    if (len && (ret = mbedtls_x509_get_name(&p, p + len, &crt->subject)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    crt->subject_raw.len = (size_t) (p - crt->subject_raw.p);
    crt->pk_raw.p = p;
    if ((ret = mbedtls_pk_parse_subpubkey(&p, end, &crt->pk)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    crt->pk_raw.len = (size_t) (p - crt->pk_raw.p);
    if (crt->version == 2 || crt->version == 3) {
        ret = x509_get_uid(&p, end, &crt->issuer_id, 1);
        if (ret != 0) {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }
    if (crt->version == 2 || crt->version == 3) {
        ret = x509_get_uid(&p, end, &crt->subject_id, 2);
        if (ret != 0) {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }
    if (crt->version == 3) {
        ret = x509_get_crt_ext(&p, end, crt, cb, p_ctx);
        if (ret != 0) {
            mbedtls_x509_crt_free(crt);
            return ret;
        }
    }
    if (p != end) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    end = crt_end;
    if ((ret = mbedtls_x509_get_alg(&p, end, &sig_oid2, &sig_params2)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    if (crt->sig_oid.len != sig_oid2.len ||
        memcmp(crt->sig_oid.p, sig_oid2.p, crt->sig_oid.len) != 0 ||
        sig_params1.tag != sig_params2.tag ||
        sig_params1.len != sig_params2.len ||
        (sig_params1.len != 0 &&
         memcmp(sig_params1.p, sig_params2.p, sig_params1.len) != 0)) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERR_X509_SIG_MISMATCH;
    }
    if ((ret = mbedtls_x509_get_sig(&p, end, &crt->sig)) != 0) {
        mbedtls_x509_crt_free(crt);
        return ret;
    }
    if (p != end) {
        mbedtls_x509_crt_free(crt);
        return MBEDTLS_ERROR_ADD(MBEDTLS_ERR_X509_INVALID_FORMAT,
                                 MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    }
    return 0;
}
static int mbedtls_x509_crt_parse_der_internal(mbedtls_x509_crt *chain,
                                               const unsigned char *buf,
                                               size_t buflen,
                                               int make_copy,
                                               mbedtls_x509_crt_ext_cb_t cb,
                                               void *p_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *crt = chain, *prev = NULL;
    if (crt == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    while (crt->version != 0 && crt->next != NULL) {
        prev = crt;
        crt = crt->next;
    }
    if (crt->version != 0 && crt->next == NULL) {
        crt->next = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
        if (crt->next == NULL) {
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }
        prev = crt;
        mbedtls_x509_crt_init(crt->next);
        crt = crt->next;
    }
    ret = x509_crt_parse_der_core(crt, buf, buflen, make_copy, cb, p_ctx);
    if (ret != 0) {
        if (prev) {
            prev->next = NULL;
        }
        if (crt != chain) {
            mbedtls_free(crt);
        }
        return ret;
    }
    return 0;
}
int mbedtls_x509_crt_parse_der_nocopy(mbedtls_x509_crt *chain,
                                      const unsigned char *buf,
                                      size_t buflen)
{
    return mbedtls_x509_crt_parse_der_internal(chain, buf, buflen, 0, NULL, NULL);
}
int mbedtls_x509_crt_parse_der_with_ext_cb(mbedtls_x509_crt *chain,
                                           const unsigned char *buf,
                                           size_t buflen,
                                           int make_copy,
                                           mbedtls_x509_crt_ext_cb_t cb,
                                           void *p_ctx)
{
    return mbedtls_x509_crt_parse_der_internal(chain, buf, buflen, make_copy, cb, p_ctx);
}
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen)
{
    return mbedtls_x509_crt_parse_der_internal(chain, buf, buflen, 1, NULL, NULL);
}
int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain,
                           const unsigned char *buf,
                           size_t buflen)
{
#if defined(MBEDTLS_PEM_PARSE_C)
    int success = 0, first_error = 0, total_failed = 0;
    int buf_format = MBEDTLS_X509_FORMAT_DER;
#endif
    if (chain == NULL || buf == NULL) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
#if defined(MBEDTLS_PEM_PARSE_C)
    if (buflen != 0 && buf[buflen - 1] == '\0' &&
        strstr((const char *) buf, "-----BEGIN CERTIFICATE-----") != NULL) {
        buf_format = MBEDTLS_X509_FORMAT_PEM;
    }
    if (buf_format == MBEDTLS_X509_FORMAT_DER) {
        return mbedtls_x509_crt_parse_der(chain, buf, buflen);
    }
#else
    return mbedtls_x509_crt_parse_der(chain, buf, buflen);
#endif
#if defined(MBEDTLS_PEM_PARSE_C)
    if (buf_format == MBEDTLS_X509_FORMAT_PEM) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        mbedtls_pem_context pem;
        while (buflen > 1) {
            size_t use_len;
            mbedtls_pem_init(&pem);
            ret = mbedtls_pem_read_buffer(&pem,
                                          "-----BEGIN CERTIFICATE-----",
                                          "-----END CERTIFICATE-----",
                                          buf, NULL, 0, &use_len);
            if (ret == 0) {
                buflen -= use_len;
                buf += use_len;
            } else if (ret == MBEDTLS_ERR_PEM_BAD_INPUT_DATA) {
                return ret;
            } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
                mbedtls_pem_free(&pem);
                buflen -= use_len;
                buf += use_len;
                if (first_error == 0) {
                    first_error = ret;
                }
                total_failed++;
                continue;
            } else {
                break;
            }
            ret = mbedtls_x509_crt_parse_der(chain, pem.buf, pem.buflen);
            mbedtls_pem_free(&pem);
            if (ret != 0) {
                if (ret == MBEDTLS_ERR_X509_ALLOC_FAILED) {
                    return ret;
                }
                if (first_error == 0) {
                    first_error = ret;
                }
                total_failed++;
                continue;
            }
            success = 1;
        }
    }
    if (success) {
        return total_failed;
    } else if (first_error) {
        return first_error;
    } else {
        return MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT;
    }
#endif
}
#if defined(MBEDTLS_FS_IO)
int mbedtls_x509_crt_parse_file(mbedtls_x509_crt *chain, const char *path)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char *buf;
    if ((ret = mbedtls_pk_load_file(path, &buf, &n)) != 0) {
        return ret;
    }
    ret = mbedtls_x509_crt_parse(chain, buf, n);
    mbedtls_zeroize_and_free(buf, n);
    return ret;
}
int mbedtls_x509_crt_parse_path(mbedtls_x509_crt *chain, const char *path)
{
    int ret = 0;
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
    int w_ret;
    WCHAR szDir[MAX_PATH];
    char filename[MAX_PATH];
    char *p;
    size_t len = strlen(path);
    WIN32_FIND_DATAW file_data;
    HANDLE hFind;
    if (len > MAX_PATH - 3) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    memset(szDir, 0, sizeof(szDir));
    memset(filename, 0, MAX_PATH);
    memcpy(filename, path, len);
    filename[len++] = '\\';
    p = filename + len;
    filename[len++] = '*';
    w_ret = MultiByteToWideChar(CP_ACP, 0, filename, (int) len, szDir,
                                MAX_PATH - 3);
    if (w_ret == 0) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    hFind = FindFirstFileW(szDir, &file_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }
    len = MAX_PATH - len;
    do {
        memset(p, 0, len);
        if (file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        w_ret = WideCharToMultiByte(CP_ACP, 0, file_data.cFileName,
                                    -1, p, (int) len, NULL, NULL);
        if (w_ret == 0) {
            ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
            goto cleanup;
        }
        w_ret = mbedtls_x509_crt_parse_file(chain, filename);
        if (w_ret < 0) {
            ret++;
        } else {
            ret += w_ret;
        }
    } while (FindNextFileW(hFind, &file_data) != 0);
    if (GetLastError() != ERROR_NO_MORE_FILES) {
        ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }
cleanup:
    FindClose(hFind);
#else
    int t_ret;
    int snp_ret;
    struct stat sb;
    struct dirent *entry;
    char entry_name[MBEDTLS_X509_MAX_FILE_PATH_LEN];
    DIR *dir = opendir(path);
    if (dir == NULL) {
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }
#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&mbedtls_threading_readdir_mutex)) != 0) {
        closedir(dir);
        return ret;
    }
#endif
    memset(&sb, 0, sizeof(sb));
    while ((entry = readdir(dir)) != NULL) {
        snp_ret = mbedtls_snprintf(entry_name, sizeof(entry_name),
                                   "%s/%s", path, entry->d_name);
        if (snp_ret < 0 || (size_t) snp_ret >= sizeof(entry_name)) {
            ret = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
            goto cleanup;
        } else if (stat(entry_name, &sb) == -1) {
            if (errno == ENOENT) {
                continue;
            } else {
                ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
                goto cleanup;
            }
        }
        if (!S_ISREG(sb.st_mode)) {
            continue;
        }
        t_ret = mbedtls_x509_crt_parse_file(chain, entry_name);
        if (t_ret < 0) {
            ret++;
        } else {
            ret += t_ret;
        }
    }
cleanup:
    closedir(dir);
#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&mbedtls_threading_readdir_mutex) != 0) {
        ret = MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif
#endif
    return ret;
}
#endif
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#define PRINT_ITEM(i) \
    do { \
        ret = mbedtls_snprintf(p, n, "%s" i, sep); \
        MBEDTLS_X509_SAFE_SNPRINTF; \
        sep = ", "; \
    } while (0)
#define CERT_TYPE(type,name) \
    do { \
        if (ns_cert_type & (type)) { \
            PRINT_ITEM(name); \
        } \
    } while (0)
#define KEY_USAGE(code,name) \
    do { \
        if (key_usage & (code)) { \
            PRINT_ITEM(name); \
        } \
    } while (0)
static int x509_info_ext_key_usage(char **buf, size_t *size,
                                   const mbedtls_x509_sequence *extended_key_usage)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *desc;
    size_t n = *size;
    char *p = *buf;
    const mbedtls_x509_sequence *cur = extended_key_usage;
    const char *sep = "";
    while (cur != NULL) {
        if (mbedtls_oid_get_extended_key_usage(&cur->buf, &desc) != 0) {
            desc = "???";
        }
        ret = mbedtls_snprintf(p, n, "%s%s", sep, desc);
        MBEDTLS_X509_SAFE_SNPRINTF;
        sep = ", ";
        cur = cur->next;
    }
    *size = n;
    *buf = p;
    return 0;
}
static int x509_info_cert_policies(char **buf, size_t *size,
                                   const mbedtls_x509_sequence *certificate_policies)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *desc;
    size_t n = *size;
    char *p = *buf;
    const mbedtls_x509_sequence *cur = certificate_policies;
    const char *sep = "";
    while (cur != NULL) {
        if (mbedtls_oid_get_certificate_policies(&cur->buf, &desc) != 0) {
            desc = "???";
        }
        ret = mbedtls_snprintf(p, n, "%s%s", sep, desc);
        MBEDTLS_X509_SAFE_SNPRINTF;
        sep = ", ";
        cur = cur->next;
    }
    *size = n;
    *buf = p;
    return 0;
}
#define BEFORE_COLON 18
#define BC "18"
int mbedtls_x509_crt_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_crt *crt)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON];
    p = buf;
    n = size;
    if (NULL == crt) {
        ret = mbedtls_snprintf(p, n, "\nCertificate is uninitialised!\n");
        MBEDTLS_X509_SAFE_SNPRINTF;
        return (int) (size - n);
    }
    ret = mbedtls_snprintf(p, n, "%scert. version     : %d\n",
                           prefix, crt->version);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_snprintf(p, n, "%sserial number     : ",
                           prefix);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_serial_gets(p, n, &crt->serial);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_snprintf(p, n, "\n%sissuer name       : ", prefix);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets(p, n, &crt->issuer);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_snprintf(p, n, "\n%ssubject name      : ", prefix);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets(p, n, &crt->subject);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_snprintf(p, n, "\n%sissued  on        : " \
                                 "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                           crt->valid_from.year, crt->valid_from.mon,
                           crt->valid_from.day, crt->valid_from.hour,
                           crt->valid_from.min, crt->valid_from.sec);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_snprintf(p, n, "\n%sexpires on        : " \
                                 "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                           crt->valid_to.year, crt->valid_to.mon,
                           crt->valid_to.day, crt->valid_to.hour,
                           crt->valid_to.min, crt->valid_to.sec);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_snprintf(p, n, "\n%ssigned using      : ", prefix);
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_sig_alg_gets(p, n, &crt->sig_oid, crt->sig_pk,
                                    crt->sig_md, crt->sig_opts);
    MBEDTLS_X509_SAFE_SNPRINTF;
    if ((ret = mbedtls_x509_key_size_helper(key_size_str, BEFORE_COLON,
                                            mbedtls_pk_get_name(&crt->pk))) != 0) {
        return ret;
    }
    ret = mbedtls_snprintf(p, n, "\n%s%-" BC "s: %d bits", prefix, key_size_str,
                           (int) mbedtls_pk_get_bitlen(&crt->pk));
    MBEDTLS_X509_SAFE_SNPRINTF;
    if (crt->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) {
        ret = mbedtls_snprintf(p, n, "\n%sbasic constraints : CA=%s", prefix,
                               crt->ca_istrue ? "true" : "false");
        MBEDTLS_X509_SAFE_SNPRINTF;
        if (crt->max_pathlen > 0) {
            ret = mbedtls_snprintf(p, n, ", max_pathlen=%d", crt->max_pathlen - 1);
            MBEDTLS_X509_SAFE_SNPRINTF;
        }
    }
    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        ret = mbedtls_snprintf(p, n, "\n%ssubject alt name  :", prefix);
        MBEDTLS_X509_SAFE_SNPRINTF;
        if ((ret = mbedtls_x509_info_subject_alt_name(&p, &n,
                                                      &crt->subject_alt_names,
                                                      prefix)) != 0) {
            return ret;
        }
    }
    if (crt->ext_types & MBEDTLS_X509_EXT_NS_CERT_TYPE) {
        ret = mbedtls_snprintf(p, n, "\n%scert. type        : ", prefix);
        MBEDTLS_X509_SAFE_SNPRINTF;
        if ((ret = mbedtls_x509_info_cert_type(&p, &n, crt->ns_cert_type)) != 0) {
            return ret;
        }
    }
    if (crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) {
        ret = mbedtls_snprintf(p, n, "\n%skey usage         : ", prefix);
        MBEDTLS_X509_SAFE_SNPRINTF;
        if ((ret = mbedtls_x509_info_key_usage(&p, &n, crt->key_usage)) != 0) {
            return ret;
        }
    }
    if (crt->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) {
        ret = mbedtls_snprintf(p, n, "\n%sext key usage     : ", prefix);
        MBEDTLS_X509_SAFE_SNPRINTF;
        if ((ret = x509_info_ext_key_usage(&p, &n,
                                           &crt->ext_key_usage)) != 0) {
            return ret;
        }
    }
    if (crt->ext_types & MBEDTLS_OID_X509_EXT_CERTIFICATE_POLICIES) {
        ret = mbedtls_snprintf(p, n, "\n%scertificate policies : ", prefix);
        MBEDTLS_X509_SAFE_SNPRINTF;
        if ((ret = x509_info_cert_policies(&p, &n,
                                           &crt->certificate_policies)) != 0) {
            return ret;
        }
    }
    ret = mbedtls_snprintf(p, n, "\n");
    MBEDTLS_X509_SAFE_SNPRINTF;
    return (int) (size - n);
}
struct x509_crt_verify_string {
    int code;
    const char *string;
};
#define X509_CRT_ERROR_INFO(err,err_str,info) { err, info },
static const struct x509_crt_verify_string x509_crt_verify_strings[] = {
    MBEDTLS_X509_CRT_ERROR_INFO_LIST
    { 0, NULL }
};
#undef X509_CRT_ERROR_INFO
int mbedtls_x509_crt_verify_info(char *buf, size_t size, const char *prefix,
                                 uint32_t flags)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const struct x509_crt_verify_string *cur;
    char *p = buf;
    size_t n = size;
    for (cur = x509_crt_verify_strings; cur->string != NULL; cur++) {
        if ((flags & cur->code) == 0) {
            continue;
        }
        ret = mbedtls_snprintf(p, n, "%s%s\n", prefix, cur->string);
        MBEDTLS_X509_SAFE_SNPRINTF;
        flags ^= cur->code;
    }
    if (flags != 0) {
        ret = mbedtls_snprintf(p, n, "%sUnknown reason "
                                     "(this should not happen)\n", prefix);
        MBEDTLS_X509_SAFE_SNPRINTF;
    }
    return (int) (size - n);
}
#endif
int mbedtls_x509_crt_check_key_usage(const mbedtls_x509_crt *crt,
                                     unsigned int usage)
{
    unsigned int usage_must, usage_may;
    unsigned int may_mask = MBEDTLS_X509_KU_ENCIPHER_ONLY
                            | MBEDTLS_X509_KU_DECIPHER_ONLY;
    if ((crt->ext_types & MBEDTLS_X509_EXT_KEY_USAGE) == 0) {
        return 0;
    }
    usage_must = usage & ~may_mask;
    if (((crt->key_usage & ~may_mask) & usage_must) != usage_must) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    usage_may = usage & may_mask;
    if (((crt->key_usage & may_mask) | usage_may) != usage_may) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    return 0;
}
int mbedtls_x509_crt_check_extended_key_usage(const mbedtls_x509_crt *crt,
                                              const char *usage_oid,
                                              size_t usage_len)
{
    const mbedtls_x509_sequence *cur;
    if ((crt->ext_types & MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE) == 0) {
        return 0;
    }
    for (cur = &crt->ext_key_usage; cur != NULL; cur = cur->next) {
        const mbedtls_x509_buf *cur_oid = &cur->buf;
        if (cur_oid->len == usage_len &&
            memcmp(cur_oid->p, usage_oid, usage_len) == 0) {
            return 0;
        }
        if (MBEDTLS_OID_CMP(MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE, cur_oid) == 0) {
            return 0;
        }
    }
    return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
}
#if defined(MBEDTLS_X509_CRL_PARSE_C)
int mbedtls_x509_crt_is_revoked(const mbedtls_x509_crt *crt, const mbedtls_x509_crl *crl)
{
    const mbedtls_x509_crl_entry *cur = &crl->entry;
    while (cur != NULL && cur->serial.len != 0) {
        if (crt->serial.len == cur->serial.len &&
            memcmp(crt->serial.p, cur->serial.p, crt->serial.len) == 0) {
            return 1;
        }
        cur = cur->next;
    }
    return 0;
}
static int x509_crt_verifycrl(mbedtls_x509_crt *crt, mbedtls_x509_crt *ca,
                              mbedtls_x509_crl *crl_list,
                              const mbedtls_x509_crt_profile *profile,
                              const mbedtls_x509_time *now)
{
    int flags = 0;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_algorithm_t psa_algorithm;
#else
    const mbedtls_md_info_t *md_info;
#endif
    size_t hash_length;
    if (ca == NULL) {
        return flags;
    }
    while (crl_list != NULL) {
        if (crl_list->version == 0 ||
            x509_name_cmp(&crl_list->issuer, &ca->subject) != 0) {
            crl_list = crl_list->next;
            continue;
        }
        if (mbedtls_x509_crt_check_key_usage(ca,
                                             MBEDTLS_X509_KU_CRL_SIGN) != 0) {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
        if (x509_profile_check_md_alg(profile, crl_list->sig_md) != 0) {
            flags |= MBEDTLS_X509_BADCRL_BAD_MD;
        }
        if (x509_profile_check_pk_alg(profile, crl_list->sig_pk) != 0) {
            flags |= MBEDTLS_X509_BADCRL_BAD_PK;
        }
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        psa_algorithm = mbedtls_md_psa_alg_from_type(crl_list->sig_md);
        if (psa_hash_compute(psa_algorithm,
                             crl_list->tbs.p,
                             crl_list->tbs.len,
                             hash,
                             sizeof(hash),
                             &hash_length) != PSA_SUCCESS) {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
#else
        md_info = mbedtls_md_info_from_type(crl_list->sig_md);
        hash_length = mbedtls_md_get_size(md_info);
        if (mbedtls_md(md_info,
                       crl_list->tbs.p,
                       crl_list->tbs.len,
                       hash) != 0) {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
#endif
        if (x509_profile_check_key(profile, &ca->pk) != 0) {
            flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
        }
        if (mbedtls_pk_verify_ext(crl_list->sig_pk, crl_list->sig_opts, &ca->pk,
                                  crl_list->sig_md, hash, hash_length,
                                  crl_list->sig.p, crl_list->sig.len) != 0) {
            flags |= MBEDTLS_X509_BADCRL_NOT_TRUSTED;
            break;
        }
#if defined(MBEDTLS_HAVE_TIME_DATE)
        if (mbedtls_x509_time_cmp(&crl_list->next_update, now) < 0) {
            flags |= MBEDTLS_X509_BADCRL_EXPIRED;
        }
        if (mbedtls_x509_time_cmp(&crl_list->this_update, now) > 0) {
            flags |= MBEDTLS_X509_BADCRL_FUTURE;
        }
#else
        ((void) now);
#endif
        if (mbedtls_x509_crt_is_revoked(crt, crl_list)) {
            flags |= MBEDTLS_X509_BADCERT_REVOKED;
            break;
        }
        crl_list = crl_list->next;
    }
    return flags;
}
#endif
static int x509_crt_check_signature(const mbedtls_x509_crt *child,
                                    mbedtls_x509_crt *parent,
                                    mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    size_t hash_len;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_type(child->sig_md);
    hash_len = mbedtls_md_get_size(md_info);
    if (mbedtls_md(md_info, child->tbs.p, child->tbs.len, hash) != 0) {
        return -1;
    }
#else
    psa_algorithm_t hash_alg = mbedtls_md_psa_alg_from_type(child->sig_md);
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    status = psa_hash_compute(hash_alg,
                              child->tbs.p,
                              child->tbs.len,
                              hash,
                              sizeof(hash),
                              &hash_len);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#endif
    if (!mbedtls_pk_can_do(&parent->pk, child->sig_pk)) {
        return -1;
    }
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && child->sig_pk == MBEDTLS_PK_ECDSA) {
        return mbedtls_pk_verify_restartable(&parent->pk,
                                             child->sig_md, hash, hash_len,
                                             child->sig.p, child->sig.len, &rs_ctx->pk);
    }
#else
    (void) rs_ctx;
#endif
    return mbedtls_pk_verify_ext(child->sig_pk, child->sig_opts, &parent->pk,
                                 child->sig_md, hash, hash_len,
                                 child->sig.p, child->sig.len);
}
static int x509_crt_check_parent(const mbedtls_x509_crt *child,
                                 const mbedtls_x509_crt *parent,
                                 int top)
{
    int need_ca_bit;
    if (x509_name_cmp(&child->issuer, &parent->subject) != 0) {
        return -1;
    }
    need_ca_bit = 1;
    if (top && parent->version < 3) {
        need_ca_bit = 0;
    }
    if (need_ca_bit && !parent->ca_istrue) {
        return -1;
    }
    if (need_ca_bit &&
        mbedtls_x509_crt_check_key_usage(parent, MBEDTLS_X509_KU_KEY_CERT_SIGN) != 0) {
        return -1;
    }
    return 0;
}
static int x509_crt_find_parent_in(
    mbedtls_x509_crt *child,
    mbedtls_x509_crt *candidates,
    mbedtls_x509_crt **r_parent,
    int *r_signature_is_good,
    int top,
    unsigned path_cnt,
    unsigned self_cnt,
    mbedtls_x509_crt_restart_ctx *rs_ctx,
    const mbedtls_x509_time *now)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *parent, *fallback_parent;
    int signature_is_good = 0, fallback_signature_is_good;
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->parent != NULL) {
        parent = rs_ctx->parent;
        fallback_parent = rs_ctx->fallback_parent;
        fallback_signature_is_good = rs_ctx->fallback_signature_is_good;
        rs_ctx->parent = NULL;
        rs_ctx->fallback_parent = NULL;
        rs_ctx->fallback_signature_is_good = 0;
        goto check_signature;
    }
#endif
    fallback_parent = NULL;
    fallback_signature_is_good = 0;
    for (parent = candidates; parent != NULL; parent = parent->next) {
        if (x509_crt_check_parent(child, parent, top) != 0) {
            continue;
        }
        if (parent->max_pathlen > 0 &&
            (size_t) parent->max_pathlen < 1 + path_cnt - self_cnt) {
            continue;
        }
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
check_signature:
#endif
        ret = x509_crt_check_signature(child, parent, rs_ctx);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
            rs_ctx->parent = parent;
            rs_ctx->fallback_parent = fallback_parent;
            rs_ctx->fallback_signature_is_good = fallback_signature_is_good;
            return ret;
        }
#else
        (void) ret;
#endif
        signature_is_good = ret == 0;
        if (top && !signature_is_good) {
            continue;
        }
#if defined(MBEDTLS_HAVE_TIME_DATE)
        if (mbedtls_x509_time_cmp(&parent->valid_to, now) < 0 ||
            mbedtls_x509_time_cmp(&parent->valid_from, now) > 0) {
            if (fallback_parent == NULL) {
                fallback_parent = parent;
                fallback_signature_is_good = signature_is_good;
            }
            continue;
        }
#else
        ((void) now);
#endif
        *r_parent = parent;
        *r_signature_is_good = signature_is_good;
        break;
    }
    if (parent == NULL) {
        *r_parent = fallback_parent;
        *r_signature_is_good = fallback_signature_is_good;
    }
    return 0;
}
static int x509_crt_find_parent(
    mbedtls_x509_crt *child,
    mbedtls_x509_crt *trust_ca,
    mbedtls_x509_crt **parent,
    int *parent_is_trusted,
    int *signature_is_good,
    unsigned path_cnt,
    unsigned self_cnt,
    mbedtls_x509_crt_restart_ctx *rs_ctx,
    const mbedtls_x509_time *now)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *search_list;
    *parent_is_trusted = 1;
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->parent_is_trusted != -1) {
        *parent_is_trusted = rs_ctx->parent_is_trusted;
        rs_ctx->parent_is_trusted = -1;
    }
#endif
    while (1) {
        search_list = *parent_is_trusted ? trust_ca : child->next;
        ret = x509_crt_find_parent_in(child, search_list,
                                      parent, signature_is_good,
                                      *parent_is_trusted,
                                      path_cnt, self_cnt, rs_ctx, now);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
            rs_ctx->parent_is_trusted = *parent_is_trusted;
            return ret;
        }
#else
        (void) ret;
#endif
        if (*parent != NULL || *parent_is_trusted == 0) {
            break;
        }
        *parent_is_trusted = 0;
    }
    if (*parent == NULL) {
        *parent_is_trusted = 0;
        *signature_is_good = 0;
    }
    return 0;
}
static int x509_crt_check_ee_locally_trusted(
    mbedtls_x509_crt *crt,
    mbedtls_x509_crt *trust_ca)
{
    mbedtls_x509_crt *cur;
    if (x509_name_cmp(&crt->issuer, &crt->subject) != 0) {
        return -1;
    }
    for (cur = trust_ca; cur != NULL; cur = cur->next) {
        if (crt->raw.len == cur->raw.len &&
            memcmp(crt->raw.p, cur->raw.p, crt->raw.len) == 0) {
            return 0;
        }
    }
    return -1;
}
static int x509_crt_verify_chain(
    mbedtls_x509_crt *crt,
    mbedtls_x509_crt *trust_ca,
    mbedtls_x509_crl *ca_crl,
    mbedtls_x509_crt_ca_cb_t f_ca_cb,
    void *p_ca_cb,
    const mbedtls_x509_crt_profile *profile,
    mbedtls_x509_crt_verify_chain *ver_chain,
    mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t *flags;
    mbedtls_x509_crt_verify_chain_item *cur;
    mbedtls_x509_crt *child;
    mbedtls_x509_crt *parent;
    int parent_is_trusted;
    int child_is_trusted;
    int signature_is_good;
    unsigned self_cnt;
    mbedtls_x509_crt *cur_trust_ca = NULL;
    mbedtls_x509_time now;
#if defined(MBEDTLS_HAVE_TIME_DATE)
    if (mbedtls_x509_time_gmtime(mbedtls_time(NULL), &now) != 0) {
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }
#endif
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->in_progress == x509_crt_rs_find_parent) {
        *ver_chain = rs_ctx->ver_chain;
        self_cnt = rs_ctx->self_cnt;
        cur = &ver_chain->items[ver_chain->len - 1];
        child = cur->crt;
        flags = &cur->flags;
        goto find_parent;
    }
#endif
    child = crt;
    self_cnt = 0;
    parent_is_trusted = 0;
    child_is_trusted = 0;
    while (1) {
        cur = &ver_chain->items[ver_chain->len];
        cur->crt = child;
        cur->flags = 0;
        ver_chain->len++;
        flags = &cur->flags;
#if defined(MBEDTLS_HAVE_TIME_DATE)
        if (mbedtls_x509_time_cmp(&child->valid_to, &now) < 0) {
            *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
        }
        if (mbedtls_x509_time_cmp(&child->valid_from, &now) > 0) {
            *flags |= MBEDTLS_X509_BADCERT_FUTURE;
        }
#endif
        if (child_is_trusted) {
            return 0;
        }
        if (x509_profile_check_md_alg(profile, child->sig_md) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_BAD_MD;
        }
        if (x509_profile_check_pk_alg(profile, child->sig_pk) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_BAD_PK;
        }
        if (ver_chain->len == 1 &&
            x509_crt_check_ee_locally_trusted(child, trust_ca) == 0) {
            return 0;
        }
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
find_parent:
#endif
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
        if (f_ca_cb != NULL) {
            mbedtls_x509_crt_free(ver_chain->trust_ca_cb_result);
            mbedtls_free(ver_chain->trust_ca_cb_result);
            ver_chain->trust_ca_cb_result = NULL;
            ret = f_ca_cb(p_ca_cb, child, &ver_chain->trust_ca_cb_result);
            if (ret != 0) {
                return MBEDTLS_ERR_X509_FATAL_ERROR;
            }
            cur_trust_ca = ver_chain->trust_ca_cb_result;
        } else
#endif
        {
            ((void) f_ca_cb);
            ((void) p_ca_cb);
            cur_trust_ca = trust_ca;
        }
        ret = x509_crt_find_parent(child, cur_trust_ca, &parent,
                                   &parent_is_trusted, &signature_is_good,
                                   ver_chain->len - 1, self_cnt, rs_ctx,
                                   &now);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
            rs_ctx->in_progress = x509_crt_rs_find_parent;
            rs_ctx->self_cnt = self_cnt;
            rs_ctx->ver_chain = *ver_chain;
            return ret;
        }
#else
        (void) ret;
#endif
        if (parent == NULL) {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
            return 0;
        }
        if (ver_chain->len != 1 &&
            x509_name_cmp(&child->issuer, &child->subject) == 0) {
            self_cnt++;
        }
        if (!parent_is_trusted &&
            ver_chain->len > MBEDTLS_X509_MAX_INTERMEDIATE_CA) {
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }
        if (!signature_is_good) {
            *flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
        }
        if (x509_profile_check_key(profile, &parent->pk) != 0) {
            *flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
        }
#if defined(MBEDTLS_X509_CRL_PARSE_C)
        *flags |= x509_crt_verifycrl(child, parent, ca_crl, profile, &now);
#else
        (void) ca_crl;
#endif
        child = parent;
        parent = NULL;
        child_is_trusted = parent_is_trusted;
        signature_is_good = 0;
    }
}
#ifdef _WIN32
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#elif (defined(__MINGW32__) || defined(__MINGW64__)) && _WIN32_WINNT >= 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#define MBEDTLS_TEST_SW_INET_PTON 
#endif
#elif defined(__sun)
#elif defined(__has_include)
#if __has_include(<sys/socket.h>)
#include <sys/socket.h>
#endif
#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#endif
#endif
#if !defined(AF_INET6) || defined(MBEDTLS_TEST_SW_INET_PTON)
static int x509_inet_pton_ipv4(const char *src, void *dst);
#define li_cton(c,n) \
    (((n) = (c) - '0') <= 9 || (((n) = ((c)&0xdf) - 'A') <= 5 ? ((n) += 10) : 0))
static int x509_inet_pton_ipv6(const char *src, void *dst)
{
    const unsigned char *p = (const unsigned char *) src;
    int nonzero_groups = 0, num_digits, zero_group_start = -1;
    uint16_t addr[8];
    do {
        uint16_t group = num_digits = 0;
        for (uint8_t digit; num_digits < 4; num_digits++) {
            if (li_cton(*p, digit) == 0) {
                break;
            }
            group = (group << 4) | digit;
            p++;
        }
        if (num_digits != 0) {
            MBEDTLS_PUT_UINT16_BE(group, addr, nonzero_groups);
            nonzero_groups++;
            if (*p == '\0') {
                break;
            } else if (*p == '.') {
                if ((nonzero_groups == 0 && zero_group_start == -1) ||
                    nonzero_groups >= 7) {
                    break;
                }
                int steps = 4;
                do {
                    p--;
                    steps--;
                } while (*p != ':' && steps > 0);
                if (*p != ':') {
                    break;
                }
                p++;
                nonzero_groups--;
                if (x509_inet_pton_ipv4((const char *) p,
                                        addr + nonzero_groups) != 0) {
                    break;
                }
                nonzero_groups += 2;
                p = (const unsigned char *) "";
                break;
            } else if (*p != ':') {
                return -1;
            }
        } else {
            if (zero_group_start != -1 || *p != ':') {
                return -1;
            }
            zero_group_start = nonzero_groups;
            if (zero_group_start == 0 && *++p != ':') {
                return -1;
            }
            if (p[1] == '\0') {
                ++p;
                break;
            }
        }
        ++p;
    } while (nonzero_groups < 8);
    if (*p != '\0') {
        return -1;
    }
    if (zero_group_start != -1) {
        if (nonzero_groups > 6) {
            return -1;
        }
        int zero_groups = 8 - nonzero_groups;
        int groups_after_zero = nonzero_groups - zero_group_start;
        if (groups_after_zero) {
            memmove(addr + zero_group_start + zero_groups,
                    addr + zero_group_start,
                    groups_after_zero * sizeof(*addr));
        }
        memset(addr + zero_group_start, 0, zero_groups * sizeof(*addr));
    } else {
        if (nonzero_groups != 8) {
            return -1;
        }
    }
    memcpy(dst, addr, sizeof(addr));
    return 0;
}
static int x509_inet_pton_ipv4(const char *src, void *dst)
{
    const unsigned char *p = (const unsigned char *) src;
    uint8_t *res = (uint8_t *) dst;
    uint8_t digit, num_digits = 0;
    uint8_t num_octets = 0;
    uint16_t octet;
    do {
        octet = num_digits = 0;
        do {
            digit = *p - '0';
            if (digit > 9) {
                break;
            }
            if (octet == 0 && num_digits > 0) {
                return -1;
            }
            octet = octet * 10 + digit;
            num_digits++;
            p++;
        } while (num_digits < 3);
        if (octet >= 256 || num_digits > 3 || num_digits == 0) {
            return -1;
        }
        *res++ = (uint8_t) octet;
        num_octets++;
    } while (num_octets < 4 && *p++ == '.');
    return num_octets == 4 && *p == '\0' ? 0 : -1;
}
#else
static int x509_inet_pton_ipv6(const char *src, void *dst)
{
    return inet_pton(AF_INET6, src, dst) == 1 ? 0 : -1;
}
static int x509_inet_pton_ipv4(const char *src, void *dst)
{
    return inet_pton(AF_INET, src, dst) == 1 ? 0 : -1;
}
#endif
size_t mbedtls_x509_crt_parse_cn_inet_pton(const char *cn, void *dst)
{
    return strchr(cn, ':') == NULL
            ? x509_inet_pton_ipv4(cn, dst) == 0 ? 4 : 0
            : x509_inet_pton_ipv6(cn, dst) == 0 ? 16 : 0;
}
static int x509_crt_check_cn(const mbedtls_x509_buf *name,
                             const char *cn, size_t cn_len)
{
    if (name->len == cn_len &&
        x509_memcasecmp(cn, name->p, cn_len) == 0) {
        return 0;
    }
    if (x509_check_wildcard(cn, name) == 0) {
        return 0;
    }
    return -1;
}
static int x509_crt_check_san_ip(const mbedtls_x509_sequence *san,
                                 const char *cn, size_t cn_len)
{
    uint32_t ip[4];
    cn_len = mbedtls_x509_crt_parse_cn_inet_pton(cn, ip);
    if (cn_len == 0) {
        return -1;
    }
    for (const mbedtls_x509_sequence *cur = san; cur != NULL; cur = cur->next) {
        const unsigned char san_type = (unsigned char) cur->buf.tag &
                                       MBEDTLS_ASN1_TAG_VALUE_MASK;
        if (san_type == MBEDTLS_X509_SAN_IP_ADDRESS &&
            cur->buf.len == cn_len && memcmp(cur->buf.p, ip, cn_len) == 0) {
            return 0;
        }
    }
    return -1;
}
static int x509_crt_check_san_uri(const mbedtls_x509_sequence *san,
                                  const char *cn, size_t cn_len)
{
    for (const mbedtls_x509_sequence *cur = san; cur != NULL; cur = cur->next) {
        const unsigned char san_type = (unsigned char) cur->buf.tag &
                                       MBEDTLS_ASN1_TAG_VALUE_MASK;
        if (san_type == MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER &&
            cur->buf.len == cn_len && memcmp(cur->buf.p, cn, cn_len) == 0) {
            return 0;
        }
    }
    return -1;
}
static int x509_crt_check_san(const mbedtls_x509_sequence *san,
                              const char *cn, size_t cn_len)
{
    int san_ip = 0;
    int san_uri = 0;
    for (const mbedtls_x509_sequence *cur = san; cur != NULL; cur = cur->next) {
        switch ((unsigned char) cur->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) {
            case MBEDTLS_X509_SAN_DNS_NAME:
                if (x509_crt_check_cn(&cur->buf, cn, cn_len) == 0) {
                    return 0;
                }
                break;
            case MBEDTLS_X509_SAN_IP_ADDRESS:
                san_ip = 1;
                break;
            case MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER:
                san_uri = 1;
                break;
            default:
                break;
        }
    }
    if (san_ip) {
        if (x509_crt_check_san_ip(san, cn, cn_len) == 0) {
            return 0;
        }
    }
    if (san_uri) {
        if (x509_crt_check_san_uri(san, cn, cn_len) == 0) {
            return 0;
        }
    }
    return -1;
}
static void x509_crt_verify_name(const mbedtls_x509_crt *crt,
                                 const char *cn,
                                 uint32_t *flags)
{
    const mbedtls_x509_name *name;
    size_t cn_len = strlen(cn);
    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
        if (x509_crt_check_san(&crt->subject_alt_names, cn, cn_len) == 0) {
            return;
        }
    } else {
        for (name = &crt->subject; name != NULL; name = name->next) {
            if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0 &&
                x509_crt_check_cn(&name->val, cn, cn_len) == 0) {
                return;
            }
        }
    }
    *flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
}
static int x509_crt_merge_flags_with_cb(
    uint32_t *flags,
    const mbedtls_x509_crt_verify_chain *ver_chain,
    int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
    void *p_vrfy)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned i;
    uint32_t cur_flags;
    const mbedtls_x509_crt_verify_chain_item *cur;
    for (i = ver_chain->len; i != 0; --i) {
        cur = &ver_chain->items[i-1];
        cur_flags = cur->flags;
        if (NULL != f_vrfy) {
            if ((ret = f_vrfy(p_vrfy, cur->crt, (int) i-1, &cur_flags)) != 0) {
                return ret;
            }
        }
        *flags |= cur_flags;
    }
    return 0;
}
static int x509_crt_verify_restartable_ca_cb(mbedtls_x509_crt *crt,
                                             mbedtls_x509_crt *trust_ca,
                                             mbedtls_x509_crl *ca_crl,
                                             mbedtls_x509_crt_ca_cb_t f_ca_cb,
                                             void *p_ca_cb,
                                             const mbedtls_x509_crt_profile *profile,
                                             const char *cn, uint32_t *flags,
                                             int (*f_vrfy)(void *,
                                                           mbedtls_x509_crt *,
                                                           int,
                                                           uint32_t *),
                                             void *p_vrfy,
                                             mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_pk_type_t pk_type;
    mbedtls_x509_crt_verify_chain ver_chain;
    uint32_t ee_flags;
    *flags = 0;
    ee_flags = 0;
    x509_crt_verify_chain_reset(&ver_chain);
    if (profile == NULL) {
        ret = MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        goto exit;
    }
    if (cn != NULL) {
        x509_crt_verify_name(crt, cn, &ee_flags);
    }
    pk_type = mbedtls_pk_get_type(&crt->pk);
    if (x509_profile_check_pk_alg(profile, pk_type) != 0) {
        ee_flags |= MBEDTLS_X509_BADCERT_BAD_PK;
    }
    if (x509_profile_check_key(profile, &crt->pk) != 0) {
        ee_flags |= MBEDTLS_X509_BADCERT_BAD_KEY;
    }
    ret = x509_crt_verify_chain(crt, trust_ca, ca_crl,
                                f_ca_cb, p_ca_cb, profile,
                                &ver_chain, rs_ctx);
    if (ret != 0) {
        goto exit;
    }
    ver_chain.items[0].flags |= ee_flags;
    ret = x509_crt_merge_flags_with_cb(flags, &ver_chain, f_vrfy, p_vrfy);
exit:
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    mbedtls_x509_crt_free(ver_chain.trust_ca_cb_result);
    mbedtls_free(ver_chain.trust_ca_cb_result);
    ver_chain.trust_ca_cb_result = NULL;
#endif
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && ret != MBEDTLS_ERR_ECP_IN_PROGRESS) {
        mbedtls_x509_crt_restart_free(rs_ctx);
    }
#endif
    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
    }
    if (ret != 0) {
        *flags = (uint32_t) -1;
        return ret;
    }
    if (*flags != 0) {
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
    }
    return 0;
}
int mbedtls_x509_crt_verify(mbedtls_x509_crt *crt,
                            mbedtls_x509_crt *trust_ca,
                            mbedtls_x509_crl *ca_crl,
                            const char *cn, uint32_t *flags,
                            int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy)
{
    return x509_crt_verify_restartable_ca_cb(crt, trust_ca, ca_crl,
                                             NULL, NULL,
                                             &mbedtls_x509_crt_profile_default,
                                             cn, flags,
                                             f_vrfy, p_vrfy, NULL);
}
int mbedtls_x509_crt_verify_with_profile(mbedtls_x509_crt *crt,
                                         mbedtls_x509_crt *trust_ca,
                                         mbedtls_x509_crl *ca_crl,
                                         const mbedtls_x509_crt_profile *profile,
                                         const char *cn, uint32_t *flags,
                                         int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                                         void *p_vrfy)
{
    return x509_crt_verify_restartable_ca_cb(crt, trust_ca, ca_crl,
                                             NULL, NULL,
                                             profile, cn, flags,
                                             f_vrfy, p_vrfy, NULL);
}
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
int mbedtls_x509_crt_verify_with_ca_cb(mbedtls_x509_crt *crt,
                                       mbedtls_x509_crt_ca_cb_t f_ca_cb,
                                       void *p_ca_cb,
                                       const mbedtls_x509_crt_profile *profile,
                                       const char *cn, uint32_t *flags,
                                       int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                                       void *p_vrfy)
{
    return x509_crt_verify_restartable_ca_cb(crt, NULL, NULL,
                                             f_ca_cb, p_ca_cb,
                                             profile, cn, flags,
                                             f_vrfy, p_vrfy, NULL);
}
#endif
int mbedtls_x509_crt_verify_restartable(mbedtls_x509_crt *crt,
                                        mbedtls_x509_crt *trust_ca,
                                        mbedtls_x509_crl *ca_crl,
                                        const mbedtls_x509_crt_profile *profile,
                                        const char *cn, uint32_t *flags,
                                        int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                                        void *p_vrfy,
                                        mbedtls_x509_crt_restart_ctx *rs_ctx)
{
    return x509_crt_verify_restartable_ca_cb(crt, trust_ca, ca_crl,
                                             NULL, NULL,
                                             profile, cn, flags,
                                             f_vrfy, p_vrfy, rs_ctx);
}
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt)
{
    memset(crt, 0, sizeof(mbedtls_x509_crt));
}
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt)
{
    mbedtls_x509_crt *cert_cur = crt;
    mbedtls_x509_crt *cert_prv;
    while (cert_cur != NULL) {
        mbedtls_pk_free(&cert_cur->pk);
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
        mbedtls_free(cert_cur->sig_opts);
#endif
        mbedtls_asn1_free_named_data_list_shallow(cert_cur->issuer.next);
        mbedtls_asn1_free_named_data_list_shallow(cert_cur->subject.next);
        mbedtls_asn1_sequence_free(cert_cur->ext_key_usage.next);
        mbedtls_asn1_sequence_free(cert_cur->subject_alt_names.next);
        mbedtls_asn1_sequence_free(cert_cur->certificate_policies.next);
        mbedtls_asn1_sequence_free(cert_cur->authority_key_id.authorityCertIssuer.next);
        if (cert_cur->raw.p != NULL && cert_cur->own_buffer) {
            mbedtls_zeroize_and_free(cert_cur->raw.p, cert_cur->raw.len);
        }
        cert_prv = cert_cur;
        cert_cur = cert_cur->next;
        mbedtls_platform_zeroize(cert_prv, sizeof(mbedtls_x509_crt));
        if (cert_prv != crt) {
            mbedtls_free(cert_prv);
        }
    }
}
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
void mbedtls_x509_crt_restart_init(mbedtls_x509_crt_restart_ctx *ctx)
{
    mbedtls_pk_restart_init(&ctx->pk);
    ctx->parent = NULL;
    ctx->fallback_parent = NULL;
    ctx->fallback_signature_is_good = 0;
    ctx->parent_is_trusted = -1;
    ctx->in_progress = x509_crt_rs_none;
    ctx->self_cnt = 0;
    x509_crt_verify_chain_reset(&ctx->ver_chain);
}
void mbedtls_x509_crt_restart_free(mbedtls_x509_crt_restart_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    mbedtls_pk_restart_free(&ctx->pk);
    mbedtls_x509_crt_restart_init(ctx);
}
#endif
int mbedtls_x509_crt_get_ca_istrue(const mbedtls_x509_crt *crt)
{
    if ((crt->ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) != 0) {
        return crt->MBEDTLS_PRIVATE(ca_istrue);
    }
    return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
}
#endif
