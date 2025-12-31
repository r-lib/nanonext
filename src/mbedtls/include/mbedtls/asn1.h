/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ASN1_H
#define MBEDTLS_ASN1_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"

#include <stddef.h>

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#define MBEDTLS_ERR_ASN1_OUT_OF_DATA                      -0x0060

#define MBEDTLS_ERR_ASN1_UNEXPECTED_TAG                   -0x0062

#define MBEDTLS_ERR_ASN1_INVALID_LENGTH                   -0x0064

#define MBEDTLS_ERR_ASN1_LENGTH_MISMATCH                  -0x0066

#define MBEDTLS_ERR_ASN1_INVALID_DATA                     -0x0068

#define MBEDTLS_ERR_ASN1_ALLOC_FAILED                     -0x006A

#define MBEDTLS_ERR_ASN1_BUF_TOO_SMALL                    -0x006C

#define MBEDTLS_ASN1_BOOLEAN                 0x01
#define MBEDTLS_ASN1_INTEGER                 0x02
#define MBEDTLS_ASN1_BIT_STRING              0x03
#define MBEDTLS_ASN1_OCTET_STRING            0x04
#define MBEDTLS_ASN1_NULL                    0x05
#define MBEDTLS_ASN1_OID                     0x06
#define MBEDTLS_ASN1_ENUMERATED              0x0A
#define MBEDTLS_ASN1_UTF8_STRING             0x0C
#define MBEDTLS_ASN1_SEQUENCE                0x10
#define MBEDTLS_ASN1_SET                     0x11
#define MBEDTLS_ASN1_PRINTABLE_STRING        0x13
#define MBEDTLS_ASN1_T61_STRING              0x14
#define MBEDTLS_ASN1_IA5_STRING              0x16
#define MBEDTLS_ASN1_UTC_TIME                0x17
#define MBEDTLS_ASN1_GENERALIZED_TIME        0x18
#define MBEDTLS_ASN1_UNIVERSAL_STRING        0x1C
#define MBEDTLS_ASN1_BMP_STRING              0x1E
#define MBEDTLS_ASN1_PRIMITIVE               0x00
#define MBEDTLS_ASN1_CONSTRUCTED             0x20
#define MBEDTLS_ASN1_CONTEXT_SPECIFIC        0x80

#define MBEDTLS_ASN1_IS_STRING_TAG(tag)                                \
    ((unsigned int) (tag) < 32u && (                                   \
         ((1u << (tag)) & ((1u << MBEDTLS_ASN1_BMP_STRING)       |     \
                           (1u << MBEDTLS_ASN1_UTF8_STRING)      |     \
                           (1u << MBEDTLS_ASN1_T61_STRING)       |     \
                           (1u << MBEDTLS_ASN1_IA5_STRING)       |     \
                           (1u << MBEDTLS_ASN1_UNIVERSAL_STRING) |     \
                           (1u << MBEDTLS_ASN1_PRINTABLE_STRING))) != 0))

#define MBEDTLS_ASN1_TAG_CLASS_MASK          0xC0
#define MBEDTLS_ASN1_TAG_PC_MASK             0x20
#define MBEDTLS_ASN1_TAG_VALUE_MASK          0x1F

#define MBEDTLS_OID_SIZE(x) (sizeof(x) - 1)

#define MBEDTLS_OID_CMP(oid_str, oid_buf)                                   \
    ((MBEDTLS_OID_SIZE(oid_str) != (oid_buf)->len) ||                \
     memcmp((oid_str), (oid_buf)->p, (oid_buf)->len) != 0)

#define MBEDTLS_OID_CMP_RAW(oid_str, oid_buf, oid_buf_len)              \
    ((MBEDTLS_OID_SIZE(oid_str) != (oid_buf_len)) ||             \
     memcmp((oid_str), (oid_buf), (oid_buf_len)) != 0)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_asn1_buf {
    int tag;
    size_t len;
    unsigned char *p;
}
mbedtls_asn1_buf;

typedef struct mbedtls_asn1_bitstring {
    size_t len;
    unsigned char unused_bits;
    unsigned char *p;
}
mbedtls_asn1_bitstring;

typedef struct mbedtls_asn1_sequence {
    mbedtls_asn1_buf buf;

    struct mbedtls_asn1_sequence *next;
}
mbedtls_asn1_sequence;

typedef struct mbedtls_asn1_named_data {
    mbedtls_asn1_buf oid;
    mbedtls_asn1_buf val;

    struct mbedtls_asn1_named_data *next;

    unsigned char MBEDTLS_PRIVATE(next_merged);
}
mbedtls_asn1_named_data;

#if defined(MBEDTLS_ASN1_PARSE_C) || defined(MBEDTLS_X509_CREATE_C) || \
    defined(MBEDTLS_PSA_UTIL_HAVE_ECDSA)

int mbedtls_asn1_get_len(unsigned char **p,
                         const unsigned char *end,
                         size_t *len);

int mbedtls_asn1_get_tag(unsigned char **p,
                         const unsigned char *end,
                         size_t *len, int tag);
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)

int mbedtls_asn1_get_bool(unsigned char **p,
                          const unsigned char *end,
                          int *val);

int mbedtls_asn1_get_int(unsigned char **p,
                         const unsigned char *end,
                         int *val);

int mbedtls_asn1_get_enum(unsigned char **p,
                          const unsigned char *end,
                          int *val);

int mbedtls_asn1_get_bitstring(unsigned char **p, const unsigned char *end,
                               mbedtls_asn1_bitstring *bs);

int mbedtls_asn1_get_bitstring_null(unsigned char **p,
                                    const unsigned char *end,
                                    size_t *len);

int mbedtls_asn1_get_sequence_of(unsigned char **p,
                                 const unsigned char *end,
                                 mbedtls_asn1_sequence *cur,
                                 int tag);

void mbedtls_asn1_sequence_free(mbedtls_asn1_sequence *seq);

int mbedtls_asn1_traverse_sequence_of(
    unsigned char **p,
    const unsigned char *end,
    unsigned char tag_must_mask, unsigned char tag_must_val,
    unsigned char tag_may_mask, unsigned char tag_may_val,
    int (*cb)(void *ctx, int tag,
              unsigned char *start, size_t len),
    void *ctx);

#if defined(MBEDTLS_BIGNUM_C)

int mbedtls_asn1_get_mpi(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_mpi *X);
#endif

int mbedtls_asn1_get_alg(unsigned char **p,
                         const unsigned char *end,
                         mbedtls_asn1_buf *alg, mbedtls_asn1_buf *params);

int mbedtls_asn1_get_alg_null(unsigned char **p,
                              const unsigned char *end,
                              mbedtls_asn1_buf *alg);

const mbedtls_asn1_named_data *mbedtls_asn1_find_named_data(const mbedtls_asn1_named_data *list,
                                                            const char *oid, size_t len);

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

void MBEDTLS_DEPRECATED mbedtls_asn1_free_named_data(mbedtls_asn1_named_data *entry);
#endif

void mbedtls_asn1_free_named_data_list(mbedtls_asn1_named_data **head);

void mbedtls_asn1_free_named_data_list_shallow(mbedtls_asn1_named_data *name);

#endif

#ifdef __cplusplus
}
#endif

#endif
