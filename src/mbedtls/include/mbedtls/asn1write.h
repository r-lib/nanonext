/**
 * \file asn1write.h
 *
 * \brief ASN.1 buffer writing functionality
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ASN1_WRITE_H
#define MBEDTLS_ASN1_WRITE_H 
#include "mbedtls/build_info.h"
#include "mbedtls/asn1.h"
#define MBEDTLS_ASN1_CHK_ADD(g,f) \
    do \
    { \
        if ((ret = (f)) < 0) \
        return ret; \
        else \
        (g) += ret; \
    } while (0)
#define MBEDTLS_ASN1_CHK_CLEANUP_ADD(g,f) \
    do \
    { \
        if ((ret = (f)) < 0) \
        goto cleanup; \
        else \
        (g) += ret; \
    } while (0)
#ifdef __cplusplus
extern "C" {
#endif
#if defined(MBEDTLS_ASN1_WRITE_C) || defined(MBEDTLS_X509_USE_C) || \
    defined(MBEDTLS_PSA_UTIL_HAVE_ECDSA)
int mbedtls_asn1_write_len(unsigned char **p, const unsigned char *start,
                           size_t len);
int mbedtls_asn1_write_tag(unsigned char **p, const unsigned char *start,
                           unsigned char tag);
#endif
#if defined(MBEDTLS_ASN1_WRITE_C)
int mbedtls_asn1_write_raw_buffer(unsigned char **p, const unsigned char *start,
                                  const unsigned char *buf, size_t size);
#if defined(MBEDTLS_BIGNUM_C)
int mbedtls_asn1_write_mpi(unsigned char **p, const unsigned char *start,
                           const mbedtls_mpi *X);
#endif
int mbedtls_asn1_write_null(unsigned char **p, const unsigned char *start);
int mbedtls_asn1_write_oid(unsigned char **p, const unsigned char *start,
                           const char *oid, size_t oid_len);
int mbedtls_asn1_write_algorithm_identifier(unsigned char **p,
                                            const unsigned char *start,
                                            const char *oid, size_t oid_len,
                                            size_t par_len);
int mbedtls_asn1_write_algorithm_identifier_ext(unsigned char **p,
                                                const unsigned char *start,
                                                const char *oid, size_t oid_len,
                                                size_t par_len, int has_par);
int mbedtls_asn1_write_bool(unsigned char **p, const unsigned char *start,
                            int boolean);
int mbedtls_asn1_write_int(unsigned char **p, const unsigned char *start, int val);
int mbedtls_asn1_write_enum(unsigned char **p, const unsigned char *start, int val);
int mbedtls_asn1_write_tagged_string(unsigned char **p, const unsigned char *start,
                                     int tag, const char *text,
                                     size_t text_len);
int mbedtls_asn1_write_printable_string(unsigned char **p,
                                        const unsigned char *start,
                                        const char *text, size_t text_len);
int mbedtls_asn1_write_utf8_string(unsigned char **p, const unsigned char *start,
                                   const char *text, size_t text_len);
int mbedtls_asn1_write_ia5_string(unsigned char **p, const unsigned char *start,
                                  const char *text, size_t text_len);
int mbedtls_asn1_write_bitstring(unsigned char **p, const unsigned char *start,
                                 const unsigned char *buf, size_t bits);
int mbedtls_asn1_write_named_bitstring(unsigned char **p,
                                       const unsigned char *start,
                                       const unsigned char *buf,
                                       size_t bits);
int mbedtls_asn1_write_octet_string(unsigned char **p, const unsigned char *start,
                                    const unsigned char *buf, size_t size);
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data(mbedtls_asn1_named_data **list,
                                                       const char *oid, size_t oid_len,
                                                       const unsigned char *val,
                                                       size_t val_len);
#ifdef __cplusplus
}
#endif
#endif
#endif
