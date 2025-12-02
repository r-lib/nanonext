/**
 * \file pkcs7.h
 *
 * \brief PKCS #7 generic defines and structures
 *  https://tools.ietf.org/html/rfc2315
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PKCS7_H
#define MBEDTLS_PKCS7_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509_crt.h"
#define MBEDTLS_ERR_PKCS7_INVALID_FORMAT -0x5300
#define MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE -0x5380
#define MBEDTLS_ERR_PKCS7_INVALID_VERSION -0x5400
#define MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO -0x5480
#define MBEDTLS_ERR_PKCS7_INVALID_ALG -0x5500
#define MBEDTLS_ERR_PKCS7_INVALID_CERT -0x5580
#define MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE -0x5600
#define MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO -0x5680
#define MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA -0x5700
#define MBEDTLS_ERR_PKCS7_ALLOC_FAILED -0x5780
#define MBEDTLS_ERR_PKCS7_VERIFY_FAIL -0x5800
#define MBEDTLS_ERR_PKCS7_CERT_DATE_INVALID -0x5880
#define MBEDTLS_PKCS7_SUPPORTED_VERSION 0x01
#ifdef __cplusplus
extern "C" {
#endif
typedef mbedtls_asn1_buf mbedtls_pkcs7_buf;
typedef mbedtls_asn1_named_data mbedtls_pkcs7_name;
typedef mbedtls_asn1_sequence mbedtls_pkcs7_sequence;
typedef enum {
    MBEDTLS_PKCS7_NONE=0,
    MBEDTLS_PKCS7_DATA,
    MBEDTLS_PKCS7_SIGNED_DATA,
    MBEDTLS_PKCS7_ENVELOPED_DATA,
    MBEDTLS_PKCS7_SIGNED_AND_ENVELOPED_DATA,
    MBEDTLS_PKCS7_DIGESTED_DATA,
    MBEDTLS_PKCS7_ENCRYPTED_DATA,
}
mbedtls_pkcs7_type;
typedef struct mbedtls_pkcs7_signer_info {
    int MBEDTLS_PRIVATE(version);
    mbedtls_x509_buf MBEDTLS_PRIVATE(serial);
    mbedtls_x509_name MBEDTLS_PRIVATE(issuer);
    mbedtls_x509_buf MBEDTLS_PRIVATE(issuer_raw);
    mbedtls_x509_buf MBEDTLS_PRIVATE(alg_identifier);
    mbedtls_x509_buf MBEDTLS_PRIVATE(sig_alg_identifier);
    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);
    struct mbedtls_pkcs7_signer_info *MBEDTLS_PRIVATE(next);
}
mbedtls_pkcs7_signer_info;
typedef struct mbedtls_pkcs7_signed_data {
    int MBEDTLS_PRIVATE(version);
    mbedtls_pkcs7_buf MBEDTLS_PRIVATE(digest_alg_identifiers);
    int MBEDTLS_PRIVATE(no_of_certs);
    mbedtls_x509_crt MBEDTLS_PRIVATE(certs);
    int MBEDTLS_PRIVATE(no_of_crls);
    mbedtls_x509_crl MBEDTLS_PRIVATE(crl);
    int MBEDTLS_PRIVATE(no_of_signers);
    mbedtls_pkcs7_signer_info MBEDTLS_PRIVATE(signers);
}
mbedtls_pkcs7_signed_data;
typedef struct mbedtls_pkcs7 {
    mbedtls_pkcs7_buf MBEDTLS_PRIVATE(raw);
    mbedtls_pkcs7_signed_data MBEDTLS_PRIVATE(signed_data);
}
mbedtls_pkcs7;
void mbedtls_pkcs7_init(mbedtls_pkcs7 *pkcs7);
int mbedtls_pkcs7_parse_der(mbedtls_pkcs7 *pkcs7, const unsigned char *buf,
                            const size_t buflen);
int mbedtls_pkcs7_signed_data_verify(mbedtls_pkcs7 *pkcs7,
                                     const mbedtls_x509_crt *cert,
                                     const unsigned char *data,
                                     size_t datalen);
int mbedtls_pkcs7_signed_hash_verify(mbedtls_pkcs7 *pkcs7,
                                     const mbedtls_x509_crt *cert,
                                     const unsigned char *hash, size_t hashlen);
void mbedtls_pkcs7_free(mbedtls_pkcs7 *pkcs7);
#ifdef __cplusplus
}
#endif
#endif
