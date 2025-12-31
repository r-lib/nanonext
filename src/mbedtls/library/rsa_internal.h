/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_RSA_INTERNAL_H
#define MBEDTLS_RSA_INTERNAL_H

#include "mbedtls/rsa.h"
#include "mbedtls/asn1.h"

int mbedtls_rsa_parse_key(mbedtls_rsa_context *rsa, const unsigned char *key, size_t keylen);

int mbedtls_rsa_parse_pubkey(mbedtls_rsa_context *rsa, const unsigned char *key, size_t keylen);

int mbedtls_rsa_write_key(const mbedtls_rsa_context *rsa, unsigned char *start,
                          unsigned char **p);

int mbedtls_rsa_write_pubkey(const mbedtls_rsa_context *rsa, unsigned char *start,
                             unsigned char **p);

#if defined(MBEDTLS_PKCS1_V21)

int mbedtls_rsa_rsassa_pss_sign_no_mode_check(mbedtls_rsa_context *ctx,
                                              int (*f_rng)(void *, unsigned char *, size_t),
                                              void *p_rng,
                                              mbedtls_md_type_t md_alg,
                                              unsigned int hashlen,
                                              const unsigned char *hash,
                                              unsigned char *sig);
#endif

#endif
