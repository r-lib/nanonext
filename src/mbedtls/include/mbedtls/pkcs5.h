/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PKCS5_H
#define MBEDTLS_PKCS5_H

#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"

#include "mbedtls/asn1.h"
#include "mbedtls/md.h"
#include "mbedtls/cipher.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA                  -0x2f80

#define MBEDTLS_ERR_PKCS5_INVALID_FORMAT                  -0x2f00

#define MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE             -0x2e80

#define MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH               -0x2e00

#define MBEDTLS_PKCS5_DECRYPT      MBEDTLS_DECRYPT
#define MBEDTLS_PKCS5_ENCRYPT      MBEDTLS_ENCRYPT

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_ASN1_PARSE_C) && defined(MBEDTLS_CIPHER_C)

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

int MBEDTLS_DEPRECATED mbedtls_pkcs5_pbes2(const mbedtls_asn1_buf *pbe_params, int mode,
                                           const unsigned char *pwd,  size_t pwdlen,
                                           const unsigned char *data, size_t datalen,
                                           unsigned char *output);
#endif

#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)

int mbedtls_pkcs5_pbes2_ext(const mbedtls_asn1_buf *pbe_params, int mode,
                            const unsigned char *pwd,  size_t pwdlen,
                            const unsigned char *data, size_t datalen,
                            unsigned char *output, size_t output_size,
                            size_t *output_len);

#endif

#endif

int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_type,
                                  const unsigned char *password,
                                  size_t plen, const unsigned char *salt, size_t slen,
                                  unsigned int iteration_count,
                                  uint32_t key_length, unsigned char *output);

#if defined(MBEDTLS_MD_C)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)

int MBEDTLS_DEPRECATED mbedtls_pkcs5_pbkdf2_hmac(mbedtls_md_context_t *ctx,
                                                 const unsigned char *password,
                                                 size_t plen,
                                                 const unsigned char *salt,
                                                 size_t slen,
                                                 unsigned int iteration_count,
                                                 uint32_t key_length,
                                                 unsigned char *output);
#endif
#endif
#if defined(MBEDTLS_SELF_TEST)

int mbedtls_pkcs5_self_test(int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif
