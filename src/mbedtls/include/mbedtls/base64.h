/**
 * \file base64.h
 *
 * \brief RFC 1521 base64 encoding/decoding
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_BASE64_H
#define MBEDTLS_BASE64_H

#include "mbedtls/build_info.h"

#include <stddef.h>

#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL               -0x002A
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER              -0x002C

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                          const unsigned char *src, size_t slen);

int mbedtls_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
                          const unsigned char *src, size_t slen);

#ifdef __cplusplus
}
#endif

#endif
