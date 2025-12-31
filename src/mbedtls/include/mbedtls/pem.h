/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PEM_H
#define MBEDTLS_PEM_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>

#define MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT          -0x1080

#define MBEDTLS_ERR_PEM_INVALID_DATA                      -0x1100

#define MBEDTLS_ERR_PEM_ALLOC_FAILED                      -0x1180

#define MBEDTLS_ERR_PEM_INVALID_ENC_IV                    -0x1200

#define MBEDTLS_ERR_PEM_UNKNOWN_ENC_ALG                   -0x1280

#define MBEDTLS_ERR_PEM_PASSWORD_REQUIRED                 -0x1300

#define MBEDTLS_ERR_PEM_PASSWORD_MISMATCH                 -0x1380

#define MBEDTLS_ERR_PEM_FEATURE_UNAVAILABLE               -0x1400

#define MBEDTLS_ERR_PEM_BAD_INPUT_DATA                    -0x1480

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_PEM_PARSE_C)

typedef struct mbedtls_pem_context {
    unsigned char *MBEDTLS_PRIVATE(buf);
    size_t MBEDTLS_PRIVATE(buflen);
    unsigned char *MBEDTLS_PRIVATE(info);
}
mbedtls_pem_context;

void mbedtls_pem_init(mbedtls_pem_context *ctx);

int mbedtls_pem_read_buffer(mbedtls_pem_context *ctx, const char *header, const char *footer,
                            const unsigned char *data,
                            const unsigned char *pwd,
                            size_t pwdlen, size_t *use_len);

static inline const unsigned char *mbedtls_pem_get_buffer(mbedtls_pem_context *ctx, size_t *buflen)
{
    *buflen = ctx->MBEDTLS_PRIVATE(buflen);
    return ctx->MBEDTLS_PRIVATE(buf);
}

void mbedtls_pem_free(mbedtls_pem_context *ctx);
#endif

#if defined(MBEDTLS_PEM_WRITE_C)

int mbedtls_pem_write_buffer(const char *header, const char *footer,
                             const unsigned char *der_data, size_t der_len,
                             unsigned char *buf, size_t buf_len, size_t *olen);
#endif

#ifdef __cplusplus
}
#endif

#endif
