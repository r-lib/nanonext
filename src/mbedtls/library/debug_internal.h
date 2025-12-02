/**
 * \file debug_internal.h
 *
 * \brief Internal part of the public "debug.h".
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_DEBUG_INTERNAL_H
#define MBEDTLS_DEBUG_INTERNAL_H

#include "mbedtls/debug.h"

void mbedtls_debug_print_msg(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *format, ...) MBEDTLS_PRINTF_ATTRIBUTE(5, 6);

void mbedtls_debug_print_ret(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, int ret);

void mbedtls_debug_print_buf(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line, const char *text,
                             const unsigned char *buf, size_t len);

#if defined(MBEDTLS_BIGNUM_C)

void mbedtls_debug_print_mpi(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const mbedtls_mpi *X);
#endif

#if defined(MBEDTLS_ECP_LIGHT)

void mbedtls_debug_print_ecp(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const mbedtls_ecp_point *X);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)

void mbedtls_debug_print_crt(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const mbedtls_x509_crt *crt);
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED) && \
    defined(MBEDTLS_ECDH_C)
typedef enum {
    MBEDTLS_DEBUG_ECDH_Q,
    MBEDTLS_DEBUG_ECDH_QP,
    MBEDTLS_DEBUG_ECDH_Z,
} mbedtls_debug_ecdh_attr;

void mbedtls_debug_printf_ecdh(const mbedtls_ssl_context *ssl, int level,
                               const char *file, int line,
                               const mbedtls_ecdh_context *ecdh,
                               mbedtls_debug_ecdh_attr attr);
#endif
#endif
