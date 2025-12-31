/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_DEBUG_H
#define MBEDTLS_DEBUG_H

#include "mbedtls/build_info.h"

#include "mbedtls/ssl.h"

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_DEBUG_C)

#define MBEDTLS_DEBUG_STRIP_PARENS(...)   __VA_ARGS__

#define MBEDTLS_SSL_DEBUG_MSG(level, args)                    \
    mbedtls_debug_print_msg(ssl, level, __FILE__, __LINE__,    \
                            MBEDTLS_DEBUG_STRIP_PARENS args)

#define MBEDTLS_SSL_DEBUG_RET(level, text, ret)                \
    mbedtls_debug_print_ret(ssl, level, __FILE__, __LINE__, text, ret)

#define MBEDTLS_SSL_DEBUG_BUF(level, text, buf, len)           \
    mbedtls_debug_print_buf(ssl, level, __FILE__, __LINE__, text, buf, len)

#if defined(MBEDTLS_BIGNUM_C)
#define MBEDTLS_SSL_DEBUG_MPI(level, text, X)                  \
    mbedtls_debug_print_mpi(ssl, level, __FILE__, __LINE__, text, X)
#endif

#if defined(MBEDTLS_ECP_C)
#define MBEDTLS_SSL_DEBUG_ECP(level, text, X)                  \
    mbedtls_debug_print_ecp(ssl, level, __FILE__, __LINE__, text, X)
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#define MBEDTLS_SSL_DEBUG_CRT(level, text, crt)                \
    mbedtls_debug_print_crt(ssl, level, __FILE__, __LINE__, text, crt)
#else
#define MBEDTLS_SSL_DEBUG_CRT(level, text, crt)       do { } while (0)
#endif
#endif

#if defined(MBEDTLS_ECDH_C)
#define MBEDTLS_SSL_DEBUG_ECDH(level, ecdh, attr)               \
    mbedtls_debug_printf_ecdh(ssl, level, __FILE__, __LINE__, ecdh, attr)
#endif

#else

#define MBEDTLS_SSL_DEBUG_MSG(level, args)            do { } while (0)
#define MBEDTLS_SSL_DEBUG_RET(level, text, ret)       do { } while (0)
#define MBEDTLS_SSL_DEBUG_BUF(level, text, buf, len)  do { } while (0)
#define MBEDTLS_SSL_DEBUG_MPI(level, text, X)         do { } while (0)
#define MBEDTLS_SSL_DEBUG_ECP(level, text, X)         do { } while (0)
#define MBEDTLS_SSL_DEBUG_CRT(level, text, crt)       do { } while (0)
#define MBEDTLS_SSL_DEBUG_ECDH(level, ecdh, attr)     do { } while (0)

#endif

#if defined(__has_attribute)
#if __has_attribute(format)
#if defined(__MINGW32__) && __USE_MINGW_ANSI_STDIO == 1
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)    \
    __attribute__((__format__(gnu_printf, string_index, first_to_check)))
#else
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)    \
    __attribute__((format(printf, string_index, first_to_check)))
#endif
#else
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif
#else
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER < 1900)
   #include <inttypes.h>
   #define MBEDTLS_PRINTF_SIZET     PRIuPTR
   #define MBEDTLS_PRINTF_LONGLONG  "I64d"
#else \

   #define MBEDTLS_PRINTF_SIZET     "zu"
   #define MBEDTLS_PRINTF_LONGLONG  "lld"
#endif \

#if !defined(MBEDTLS_PRINTF_MS_TIME)
#include <inttypes.h>
#if !defined(PRId64)
#define MBEDTLS_PRINTF_MS_TIME MBEDTLS_PRINTF_LONGLONG
#else
#define MBEDTLS_PRINTF_MS_TIME PRId64
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

void mbedtls_debug_set_threshold(int threshold);

#ifdef __cplusplus
}
#endif

#endif
