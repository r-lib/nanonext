/**
 * \file error.h
 *
 * \brief Error to string translation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ERROR_H
#define MBEDTLS_ERROR_H 
#include "mbedtls/build_info.h"
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
#define MBEDTLS_ERR_ERROR_GENERIC_ERROR -0x0001
#define MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED -0x006E
#define MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED -0x0070
#define MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072
#define MBEDTLS_ERROR_ADD(high,low) \
    mbedtls_error_add(high, low, __FILE__, __LINE__)
#if defined(MBEDTLS_TEST_HOOKS)
extern void (*mbedtls_test_hook_error_add)(int, int, const char *, int);
#endif
static inline int mbedtls_error_add(int high, int low,
                                    const char *file, int line)
{
#if defined(MBEDTLS_TEST_HOOKS)
    if (*mbedtls_test_hook_error_add != NULL) {
        (*mbedtls_test_hook_error_add)(high, low, file, line);
    }
#endif
    (void) file;
    (void) line;
    return high + low;
}
void mbedtls_strerror(int errnum, char *buffer, size_t buflen);
const char *mbedtls_high_level_strerr(int error_code);
const char *mbedtls_low_level_strerr(int error_code);
#ifdef __cplusplus
}
#endif
#endif
