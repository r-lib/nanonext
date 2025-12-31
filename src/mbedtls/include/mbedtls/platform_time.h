/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PLATFORM_TIME_H
#define MBEDTLS_PLATFORM_TIME_H

#include "mbedtls/build_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_PLATFORM_TIME_TYPE_MACRO)
typedef MBEDTLS_PLATFORM_TIME_TYPE_MACRO mbedtls_time_t;
#else

#include <time.h>
typedef time_t mbedtls_time_t;
#endif

#if defined(MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO)
typedef MBEDTLS_PLATFORM_MS_TIME_TYPE_MACRO mbedtls_ms_time_t;
#else
#include <stdint.h>
#include <inttypes.h>
typedef int64_t mbedtls_ms_time_t;
#endif

mbedtls_ms_time_t mbedtls_ms_time(void);

#if defined(MBEDTLS_PLATFORM_TIME_ALT)
extern mbedtls_time_t (*mbedtls_time)(mbedtls_time_t *time);

int mbedtls_platform_set_time(mbedtls_time_t (*time_func)(mbedtls_time_t *time));
#else
#if defined(MBEDTLS_PLATFORM_TIME_MACRO)
#define mbedtls_time    MBEDTLS_PLATFORM_TIME_MACRO
#else
#define mbedtls_time   time
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif
