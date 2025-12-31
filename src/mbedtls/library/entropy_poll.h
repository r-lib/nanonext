/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ENTROPY_POLL_H
#define MBEDTLS_ENTROPY_POLL_H

#include "mbedtls/build_info.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ENTROPY_MIN_PLATFORM     32
#if !defined(MBEDTLS_ENTROPY_MIN_HARDWARE)
#define MBEDTLS_ENTROPY_MIN_HARDWARE     32
#endif

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)

int mbedtls_platform_entropy_poll(void *data,
                                  unsigned char *output, size_t len, size_t *olen);
#endif

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

int mbedtls_hardware_poll(void *data,
                          unsigned char *output, size_t len, size_t *olen);
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED)

int mbedtls_nv_seed_poll(void *data,
                         unsigned char *output, size_t len, size_t *olen);
#endif

#ifdef __cplusplus
}
#endif

#endif
