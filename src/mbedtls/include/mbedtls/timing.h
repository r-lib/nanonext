/**
 * \file timing.h
 *
 * \brief Portable interface to timeouts and to the CPU cycle counter
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_TIMING_H
#define MBEDTLS_TIMING_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#if !defined(MBEDTLS_TIMING_ALT)
struct mbedtls_timing_hr_time {
    uint64_t MBEDTLS_PRIVATE(opaque)[4];
};
typedef struct mbedtls_timing_delay_context {
    struct mbedtls_timing_hr_time MBEDTLS_PRIVATE(timer);
    uint32_t MBEDTLS_PRIVATE(int_ms);
    uint32_t MBEDTLS_PRIVATE(fin_ms);
} mbedtls_timing_delay_context;
#else
#include "timing_alt.h"
#endif
unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset);
void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms);
int mbedtls_timing_get_delay(void *data);
uint32_t mbedtls_timing_get_final_delay(
    const mbedtls_timing_delay_context *data);
#ifdef __cplusplus
}
#endif
#endif
