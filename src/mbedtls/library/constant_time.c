/**
 *  Constant-time functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include <stdint.h>
#include <limits.h>
#include "common.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include <string.h>
#if !defined(MBEDTLS_CT_ASM)
volatile mbedtls_ct_uint_t mbedtls_ct_zero = 0;
#endif
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS) && \
    ((defined(MBEDTLS_CT_ARM_ASM) && (UINTPTR_MAX == 0xfffffffful)) || \
    defined(MBEDTLS_CT_AARCH64_ASM))
#define MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS 
static inline uint32_t mbedtls_get_unaligned_volatile_uint32(volatile const unsigned char *p)
{
    uint32_t r;
#if defined(MBEDTLS_CT_ARM_ASM)
    asm volatile ("ldr %0, [%1]" : "=r" (r) : "r" (p) :);
#elif defined(MBEDTLS_CT_AARCH64_ASM)
    asm volatile ("ldr %w0, [%1]" : "=r" (r) : MBEDTLS_ASM_AARCH64_PTR_CONSTRAINT(p) :);
#else
#error "No assembly defined for mbedtls_get_unaligned_volatile_uint32"
#endif
    return r;
}
#endif
int mbedtls_ct_memcmp(const void *a,
                      const void *b,
                      size_t n)
{
    size_t i = 0;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    uint32_t diff = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_VOLATILE_ACCESS)
    for (; (i + 4) <= n; i += 4) {
        uint32_t x = mbedtls_get_unaligned_volatile_uint32(A + i);
        uint32_t y = mbedtls_get_unaligned_volatile_uint32(B + i);
        diff |= x ^ y;
    }
#endif
    for (; i < n; i++) {
        unsigned char x = A[i], y = B[i];
        diff |= x ^ y;
    }
#if (INT_MAX < INT32_MAX)
#error "mbedtls_ct_memcmp() requires minimum 32-bit ints"
#else
    return (int) ((diff & 0xffff) | (diff >> 16));
#endif
}
#if defined(MBEDTLS_NIST_KW_C)
int mbedtls_ct_memcmp_partial(const void *a,
                              const void *b,
                              size_t n,
                              size_t skip_head,
                              size_t skip_tail)
{
    unsigned int diff = 0;
    volatile const unsigned char *A = (volatile const unsigned char *) a;
    volatile const unsigned char *B = (volatile const unsigned char *) b;
    size_t valid_end = n - skip_tail;
    for (size_t i = 0; i < n; i++) {
        unsigned char x = A[i], y = B[i];
        unsigned int d = x ^ y;
        mbedtls_ct_condition_t valid = mbedtls_ct_bool_and(mbedtls_ct_uint_ge(i, skip_head),
                                                           mbedtls_ct_uint_lt(i, valid_end));
        diff |= mbedtls_ct_uint_if_else_0(valid, d);
    }
    return (int) diff;
}
#endif
#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT)
void mbedtls_ct_memmove_left(void *start, size_t total, size_t offset)
{
    volatile unsigned char *buf = start;
    for (size_t i = 0; i < total; i++) {
        mbedtls_ct_condition_t no_op = mbedtls_ct_uint_gt(total - offset, i);
        for (size_t n = 0; n < total - 1; n++) {
            unsigned char current = buf[n];
            unsigned char next = buf[n+1];
            buf[n] = mbedtls_ct_uint_if(no_op, current, next);
        }
        buf[total-1] = mbedtls_ct_uint_if_else_0(no_op, buf[total-1]);
    }
}
#endif
void mbedtls_ct_memcpy_if(mbedtls_ct_condition_t condition,
                          unsigned char *dest,
                          const unsigned char *src1,
                          const unsigned char *src2,
                          size_t len)
{
#if defined(MBEDTLS_CT_SIZE_64)
    const uint64_t mask = (uint64_t) condition;
    const uint64_t not_mask = (uint64_t) ~mbedtls_ct_compiler_opaque(condition);
#else
    const uint32_t mask = (uint32_t) condition;
    const uint32_t not_mask = (uint32_t) ~mbedtls_ct_compiler_opaque(condition);
#endif
    if (src2 == NULL) {
        src2 = dest;
    }
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
#if defined(MBEDTLS_CT_SIZE_64)
    for (; (i + 8) <= len; i += 8) {
        uint64_t a = mbedtls_get_unaligned_uint64(src1 + i) & mask;
        uint64_t b = mbedtls_get_unaligned_uint64(src2 + i) & not_mask;
        mbedtls_put_unaligned_uint64(dest + i, a | b);
    }
#else
    for (; (i + 4) <= len; i += 4) {
        uint32_t a = mbedtls_get_unaligned_uint32(src1 + i) & mask;
        uint32_t b = mbedtls_get_unaligned_uint32(src2 + i) & not_mask;
        mbedtls_put_unaligned_uint32(dest + i, a | b);
    }
#endif
#endif
    for (; i < len; i++) {
        dest[i] = (src1[i] & mask) | (src2[i] & not_mask);
    }
}
void mbedtls_ct_memcpy_offset(unsigned char *dest,
                              const unsigned char *src,
                              size_t offset,
                              size_t offset_min,
                              size_t offset_max,
                              size_t len)
{
    size_t offsetval;
    for (offsetval = offset_min; offsetval <= offset_max; offsetval++) {
        mbedtls_ct_memcpy_if(mbedtls_ct_uint_eq(offsetval, offset), dest, src + offsetval, NULL,
                             len);
    }
}
#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT)
void mbedtls_ct_zeroize_if(mbedtls_ct_condition_t condition, void *buf, size_t len)
{
    uint32_t mask = (uint32_t) ~condition;
    uint8_t *p = (uint8_t *) buf;
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
    for (; (i + 4) <= len; i += 4) {
        mbedtls_put_unaligned_uint32((void *) (p + i),
                                     mbedtls_get_unaligned_uint32((void *) (p + i)) & mask);
    }
#endif
    for (; i < len; i++) {
        p[i] = p[i] & mask;
    }
}
#endif
