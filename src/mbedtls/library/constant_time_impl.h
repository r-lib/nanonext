/**
 *  Constant-time functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CONSTANT_TIME_IMPL_H
#define MBEDTLS_CONSTANT_TIME_IMPL_H

#include <stddef.h>

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_HAVE_ASM) && defined(__GNUC__) && (!defined(__ARMCC_VERSION) || \
    __ARMCC_VERSION >= 6000000)
#define MBEDTLS_CT_ASM
#if (defined(__arm__) || defined(__thumb__) || defined(__thumb2__))
#define MBEDTLS_CT_ARM_ASM
#elif defined(__aarch64__)
#define MBEDTLS_CT_AARCH64_ASM
#elif defined(__amd64__) || defined(__x86_64__)
#define MBEDTLS_CT_X86_64_ASM
#elif defined(__i386__)
#define MBEDTLS_CT_X86_ASM
#endif
#endif

#define MBEDTLS_CT_SIZE (sizeof(mbedtls_ct_uint_t) * 8)

#if !defined(MBEDTLS_CT_ASM)
extern volatile mbedtls_ct_uint_t mbedtls_ct_zero;
#endif

static inline mbedtls_ct_uint_t mbedtls_ct_compiler_opaque(mbedtls_ct_uint_t x)
{
#if defined(MBEDTLS_CT_ASM)
    asm volatile ("" : [x] "+r" (x) :);
    return x;
#else
    return x ^ mbedtls_ct_zero;
#endif
}

#if defined(MBEDTLS_COMPILER_IS_GCC) && defined(__thumb__) && !defined(__thumb2__) && \
    (__GNUC__ < 11) && !defined(__ARM_ARCH_2__)
#define RESTORE_ASM_SYNTAX  ".syntax divided                      \n\t"
#else
#define RESTORE_ASM_SYNTAX
#endif

static inline mbedtls_ct_condition_t mbedtls_ct_bool(mbedtls_ct_uint_t x)
{

#if defined(MBEDTLS_CT_AARCH64_ASM) && (defined(MBEDTLS_CT_SIZE_32) || defined(MBEDTLS_CT_SIZE_64))
    mbedtls_ct_uint_t s;
    asm volatile ("neg %x[s], %x[x]                               \n\t"
                  "orr %x[x], %x[s], %x[x]                        \n\t"
                  "asr %x[x], %x[x], 63                           \n\t"
                  :
                  [s] "=&r" (s),
                  [x] "+&r" (x)
                  :
                  :
                  );
    return (mbedtls_ct_condition_t) x;
#elif defined(MBEDTLS_CT_ARM_ASM) && defined(MBEDTLS_CT_SIZE_32)
    uint32_t s;
    asm volatile (".syntax unified                                \n\t"
                  "negs %[s], %[x]                                \n\t"
                  "orrs %[x], %[x], %[s]                          \n\t"
                  "asrs %[x], %[x], #31                           \n\t"
                  RESTORE_ASM_SYNTAX
                  :
                  [s] "=&l" (s),
                  [x] "+&l" (x)
                  :
                  :
                  "cc"
                  );
    return (mbedtls_ct_condition_t) x;
#elif defined(MBEDTLS_CT_X86_64_ASM) && (defined(MBEDTLS_CT_SIZE_32) || defined(MBEDTLS_CT_SIZE_64))
    uint64_t s;
    asm volatile ("mov  %[x], %[s]                                \n\t"
                  "neg  %[s]                                      \n\t"
                  "or   %[x], %[s]                                \n\t"
                  "sar  $63, %[s]                                 \n\t"
                  :
                  [s] "=&a" (s)
                  :
                  [x] "D" (x)
                  :
                  );
    return (mbedtls_ct_condition_t) s;
#elif defined(MBEDTLS_CT_X86_ASM) && defined(MBEDTLS_CT_SIZE_32)
    uint32_t s;
    asm volatile ("mov %[x], %[s]                                 \n\t"
                  "neg %[s]                                       \n\t"
                  "or %[s], %[x]                                  \n\t"
                  "sar $31, %[x]                                  \n\t"
                  :
                  [s] "=&c" (s),
                  [x] "+&a" (x)
                  :
                  :
                  );
    return (mbedtls_ct_condition_t) x;
#else
    const mbedtls_ct_uint_t xo = mbedtls_ct_compiler_opaque(x);
#if defined(_MSC_VER)

#pragma warning( push )
#pragma warning( disable : 4146 )
#endif

    mbedtls_ct_int_t y = (-xo) | -(xo >> 1);

    y = (((mbedtls_ct_uint_t) y) >> (MBEDTLS_CT_SIZE - 1));

    return (mbedtls_ct_condition_t) (-y);
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
#endif
}

static inline mbedtls_ct_uint_t mbedtls_ct_if(mbedtls_ct_condition_t condition,
                                              mbedtls_ct_uint_t if1,
                                              mbedtls_ct_uint_t if0)
{
#if defined(MBEDTLS_CT_AARCH64_ASM) && (defined(MBEDTLS_CT_SIZE_32) || defined(MBEDTLS_CT_SIZE_64))
    asm volatile ("and %x[if1], %x[if1], %x[condition]            \n\t"
                  "mvn %x[condition], %x[condition]               \n\t"
                  "and %x[condition], %x[condition], %x[if0]      \n\t"
                  "orr %x[condition], %x[if1], %x[condition]"
                  :
                  [condition] "+&r" (condition),
                  [if1] "+&r" (if1)
                  :
                  [if0] "r" (if0)
                  :
                  );
    return (mbedtls_ct_uint_t) condition;
#elif defined(MBEDTLS_CT_ARM_ASM) && defined(MBEDTLS_CT_SIZE_32)
    asm volatile (".syntax unified                                \n\t"
                  "ands %[if1], %[if1], %[condition]              \n\t"
                  "mvns %[condition], %[condition]                \n\t"
                  "ands %[condition], %[condition], %[if0]        \n\t"
                  "orrs %[condition], %[if1], %[condition]        \n\t"
                  RESTORE_ASM_SYNTAX
                  :
                  [condition] "+&l" (condition),
                  [if1] "+&l" (if1)
                  :
                  [if0] "l" (if0)
                  :
                  "cc"
                  );
    return (mbedtls_ct_uint_t) condition;
#elif defined(MBEDTLS_CT_X86_64_ASM) && (defined(MBEDTLS_CT_SIZE_32) || defined(MBEDTLS_CT_SIZE_64))
    asm volatile ("and  %[condition], %[if1]                      \n\t"
                  "not  %[condition]                              \n\t"
                  "and  %[condition], %[if0]                      \n\t"
                  "or   %[if1], %[if0]                            \n\t"
                  :
                  [condition] "+&D" (condition),
                  [if1] "+&S" (if1),
                  [if0] "+&a" (if0)
                  :
                  :
                  );
    return if0;
#elif defined(MBEDTLS_CT_X86_ASM) && defined(MBEDTLS_CT_SIZE_32)
    asm volatile ("and %[condition], %[if1]                       \n\t"
                  "not %[condition]                               \n\t"
                  "and %[if0], %[condition]                       \n\t"
                  "or %[condition], %[if1]                        \n\t"
                  :
                  [condition] "+&c" (condition),
                  [if1] "+&a" (if1)
                  :
                  [if0] "b" (if0)
                  :
                  );
    return if1;
#else
    mbedtls_ct_condition_t not_cond =
        (mbedtls_ct_condition_t) (~mbedtls_ct_compiler_opaque(condition));
    return (mbedtls_ct_uint_t) ((condition & if1) | (not_cond & if0));
#endif
}

static inline mbedtls_ct_condition_t mbedtls_ct_uint_lt(mbedtls_ct_uint_t x, mbedtls_ct_uint_t y)
{
#if defined(MBEDTLS_CT_AARCH64_ASM) && (defined(MBEDTLS_CT_SIZE_32) || defined(MBEDTLS_CT_SIZE_64))
    uint64_t s1;
    asm volatile ("eor     %x[s1], %x[y], %x[x]                   \n\t"
                  "sub     %x[x], %x[x], %x[y]                    \n\t"
                  "bic     %x[x], %x[x], %x[s1]                   \n\t"
                  "and     %x[s1], %x[s1], %x[y]                  \n\t"
                  "orr     %x[s1], %x[x], %x[s1]                  \n\t"
                  "asr     %x[x], %x[s1], 63"
                  :
                  [s1] "=&r" (s1),
                  [x] "+&r" (x)
                  :
                  [y] "r" (y)
                  :
                  );
    return (mbedtls_ct_condition_t) x;
#elif defined(MBEDTLS_CT_ARM_ASM) && defined(MBEDTLS_CT_SIZE_32)
    uint32_t s1;
    asm volatile (
        ".syntax unified                                          \n\t"
#if defined(__thumb__) && !defined(__thumb2__)
        "movs     %[s1], %[x]                                     \n\t"
        "eors     %[s1], %[s1], %[y]                              \n\t"
#else
        "eors     %[s1], %[x], %[y]                               \n\t"
#endif
        "subs    %[x], %[x], %[y]                                 \n\t"
        "bics    %[x], %[x], %[s1]                                \n\t"
        "ands    %[y], %[s1], %[y]                                \n\t"
        "orrs    %[x], %[x], %[y]                                 \n\t"
        "asrs    %[x], %[x], #31                                  \n\t"
        RESTORE_ASM_SYNTAX
        :
        [s1] "=&l" (s1),
        [x] "+&l" (x),
        [y] "+&l" (y)
        :
        :
        "cc"
        );
    return (mbedtls_ct_condition_t) x;
#elif defined(MBEDTLS_CT_X86_64_ASM) && (defined(MBEDTLS_CT_SIZE_32) || defined(MBEDTLS_CT_SIZE_64))
    uint64_t s;
    asm volatile ("mov %[x], %[s]                                 \n\t"
                  "xor %[y], %[s]                                 \n\t"
                  "sub %[y], %[x]                                 \n\t"
                  "and %[s], %[y]                                 \n\t"
                  "not %[s]                                       \n\t"
                  "and %[s], %[x]                                 \n\t"
                  "or %[y], %[x]                                  \n\t"
                  "sar $63, %[x]                                  \n\t"
                  :
                  [s] "=&a" (s),
                  [x] "+&D" (x),
                  [y] "+&S" (y)
                  :
                  :
                  );
    return (mbedtls_ct_condition_t) x;
#elif defined(MBEDTLS_CT_X86_ASM) && defined(MBEDTLS_CT_SIZE_32)
    uint32_t s;
    asm volatile ("mov %[x], %[s]                                 \n\t"
                  "xor %[y], %[s]                                 \n\t"
                  "sub %[y], %[x]                                 \n\t"
                  "and %[s], %[y]                                 \n\t"
                  "not %[s]                                       \n\t"
                  "and %[s], %[x]                                 \n\t"
                  "or  %[y], %[x]                                 \n\t"
                  "sar $31, %[x]                                  \n\t"
                  :
                  [s] "=&b" (s),
                  [x] "+&a" (x),
                  [y] "+&c" (y)
                  :
                  :
                  );
    return (mbedtls_ct_condition_t) x;
#else

    const mbedtls_ct_uint_t xo = mbedtls_ct_compiler_opaque(x);
    const mbedtls_ct_uint_t yo = mbedtls_ct_compiler_opaque(y);

    mbedtls_ct_condition_t cond = mbedtls_ct_bool((xo ^ yo) >> (MBEDTLS_CT_SIZE - 1));

    mbedtls_ct_uint_t ret = mbedtls_ct_if(cond, yo, (mbedtls_ct_uint_t) (xo - yo));

    ret = ret >> (MBEDTLS_CT_SIZE - 1);

    return mbedtls_ct_bool(ret);
#endif
}

static inline mbedtls_ct_condition_t mbedtls_ct_uint_ne(mbedtls_ct_uint_t x, mbedtls_ct_uint_t y)
{

    const mbedtls_ct_uint_t diff = mbedtls_ct_compiler_opaque(x) ^ mbedtls_ct_compiler_opaque(y);

    return mbedtls_ct_bool(diff);
}

static inline unsigned char mbedtls_ct_uchar_in_range_if(unsigned char low,
                                                         unsigned char high,
                                                         unsigned char c,
                                                         unsigned char t)
{
    const unsigned char co = (unsigned char) mbedtls_ct_compiler_opaque(c);
    const unsigned char to = (unsigned char) mbedtls_ct_compiler_opaque(t);

    unsigned low_mask = ((unsigned) co - low) >> 8;

    unsigned high_mask = ((unsigned) high - co) >> 8;

    return (unsigned char) (~(low_mask | high_mask)) & to;
}

static inline size_t mbedtls_ct_size_if(mbedtls_ct_condition_t condition,
                                        size_t if1,
                                        size_t if0)
{
    return (size_t) mbedtls_ct_if(condition, (mbedtls_ct_uint_t) if1, (mbedtls_ct_uint_t) if0);
}

static inline unsigned mbedtls_ct_uint_if(mbedtls_ct_condition_t condition,
                                          unsigned if1,
                                          unsigned if0)
{
    return (unsigned) mbedtls_ct_if(condition, (mbedtls_ct_uint_t) if1, (mbedtls_ct_uint_t) if0);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_if(mbedtls_ct_condition_t condition,
                                                        mbedtls_ct_condition_t if1,
                                                        mbedtls_ct_condition_t if0)
{
    return (mbedtls_ct_condition_t) mbedtls_ct_if(condition, (mbedtls_ct_uint_t) if1,
                                                  (mbedtls_ct_uint_t) if0);
}

#if defined(MBEDTLS_BIGNUM_C)

static inline mbedtls_mpi_uint mbedtls_ct_mpi_uint_if(mbedtls_ct_condition_t condition,
                                                      mbedtls_mpi_uint if1,
                                                      mbedtls_mpi_uint if0)
{
    return (mbedtls_mpi_uint) mbedtls_ct_if(condition,
                                            (mbedtls_ct_uint_t) if1,
                                            (mbedtls_ct_uint_t) if0);
}

#endif

static inline size_t mbedtls_ct_size_if_else_0(mbedtls_ct_condition_t condition, size_t if1)
{
    return (size_t) (condition & if1);
}

static inline unsigned mbedtls_ct_uint_if_else_0(mbedtls_ct_condition_t condition, unsigned if1)
{
    return (unsigned) (condition & if1);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_if_else_0(mbedtls_ct_condition_t condition,
                                                               mbedtls_ct_condition_t if1)
{
    return (mbedtls_ct_condition_t) (condition & if1);
}

#if defined(MBEDTLS_BIGNUM_C)

static inline mbedtls_mpi_uint mbedtls_ct_mpi_uint_if_else_0(mbedtls_ct_condition_t condition,
                                                             mbedtls_mpi_uint if1)
{
    return (mbedtls_mpi_uint) (condition & if1);
}

#endif

static inline int mbedtls_ct_error_if(mbedtls_ct_condition_t condition, int if1, int if0)
{

    return -((int) mbedtls_ct_if(condition, (mbedtls_ct_uint_t) (-if1),
                                 (mbedtls_ct_uint_t) (-if0)));
}

static inline int mbedtls_ct_error_if_else_0(mbedtls_ct_condition_t condition, int if1)
{
    return -((int) (condition & (-if1)));
}

static inline mbedtls_ct_condition_t mbedtls_ct_uint_eq(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return ~mbedtls_ct_uint_ne(x, y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_uint_gt(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return mbedtls_ct_uint_lt(y, x);
}

static inline mbedtls_ct_condition_t mbedtls_ct_uint_ge(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return ~mbedtls_ct_uint_lt(x, y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_uint_le(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y)
{
    return ~mbedtls_ct_uint_gt(x, y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_ne(mbedtls_ct_condition_t x,
                                                        mbedtls_ct_condition_t y)
{
    return (mbedtls_ct_condition_t) (x ^ y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_and(mbedtls_ct_condition_t x,
                                                         mbedtls_ct_condition_t y)
{
    return (mbedtls_ct_condition_t) (x & y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_or(mbedtls_ct_condition_t x,
                                                        mbedtls_ct_condition_t y)
{
    return (mbedtls_ct_condition_t) (x | y);
}

static inline mbedtls_ct_condition_t mbedtls_ct_bool_not(mbedtls_ct_condition_t x)
{
    return (mbedtls_ct_condition_t) (~x);
}

#if defined(MBEDTLS_COMPILER_IS_GCC) && (__GNUC__ > 4)

    #pragma GCC diagnostic pop
#endif

#endif
