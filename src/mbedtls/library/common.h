/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_LIBRARY_COMMON_H
#define MBEDTLS_LIBRARY_COMMON_H

#include "mbedtls/build_info.h"
#include "alignment.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stddef.h>

#if defined(__ARM_NEON)
#include <arm_neon.h>
#define MBEDTLS_HAVE_NEON_INTRINSICS
#elif defined(MBEDTLS_PLATFORM_IS_WINDOWS_ON_ARM64)
#include <arm64_neon.h>
#define MBEDTLS_HAVE_NEON_INTRINSICS
#endif

#if defined(MBEDTLS_TEST_HOOKS)
#define MBEDTLS_STATIC_TESTABLE
#else
#define MBEDTLS_STATIC_TESTABLE static
#endif

#if defined(MBEDTLS_TEST_HOOKS)
extern void (*mbedtls_test_hook_test_fail)(const char *test, int line, const char *file);
#define MBEDTLS_TEST_HOOK_TEST_ASSERT(TEST) \
    do { \
        if ((!(TEST)) && ((*mbedtls_test_hook_test_fail) != NULL)) \
        { \
            (*mbedtls_test_hook_test_fail)( #TEST, __LINE__, __FILE__); \
        } \
    } while (0)
#else
#define MBEDTLS_TEST_HOOK_TEST_ASSERT(TEST)
#endif

#define ARRAY_LENGTH_UNSAFE(array)            \
    (sizeof(array) / sizeof(*(array)))

#if defined(__GNUC__)

#define IS_ARRAY_NOT_POINTER(arg)                                     \
    (!__builtin_types_compatible_p(__typeof__(arg),                \
                                   __typeof__(&(arg)[0])))

#define STATIC_ASSERT_EXPR(const_expr)                                \
    (0 && sizeof(struct { unsigned int STATIC_ASSERT : 1 - 2 * !(const_expr); }))

#define STATIC_ASSERT_THEN_RETURN(condition, value)   \
    (STATIC_ASSERT_EXPR(condition) ? 0 : (value))

#define ARRAY_LENGTH(array)                                           \
    (STATIC_ASSERT_THEN_RETURN(IS_ARRAY_NOT_POINTER(array),         \
                               ARRAY_LENGTH_UNSAFE(array)))

#else

#define ARRAY_LENGTH(array) ARRAY_LENGTH_UNSAFE(array)
#endif

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

void mbedtls_zeroize_and_free(void *buf, size_t len);

static inline unsigned char *mbedtls_buffer_offset(
    unsigned char *p, size_t n)
{
    return p == NULL ? NULL : p + n;
}

static inline const unsigned char *mbedtls_buffer_offset_const(
    const unsigned char *p, size_t n)
{
    return p == NULL ? NULL : p + n;
}

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif

static inline void mbedtls_xor(unsigned char *r,
                               const unsigned char *a,
                               const unsigned char *b,
                               size_t n)
{
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
#if defined(MBEDTLS_HAVE_NEON_INTRINSICS) && \
    (!(defined(MBEDTLS_COMPILER_IS_GCC) && MBEDTLS_GCC_VERSION < 70300))

    for (; (i + 16) <= n; i += 16) {
        uint8x16_t v1 = vld1q_u8(a + i);
        uint8x16_t v2 = vld1q_u8(b + i);
        uint8x16_t x = veorq_u8(v1, v2);
        vst1q_u8(r + i, x);
    }
#if defined(__IAR_SYSTEMS_ICC__)

    if (n % 16 == 0) {
        return;
    }
#endif
#elif defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_ARM64)

    for (; (i + 8) <= n; i += 8) {
        uint64_t x = mbedtls_get_unaligned_uint64(a + i) ^ mbedtls_get_unaligned_uint64(b + i);
        mbedtls_put_unaligned_uint64(r + i, x);
    }
#if defined(__IAR_SYSTEMS_ICC__)
    if (n % 8 == 0) {
        return;
    }
#endif
#else
    for (; (i + 4) <= n; i += 4) {
        uint32_t x = mbedtls_get_unaligned_uint32(a + i) ^ mbedtls_get_unaligned_uint32(b + i);
        mbedtls_put_unaligned_uint32(r + i, x);
    }
#if defined(__IAR_SYSTEMS_ICC__)
    if (n % 4 == 0) {
        return;
    }
#endif
#endif
#endif
    for (; i < n; i++) {
        r[i] = a[i] ^ b[i];
    }
}

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif

static inline void mbedtls_xor_no_simd(unsigned char *r,
                                       const unsigned char *a,
                                       const unsigned char *b,
                                       size_t n)
{
    size_t i = 0;
#if defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)
#if defined(MBEDTLS_ARCH_IS_X64) || defined(MBEDTLS_ARCH_IS_ARM64)

    for (; (i + 8) <= n; i += 8) {
        uint64_t x = mbedtls_get_unaligned_uint64(a + i) ^ mbedtls_get_unaligned_uint64(b + i);
        mbedtls_put_unaligned_uint64(r + i, x);
    }
#if defined(__IAR_SYSTEMS_ICC__)

    if (n % 8 == 0) {
        return;
    }
#endif
#else
    for (; (i + 4) <= n; i += 4) {
        uint32_t x = mbedtls_get_unaligned_uint32(a + i) ^ mbedtls_get_unaligned_uint32(b + i);
        mbedtls_put_unaligned_uint32(r + i, x);
    }
#if defined(__IAR_SYSTEMS_ICC__)
    if (n % 4 == 0) {
        return;
    }
#endif
#endif
#endif
    for (; i < n; i++) {
        r[i] = a[i] ^ b[i];
    }
}

#if (defined(_MSC_VER) && (_MSC_VER <= 1900))
#define  __func__ __FUNCTION__
#endif

#ifndef asm
#if defined(__IAR_SYSTEMS_ICC__)
#define asm __asm
#else
#define asm __asm__
#endif
#endif

#if defined(__aarch64__) && defined(MBEDTLS_HAVE_ASM)
#if UINTPTR_MAX == 0xfffffffful

#define MBEDTLS_ASM_AARCH64_PTR_CONSTRAINT "p"
#elif UINTPTR_MAX == 0xfffffffffffffffful

#define MBEDTLS_ASM_AARCH64_PTR_CONSTRAINT "r"
#else
#error "Unrecognised pointer size for aarch64"
#endif
#endif

#if defined(static_assert) && !defined(__FreeBSD__)
#define MBEDTLS_STATIC_ASSERT(expr, msg)    static_assert(expr, msg)
#else

#define MBEDTLS_STATIC_ASSERT(expr, msg)                                \
    struct ISO_C_does_not_allow_extra_semicolon_outside_of_a_function
#endif

#if defined(__has_builtin)
#define MBEDTLS_HAS_BUILTIN(x) __has_builtin(x)
#else
#define MBEDTLS_HAS_BUILTIN(x) 0
#endif

#if MBEDTLS_HAS_BUILTIN(__builtin_expect)
#define MBEDTLS_LIKELY(x)       __builtin_expect(!!(x), 1)
#define MBEDTLS_UNLIKELY(x)     __builtin_expect(!!(x), 0)
#else
#define MBEDTLS_LIKELY(x)       x
#define MBEDTLS_UNLIKELY(x)     x
#endif

#if MBEDTLS_HAS_BUILTIN(__builtin_assume)

#define MBEDTLS_ASSUME(x)       __builtin_assume(x)
#elif MBEDTLS_HAS_BUILTIN(__builtin_unreachable)

#define MBEDTLS_ASSUME(x)       do { if (!(x)) __builtin_unreachable(); } while (0)
#elif defined(_MSC_VER)

#define MBEDTLS_ASSUME(x)       __assume(x)
#else
#define MBEDTLS_ASSUME(x)       do { } while (0)
#endif

#if defined(MBEDTLS_COMPILER_IS_GCC) && defined(__OPTIMIZE_SIZE__)
#define MBEDTLS_OPTIMIZE_FOR_PERFORMANCE __attribute__((optimize("-O2")))
#else
#define MBEDTLS_OPTIMIZE_FOR_PERFORMANCE
#endif

#if !defined(MBEDTLS_MAYBE_UNUSED) && defined(__has_attribute)
#    if __has_attribute(unused)
#        define MBEDTLS_MAYBE_UNUSED __attribute__((unused))
#    endif
#endif
#if !defined(MBEDTLS_MAYBE_UNUSED) && defined(__GNUC__)
#    define MBEDTLS_MAYBE_UNUSED __attribute__((unused))
#endif
#if !defined(MBEDTLS_MAYBE_UNUSED) && defined(__IAR_SYSTEMS_ICC__) && defined(__VER__)

#    if (__VER__ >= 5020000)
#        define MBEDTLS_MAYBE_UNUSED _Pragma("diag_suppress=Pe177")
#    endif
#endif
#if !defined(MBEDTLS_MAYBE_UNUSED) && defined(_MSC_VER)
#    define MBEDTLS_MAYBE_UNUSED __pragma(warning(suppress:4189))
#endif
#if !defined(MBEDTLS_MAYBE_UNUSED)
#    define MBEDTLS_MAYBE_UNUSED
#endif

#if defined(__has_attribute)
#if __has_attribute(nonstring)
#define MBEDTLS_HAS_ATTRIBUTE_NONSTRING
#endif
#endif
#if defined(MBEDTLS_HAS_ATTRIBUTE_NONSTRING)
#define MBEDTLS_ATTRIBUTE_UNTERMINATED_STRING __attribute__((nonstring))
#else
#define MBEDTLS_ATTRIBUTE_UNTERMINATED_STRING
#endif

#endif
