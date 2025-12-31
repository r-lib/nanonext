/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_LIBRARY_ALIGNMENT_H
#define MBEDTLS_LIBRARY_ALIGNMENT_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#if defined(__ARM_FEATURE_UNALIGNED) \
    || defined(MBEDTLS_ARCH_IS_X86) || defined(MBEDTLS_ARCH_IS_X64) \
    || defined(MBEDTLS_PLATFORM_IS_WINDOWS_ON_ARM64)

#define MBEDTLS_EFFICIENT_UNALIGNED_ACCESS
#endif

#if defined(__IAR_SYSTEMS_ICC__) && \
    (defined(MBEDTLS_ARCH_IS_ARM64) || defined(MBEDTLS_ARCH_IS_ARM32) \
    || defined(__ICCRX__) || defined(__ICCRL78__) || defined(__ICCRISCV__))
#pragma language=save
#pragma language=extended
#define MBEDTLS_POP_IAR_LANGUAGE_PRAGMA

    #define UINT_UNALIGNED
typedef uint16_t __packed mbedtls_uint16_unaligned_t;
typedef uint32_t __packed mbedtls_uint32_unaligned_t;
typedef uint64_t __packed mbedtls_uint64_unaligned_t;
#elif defined(MBEDTLS_COMPILER_IS_GCC) && (MBEDTLS_GCC_VERSION >= 40504) && \
    ((MBEDTLS_GCC_VERSION < 60300) || (!defined(MBEDTLS_EFFICIENT_UNALIGNED_ACCESS)))

 #define UINT_UNALIGNED_STRUCT
typedef struct {
    uint16_t x;
} __attribute__((packed)) mbedtls_uint16_unaligned_t;
typedef struct {
    uint32_t x;
} __attribute__((packed)) mbedtls_uint32_unaligned_t;
typedef struct {
    uint64_t x;
} __attribute__((packed)) mbedtls_uint64_unaligned_t;
 #endif

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint16_t mbedtls_get_unaligned_uint16(const void *p)
{
    uint16_t r;
#if defined(UINT_UNALIGNED)
    mbedtls_uint16_unaligned_t *p16 = (mbedtls_uint16_unaligned_t *) p;
    r = *p16;
#elif defined(UINT_UNALIGNED_STRUCT)
    mbedtls_uint16_unaligned_t *p16 = (mbedtls_uint16_unaligned_t *) p;
    r = p16->x;
#else
    memcpy(&r, p, sizeof(r));
#endif
    return r;
}

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void mbedtls_put_unaligned_uint16(void *p, uint16_t x)
{
#if defined(UINT_UNALIGNED)
    mbedtls_uint16_unaligned_t *p16 = (mbedtls_uint16_unaligned_t *) p;
    *p16 = x;
#elif defined(UINT_UNALIGNED_STRUCT)
    mbedtls_uint16_unaligned_t *p16 = (mbedtls_uint16_unaligned_t *) p;
    p16->x = x;
#else
    memcpy(p, &x, sizeof(x));
#endif
}

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint32_t mbedtls_get_unaligned_uint32(const void *p)
{
    uint32_t r;
#if defined(UINT_UNALIGNED)
    mbedtls_uint32_unaligned_t *p32 = (mbedtls_uint32_unaligned_t *) p;
    r = *p32;
#elif defined(UINT_UNALIGNED_STRUCT)
    mbedtls_uint32_unaligned_t *p32 = (mbedtls_uint32_unaligned_t *) p;
    r = p32->x;
#else
    memcpy(&r, p, sizeof(r));
#endif
    return r;
}

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void mbedtls_put_unaligned_uint32(void *p, uint32_t x)
{
#if defined(UINT_UNALIGNED)
    mbedtls_uint32_unaligned_t *p32 = (mbedtls_uint32_unaligned_t *) p;
    *p32 = x;
#elif defined(UINT_UNALIGNED_STRUCT)
    mbedtls_uint32_unaligned_t *p32 = (mbedtls_uint32_unaligned_t *) p;
    p32->x = x;
#else
    memcpy(p, &x, sizeof(x));
#endif
}

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline uint64_t mbedtls_get_unaligned_uint64(const void *p)
{
    uint64_t r;
#if defined(UINT_UNALIGNED)
    mbedtls_uint64_unaligned_t *p64 = (mbedtls_uint64_unaligned_t *) p;
    r = *p64;
#elif defined(UINT_UNALIGNED_STRUCT)
    mbedtls_uint64_unaligned_t *p64 = (mbedtls_uint64_unaligned_t *) p;
    r = p64->x;
#else
    memcpy(&r, p, sizeof(r));
#endif
    return r;
}

#if defined(__IAR_SYSTEMS_ICC__)
#pragma inline = forced
#elif defined(__GNUC__)
__attribute__((always_inline))
#endif
static inline void mbedtls_put_unaligned_uint64(void *p, uint64_t x)
{
#if defined(UINT_UNALIGNED)
    mbedtls_uint64_unaligned_t *p64 = (mbedtls_uint64_unaligned_t *) p;
    *p64 = x;
#elif defined(UINT_UNALIGNED_STRUCT)
    mbedtls_uint64_unaligned_t *p64 = (mbedtls_uint64_unaligned_t *) p;
    p64->x = x;
#else
    memcpy(p, &x, sizeof(x));
#endif
}

#if defined(MBEDTLS_POP_IAR_LANGUAGE_PRAGMA)
#pragma language=restore
#endif

#define MBEDTLS_BYTE_0(x) ((uint8_t) ((x)         & 0xff))
#define MBEDTLS_BYTE_1(x) ((uint8_t) (((x) >>  8) & 0xff))
#define MBEDTLS_BYTE_2(x) ((uint8_t) (((x) >> 16) & 0xff))
#define MBEDTLS_BYTE_3(x) ((uint8_t) (((x) >> 24) & 0xff))
#define MBEDTLS_BYTE_4(x) ((uint8_t) (((x) >> 32) & 0xff))
#define MBEDTLS_BYTE_5(x) ((uint8_t) (((x) >> 40) & 0xff))
#define MBEDTLS_BYTE_6(x) ((uint8_t) (((x) >> 48) & 0xff))
#define MBEDTLS_BYTE_7(x) ((uint8_t) (((x) >> 56) & 0xff))

#if defined(__GNUC__) && defined(__GNUC_PREREQ)
#if __GNUC_PREREQ(4, 8)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif
#if __GNUC_PREREQ(4, 3)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#define MBEDTLS_BSWAP64 __builtin_bswap64
#endif
#endif

#if defined(__clang__) && defined(__has_builtin)
#if __has_builtin(__builtin_bswap16) && !defined(MBEDTLS_BSWAP16)
#define MBEDTLS_BSWAP16 __builtin_bswap16
#endif
#if __has_builtin(__builtin_bswap32) && !defined(MBEDTLS_BSWAP32)
#define MBEDTLS_BSWAP32 __builtin_bswap32
#endif
#if __has_builtin(__builtin_bswap64) && !defined(MBEDTLS_BSWAP64)
#define MBEDTLS_BSWAP64 __builtin_bswap64
#endif
#endif

#if defined(_MSC_VER)
#if !defined(MBEDTLS_BSWAP16)
#define MBEDTLS_BSWAP16 _byteswap_ushort
#endif
#if !defined(MBEDTLS_BSWAP32)
#define MBEDTLS_BSWAP32 _byteswap_ulong
#endif
#if !defined(MBEDTLS_BSWAP64)
#define MBEDTLS_BSWAP64 _byteswap_uint64
#endif
#endif

#if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 410000) && !defined(MBEDTLS_BSWAP32)
#if defined(__ARM_ACLE)
#include <arm_acle.h>
#endif
#define MBEDTLS_BSWAP32 __rev
#endif

#if defined(__IAR_SYSTEMS_ICC__)
#if defined(__ARM_ACLE)
#include <arm_acle.h>
#define MBEDTLS_BSWAP16(x) ((uint16_t) __rev16((uint32_t) (x)))
#define MBEDTLS_BSWAP32 __rev
#define MBEDTLS_BSWAP64 __revll
#endif
#endif

#if !defined(MBEDTLS_BSWAP16)
static inline uint16_t mbedtls_bswap16(uint16_t x)
{
    return
        (x & 0x00ff) << 8 |
        (x & 0xff00) >> 8;
}
#define MBEDTLS_BSWAP16 mbedtls_bswap16
#endif

#if !defined(MBEDTLS_BSWAP32)
static inline uint32_t mbedtls_bswap32(uint32_t x)
{
    return
        (x & 0x000000ff) << 24 |
        (x & 0x0000ff00) <<  8 |
        (x & 0x00ff0000) >>  8 |
        (x & 0xff000000) >> 24;
}
#define MBEDTLS_BSWAP32 mbedtls_bswap32
#endif

#if !defined(MBEDTLS_BSWAP64)
static inline uint64_t mbedtls_bswap64(uint64_t x)
{
    return
        (x & 0x00000000000000ffULL) << 56 |
        (x & 0x000000000000ff00ULL) << 40 |
        (x & 0x0000000000ff0000ULL) << 24 |
        (x & 0x00000000ff000000ULL) <<  8 |
        (x & 0x000000ff00000000ULL) >>  8 |
        (x & 0x0000ff0000000000ULL) >> 24 |
        (x & 0x00ff000000000000ULL) >> 40 |
        (x & 0xff00000000000000ULL) >> 56;
}
#define MBEDTLS_BSWAP64 mbedtls_bswap64
#endif

#if !defined(__BYTE_ORDER__)

#if defined(__LITTLE_ENDIAN__)

#define MBEDTLS_IS_BIG_ENDIAN 0
#elif defined(__BIG_ENDIAN__)
#define MBEDTLS_IS_BIG_ENDIAN 1
#else
static const uint16_t mbedtls_byte_order_detector = { 0x100 };
#define MBEDTLS_IS_BIG_ENDIAN (*((unsigned char *) (&mbedtls_byte_order_detector)) == 0x01)
#endif

#else

#if (__BYTE_ORDER__) == (__ORDER_BIG_ENDIAN__)
#define MBEDTLS_IS_BIG_ENDIAN 1
#else
#define MBEDTLS_IS_BIG_ENDIAN 0
#endif

#endif

#define MBEDTLS_GET_UINT32_BE(data, offset)                                \
    ((MBEDTLS_IS_BIG_ENDIAN)                                               \
        ? mbedtls_get_unaligned_uint32((data) + (offset))                  \
        : MBEDTLS_BSWAP32(mbedtls_get_unaligned_uint32((data) + (offset))) \
    )

#define MBEDTLS_PUT_UINT32_BE(n, data, offset)                                   \
    {                                                                            \
        if (MBEDTLS_IS_BIG_ENDIAN)                                               \
        {                                                                        \
            mbedtls_put_unaligned_uint32((data) + (offset), (uint32_t) (n));     \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            mbedtls_put_unaligned_uint32((data) + (offset), MBEDTLS_BSWAP32((uint32_t) (n))); \
        }                                                                        \
    }

#define MBEDTLS_GET_UINT32_LE(data, offset)                                \
    ((MBEDTLS_IS_BIG_ENDIAN)                                               \
        ? MBEDTLS_BSWAP32(mbedtls_get_unaligned_uint32((data) + (offset))) \
        : mbedtls_get_unaligned_uint32((data) + (offset))                  \
    )

#define MBEDTLS_PUT_UINT32_LE(n, data, offset)                                   \
    {                                                                            \
        if (MBEDTLS_IS_BIG_ENDIAN)                                               \
        {                                                                        \
            mbedtls_put_unaligned_uint32((data) + (offset), MBEDTLS_BSWAP32((uint32_t) (n))); \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            mbedtls_put_unaligned_uint32((data) + (offset), ((uint32_t) (n)));   \
        }                                                                        \
    }

#define MBEDTLS_GET_UINT16_LE(data, offset)                                \
    ((MBEDTLS_IS_BIG_ENDIAN)                                               \
        ? MBEDTLS_BSWAP16(mbedtls_get_unaligned_uint16((data) + (offset))) \
        : mbedtls_get_unaligned_uint16((data) + (offset))                  \
    )

#define MBEDTLS_PUT_UINT16_LE(n, data, offset)                                   \
    {                                                                            \
        if (MBEDTLS_IS_BIG_ENDIAN)                                               \
        {                                                                        \
            mbedtls_put_unaligned_uint16((data) + (offset), MBEDTLS_BSWAP16((uint16_t) (n))); \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            mbedtls_put_unaligned_uint16((data) + (offset), (uint16_t) (n));     \
        }                                                                        \
    }

#define MBEDTLS_GET_UINT16_BE(data, offset)                                \
    ((MBEDTLS_IS_BIG_ENDIAN)                                               \
        ? mbedtls_get_unaligned_uint16((data) + (offset))                  \
        : MBEDTLS_BSWAP16(mbedtls_get_unaligned_uint16((data) + (offset))) \
    )

#define MBEDTLS_PUT_UINT16_BE(n, data, offset)                                   \
    {                                                                            \
        if (MBEDTLS_IS_BIG_ENDIAN)                                               \
        {                                                                        \
            mbedtls_put_unaligned_uint16((data) + (offset), (uint16_t) (n));     \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            mbedtls_put_unaligned_uint16((data) + (offset), MBEDTLS_BSWAP16((uint16_t) (n))); \
        }                                                                        \
    }

#define MBEDTLS_GET_UINT24_BE(data, offset)        \
    (                                              \
        ((uint32_t) (data)[(offset)] << 16)        \
        | ((uint32_t) (data)[(offset) + 1] << 8)   \
        | ((uint32_t) (data)[(offset) + 2])        \
    )

#define MBEDTLS_PUT_UINT24_BE(n, data, offset)                \
    {                                                         \
        (data)[(offset)] = MBEDTLS_BYTE_2(n);                 \
        (data)[(offset) + 1] = MBEDTLS_BYTE_1(n);             \
        (data)[(offset) + 2] = MBEDTLS_BYTE_0(n);             \
    }

#define MBEDTLS_GET_UINT24_LE(data, offset)               \
    (                                                     \
        ((uint32_t) (data)[(offset)])                     \
        | ((uint32_t) (data)[(offset) + 1] <<  8)         \
        | ((uint32_t) (data)[(offset) + 2] << 16)         \
    )

#define MBEDTLS_PUT_UINT24_LE(n, data, offset)                \
    {                                                         \
        (data)[(offset)] = MBEDTLS_BYTE_0(n);                 \
        (data)[(offset) + 1] = MBEDTLS_BYTE_1(n);             \
        (data)[(offset) + 2] = MBEDTLS_BYTE_2(n);             \
    }

#define MBEDTLS_GET_UINT64_BE(data, offset)                                \
    ((MBEDTLS_IS_BIG_ENDIAN)                                               \
        ? mbedtls_get_unaligned_uint64((data) + (offset))                  \
        : MBEDTLS_BSWAP64(mbedtls_get_unaligned_uint64((data) + (offset))) \
    )

#define MBEDTLS_PUT_UINT64_BE(n, data, offset)                                   \
    {                                                                            \
        if (MBEDTLS_IS_BIG_ENDIAN)                                               \
        {                                                                        \
            mbedtls_put_unaligned_uint64((data) + (offset), (uint64_t) (n));     \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            mbedtls_put_unaligned_uint64((data) + (offset), MBEDTLS_BSWAP64((uint64_t) (n))); \
        }                                                                        \
    }

#define MBEDTLS_GET_UINT64_LE(data, offset)                                \
    ((MBEDTLS_IS_BIG_ENDIAN)                                               \
        ? MBEDTLS_BSWAP64(mbedtls_get_unaligned_uint64((data) + (offset))) \
        : mbedtls_get_unaligned_uint64((data) + (offset))                  \
    )

#define MBEDTLS_PUT_UINT64_LE(n, data, offset)                                   \
    {                                                                            \
        if (MBEDTLS_IS_BIG_ENDIAN)                                               \
        {                                                                        \
            mbedtls_put_unaligned_uint64((data) + (offset), MBEDTLS_BSWAP64((uint64_t) (n))); \
        }                                                                        \
        else                                                                     \
        {                                                                        \
            mbedtls_put_unaligned_uint64((data) + (offset), (uint64_t) (n));     \
        }                                                                        \
    }

#endif
