/*
 *  Armv8-A Cryptographic Extension support functions for Aarch64
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#if defined(__clang__) && (__clang_major__ >= 4)
#if defined(__ARM_ARCH)
#if __ARM_ARCH >= 8
#define MBEDTLS_AESCE_ARCH_IS_ARMV8_A 
#endif
#endif
#if defined(MBEDTLS_AESCE_ARCH_IS_ARMV8_A) && !defined(__ARM_FEATURE_CRYPTO)
#define __ARM_FEATURE_CRYPTO 1
#define __ARM_FEATURE_AES 1
#define MBEDTLS_ENABLE_ARM_CRYPTO_EXTENSIONS_COMPILER_FLAG 
#endif
#endif
#include <string.h>
#include "common.h"
#if defined(MBEDTLS_AESCE_C)
#include "aesce.h"
#if defined(MBEDTLS_AESCE_HAVE_CODE)
#if defined(__clang__)
# if defined(MBEDTLS_ARCH_IS_ARM32) && (__clang_major__ < 11)
# error "Minimum version of Clang for MBEDTLS_AESCE_C on 32-bit Arm or Thumb is 11.0."
# elif defined(MBEDTLS_ARCH_IS_ARM64) && (__clang_major__ < 4)
# error "Minimum version of Clang for MBEDTLS_AESCE_C on aarch64 is 4.0."
# endif
#elif defined(__GNUC__)
# if __GNUC__ < 6
# error "Minimum version of GCC for MBEDTLS_AESCE_C is 6.0."
# endif
#elif defined(_MSC_VER)
# if _MSC_VER < 1929
# error "Minimum version of MSVC for MBEDTLS_AESCE_C is 2019 version 16.11.2."
# endif
#elif defined(__ARMCC_VERSION)
# if defined(MBEDTLS_ARCH_IS_ARM32) && (__ARMCC_VERSION < 6200002)
# error "Minimum version of armclang for MBEDTLS_AESCE_C on 32-bit Arm is 6.20."
# elif defined(MBEDTLS_ARCH_IS_ARM64) && (__ARMCC_VERSION < 6060000)
# error "Minimum version of armclang for MBEDTLS_AESCE_C on aarch64 is 6.6."
# endif
#endif
#if !(defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_AES)) || \
    defined(MBEDTLS_ENABLE_ARM_CRYPTO_EXTENSIONS_COMPILER_FLAG)
# if defined(__ARMCOMPILER_VERSION)
# if __ARMCOMPILER_VERSION <= 6090000
# error "Must use minimum -march=armv8-a+crypto for MBEDTLS_AESCE_C"
# else
#pragma clang attribute push (__attribute__((target("aes"))), apply_to=function)
#define MBEDTLS_POP_TARGET_PRAGMA 
# endif
# elif defined(__clang__)
#pragma clang attribute push (__attribute__((target("aes"))), apply_to=function)
#define MBEDTLS_POP_TARGET_PRAGMA 
# elif defined(__GNUC__)
#pragma GCC push_options
#pragma GCC target ("+crypto")
#define MBEDTLS_POP_TARGET_PRAGMA 
# elif defined(_MSC_VER)
# error "Required feature(__ARM_FEATURE_AES) is not enabled."
# endif
#endif
#if defined(__linux__) && !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
#include <sys/auxv.h>
#if !defined(HWCAP_NEON)
#define HWCAP_NEON (1 << 12)
#endif
#if !defined(HWCAP2_AES)
#define HWCAP2_AES (1 << 0)
#endif
#if !defined(HWCAP_AES)
#define HWCAP_AES (1 << 3)
#endif
#if !defined(HWCAP_ASIMD)
#define HWCAP_ASIMD (1 << 1)
#endif
signed char mbedtls_aesce_has_support_result = -1;
#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
int mbedtls_aesce_has_support_impl(void)
{
    if (mbedtls_aesce_has_support_result == -1) {
#if defined(MBEDTLS_ARCH_IS_ARM32)
        unsigned long auxval = getauxval(AT_HWCAP);
        unsigned long auxval2 = getauxval(AT_HWCAP2);
        if (((auxval & HWCAP_NEON) == HWCAP_NEON) &&
            ((auxval2 & HWCAP2_AES) == HWCAP2_AES)) {
            mbedtls_aesce_has_support_result = 1;
        } else {
            mbedtls_aesce_has_support_result = 0;
        }
#else
        unsigned long auxval = getauxval(AT_HWCAP);
        if ((auxval & (HWCAP_ASIMD | HWCAP_AES)) ==
            (HWCAP_ASIMD | HWCAP_AES)) {
            mbedtls_aesce_has_support_result = 1;
        } else {
            mbedtls_aesce_has_support_result = 0;
        }
#endif
    }
    return mbedtls_aesce_has_support_result;
}
#endif
#endif
#define AESCE_ENCRYPT_ROUND \
    block = vaeseq_u8(block, vld1q_u8(keys)); \
    block = vaesmcq_u8(block); \
    keys += 16
#define AESCE_ENCRYPT_ROUND_X2 AESCE_ENCRYPT_ROUND; AESCE_ENCRYPT_ROUND
MBEDTLS_OPTIMIZE_FOR_PERFORMANCE
static uint8x16_t aesce_encrypt_block(uint8x16_t block,
                                      unsigned char *keys,
                                      int rounds)
{
    if (rounds == 10) {
        goto rounds_10;
    }
    if (rounds == 12) {
        goto rounds_12;
    }
    AESCE_ENCRYPT_ROUND_X2;
rounds_12:
    AESCE_ENCRYPT_ROUND_X2;
rounds_10:
    AESCE_ENCRYPT_ROUND_X2;
    AESCE_ENCRYPT_ROUND_X2;
    AESCE_ENCRYPT_ROUND_X2;
    AESCE_ENCRYPT_ROUND_X2;
    AESCE_ENCRYPT_ROUND;
    block = vaeseq_u8(block, vld1q_u8(keys));
    keys += 16;
    block = veorq_u8(block, vld1q_u8(keys));
    return block;
}
#define AESCE_DECRYPT_ROUND \
    block = vaesdq_u8(block, vld1q_u8(keys)); \
    block = vaesimcq_u8(block); \
    keys += 16
#define AESCE_DECRYPT_ROUND_X2 AESCE_DECRYPT_ROUND; AESCE_DECRYPT_ROUND
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
static uint8x16_t aesce_decrypt_block(uint8x16_t block,
                                      unsigned char *keys,
                                      int rounds)
{
    if (rounds == 10) {
        goto rounds_10;
    }
    if (rounds == 12) {
        goto rounds_12;
    }
    AESCE_DECRYPT_ROUND_X2;
rounds_12:
    AESCE_DECRYPT_ROUND_X2;
rounds_10:
    AESCE_DECRYPT_ROUND_X2;
    AESCE_DECRYPT_ROUND_X2;
    AESCE_DECRYPT_ROUND_X2;
    AESCE_DECRYPT_ROUND_X2;
    AESCE_DECRYPT_ROUND;
    block = vaesdq_u8(block, vld1q_u8(keys));
    keys += 16;
    block = veorq_u8(block, vld1q_u8(keys));
    return block;
}
#endif
int mbedtls_aesce_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    uint8x16_t block = vld1q_u8(&input[0]);
    unsigned char *keys = (unsigned char *) (ctx->buf + ctx->rk_offset);
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (mode == MBEDTLS_AES_DECRYPT) {
        block = aesce_decrypt_block(block, keys, ctx->nr);
    } else
#else
    (void) mode;
#endif
    {
        block = aesce_encrypt_block(block, keys, ctx->nr);
    }
    vst1q_u8(&output[0], block);
    return 0;
}
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
void mbedtls_aesce_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey,
                               int nr)
{
    int i, j;
    j = nr;
    vst1q_u8(invkey, vld1q_u8(fwdkey + j * 16));
    for (i = 1, j--; j > 0; i++, j--) {
        vst1q_u8(invkey + i * 16,
                 vaesimcq_u8(vld1q_u8(fwdkey + j * 16)));
    }
    vst1q_u8(invkey + i * 16, vld1q_u8(fwdkey + j * 16));
}
#endif
static inline uint32_t aes_rot_word(uint32_t word)
{
    return (word << (32 - 8)) | (word >> 8);
}
static inline uint32_t aes_sub_word(uint32_t in)
{
    uint8x16_t v = vreinterpretq_u8_u32(vdupq_n_u32(in));
    uint8x16_t zero = vdupq_n_u8(0);
    v = vaeseq_u8(zero, v);
    return vgetq_lane_u32(vreinterpretq_u32_u8(v), 0);
}
static void aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             const size_t key_bit_length)
{
    static uint8_t const rcon[] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36 };
    const size_t key_len_in_words = key_bit_length / 32;
    const size_t round_key_len_in_words = 4;
    const size_t rounds_needed = key_len_in_words + 6;
    const size_t round_keys_len_in_words =
        round_key_len_in_words * (rounds_needed + 1);
    const uint32_t *rko_end = (uint32_t *) rk + round_keys_len_in_words;
    memcpy(rk, key, key_len_in_words * 4);
    for (uint32_t *rki = (uint32_t *) rk;
         rki + key_len_in_words < rko_end;
         rki += key_len_in_words) {
        size_t iteration = (size_t) (rki - (uint32_t *) rk) / key_len_in_words;
        uint32_t *rko;
        rko = rki + key_len_in_words;
        rko[0] = aes_rot_word(aes_sub_word(rki[key_len_in_words - 1]));
        rko[0] ^= rcon[iteration] ^ rki[0];
        rko[1] = rko[0] ^ rki[1];
        rko[2] = rko[1] ^ rki[2];
        rko[3] = rko[2] ^ rki[3];
        if (rko + key_len_in_words > rko_end) {
            continue;
        }
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        switch (key_bit_length) {
            case 128:
                break;
            case 192:
                rko[4] = rko[3] ^ rki[4];
                rko[5] = rko[4] ^ rki[5];
                break;
            case 256:
                rko[4] = aes_sub_word(rko[3]) ^ rki[4];
                rko[5] = rko[4] ^ rki[5];
                rko[6] = rko[5] ^ rki[6];
                rko[7] = rko[6] ^ rki[7];
                break;
        }
#endif
    }
}
int mbedtls_aesce_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits)
{
    switch (bits) {
        case 128:
        case 192:
        case 256:
            aesce_setkey_enc(rk, key, bits);
            break;
        default:
            return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }
    return 0;
}
#if defined(MBEDTLS_GCM_C)
#if defined(MBEDTLS_ARCH_IS_ARM32)
#if defined(__clang__)
#define vreinterpretq_u64_p64(a) ((uint64x2_t) a)
typedef uint8x16_t poly128_t;
static inline poly128_t vmull_p64(poly64_t a, poly64_t b)
{
    poly128_t r;
    asm ("vmull.p64 %[r], %[a], %[b]" : [r] "=w" (r) : [a] "w" (a), [b] "w" (b) :);
    return r;
}
#define COMMON_MISSING_INTRINSICS 
static inline poly128_t vmull_high_p64(poly64x2_t a, poly64x2_t b)
{
    return vmull_p64((poly64_t) (vget_high_u64((uint64x2_t) a)),
                     (poly64_t) (vget_high_u64((uint64x2_t) b)));
}
#endif
static inline uint8x16_t vrbitq_u8(uint8x16_t x)
{
    asm ("ldm  %[p], { r2-r5 } \n\t"
         "rbit r2, r2          \n\t"
         "rev  r2, r2          \n\t"
         "rbit r3, r3          \n\t"
         "rev  r3, r3          \n\t"
         "rbit r4, r4          \n\t"
         "rev  r4, r4          \n\t"
         "rbit r5, r5          \n\t"
         "rev  r5, r5          \n\t"
         "stm  %[p], { r2-r5 } \n\t"
         :
         "+m" (*(uint8_t(*)[16]) &x)
         :
         [p] "r" (&x)
         :
         "r2", "r3", "r4", "r5"
         );
    return x;
}
#endif
#if defined(MBEDTLS_COMPILER_IS_GCC) && __GNUC__ == 5
#define COMMON_MISSING_INTRINSICS 
#endif
#if defined(COMMON_MISSING_INTRINSICS)
#define vreinterpretq_p64_u8(a) ((poly64x2_t) a)
#define vreinterpretq_u8_p128(a) ((uint8x16_t) a)
static inline poly64x1_t vget_low_p64(poly64x2_t a)
{
    uint64x1_t r = vget_low_u64(vreinterpretq_u64_p64(a));
    return (poly64x1_t) r;
}
#endif
#if defined(MBEDTLS_COMPILER_IS_GCC)
#define MBEDTLS_VMULL_P64(a,b) vmull_p64((poly64_t) a, (poly64_t) b)
#else
#define MBEDTLS_VMULL_P64(a,b) vmull_p64(a, b)
#endif
static inline uint8x16_t pmull_low(uint8x16_t a, uint8x16_t b)
{
    return vreinterpretq_u8_p128(
        MBEDTLS_VMULL_P64(
            (poly64_t) vget_low_p64(vreinterpretq_p64_u8(a)),
            (poly64_t) vget_low_p64(vreinterpretq_p64_u8(b))
            ));
}
static inline uint8x16_t pmull_high(uint8x16_t a, uint8x16_t b)
{
    return vreinterpretq_u8_p128(
        vmull_high_p64(vreinterpretq_p64_u8(a),
                       vreinterpretq_p64_u8(b)));
}
static inline uint8x16x3_t poly_mult_128(uint8x16_t a, uint8x16_t b)
{
    uint8x16x3_t ret;
    uint8x16_t h, m, l;
    uint8x16_t c, d, e;
    h = pmull_high(a, b);
    l = pmull_low(a, b);
    c = vextq_u8(b, b, 8);
    d = pmull_high(a, c);
    e = pmull_low(a, c);
    m = veorq_u8(d, e);
    ret.val[0] = h;
    ret.val[1] = m;
    ret.val[2] = l;
    return ret;
}
static inline uint8x16_t poly_mult_reduce(uint8x16x3_t input)
{
    uint8x16_t const ZERO = vdupq_n_u8(0);
    uint64x2_t r = vreinterpretq_u64_u8(vdupq_n_u8(0x87));
#if defined(__GNUC__)
    asm volatile ("" : "+w" (r));
#endif
    uint8x16_t const MODULO = vreinterpretq_u8_u64(vshrq_n_u64(r, 64 - 8));
    uint8x16_t h, m, l;
    uint8x16_t c, d, e, f, g, n, o;
    h = input.val[0];
    m = input.val[1];
    l = input.val[2];
    c = pmull_high(h, MODULO);
    d = pmull_low(h, MODULO);
    e = veorq_u8(c, m);
    f = pmull_high(e, MODULO);
    g = vextq_u8(ZERO, e, 8);
    n = veorq_u8(d, l);
    o = veorq_u8(n, f);
    return veorq_u8(o, g);
}
void mbedtls_aesce_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16])
{
    uint8x16_t va, vb, vc;
    va = vrbitq_u8(vld1q_u8(&a[0]));
    vb = vrbitq_u8(vld1q_u8(&b[0]));
    vc = vrbitq_u8(poly_mult_reduce(poly_mult_128(va, vb)));
    vst1q_u8(&c[0], vc);
}
#endif
#if defined(MBEDTLS_POP_TARGET_PRAGMA)
#if defined(__clang__)
#pragma clang attribute pop
#elif defined(__GNUC__)
#pragma GCC pop_options
#endif
#undef MBEDTLS_POP_TARGET_PRAGMA
#endif
#endif
#endif
