/*
 *  AES-NI support functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_AESNI_C)

#include "aesni.h"

#include <string.h>

#if defined(MBEDTLS_AESNI_HAVE_CODE)

#if MBEDTLS_AESNI_HAVE_CODE == 2
#if defined(__GNUC__)
#include <cpuid.h>
#elif defined(_MSC_VER)
#include <intrin.h>
#else
#error "`__cpuid` required by MBEDTLS_AESNI_C is not supported by the compiler"
#endif
#include <immintrin.h>
#endif

#if defined(MBEDTLS_ARCH_IS_X86)
#if defined(MBEDTLS_COMPILER_IS_GCC)
#pragma GCC push_options
#pragma GCC target ("pclmul,sse2,aes")
#define MBEDTLS_POP_TARGET_PRAGMA
#elif defined(__clang__) && (__clang_major__ >= 5)
#pragma clang attribute push (__attribute__((target("pclmul,sse2,aes"))), apply_to=function)
#define MBEDTLS_POP_TARGET_PRAGMA
#endif
#endif

#if !defined(MBEDTLS_AES_USE_HARDWARE_ONLY)

int mbedtls_aesni_has_support(unsigned int what)
{

    static volatile int done = 0;
    static volatile unsigned int c = 0;

    if (!done) {
#if MBEDTLS_AESNI_HAVE_CODE == 2
        static int info[4] = { 0, 0, 0, 0 };
#if defined(_MSC_VER)
        __cpuid(info, 1);
#else
        __cpuid(1, info[0], info[1], info[2], info[3]);
#endif
        c = info[2];
#else
        asm ("movl  $1, %%eax   \n\t"
             "cpuid             \n\t"
             : "=c" (c)
             :
             : "eax", "ebx", "edx");
#endif
        done = 1;
    }

    return (c & what) != 0;
}
#endif

#if MBEDTLS_AESNI_HAVE_CODE == 2

int mbedtls_aesni_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    const __m128i *rk = (const __m128i *) (ctx->buf + ctx->rk_offset);
    unsigned nr = ctx->nr;

    __m128i state;
    memcpy(&state, input, 16);
    state = _mm_xor_si128(state, rk[0]);
    ++rk;
    --nr;

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    if (mode == MBEDTLS_AES_DECRYPT) {
        while (nr != 0) {
            state = _mm_aesdec_si128(state, *rk);
            ++rk;
            --nr;
        }
        state = _mm_aesdeclast_si128(state, *rk);
    } else
#else
    (void) mode;
#endif
    {
        while (nr != 0) {
            state = _mm_aesenc_si128(state, *rk);
            ++rk;
            --nr;
        }
        state = _mm_aesenclast_si128(state, *rk);
    }

    memcpy(output, &state, 16);
    return 0;
}

static void gcm_clmul(const __m128i aa, const __m128i bb,
                      __m128i *cc, __m128i *dd)
{

    *cc = _mm_clmulepi64_si128(aa, bb, 0x00);
    *dd = _mm_clmulepi64_si128(aa, bb, 0x11);
    __m128i ee = _mm_clmulepi64_si128(aa, bb, 0x10);
    __m128i ff = _mm_clmulepi64_si128(aa, bb, 0x01);
    ff = _mm_xor_si128(ff, ee);
    ee = ff;
    ff = _mm_srli_si128(ff, 8);
    ee = _mm_slli_si128(ee, 8);
    *dd = _mm_xor_si128(*dd, ff);
    *cc = _mm_xor_si128(*cc, ee);
}

static void gcm_shift(__m128i *cc, __m128i *dd)
{

    __m128i cc_lo = _mm_slli_epi64(*cc, 1);
    __m128i dd_lo = _mm_slli_epi64(*dd, 1);
    __m128i cc_hi = _mm_srli_epi64(*cc, 63);
    __m128i dd_hi = _mm_srli_epi64(*dd, 63);
    __m128i xmm5 = _mm_srli_si128(cc_hi, 8);
    cc_hi = _mm_slli_si128(cc_hi, 8);
    dd_hi = _mm_slli_si128(dd_hi, 8);

    *cc = _mm_or_si128(cc_lo, cc_hi);
    *dd = _mm_or_si128(_mm_or_si128(dd_lo, dd_hi), xmm5);
}

static __m128i gcm_reduce(__m128i xx)
{

    __m128i aa = _mm_slli_epi64(xx, 63);
    __m128i bb = _mm_slli_epi64(xx, 62);
    __m128i cc = _mm_slli_epi64(xx, 57);
    __m128i dd = _mm_slli_si128(_mm_xor_si128(_mm_xor_si128(aa, bb), cc), 8);
    return _mm_xor_si128(dd, xx);
}

static __m128i gcm_mix(__m128i dx)
{

    __m128i ee = _mm_srli_epi64(dx, 1);
    __m128i ff = _mm_srli_epi64(dx, 2);
    __m128i gg = _mm_srli_epi64(dx, 7);

    __m128i eh = _mm_slli_epi64(dx, 63);
    __m128i fh = _mm_slli_epi64(dx, 62);
    __m128i gh = _mm_slli_epi64(dx, 57);
    __m128i hh = _mm_srli_si128(_mm_xor_si128(_mm_xor_si128(eh, fh), gh), 8);

    return _mm_xor_si128(_mm_xor_si128(_mm_xor_si128(_mm_xor_si128(ee, ff), gg), hh), dx);
}

void mbedtls_aesni_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16])
{
    __m128i aa = { 0 }, bb = { 0 }, cc, dd;

    for (size_t i = 0; i < 16; i++) {
        ((uint8_t *) &aa)[i] = a[15 - i];
        ((uint8_t *) &bb)[i] = b[15 - i];
    }

    gcm_clmul(aa, bb, &cc, &dd);
    gcm_shift(&cc, &dd);

    __m128i dx = gcm_reduce(cc);
    __m128i xh = gcm_mix(dx);
    cc = _mm_xor_si128(xh, dd);

    for (size_t i = 0; i < 16; i++) {
        c[i] = ((uint8_t *) &cc)[15 - i];
    }

    return;
}

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
void mbedtls_aesni_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey, int nr)
{
    __m128i *ik = (__m128i *) invkey;
    const __m128i *fk = (const __m128i *) fwdkey + nr;

    *ik = *fk;
    for (--fk, ++ik; fk > (const __m128i *) fwdkey; --fk, ++ik) {
        *ik = _mm_aesimc_si128(*fk);
    }
    *ik = *fk;
}
#endif

static __m128i aesni_set_rk_128(__m128i state, __m128i xword)
{

    xword = _mm_shuffle_epi32(xword, 0xff);
    xword = _mm_xor_si128(xword, state);
    state = _mm_slli_si128(state, 4);
    xword = _mm_xor_si128(xword, state);
    state = _mm_slli_si128(state, 4);
    xword = _mm_xor_si128(xword, state);
    state = _mm_slli_si128(state, 4);
    state = _mm_xor_si128(xword, state);
    return state;
}

static void aesni_setkey_enc_128(unsigned char *rk_bytes,
                                 const unsigned char *key)
{
    __m128i *rk = (__m128i *) rk_bytes;

    memcpy(&rk[0], key, 16);
    rk[1] = aesni_set_rk_128(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
    rk[2] = aesni_set_rk_128(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
    rk[3] = aesni_set_rk_128(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
    rk[4] = aesni_set_rk_128(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
    rk[5] = aesni_set_rk_128(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
    rk[6] = aesni_set_rk_128(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
    rk[7] = aesni_set_rk_128(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
    rk[8] = aesni_set_rk_128(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
    rk[9] = aesni_set_rk_128(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1B));
    rk[10] = aesni_set_rk_128(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static void aesni_set_rk_192(__m128i *state0, __m128i *state1, __m128i xword,
                             unsigned char *rk)
{

    xword = _mm_shuffle_epi32(xword, 0x55);
    xword = _mm_xor_si128(xword, *state0);
    *state0 = _mm_slli_si128(*state0, 4);
    xword = _mm_xor_si128(xword, *state0);
    *state0 = _mm_slli_si128(*state0, 4);
    xword = _mm_xor_si128(xword, *state0);
    *state0 = _mm_slli_si128(*state0, 4);
    xword = _mm_xor_si128(xword, *state0);
    *state0 = xword;

    xword = _mm_shuffle_epi32(xword, 0xff);
    xword = _mm_xor_si128(xword, *state1);
    *state1 = _mm_slli_si128(*state1, 4);
    xword = _mm_xor_si128(xword, *state1);
    *state1 = xword;

    memcpy(rk, state0, 16);
    memcpy(rk + 16, state1, 8);
}

static void aesni_setkey_enc_192(unsigned char *rk,
                                 const unsigned char *key)
{

    memcpy(rk, key, 24);

    __m128i state0 = ((__m128i *) rk)[0];
    __m128i state1 = _mm_loadl_epi64(((__m128i *) rk) + 1);

    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x01), rk + 24 * 1);
    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x02), rk + 24 * 2);
    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x04), rk + 24 * 3);
    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x08), rk + 24 * 4);
    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x10), rk + 24 * 5);
    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x20), rk + 24 * 6);
    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x40), rk + 24 * 7);
    aesni_set_rk_192(&state0, &state1, _mm_aeskeygenassist_si128(state1, 0x80), rk + 24 * 8);
}
#endif

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static void aesni_set_rk_256(__m128i state0, __m128i state1, __m128i xword,
                             __m128i *rk0, __m128i *rk1)
{

    xword = _mm_shuffle_epi32(xword, 0xff);
    xword = _mm_xor_si128(xword, state0);
    state0 = _mm_slli_si128(state0, 4);
    xword = _mm_xor_si128(xword, state0);
    state0 = _mm_slli_si128(state0, 4);
    xword = _mm_xor_si128(xword, state0);
    state0 = _mm_slli_si128(state0, 4);
    state0 = _mm_xor_si128(state0, xword);
    *rk0 = state0;

    xword = _mm_aeskeygenassist_si128(state0, 0x00);
    xword = _mm_shuffle_epi32(xword, 0xaa);
    xword = _mm_xor_si128(xword, state1);
    state1 = _mm_slli_si128(state1, 4);
    xword = _mm_xor_si128(xword, state1);
    state1 = _mm_slli_si128(state1, 4);
    xword = _mm_xor_si128(xword, state1);
    state1 = _mm_slli_si128(state1, 4);
    state1 = _mm_xor_si128(state1, xword);
    *rk1 = state1;
}

static void aesni_setkey_enc_256(unsigned char *rk_bytes,
                                 const unsigned char *key)
{
    __m128i *rk = (__m128i *) rk_bytes;

    memcpy(&rk[0], key, 16);
    memcpy(&rk[1], key + 16, 16);

    aesni_set_rk_256(rk[0], rk[1], _mm_aeskeygenassist_si128(rk[1], 0x01), &rk[2], &rk[3]);
    aesni_set_rk_256(rk[2], rk[3], _mm_aeskeygenassist_si128(rk[3], 0x02), &rk[4], &rk[5]);
    aesni_set_rk_256(rk[4], rk[5], _mm_aeskeygenassist_si128(rk[5], 0x04), &rk[6], &rk[7]);
    aesni_set_rk_256(rk[6], rk[7], _mm_aeskeygenassist_si128(rk[7], 0x08), &rk[8], &rk[9]);
    aesni_set_rk_256(rk[8], rk[9], _mm_aeskeygenassist_si128(rk[9], 0x10), &rk[10], &rk[11]);
    aesni_set_rk_256(rk[10], rk[11], _mm_aeskeygenassist_si128(rk[11], 0x20), &rk[12], &rk[13]);
    aesni_set_rk_256(rk[12], rk[13], _mm_aeskeygenassist_si128(rk[13], 0x40), &rk[14], &rk[15]);
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

#else

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#warning \
    "MBEDTLS_AESNI_C is known to cause spurious error reports with some memory sanitizers as they do not understand the assembly code."
#endif
#endif

#define AESDEC(regs)      ".byte 0x66,0x0F,0x38,0xDE," regs "\n\t"
#define AESDECLAST(regs)  ".byte 0x66,0x0F,0x38,0xDF," regs "\n\t"
#define AESENC(regs)      ".byte 0x66,0x0F,0x38,0xDC," regs "\n\t"
#define AESENCLAST(regs)  ".byte 0x66,0x0F,0x38,0xDD," regs "\n\t"
#define AESIMC(regs)      ".byte 0x66,0x0F,0x38,0xDB," regs "\n\t"
#define AESKEYGENA(regs, imm)  ".byte 0x66,0x0F,0x3A,0xDF," regs "," imm "\n\t"
#define PCLMULQDQ(regs, imm)   ".byte 0x66,0x0F,0x3A,0x44," regs "," imm "\n\t"

#define xmm0_xmm0   "0xC0"
#define xmm0_xmm1   "0xC8"
#define xmm0_xmm2   "0xD0"
#define xmm0_xmm3   "0xD8"
#define xmm0_xmm4   "0xE0"
#define xmm1_xmm0   "0xC1"
#define xmm1_xmm2   "0xD1"

int mbedtls_aesni_crypt_ecb(mbedtls_aes_context *ctx,
                            int mode,
                            const unsigned char input[16],
                            unsigned char output[16])
{
    asm ("movdqu    (%3), %%xmm0    \n\t"
         "movdqu    (%1), %%xmm1    \n\t"
         "pxor      %%xmm1, %%xmm0  \n\t"
         "add       $16, %1         \n\t"
         "subl      $1, %0          \n\t"
         "test      %2, %2          \n\t"
         "jz        2f              \n\t"

         "1:                        \n\t"
         "movdqu    (%1), %%xmm1    \n\t"
         AESENC(xmm1_xmm0)
         "add       $16, %1         \n\t"
         "subl      $1, %0          \n\t"
         "jnz       1b              \n\t"
         "movdqu    (%1), %%xmm1    \n\t"
         AESENCLAST(xmm1_xmm0)
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
         "jmp       3f              \n\t"

         "2:                        \n\t"
         "movdqu    (%1), %%xmm1    \n\t"
         AESDEC(xmm1_xmm0)
         "add       $16, %1         \n\t"
         "subl      $1, %0          \n\t"
         "jnz       2b              \n\t"
         "movdqu    (%1), %%xmm1    \n\t"
         AESDECLAST(xmm1_xmm0)
#endif

         "3:                        \n\t"
         "movdqu    %%xmm0, (%4)    \n\t"
         :
         : "r" (ctx->nr), "r" (ctx->buf + ctx->rk_offset), "r" (mode), "r" (input), "r" (output)
         : "memory", "cc", "xmm0", "xmm1", "0", "1");

    return 0;
}

void mbedtls_aesni_gcm_mult(unsigned char c[16],
                            const unsigned char a[16],
                            const unsigned char b[16])
{
    unsigned char aa[16], bb[16], cc[16];
    size_t i;

    for (i = 0; i < 16; i++) {
        aa[i] = a[15 - i];
        bb[i] = b[15 - i];
    }

    asm ("movdqu (%0), %%xmm0               \n\t"
         "movdqu (%1), %%xmm1               \n\t"

         "movdqa %%xmm1, %%xmm2             \n\t"
         "movdqa %%xmm1, %%xmm3             \n\t"
         "movdqa %%xmm1, %%xmm4             \n\t"
         PCLMULQDQ(xmm0_xmm1, "0x00")
         PCLMULQDQ(xmm0_xmm2, "0x11")
         PCLMULQDQ(xmm0_xmm3, "0x10")
         PCLMULQDQ(xmm0_xmm4, "0x01")
         "pxor %%xmm3, %%xmm4               \n\t"
         "movdqa %%xmm4, %%xmm3             \n\t"
         "psrldq $8, %%xmm4                 \n\t"
         "pslldq $8, %%xmm3                 \n\t"
         "pxor %%xmm4, %%xmm2               \n\t"
         "pxor %%xmm3, %%xmm1               \n\t"

         "movdqa %%xmm1, %%xmm3             \n\t"
         "movdqa %%xmm2, %%xmm4             \n\t"
         "psllq $1, %%xmm1                  \n\t"
         "psllq $1, %%xmm2                  \n\t"
         "psrlq $63, %%xmm3                 \n\t"
         "psrlq $63, %%xmm4                 \n\t"
         "movdqa %%xmm3, %%xmm5             \n\t"
         "pslldq $8, %%xmm3                 \n\t"
         "pslldq $8, %%xmm4                 \n\t"
         "psrldq $8, %%xmm5                 \n\t"
         "por %%xmm3, %%xmm1                \n\t"
         "por %%xmm4, %%xmm2                \n\t"
         "por %%xmm5, %%xmm2                \n\t"

         "movdqa %%xmm1, %%xmm3             \n\t"
         "movdqa %%xmm1, %%xmm4             \n\t"
         "movdqa %%xmm1, %%xmm5             \n\t"
         "psllq $63, %%xmm3                 \n\t"
         "psllq $62, %%xmm4                 \n\t"
         "psllq $57, %%xmm5                 \n\t"

         "pxor %%xmm4, %%xmm3               \n\t"
         "pxor %%xmm5, %%xmm3               \n\t"
         "pslldq $8, %%xmm3                 \n\t"
         "pxor %%xmm3, %%xmm1               \n\t"

         "movdqa %%xmm1,%%xmm0              \n\t"
         "movdqa %%xmm1,%%xmm4              \n\t"
         "movdqa %%xmm1,%%xmm5              \n\t"
         "psrlq $1, %%xmm0                  \n\t"
         "psrlq $2, %%xmm4                  \n\t"
         "psrlq $7, %%xmm5                  \n\t"
         "pxor %%xmm4, %%xmm0               \n\t"
         "pxor %%xmm5, %%xmm0               \n\t"

         "movdqa %%xmm1,%%xmm3              \n\t"
         "movdqa %%xmm1,%%xmm4              \n\t"
         "movdqa %%xmm1,%%xmm5              \n\t"
         "psllq $63, %%xmm3                 \n\t"
         "psllq $62, %%xmm4                 \n\t"
         "psllq $57, %%xmm5                 \n\t"
         "pxor %%xmm4, %%xmm3               \n\t"
         "pxor %%xmm5, %%xmm3               \n\t"
         "psrldq $8, %%xmm3                 \n\t"
         "pxor %%xmm3, %%xmm0               \n\t"
         "pxor %%xmm1, %%xmm0               \n\t"
         "pxor %%xmm2, %%xmm0               \n\t"

         "movdqu %%xmm0, (%2)               \n\t"
         :
         : "r" (aa), "r" (bb), "r" (cc)
         : "memory", "cc", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5");

    for (i = 0; i < 16; i++) {
        c[i] = cc[15 - i];
    }

    return;
}

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
void mbedtls_aesni_inverse_key(unsigned char *invkey,
                               const unsigned char *fwdkey, int nr)
{
    unsigned char *ik = invkey;
    const unsigned char *fk = fwdkey + 16 * nr;

    memcpy(ik, fk, 16);

    for (fk -= 16, ik += 16; fk > fwdkey; fk -= 16, ik += 16) {
        asm ("movdqu (%0), %%xmm0       \n\t"
             AESIMC(xmm0_xmm0)
             "movdqu %%xmm0, (%1)       \n\t"
             :
             : "r" (fk), "r" (ik)
             : "memory", "xmm0");
    }

    memcpy(ik, fk, 16);
}
#endif

static void aesni_setkey_enc_128(unsigned char *rk,
                                 const unsigned char *key)
{
    asm ("movdqu (%1), %%xmm0               \n\t"
         "movdqu %%xmm0, (%0)               \n\t"
         "jmp 2f                            \n\t"

         "1:                                \n\t"
         "pshufd $0xff, %%xmm1, %%xmm1      \n\t"
         "pxor %%xmm0, %%xmm1               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm0, %%xmm1               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm0, %%xmm1               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm1, %%xmm0               \n\t"
         "add $16, %0                       \n\t"
         "movdqu %%xmm0, (%0)               \n\t"
         "ret                               \n\t"

         "2:                                \n\t"
         AESKEYGENA(xmm0_xmm1, "0x01")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x02")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x04")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x08")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x10")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x20")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x40")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x80")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x1B")      "call 1b \n\t"
         AESKEYGENA(xmm0_xmm1, "0x36")      "call 1b \n\t"
         :
         : "r" (rk), "r" (key)
         : "memory", "cc", "xmm0", "xmm1", "0");
}

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static void aesni_setkey_enc_192(unsigned char *rk,
                                 const unsigned char *key)
{
    asm ("movdqu (%1), %%xmm0   \n\t"
         "movdqu %%xmm0, (%0)   \n\t"
         "add $16, %0           \n\t"
         "movq 16(%1), %%xmm1   \n\t"
         "movq %%xmm1, (%0)     \n\t"
         "add $8, %0            \n\t"
         "jmp 2f                \n\t"

         "1:                            \n\t"
         "pshufd $0x55, %%xmm2, %%xmm2  \n\t"
         "pxor %%xmm0, %%xmm2           \n\t"
         "pslldq $4, %%xmm0             \n\t"
         "pxor %%xmm0, %%xmm2           \n\t"
         "pslldq $4, %%xmm0             \n\t"
         "pxor %%xmm0, %%xmm2           \n\t"
         "pslldq $4, %%xmm0             \n\t"
         "pxor %%xmm2, %%xmm0           \n\t"
         "movdqu %%xmm0, (%0)           \n\t"
         "add $16, %0                   \n\t"
         "pshufd $0xff, %%xmm0, %%xmm2  \n\t"
         "pxor %%xmm1, %%xmm2           \n\t"
         "pslldq $4, %%xmm1             \n\t"
         "pxor %%xmm2, %%xmm1           \n\t"
         "movq %%xmm1, (%0)             \n\t"
         "add $8, %0                    \n\t"
         "ret                           \n\t"

         "2:                            \n\t"
         AESKEYGENA(xmm1_xmm2, "0x01")  "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x02")  "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x04")  "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x08")  "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x10")  "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x20")  "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x40")  "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x80")  "call 1b \n\t"

         :
         : "r" (rk), "r" (key)
         : "memory", "cc", "xmm0", "xmm1", "xmm2", "0");
}
#endif

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static void aesni_setkey_enc_256(unsigned char *rk,
                                 const unsigned char *key)
{
    asm ("movdqu (%1), %%xmm0           \n\t"
         "movdqu %%xmm0, (%0)           \n\t"
         "add $16, %0                   \n\t"
         "movdqu 16(%1), %%xmm1         \n\t"
         "movdqu %%xmm1, (%0)           \n\t"
         "jmp 2f                        \n\t"

         "1:                                \n\t"
         "pshufd $0xff, %%xmm2, %%xmm2      \n\t"
         "pxor %%xmm0, %%xmm2               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm0, %%xmm2               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm0, %%xmm2               \n\t"
         "pslldq $4, %%xmm0                 \n\t"
         "pxor %%xmm2, %%xmm0               \n\t"
         "add $16, %0                       \n\t"
         "movdqu %%xmm0, (%0)               \n\t"

         AESKEYGENA(xmm0_xmm2, "0x00")
         "pshufd $0xaa, %%xmm2, %%xmm2      \n\t"
         "pxor %%xmm1, %%xmm2               \n\t"
         "pslldq $4, %%xmm1                 \n\t"
         "pxor %%xmm1, %%xmm2               \n\t"
         "pslldq $4, %%xmm1                 \n\t"
         "pxor %%xmm1, %%xmm2               \n\t"
         "pslldq $4, %%xmm1                 \n\t"
         "pxor %%xmm2, %%xmm1               \n\t"
         "add $16, %0                       \n\t"
         "movdqu %%xmm1, (%0)               \n\t"
         "ret                               \n\t"

         "2:                                \n\t"
         AESKEYGENA(xmm1_xmm2, "0x01")      "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x02")      "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x04")      "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x08")      "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x10")      "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x20")      "call 1b \n\t"
         AESKEYGENA(xmm1_xmm2, "0x40")      "call 1b \n\t"
         :
         : "r" (rk), "r" (key)
         : "memory", "cc", "xmm0", "xmm1", "xmm2", "0");
}
#endif

#endif

int mbedtls_aesni_setkey_enc(unsigned char *rk,
                             const unsigned char *key,
                             size_t bits)
{
    switch (bits) {
        case 128: aesni_setkey_enc_128(rk, key); break;
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
        case 192: aesni_setkey_enc_192(rk, key); break;
        case 256: aesni_setkey_enc_256(rk, key); break;
#endif
        default: return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;
    }

    return 0;
}

#endif

#endif
