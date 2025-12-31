/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_BIGNUM_H
#define MBEDTLS_BIGNUM_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"

#include <stddef.h>
#include <stdint.h>

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#endif

#define MBEDTLS_ERR_MPI_FILE_IO_ERROR                     -0x0002

#define MBEDTLS_ERR_MPI_BAD_INPUT_DATA                    -0x0004

#define MBEDTLS_ERR_MPI_INVALID_CHARACTER                 -0x0006

#define MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL                  -0x0008

#define MBEDTLS_ERR_MPI_NEGATIVE_VALUE                    -0x000A

#define MBEDTLS_ERR_MPI_DIVISION_BY_ZERO                  -0x000C

#define MBEDTLS_ERR_MPI_NOT_ACCEPTABLE                    -0x000E

#define MBEDTLS_ERR_MPI_ALLOC_FAILED                      -0x0010

#define MBEDTLS_MPI_CHK(f)       \
    do                           \
    {                            \
        if ((ret = (f)) != 0) \
        goto cleanup;        \
    } while (0)

#define MBEDTLS_MPI_MAX_LIMBS                             10000

#if !defined(MBEDTLS_MPI_WINDOW_SIZE)

#define MBEDTLS_MPI_WINDOW_SIZE                           3
#endif

#if !defined(MBEDTLS_MPI_MAX_SIZE)

#define MBEDTLS_MPI_MAX_SIZE                              1024
#endif

#define MBEDTLS_MPI_MAX_BITS                              (8 * MBEDTLS_MPI_MAX_SIZE)

#define MBEDTLS_MPI_MAX_BITS_SCALE100          (100 * MBEDTLS_MPI_MAX_BITS)
#define MBEDTLS_LN_2_DIV_LN_10_SCALE100                 332
#define MBEDTLS_MPI_RW_BUFFER_SIZE             (((MBEDTLS_MPI_MAX_BITS_SCALE100 + \
                                                  MBEDTLS_LN_2_DIV_LN_10_SCALE100 - 1) / \
                                                 MBEDTLS_LN_2_DIV_LN_10_SCALE100) + 10 + 6)

#if !defined(MBEDTLS_HAVE_INT32)
    #if defined(_MSC_VER) && defined(_M_AMD64)

        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif
typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
    #elif defined(__GNUC__) && (                         \
    defined(__amd64__) || defined(__x86_64__)     || \
    defined(__ppc64__) || defined(__powerpc64__)  || \
    defined(__ia64__)  || defined(__alpha__)      || \
    (defined(__sparc__) && defined(__arch64__)) || \
    defined(__s390x__) || defined(__mips64)       || \
    defined(__aarch64__))
        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif
typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
        #if !defined(MBEDTLS_NO_UDBL_DIVISION)

typedef unsigned int mbedtls_t_udbl __attribute__((mode(TI)));
            #define MBEDTLS_HAVE_UDBL
        #endif
    #elif defined(__ARMCC_VERSION) && defined(__aarch64__)

        #if !defined(MBEDTLS_HAVE_INT64)
            #define MBEDTLS_HAVE_INT64
        #endif
typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
        #if !defined(MBEDTLS_NO_UDBL_DIVISION)

typedef __uint128_t mbedtls_t_udbl;
            #define MBEDTLS_HAVE_UDBL
        #endif
    #elif defined(MBEDTLS_HAVE_INT64)

typedef  int64_t mbedtls_mpi_sint;
typedef uint64_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT64_MAX
    #endif
#endif

#if !defined(MBEDTLS_HAVE_INT64)

    #if !defined(MBEDTLS_HAVE_INT32)
        #define MBEDTLS_HAVE_INT32
    #endif
typedef  int32_t mbedtls_mpi_sint;
typedef uint32_t mbedtls_mpi_uint;
#define MBEDTLS_MPI_UINT_MAX                UINT32_MAX
    #if !defined(MBEDTLS_NO_UDBL_DIVISION)
typedef uint64_t mbedtls_t_udbl;
        #define MBEDTLS_HAVE_UDBL
    #endif
#endif

#if (!(defined(MBEDTLS_HAVE_INT32) || defined(MBEDTLS_HAVE_INT64))) || \
    (defined(MBEDTLS_HAVE_INT32) && defined(MBEDTLS_HAVE_INT64))
#error "Only 32-bit or 64-bit limbs are supported in bignum"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_mpi {

    mbedtls_mpi_uint *MBEDTLS_PRIVATE(p);

    signed short MBEDTLS_PRIVATE(s);

    unsigned short MBEDTLS_PRIVATE(n);

#if MBEDTLS_MPI_MAX_LIMBS > 65535
#error "MBEDTLS_MPI_MAX_LIMBS > 65535 is not supported"
#endif
}
mbedtls_mpi;

void mbedtls_mpi_init(mbedtls_mpi *X);

void mbedtls_mpi_free(mbedtls_mpi *X);

int mbedtls_mpi_grow(mbedtls_mpi *X, size_t nblimbs);

int mbedtls_mpi_shrink(mbedtls_mpi *X, size_t nblimbs);

int mbedtls_mpi_copy(mbedtls_mpi *X, const mbedtls_mpi *Y);

void mbedtls_mpi_swap(mbedtls_mpi *X, mbedtls_mpi *Y);

int mbedtls_mpi_safe_cond_assign(mbedtls_mpi *X, const mbedtls_mpi *Y, unsigned char assign);

int mbedtls_mpi_safe_cond_swap(mbedtls_mpi *X, mbedtls_mpi *Y, unsigned char swap);

int mbedtls_mpi_lset(mbedtls_mpi *X, mbedtls_mpi_sint z);

int mbedtls_mpi_get_bit(const mbedtls_mpi *X, size_t pos);

int mbedtls_mpi_set_bit(mbedtls_mpi *X, size_t pos, unsigned char val);

size_t mbedtls_mpi_lsb(const mbedtls_mpi *X);

size_t mbedtls_mpi_bitlen(const mbedtls_mpi *X);

size_t mbedtls_mpi_size(const mbedtls_mpi *X);

int mbedtls_mpi_read_string(mbedtls_mpi *X, int radix, const char *s);

int mbedtls_mpi_write_string(const mbedtls_mpi *X, int radix,
                             char *buf, size_t buflen, size_t *olen);

#if defined(MBEDTLS_FS_IO)

int mbedtls_mpi_read_file(mbedtls_mpi *X, int radix, FILE *fin);

int mbedtls_mpi_write_file(const char *p, const mbedtls_mpi *X,
                           int radix, FILE *fout);
#endif

int mbedtls_mpi_read_binary(mbedtls_mpi *X, const unsigned char *buf,
                            size_t buflen);

int mbedtls_mpi_read_binary_le(mbedtls_mpi *X,
                               const unsigned char *buf, size_t buflen);

int mbedtls_mpi_write_binary(const mbedtls_mpi *X, unsigned char *buf,
                             size_t buflen);

int mbedtls_mpi_write_binary_le(const mbedtls_mpi *X,
                                unsigned char *buf, size_t buflen);

int mbedtls_mpi_shift_l(mbedtls_mpi *X, size_t count);

int mbedtls_mpi_shift_r(mbedtls_mpi *X, size_t count);

int mbedtls_mpi_cmp_abs(const mbedtls_mpi *X, const mbedtls_mpi *Y);

int mbedtls_mpi_cmp_mpi(const mbedtls_mpi *X, const mbedtls_mpi *Y);

int mbedtls_mpi_lt_mpi_ct(const mbedtls_mpi *X, const mbedtls_mpi *Y,
                          unsigned *ret);

int mbedtls_mpi_cmp_int(const mbedtls_mpi *X, mbedtls_mpi_sint z);

int mbedtls_mpi_add_abs(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);

int mbedtls_mpi_sub_abs(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);

int mbedtls_mpi_add_mpi(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);

int mbedtls_mpi_sub_mpi(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);

int mbedtls_mpi_add_int(mbedtls_mpi *X, const mbedtls_mpi *A,
                        mbedtls_mpi_sint b);

int mbedtls_mpi_sub_int(mbedtls_mpi *X, const mbedtls_mpi *A,
                        mbedtls_mpi_sint b);

int mbedtls_mpi_mul_mpi(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);

int mbedtls_mpi_mul_int(mbedtls_mpi *X, const mbedtls_mpi *A,
                        mbedtls_mpi_uint b);

int mbedtls_mpi_div_mpi(mbedtls_mpi *Q, mbedtls_mpi *R, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);

int mbedtls_mpi_div_int(mbedtls_mpi *Q, mbedtls_mpi *R, const mbedtls_mpi *A,
                        mbedtls_mpi_sint b);

int mbedtls_mpi_mod_mpi(mbedtls_mpi *R, const mbedtls_mpi *A,
                        const mbedtls_mpi *B);

int mbedtls_mpi_mod_int(mbedtls_mpi_uint *r, const mbedtls_mpi *A,
                        mbedtls_mpi_sint b);

int mbedtls_mpi_exp_mod(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *E, const mbedtls_mpi *N,
                        mbedtls_mpi *prec_RR);

int mbedtls_mpi_fill_random(mbedtls_mpi *X, size_t size,
                            mbedtls_f_rng_t *f_rng,
                            void *p_rng);

int mbedtls_mpi_random(mbedtls_mpi *X,
                       mbedtls_mpi_sint min,
                       const mbedtls_mpi *N,
                       mbedtls_f_rng_t *f_rng,
                       void *p_rng);

int mbedtls_mpi_gcd(mbedtls_mpi *G, const mbedtls_mpi *A,
                    const mbedtls_mpi *B);

int mbedtls_mpi_inv_mod(mbedtls_mpi *X, const mbedtls_mpi *A,
                        const mbedtls_mpi *N);

int mbedtls_mpi_is_prime_ext(const mbedtls_mpi *X, int rounds,
                             mbedtls_f_rng_t *f_rng,
                             void *p_rng);

typedef enum {
    MBEDTLS_MPI_GEN_PRIME_FLAG_DH =      0x0001,
    MBEDTLS_MPI_GEN_PRIME_FLAG_LOW_ERR = 0x0002,
} mbedtls_mpi_gen_prime_flag_t;

int mbedtls_mpi_gen_prime(mbedtls_mpi *X, size_t nbits, int flags,
                          mbedtls_f_rng_t *f_rng,
                          void *p_rng);

#if defined(MBEDTLS_SELF_TEST)

int mbedtls_mpi_self_test(int verbose);

#endif

#ifdef __cplusplus
}
#endif

#endif
