/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H

#include "common.h"

#include "mbedtls/bignum.h"

#include "constant_time_internal.h"

#define ciL    (sizeof(mbedtls_mpi_uint))
#define biL    (ciL << 3)
#define biH    (ciL << 2)

#define BITS_TO_LIMBS(i)  ((i) / biL + ((i) % biL != 0))
#define CHARS_TO_LIMBS(i) ((i) / ciL + ((i) % ciL != 0))

#define GET_BYTE(X, i)                                \
    (((X)[(i) / ciL] >> (((i) % ciL) * 8)) & 0xff)

#define MBEDTLS_MPI_IS_PUBLIC  0x2a2a2a2a
#define MBEDTLS_MPI_IS_SECRET  0
#if defined(MBEDTLS_TEST_HOOKS) && !defined(MBEDTLS_THREADING_C)

#define MBEDTLS_MPI_IS_TEST  1
#endif

size_t mbedtls_mpi_core_clz(mbedtls_mpi_uint a);

size_t mbedtls_mpi_core_bitlen(const mbedtls_mpi_uint *A, size_t A_limbs);

void mbedtls_mpi_core_bigendian_to_host(mbedtls_mpi_uint *A,
                                        size_t A_limbs);

mbedtls_ct_condition_t mbedtls_mpi_core_uint_le_mpi(mbedtls_mpi_uint min,
                                                    const mbedtls_mpi_uint *A,
                                                    size_t A_limbs);

mbedtls_ct_condition_t mbedtls_mpi_core_lt_ct(const mbedtls_mpi_uint *A,
                                              const mbedtls_mpi_uint *B,
                                              size_t limbs);

void mbedtls_mpi_core_cond_assign(mbedtls_mpi_uint *X,
                                  const mbedtls_mpi_uint *A,
                                  size_t limbs,
                                  mbedtls_ct_condition_t assign);

void mbedtls_mpi_core_cond_swap(mbedtls_mpi_uint *X,
                                mbedtls_mpi_uint *Y,
                                size_t limbs,
                                mbedtls_ct_condition_t swap);

int mbedtls_mpi_core_read_le(mbedtls_mpi_uint *X,
                             size_t X_limbs,
                             const unsigned char *input,
                             size_t input_length);

int mbedtls_mpi_core_read_be(mbedtls_mpi_uint *X,
                             size_t X_limbs,
                             const unsigned char *input,
                             size_t input_length);

int mbedtls_mpi_core_write_le(const mbedtls_mpi_uint *A,
                              size_t A_limbs,
                              unsigned char *output,
                              size_t output_length);

int mbedtls_mpi_core_write_be(const mbedtls_mpi_uint *A,
                              size_t A_limbs,
                              unsigned char *output,
                              size_t output_length);

void mbedtls_mpi_core_shift_r(mbedtls_mpi_uint *X, size_t limbs,
                              size_t count);

void mbedtls_mpi_core_shift_l(mbedtls_mpi_uint *X, size_t limbs,
                              size_t count);

mbedtls_mpi_uint mbedtls_mpi_core_add(mbedtls_mpi_uint *X,
                                      const mbedtls_mpi_uint *A,
                                      const mbedtls_mpi_uint *B,
                                      size_t limbs);

mbedtls_mpi_uint mbedtls_mpi_core_add_if(mbedtls_mpi_uint *X,
                                         const mbedtls_mpi_uint *A,
                                         size_t limbs,
                                         unsigned cond);

mbedtls_mpi_uint mbedtls_mpi_core_sub(mbedtls_mpi_uint *X,
                                      const mbedtls_mpi_uint *A,
                                      const mbedtls_mpi_uint *B,
                                      size_t limbs);

mbedtls_mpi_uint mbedtls_mpi_core_mla(mbedtls_mpi_uint *X, size_t X_limbs,
                                      const mbedtls_mpi_uint *A, size_t A_limbs,
                                      mbedtls_mpi_uint b);

void mbedtls_mpi_core_mul(mbedtls_mpi_uint *X,
                          const mbedtls_mpi_uint *A, size_t A_limbs,
                          const mbedtls_mpi_uint *B, size_t B_limbs);

mbedtls_mpi_uint mbedtls_mpi_core_montmul_init(const mbedtls_mpi_uint *N);

void mbedtls_mpi_core_montmul(mbedtls_mpi_uint *X,
                              const mbedtls_mpi_uint *A,
                              const mbedtls_mpi_uint *B, size_t B_limbs,
                              const mbedtls_mpi_uint *N, size_t AN_limbs,
                              mbedtls_mpi_uint mm, mbedtls_mpi_uint *T);

int mbedtls_mpi_core_get_mont_r2_unsafe(mbedtls_mpi *X,
                                        const mbedtls_mpi *N);

#if defined(MBEDTLS_TEST_HOOKS)

void mbedtls_mpi_core_ct_uint_table_lookup(mbedtls_mpi_uint *dest,
                                           const mbedtls_mpi_uint *table,
                                           size_t limbs,
                                           size_t count,
                                           size_t index);
#endif

int mbedtls_mpi_core_fill_random(mbedtls_mpi_uint *X, size_t X_limbs,
                                 size_t bytes,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng);

int mbedtls_mpi_core_random(mbedtls_mpi_uint *X,
                            mbedtls_mpi_uint min,
                            const mbedtls_mpi_uint *N,
                            size_t limbs,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng);

size_t mbedtls_mpi_core_exp_mod_working_limbs(size_t AN_limbs, size_t E_limbs);

void mbedtls_mpi_core_exp_mod_unsafe(mbedtls_mpi_uint *X,
                                     const mbedtls_mpi_uint *A,
                                     const mbedtls_mpi_uint *N, size_t AN_limbs,
                                     const mbedtls_mpi_uint *E, size_t E_limbs,
                                     const mbedtls_mpi_uint *RR,
                                     mbedtls_mpi_uint *T);

void mbedtls_mpi_core_exp_mod(mbedtls_mpi_uint *X,
                              const mbedtls_mpi_uint *A,
                              const mbedtls_mpi_uint *N, size_t AN_limbs,
                              const mbedtls_mpi_uint *E, size_t E_limbs,
                              const mbedtls_mpi_uint *RR,
                              mbedtls_mpi_uint *T);

mbedtls_mpi_uint mbedtls_mpi_core_sub_int(mbedtls_mpi_uint *X,
                                          const mbedtls_mpi_uint *A,
                                          mbedtls_mpi_uint b,
                                          size_t limbs);

mbedtls_ct_condition_t mbedtls_mpi_core_check_zero_ct(const mbedtls_mpi_uint *A,
                                                      size_t limbs);

static inline size_t mbedtls_mpi_core_montmul_working_limbs(size_t AN_limbs)
{
    return 2 * AN_limbs + 1;
}

void mbedtls_mpi_core_to_mont_rep(mbedtls_mpi_uint *X,
                                  const mbedtls_mpi_uint *A,
                                  const mbedtls_mpi_uint *N,
                                  size_t AN_limbs,
                                  mbedtls_mpi_uint mm,
                                  const mbedtls_mpi_uint *rr,
                                  mbedtls_mpi_uint *T);

void mbedtls_mpi_core_from_mont_rep(mbedtls_mpi_uint *X,
                                    const mbedtls_mpi_uint *A,
                                    const mbedtls_mpi_uint *N,
                                    size_t AN_limbs,
                                    mbedtls_mpi_uint mm,
                                    mbedtls_mpi_uint *T);

void mbedtls_mpi_core_gcd_modinv_odd(mbedtls_mpi_uint *G,
                                     mbedtls_mpi_uint *I,
                                     const mbedtls_mpi_uint *A,
                                     size_t A_limbs,
                                     const mbedtls_mpi_uint *N,
                                     size_t N_limbs,
                                     mbedtls_mpi_uint *T);

#endif
