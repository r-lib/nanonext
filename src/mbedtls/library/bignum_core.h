/**
 *  Core bignum functions
 *
 *  This interface should only be used by the legacy bignum module (bignum.h)
 *  and the modular bignum modules (bignum_mod.c, bignum_mod_raw.c). All other
 *  modules should use the high-level modular bignum interface (bignum_mod.h)
 *  or the legacy bignum interface (bignum.h).
 *
 * This module is about processing non-negative integers with a fixed upper
 * bound that's of the form 2^n-1 where n is a multiple of #biL.
 * These can be thought of integers written in base 2^#biL with a fixed
 * number of digits. Digits in this base are called *limbs*.
 * Many operations treat these numbers as the principal representation of
 * a number modulo 2^n or a smaller bound.
 *
 * The functions in this module obey the following conventions unless
 * explicitly indicated otherwise:
 *
 * - **Overflow**: some functions indicate overflow from the range
 *   [0, 2^n-1] by returning carry parameters, while others operate
 *   modulo and so cannot overflow. This should be clear from the function
 *   documentation.
 * - **Bignum parameters**: Bignums are passed as pointers to an array of
 *   limbs. A limb has the type #mbedtls_mpi_uint. Unless otherwise specified:
 *     - Bignum parameters called \p A, \p B, ... are inputs, and are
 *       not modified by the function.
 *     - For operations modulo some number, the modulus is called \p N
 *       and is input-only.
 *     - Bignum parameters called \p X, \p Y are outputs or input-output.
 *       The initial content of output-only parameters is ignored.
 *     - Some functions use different names that reflect traditional
 *       naming of operands of certain operations (e.g.
 *       divisor/dividend/quotient/remainder).
 *     - \p T is a temporary storage area. The initial content of such
 *       parameter is ignored and the final content is unspecified.
 * - **Bignum sizes**: bignum sizes are always expressed in limbs.
 *   Most functions work on bignums of a given size and take a single
 *   \p limbs parameter that applies to all parameters that are limb arrays.
 *   All bignum sizes must be at least 1 and must be significantly less than
 *   #SIZE_MAX. The behavior if a size is 0 is undefined. The behavior if the
 *   total size of all parameters overflows #SIZE_MAX is undefined.
 * - **Parameter ordering**: for bignum parameters, outputs come before inputs.
 *   Temporaries come last.
 * - **Aliasing**: in general, output bignums may be aliased to one or more
 *   inputs. As an exception, parameters that are documented as a modulus value
 *   may not be aliased to an output. Outputs may not be aliased to one another.
 *   Temporaries may not be aliased to any other parameter.
 * - **Overlap**: apart from aliasing of limb array pointers (where two
 *   arguments are equal pointers), overlap is not supported and may result
 *   in undefined behavior.
 * - **Error handling**: This is a low-level module. Functions generally do not
 *   try to protect against invalid arguments such as nonsensical sizes or
 *   null pointers. Note that some functions that operate on bignums of
 *   different sizes have constraints about their size, and violating those
 *   constraints may lead to buffer overflows.
 * - **Modular representatives**: functions that operate modulo \p N expect
 *   all modular inputs to be in the range [0, \p N - 1] and guarantee outputs
 *   in the range [0, \p N - 1]. If an input is out of range, outputs are
 *   fully unspecified, though bignum values out of range should not cause
 *   buffer overflows (beware that this is not extensively tested).
 */

/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_BIGNUM_CORE_H
#define MBEDTLS_BIGNUM_CORE_H 
#include "common.h"
#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif
#include "constant_time_internal.h"
#define ciL (sizeof(mbedtls_mpi_uint))
#define biL (ciL << 3)
#define biH (ciL << 2)
#define BITS_TO_LIMBS(i) ((i) / biL + ((i) % biL != 0))
#define CHARS_TO_LIMBS(i) ((i) / ciL + ((i) % ciL != 0))
#define GET_BYTE(X,i) \
    (((X)[(i) / ciL] >> (((i) % ciL) * 8)) & 0xff)
#define MBEDTLS_MPI_IS_PUBLIC 0x2a2a2a2a
#define MBEDTLS_MPI_IS_SECRET 0
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
#if defined(MBEDTLS_TEST_HOOKS) && !defined(MBEDTLS_THREADING_C)
extern int mbedtls_mpi_optionally_safe_codepath;
static inline void mbedtls_mpi_optionally_safe_codepath_reset(void)
{
    mbedtls_mpi_optionally_safe_codepath = MBEDTLS_MPI_IS_PUBLIC + MBEDTLS_MPI_IS_SECRET + 1;
}
#endif
#endif
