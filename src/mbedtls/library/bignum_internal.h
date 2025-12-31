/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_BIGNUM_INTERNAL_H
#define MBEDTLS_BIGNUM_INTERNAL_H

int mbedtls_mpi_exp_mod_unsafe(mbedtls_mpi *X, const mbedtls_mpi *A,
                               const mbedtls_mpi *E, const mbedtls_mpi *N,
                               mbedtls_mpi *prec_RR);

int mbedtls_mpi_gcd_modinv_odd(mbedtls_mpi *G,
                               mbedtls_mpi *I,
                               const mbedtls_mpi *A,
                               const mbedtls_mpi *N);

int mbedtls_mpi_inv_mod_odd(mbedtls_mpi *X,
                            const mbedtls_mpi *A,
                            const mbedtls_mpi *N);

int mbedtls_mpi_inv_mod_even_in_range(mbedtls_mpi *X,
                                      mbedtls_mpi const *A,
                                      mbedtls_mpi const *N);

#endif
