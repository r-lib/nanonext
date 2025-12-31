/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_RSA_ALT_HELPERS_H
#define MBEDTLS_RSA_ALT_HELPERS_H

#include "mbedtls/build_info.h"

#include "mbedtls/bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_rsa_deduce_primes(mbedtls_mpi const *N, mbedtls_mpi const *E,
                              mbedtls_mpi const *D,
                              mbedtls_mpi *P, mbedtls_mpi *Q);

int mbedtls_rsa_deduce_private_exponent(mbedtls_mpi const *P,
                                        mbedtls_mpi const *Q,
                                        mbedtls_mpi const *E,
                                        mbedtls_mpi *D);

int mbedtls_rsa_deduce_crt(const mbedtls_mpi *P, const mbedtls_mpi *Q,
                           const mbedtls_mpi *D, mbedtls_mpi *DP,
                           mbedtls_mpi *DQ, mbedtls_mpi *QP);

int mbedtls_rsa_validate_params(const mbedtls_mpi *N, const mbedtls_mpi *P,
                                const mbedtls_mpi *Q, const mbedtls_mpi *D,
                                const mbedtls_mpi *E,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng);

int mbedtls_rsa_validate_crt(const mbedtls_mpi *P,  const mbedtls_mpi *Q,
                             const mbedtls_mpi *D,  const mbedtls_mpi *DP,
                             const mbedtls_mpi *DQ, const mbedtls_mpi *QP);

#ifdef __cplusplus
}
#endif

#endif
