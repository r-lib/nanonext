/*
 *  Helper functions for the RSA module
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 */

#include "common.h"

#if defined(MBEDTLS_RSA_C)

#include "mbedtls/rsa.h"
#include "mbedtls/bignum.h"
#include "bignum_internal.h"
#include "rsa_alt_helpers.h"

int mbedtls_rsa_deduce_primes(mbedtls_mpi const *N,
                              mbedtls_mpi const *E, mbedtls_mpi const *D,
                              mbedtls_mpi *P, mbedtls_mpi *Q)
{
    int ret = 0;

    uint16_t attempt;
    uint16_t iter;

    uint16_t order;

    mbedtls_mpi T;
    mbedtls_mpi K;

    const unsigned char primes[] = { 2,
                                     3,    5,    7,   11,   13,   17,   19,   23,
                                     29,   31,   37,   41,   43,   47,   53,   59,
                                     61,   67,   71,   73,   79,   83,   89,   97,
                                     101,  103,  107,  109,  113,  127,  131,  137,
                                     139,  149,  151,  157,  163,  167,  173,  179,
                                     181,  191,  193,  197,  199,  211,  223,  227,
                                     229,  233,  239,  241,  251 };

    const size_t num_primes = sizeof(primes) / sizeof(*primes);

    if (P == NULL || Q == NULL || P->p != NULL || Q->p != NULL) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (mbedtls_mpi_cmp_int(N, 0) <= 0 ||
        mbedtls_mpi_cmp_int(D, 1) <= 0 ||
        mbedtls_mpi_cmp_mpi(D, N) >= 0 ||
        mbedtls_mpi_cmp_int(E, 1) <= 0 ||
        mbedtls_mpi_cmp_mpi(E, N) >= 0) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    mbedtls_mpi_init(&K);
    mbedtls_mpi_init(&T);

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&T, D,  E));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&T, &T, 1));

    if ((order = (uint16_t) mbedtls_mpi_lsb(&T)) == 0) {
        ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&T, order));

    attempt = 0;
    if (N->p[0] % 8 == 1) {
        attempt = 1;
    }

    for (; attempt < num_primes; ++attempt) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&K, primes[attempt]));

        MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(P, NULL, &K, N));
        if (mbedtls_mpi_cmp_int(P, 1) != 0) {
            continue;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(&K, &K, &T, N,
                                            Q ));

        for (iter = 1; iter <= order; ++iter) {

            if (mbedtls_mpi_cmp_int(&K, 1) == 0) {
                break;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&K, &K, 1));
            MBEDTLS_MPI_CHK(mbedtls_mpi_gcd_modinv_odd(P, NULL, &K, N));

            if (mbedtls_mpi_cmp_int(P, 1) ==  1 &&
                mbedtls_mpi_cmp_mpi(P, N) == -1) {

                MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(Q, NULL, N, P));
                goto cleanup;
            }

            MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, &K, 1));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, &K, &K));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&K, &K, N));
        }

        if (mbedtls_mpi_cmp_int(&K, 1) != 0) {
            break;
        }
    }

    ret = MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

cleanup:

    mbedtls_mpi_free(&K);
    mbedtls_mpi_free(&T);
    return ret;
}

int mbedtls_rsa_deduce_private_exponent(mbedtls_mpi const *P,
                                        mbedtls_mpi const *Q,
                                        mbedtls_mpi const *E,
                                        mbedtls_mpi *D)
{
    int ret = 0;
    mbedtls_mpi K, L;

    if (D == NULL || mbedtls_mpi_cmp_int(D, 0) != 0) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (mbedtls_mpi_cmp_int(P, 1) <= 0 ||
        mbedtls_mpi_cmp_int(Q, 1) <= 0 ||
        mbedtls_mpi_cmp_int(E, 0) == 0) {
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;
    }

    if (mbedtls_mpi_get_bit(E, 0) != 1) {
        return MBEDTLS_ERR_MPI_NOT_ACCEPTABLE;
    }

    mbedtls_mpi_init(&K);
    mbedtls_mpi_init(&L);

    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&L, Q, 1));

    MBEDTLS_MPI_CHK(mbedtls_mpi_gcd(D, &K, &L));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, &K, &L));
    MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(&K, NULL, &K, D));

    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod_even_in_range(D, E, &K));

cleanup:

    mbedtls_mpi_free(&K);
    mbedtls_mpi_free(&L);

    return ret;
}

int mbedtls_rsa_deduce_crt(const mbedtls_mpi *P, const mbedtls_mpi *Q,
                           const mbedtls_mpi *D, mbedtls_mpi *DP,
                           mbedtls_mpi *DQ, mbedtls_mpi *QP)
{
    int ret = 0;
    mbedtls_mpi K;
    mbedtls_mpi_init(&K);

    if (DP != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, P, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(DP, D, &K));
    }

    if (DQ != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, Q, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(DQ, D, &K));
    }

    if (QP != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod_odd(QP, Q, P));
    }

cleanup:
    mbedtls_mpi_free(&K);

    return ret;
}

int mbedtls_rsa_validate_params(const mbedtls_mpi *N, const mbedtls_mpi *P,
                                const mbedtls_mpi *Q, const mbedtls_mpi *D,
                                const mbedtls_mpi *E,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    int ret = 0;
    mbedtls_mpi K, L;

    mbedtls_mpi_init(&K);
    mbedtls_mpi_init(&L);

#if defined(MBEDTLS_GENPRIME)

    if (f_rng != NULL && P != NULL &&
        (ret = mbedtls_mpi_is_prime_ext(P, 50, f_rng, p_rng)) != 0) {
        ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
        goto cleanup;
    }

    if (f_rng != NULL && Q != NULL &&
        (ret = mbedtls_mpi_is_prime_ext(Q, 50, f_rng, p_rng)) != 0) {
        ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
        goto cleanup;
    }
#else
    ((void) f_rng);
    ((void) p_rng);
#endif

    if (P != NULL && Q != NULL && N != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, P, Q));
        if (mbedtls_mpi_cmp_int(N, 1)  <= 0 ||
            mbedtls_mpi_cmp_mpi(&K, N) != 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    if (N != NULL && D != NULL && E != NULL) {
        if (mbedtls_mpi_cmp_int(D, 1) <= 0 ||
            mbedtls_mpi_cmp_int(E, 1) <= 0 ||
            mbedtls_mpi_cmp_mpi(D, N) >= 0 ||
            mbedtls_mpi_cmp_mpi(E, N) >= 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    if (P != NULL && Q != NULL && D != NULL && E != NULL) {
        if (mbedtls_mpi_cmp_int(P, 1) <= 0 ||
            mbedtls_mpi_cmp_int(Q, 1) <= 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, D, E));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, &K, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&L, P, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&K, &K, &L));
        if (mbedtls_mpi_cmp_int(&K, 0) != 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, D, E));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, &K, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&L, Q, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&K, &K, &L));
        if (mbedtls_mpi_cmp_int(&K, 0) != 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

cleanup:

    mbedtls_mpi_free(&K);
    mbedtls_mpi_free(&L);

    if (ret != 0 && ret != MBEDTLS_ERR_RSA_KEY_CHECK_FAILED) {
        ret += MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    return ret;
}

int mbedtls_rsa_validate_crt(const mbedtls_mpi *P,  const mbedtls_mpi *Q,
                             const mbedtls_mpi *D,  const mbedtls_mpi *DP,
                             const mbedtls_mpi *DQ, const mbedtls_mpi *QP)
{
    int ret = 0;

    mbedtls_mpi K, L;
    mbedtls_mpi_init(&K);
    mbedtls_mpi_init(&L);

    if (DP != NULL) {
        if (P == NULL) {
            ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, P, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&L, DP, D));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&L, &L, &K));

        if (mbedtls_mpi_cmp_int(&L, 0) != 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    if (DQ != NULL) {
        if (Q == NULL) {
            ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, Q, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&L, DQ, D));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&L, &L, &K));

        if (mbedtls_mpi_cmp_int(&L, 0) != 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

    if (QP != NULL) {
        if (P == NULL || Q == NULL) {
            ret = MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
            goto cleanup;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&K, QP, Q));
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&K, &K, 1));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&K, &K, P));
        if (mbedtls_mpi_cmp_int(&K, 0) != 0) {
            ret = MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
            goto cleanup;
        }
    }

cleanup:

    if (ret != 0 &&
        ret != MBEDTLS_ERR_RSA_KEY_CHECK_FAILED &&
        ret != MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
        ret += MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    mbedtls_mpi_free(&K);
    mbedtls_mpi_free(&L);

    return ret;
}

#endif
