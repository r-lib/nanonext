/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_ECP_INVASIVE_H
#define MBEDTLS_ECP_INVASIVE_H

#include "common.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

typedef enum {
    MBEDTLS_ECP_MOD_NONE = 0,
    MBEDTLS_ECP_MOD_COORDINATE,
    MBEDTLS_ECP_MOD_SCALAR
} mbedtls_ecp_modulus_type;

typedef enum {
    MBEDTLS_ECP_VARIANT_NONE = 0,
    MBEDTLS_ECP_VARIANT_WITH_MPI_STRUCT,
    MBEDTLS_ECP_VARIANT_WITH_MPI_UINT
} mbedtls_ecp_variant;

#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_ECP_LIGHT)

MBEDTLS_STATIC_TESTABLE
mbedtls_ecp_variant mbedtls_ecp_get_variant(void);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)

int mbedtls_ecp_gen_privkey_mx(size_t high_bit,
                               mbedtls_mpi *d,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng);

#endif

#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p192_raw(mbedtls_mpi_uint *Np, size_t Nn);

#endif

#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p224_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p256_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p521_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int  mbedtls_ecp_mod_p384_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p192k1_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p224k1_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p256k1_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p255_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_mod_p448_raw(mbedtls_mpi_uint *X, size_t X_limbs);

#endif

MBEDTLS_STATIC_TESTABLE
int mbedtls_ecp_modulus_setup(mbedtls_mpi_mod_modulus *N,
                              const mbedtls_ecp_group_id id,
                              const mbedtls_ecp_modulus_type ctype);

#endif

#endif
