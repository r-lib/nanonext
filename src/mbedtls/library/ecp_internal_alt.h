/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_ECP_INTERNAL_H
#define MBEDTLS_ECP_INTERNAL_H

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_ECP_INTERNAL_ALT)

unsigned char mbedtls_internal_ecp_grp_capable(const mbedtls_ecp_group *grp);

int mbedtls_internal_ecp_init(const mbedtls_ecp_group *grp);

void mbedtls_internal_ecp_free(const mbedtls_ecp_group *grp);

#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)

#if defined(MBEDTLS_ECP_RANDOMIZE_JAC_ALT)

int mbedtls_internal_ecp_randomize_jac(const mbedtls_ecp_group *grp,
                                       mbedtls_ecp_point *pt, int (*f_rng)(void *,
                                                                           unsigned char *,
                                                                           size_t),
                                       void *p_rng);
#endif

#if defined(MBEDTLS_ECP_ADD_MIXED_ALT)

int mbedtls_internal_ecp_add_mixed(const mbedtls_ecp_group *grp,
                                   mbedtls_ecp_point *R, const mbedtls_ecp_point *P,
                                   const mbedtls_ecp_point *Q);
#endif

#if defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
int mbedtls_internal_ecp_double_jac(const mbedtls_ecp_group *grp,
                                    mbedtls_ecp_point *R, const mbedtls_ecp_point *P);
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
int mbedtls_internal_ecp_normalize_jac_many(const mbedtls_ecp_group *grp,
                                            mbedtls_ecp_point *T[], size_t t_len);
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
int mbedtls_internal_ecp_normalize_jac(const mbedtls_ecp_group *grp,
                                       mbedtls_ecp_point *pt);
#endif

#endif

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)

#if defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)
int mbedtls_internal_ecp_double_add_mxz(const mbedtls_ecp_group *grp,
                                        mbedtls_ecp_point *R,
                                        mbedtls_ecp_point *S,
                                        const mbedtls_ecp_point *P,
                                        const mbedtls_ecp_point *Q,
                                        const mbedtls_mpi *d);
#endif

#if defined(MBEDTLS_ECP_RANDOMIZE_MXZ_ALT)
int mbedtls_internal_ecp_randomize_mxz(const mbedtls_ecp_group *grp,
                                       mbedtls_ecp_point *P, int (*f_rng)(void *,
                                                                          unsigned char *,
                                                                          size_t),
                                       void *p_rng);
#endif

#if defined(MBEDTLS_ECP_NORMALIZE_MXZ_ALT)
int mbedtls_internal_ecp_normalize_mxz(const mbedtls_ecp_group *grp,
                                       mbedtls_ecp_point *P);
#endif

#endif

#endif

#endif
