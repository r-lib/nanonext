/**
 * \file version.h
 *
 * \brief Run-time version information
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * This set of run-time variables can be used to determine the version number of
 * the Mbed TLS library used. Compile-time version defines for the same can be
 * found in build_info.h
 */
#ifndef MBEDTLS_VERSION_H
#define MBEDTLS_VERSION_H 
#include "mbedtls/build_info.h"
#if defined(MBEDTLS_VERSION_C)
#ifdef __cplusplus
extern "C" {
#endif
unsigned int mbedtls_version_get_number(void);
void mbedtls_version_get_string(char *string);
void mbedtls_version_get_string_full(char *string);
int mbedtls_version_check_feature(const char *feature);
#ifdef __cplusplus
}
#endif
#endif
#endif
