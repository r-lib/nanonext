/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_MD_WRAP_H
#define MBEDTLS_MD_WRAP_H

#include "mbedtls/build_info.h"

#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mbedtls_md_info_t {

    mbedtls_md_type_t type;

    unsigned char size;

#if defined(MBEDTLS_MD_C)

    unsigned char block_size;
#endif
};

#ifdef __cplusplus
}
#endif

#endif
