/**
 * \file base64_internal.h
 *
 * \brief RFC 1521 base64 encoding/decoding: interfaces for invasive testing
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_BASE64_INTERNAL
#define MBEDTLS_BASE64_INTERNAL 
#include "common.h"
#if defined(MBEDTLS_TEST_HOOKS)
unsigned char mbedtls_ct_base64_enc_char(unsigned char value);
signed char mbedtls_ct_base64_dec_value(unsigned char c);
#endif
#endif
