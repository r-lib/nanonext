/**
 * \file ssl_debug_helpers.h
 *
 * \brief Automatically generated helper functions for debugging
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_SSL_DEBUG_HELPERS_H
#define MBEDTLS_SSL_DEBUG_HELPERS_H

#include "common.h"

#define MBEDTLS_SSL_PRINT_EXTS(level, hs_msg_type, extension_mask)

#define MBEDTLS_SSL_PRINT_EXT(level, hs_msg_type, extension_type, extra)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
#define MBEDTLS_SSL_PRINT_TICKET_FLAGS(level, flags)
#endif

#endif /* MBEDTLS_SSL_DEBUG_HELPERS_H */
