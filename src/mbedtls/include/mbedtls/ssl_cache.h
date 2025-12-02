/**
 * \file ssl_cache.h
 *
 * \brief SSL session cache implementation
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_CACHE_H
#define MBEDTLS_SSL_CACHE_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ssl.h"
#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif
#if !defined(MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT)
#define MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT 86400
#endif
#if !defined(MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES)
#define MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES 50
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct mbedtls_ssl_cache_context mbedtls_ssl_cache_context;
typedef struct mbedtls_ssl_cache_entry mbedtls_ssl_cache_entry;
struct mbedtls_ssl_cache_entry {
#if defined(MBEDTLS_HAVE_TIME)
    mbedtls_time_t MBEDTLS_PRIVATE(timestamp);
#endif
    unsigned char MBEDTLS_PRIVATE(session_id)[32];
    size_t MBEDTLS_PRIVATE(session_id_len);
    unsigned char *MBEDTLS_PRIVATE(session);
    size_t MBEDTLS_PRIVATE(session_len);
    mbedtls_ssl_cache_entry *MBEDTLS_PRIVATE(next);
};
struct mbedtls_ssl_cache_context {
    mbedtls_ssl_cache_entry *MBEDTLS_PRIVATE(chain);
    int MBEDTLS_PRIVATE(timeout);
    int MBEDTLS_PRIVATE(max_entries);
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
};
void mbedtls_ssl_cache_init(mbedtls_ssl_cache_context *cache);
int mbedtls_ssl_cache_get(void *data,
                          unsigned char const *session_id,
                          size_t session_id_len,
                          mbedtls_ssl_session *session);
int mbedtls_ssl_cache_set(void *data,
                          unsigned char const *session_id,
                          size_t session_id_len,
                          const mbedtls_ssl_session *session);
int mbedtls_ssl_cache_remove(void *data,
                             unsigned char const *session_id,
                             size_t session_id_len);
#if defined(MBEDTLS_HAVE_TIME)
void mbedtls_ssl_cache_set_timeout(mbedtls_ssl_cache_context *cache, int timeout);
static inline int mbedtls_ssl_cache_get_timeout(mbedtls_ssl_cache_context *cache)
{
    return cache->MBEDTLS_PRIVATE(timeout);
}
#endif
void mbedtls_ssl_cache_set_max_entries(mbedtls_ssl_cache_context *cache, int max);
void mbedtls_ssl_cache_free(mbedtls_ssl_cache_context *cache);
#ifdef __cplusplus
}
#endif
#endif
