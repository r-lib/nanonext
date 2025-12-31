/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_THREADING_H
#define MBEDTLS_THREADING_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ERR_THREADING_BAD_INPUT_DATA              -0x001C

#define MBEDTLS_ERR_THREADING_MUTEX_ERROR                 -0x001E

#if defined(MBEDTLS_THREADING_PTHREAD)
#include <pthread.h>
typedef struct mbedtls_threading_mutex_t {
    pthread_mutex_t MBEDTLS_PRIVATE(mutex);

    char MBEDTLS_PRIVATE(state);

} mbedtls_threading_mutex_t;
#endif

#if defined(MBEDTLS_THREADING_ALT)

#include "threading_alt.h"

void mbedtls_threading_set_alt(void (*mutex_init)(mbedtls_threading_mutex_t *),
                               void (*mutex_free)(mbedtls_threading_mutex_t *),
                               int (*mutex_lock)(mbedtls_threading_mutex_t *),
                               int (*mutex_unlock)(mbedtls_threading_mutex_t *));

void mbedtls_threading_free_alt(void);
#endif

#if defined(MBEDTLS_THREADING_C)

extern void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *mutex);
extern void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *mutex);
extern int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *mutex);
extern int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *mutex);

#if defined(MBEDTLS_FS_IO)
extern mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex;
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

extern mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex;
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C)

extern mbedtls_threading_mutex_t mbedtls_threading_key_slot_mutex;

extern mbedtls_threading_mutex_t mbedtls_threading_psa_globaldata_mutex;

extern mbedtls_threading_mutex_t mbedtls_threading_psa_rngdata_mutex;
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
