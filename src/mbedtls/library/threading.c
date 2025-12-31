/*
 *  Threading abstraction layer
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "common.h"

#if defined(MBEDTLS_THREADING_C)

#include "threading_internal.h"

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)

#if !defined(_WIN32) && (defined(unix) || \
    defined(__unix) || defined(__unix__) || (defined(__APPLE__) && \
    defined(__MACH__)))
#include <unistd.h>
#endif

#if !((defined(_POSIX_VERSION) && _POSIX_VERSION >= 200809L) ||     \
    (defined(_POSIX_THREAD_SAFE_FUNCTIONS) &&                     \
    _POSIX_THREAD_SAFE_FUNCTIONS >= 200112L))

#if !(defined(_WIN32) && !defined(EFIX64) && !defined(EFI32))
#define THREADING_USE_GMTIME
#endif

#endif

#endif

#if defined(MBEDTLS_THREADING_PTHREAD)
static void threading_mutex_init_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    (void) pthread_mutex_init(&mutex->mutex, NULL);
}

static void threading_mutex_free_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return;
    }

    (void) pthread_mutex_destroy(&mutex->mutex);
}

static int threading_mutex_lock_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    if (pthread_mutex_lock(&mutex->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return 0;
}

static int threading_mutex_unlock_pthread(mbedtls_threading_mutex_t *mutex)
{
    if (mutex == NULL) {
        return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
    }

    if (pthread_mutex_unlock(&mutex->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }

    return 0;
}

void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *) = threading_mutex_init_pthread;
void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *) = threading_mutex_free_pthread;
int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *) = threading_mutex_lock_pthread;
int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *) = threading_mutex_unlock_pthread;

#define MUTEX_INIT  = { PTHREAD_MUTEX_INITIALIZER, 1 }

#endif

#if defined(MBEDTLS_THREADING_ALT)
static int threading_mutex_fail(mbedtls_threading_mutex_t *mutex)
{
    ((void) mutex);
    return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
}
static void threading_mutex_dummy(mbedtls_threading_mutex_t *mutex)
{
    ((void) mutex);
    return;
}

void (*mbedtls_mutex_init)(mbedtls_threading_mutex_t *) = threading_mutex_dummy;
void (*mbedtls_mutex_free)(mbedtls_threading_mutex_t *) = threading_mutex_dummy;
int (*mbedtls_mutex_lock)(mbedtls_threading_mutex_t *) = threading_mutex_fail;
int (*mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *) = threading_mutex_fail;

void mbedtls_threading_set_alt(void (*mutex_init)(mbedtls_threading_mutex_t *),
                               void (*mutex_free)(mbedtls_threading_mutex_t *),
                               int (*mutex_lock)(mbedtls_threading_mutex_t *),
                               int (*mutex_unlock)(mbedtls_threading_mutex_t *))
{
    mbedtls_mutex_init = mutex_init;
    mbedtls_mutex_free = mutex_free;
    mbedtls_mutex_lock = mutex_lock;
    mbedtls_mutex_unlock = mutex_unlock;

#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_init(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_init(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_init(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_init(&mbedtls_threading_psa_rngdata_mutex);
#endif
}

void mbedtls_threading_free_alt(void)
{
#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_free(&mbedtls_threading_readdir_mutex);
#endif
#if defined(THREADING_USE_GMTIME)
    mbedtls_mutex_free(&mbedtls_threading_gmtime_mutex);
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    mbedtls_mutex_free(&mbedtls_threading_key_slot_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_globaldata_mutex);
    mbedtls_mutex_free(&mbedtls_threading_psa_rngdata_mutex);
#endif
}
#endif

#ifndef MUTEX_INIT
#define MUTEX_INIT
#endif
#if defined(MBEDTLS_FS_IO)
mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex MUTEX_INIT;
#endif
#if defined(THREADING_USE_GMTIME)
mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex MUTEX_INIT;
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
mbedtls_threading_mutex_t mbedtls_threading_key_slot_mutex MUTEX_INIT;
mbedtls_threading_mutex_t mbedtls_threading_psa_globaldata_mutex MUTEX_INIT;
mbedtls_threading_mutex_t mbedtls_threading_psa_rngdata_mutex MUTEX_INIT;
#endif

#endif
