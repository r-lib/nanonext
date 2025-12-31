/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PLATFORM_H
#define MBEDTLS_PLATFORM_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER <= 1900)
#define MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF
#define MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF
#endif

#if !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif
#if !defined(MBEDTLS_PLATFORM_STD_SNPRINTF)
#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)
#define MBEDTLS_PLATFORM_STD_SNPRINTF   mbedtls_platform_win32_snprintf
#else
#define MBEDTLS_PLATFORM_STD_SNPRINTF   snprintf
#endif
#endif
#if !defined(MBEDTLS_PLATFORM_STD_VSNPRINTF)
#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#define MBEDTLS_PLATFORM_STD_VSNPRINTF   mbedtls_platform_win32_vsnprintf
#else
#define MBEDTLS_PLATFORM_STD_VSNPRINTF   vsnprintf
#endif
#endif
#if !defined(MBEDTLS_PLATFORM_STD_PRINTF)
#define MBEDTLS_PLATFORM_STD_PRINTF   printf
#endif
#if !defined(MBEDTLS_PLATFORM_STD_FPRINTF)
#define MBEDTLS_PLATFORM_STD_FPRINTF fprintf
#endif
#if !defined(MBEDTLS_PLATFORM_STD_CALLOC)
#define MBEDTLS_PLATFORM_STD_CALLOC   calloc
#endif
#if !defined(MBEDTLS_PLATFORM_STD_FREE)
#define MBEDTLS_PLATFORM_STD_FREE       free
#endif
#if !defined(MBEDTLS_PLATFORM_STD_SETBUF)
#define MBEDTLS_PLATFORM_STD_SETBUF   setbuf
#endif
#if !defined(MBEDTLS_PLATFORM_STD_EXIT)
#define MBEDTLS_PLATFORM_STD_EXIT      exit
#endif
#if !defined(MBEDTLS_PLATFORM_STD_TIME)
#define MBEDTLS_PLATFORM_STD_TIME       time
#endif
#if !defined(MBEDTLS_PLATFORM_STD_EXIT_SUCCESS)
#define MBEDTLS_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS
#endif
#if !defined(MBEDTLS_PLATFORM_STD_EXIT_FAILURE)
#define MBEDTLS_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE
#endif
#if defined(MBEDTLS_FS_IO)
#if !defined(MBEDTLS_PLATFORM_STD_NV_SEED_READ)
#define MBEDTLS_PLATFORM_STD_NV_SEED_READ   mbedtls_platform_std_nv_seed_read
#endif
#if !defined(MBEDTLS_PLATFORM_STD_NV_SEED_WRITE)
#define MBEDTLS_PLATFORM_STD_NV_SEED_WRITE  mbedtls_platform_std_nv_seed_write
#endif
#if !defined(MBEDTLS_PLATFORM_STD_NV_SEED_FILE)
#define MBEDTLS_PLATFORM_STD_NV_SEED_FILE   "seedfile"
#endif
#endif
#else
#if defined(MBEDTLS_PLATFORM_STD_MEM_HDR)
#include MBEDTLS_PLATFORM_STD_MEM_HDR
#endif
#endif

#if defined(__DOXYGEN__) && !defined(MBEDTLS_PLATFORM_STD_CALLOC)
#define MBEDTLS_PLATFORM_STD_CALLOC
#endif

#if defined(__DOXYGEN__) && !defined(MBEDTLS_PLATFORM_STD_FREE)
#define MBEDTLS_PLATFORM_STD_FREE
#endif

#if defined(MBEDTLS_PLATFORM_MEMORY)
#if defined(MBEDTLS_PLATFORM_FREE_MACRO) && \
    defined(MBEDTLS_PLATFORM_CALLOC_MACRO)
#undef mbedtls_free
#undef mbedtls_calloc
#define mbedtls_free       MBEDTLS_PLATFORM_FREE_MACRO
#define mbedtls_calloc     MBEDTLS_PLATFORM_CALLOC_MACRO
#else

#include <stddef.h>
extern void *mbedtls_calloc(size_t n, size_t size);
extern void mbedtls_free(void *ptr);

int mbedtls_platform_set_calloc_free(void *(*calloc_func)(size_t, size_t),
                                     void (*free_func)(void *));
#endif
#else
#undef mbedtls_free
#undef mbedtls_calloc
#define mbedtls_free       free
#define mbedtls_calloc     calloc
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT)

#include <stdio.h>
extern int (*mbedtls_fprintf)(FILE *stream, const char *format, ...);

int mbedtls_platform_set_fprintf(int (*fprintf_func)(FILE *stream, const char *,
                                                     ...));
#else
#undef mbedtls_fprintf
#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO)
#define mbedtls_fprintf    MBEDTLS_PLATFORM_FPRINTF_MACRO
#else
#define mbedtls_fprintf    fprintf
#endif
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_ALT)
extern int (*mbedtls_printf)(const char *format, ...);

int mbedtls_platform_set_printf(int (*printf_func)(const char *, ...));
#else
#undef mbedtls_printf
#if defined(MBEDTLS_PLATFORM_PRINTF_MACRO)
#define mbedtls_printf     MBEDTLS_PLATFORM_PRINTF_MACRO
#else
#define mbedtls_printf     printf
#endif
#endif

#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)

int mbedtls_platform_win32_snprintf(char *s, size_t n, const char *fmt, ...);
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
extern int (*mbedtls_snprintf)(char *s, size_t n, const char *format, ...);

int mbedtls_platform_set_snprintf(int (*snprintf_func)(char *s, size_t n,
                                                       const char *format, ...));
#else
#undef mbedtls_snprintf
#if defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO)
#define mbedtls_snprintf   MBEDTLS_PLATFORM_SNPRINTF_MACRO
#else
#define mbedtls_snprintf   MBEDTLS_PLATFORM_STD_SNPRINTF
#endif
#endif

#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#include <stdarg.h>

int mbedtls_platform_win32_vsnprintf(char *s, size_t n, const char *fmt, va_list arg);
#endif

#if defined(MBEDTLS_PLATFORM_VSNPRINTF_ALT)
#include <stdarg.h>
extern int (*mbedtls_vsnprintf)(char *s, size_t n, const char *format, va_list arg);

int mbedtls_platform_set_vsnprintf(int (*vsnprintf_func)(char *s, size_t n,
                                                         const char *format, va_list arg));
#else
#undef mbedtls_vsnprintf
#if defined(MBEDTLS_PLATFORM_VSNPRINTF_MACRO)
#define mbedtls_vsnprintf   MBEDTLS_PLATFORM_VSNPRINTF_MACRO
#else
#define mbedtls_vsnprintf   vsnprintf
#endif
#endif

#if defined(MBEDTLS_PLATFORM_SETBUF_ALT)
#include <stdio.h>

extern void (*mbedtls_setbuf)(FILE *stream, char *buf);

int mbedtls_platform_set_setbuf(void (*setbuf_func)(
                                    FILE *stream, char *buf));
#else
#undef mbedtls_setbuf
#if defined(MBEDTLS_PLATFORM_SETBUF_MACRO)

#define mbedtls_setbuf    MBEDTLS_PLATFORM_SETBUF_MACRO
#else
#define mbedtls_setbuf    setbuf
#endif
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
extern void (*mbedtls_exit)(int status);

int mbedtls_platform_set_exit(void (*exit_func)(int status));
#else
#undef mbedtls_exit
#if defined(MBEDTLS_PLATFORM_EXIT_MACRO)
#define mbedtls_exit   MBEDTLS_PLATFORM_EXIT_MACRO
#else
#define mbedtls_exit   exit
#endif
#endif

#if defined(MBEDTLS_PLATFORM_STD_EXIT_SUCCESS)
#define MBEDTLS_EXIT_SUCCESS MBEDTLS_PLATFORM_STD_EXIT_SUCCESS
#else
#define MBEDTLS_EXIT_SUCCESS 0
#endif
#if defined(MBEDTLS_PLATFORM_STD_EXIT_FAILURE)
#define MBEDTLS_EXIT_FAILURE MBEDTLS_PLATFORM_STD_EXIT_FAILURE
#else
#define MBEDTLS_EXIT_FAILURE 1
#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED)
#if !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS) && defined(MBEDTLS_FS_IO)

int mbedtls_platform_std_nv_seed_read(unsigned char *buf, size_t buf_len);
int mbedtls_platform_std_nv_seed_write(unsigned char *buf, size_t buf_len);
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
extern int (*mbedtls_nv_seed_read)(unsigned char *buf, size_t buf_len);
extern int (*mbedtls_nv_seed_write)(unsigned char *buf, size_t buf_len);

int mbedtls_platform_set_nv_seed(
    int (*nv_seed_read_func)(unsigned char *buf, size_t buf_len),
    int (*nv_seed_write_func)(unsigned char *buf, size_t buf_len)
    );
#else
#undef mbedtls_nv_seed_read
#undef mbedtls_nv_seed_write
#if defined(MBEDTLS_PLATFORM_NV_SEED_READ_MACRO) && \
    defined(MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO)
#define mbedtls_nv_seed_read    MBEDTLS_PLATFORM_NV_SEED_READ_MACRO
#define mbedtls_nv_seed_write   MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO
#else
#define mbedtls_nv_seed_read    mbedtls_platform_std_nv_seed_read
#define mbedtls_nv_seed_write   mbedtls_platform_std_nv_seed_write
#endif
#endif
#endif

#if !defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)

typedef struct mbedtls_platform_context {
    char MBEDTLS_PRIVATE(dummy);
}
mbedtls_platform_context;

#else
#include "platform_alt.h"
#endif

int mbedtls_platform_setup(mbedtls_platform_context *ctx);

void mbedtls_platform_teardown(mbedtls_platform_context *ctx);

#ifdef __cplusplus
}
#endif

#endif
