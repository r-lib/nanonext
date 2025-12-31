/*
 *  Platform abstraction layer
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_PLATFORM_C)

#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_PLATFORM_MEMORY) &&                 \
    !(defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&        \
    defined(MBEDTLS_PLATFORM_FREE_MACRO))

#if !defined(MBEDTLS_PLATFORM_STD_CALLOC)
static void *platform_calloc_uninit(size_t n, size_t size)
{
    ((void) n);
    ((void) size);
    return NULL;
}

#define MBEDTLS_PLATFORM_STD_CALLOC   platform_calloc_uninit
#endif

#if !defined(MBEDTLS_PLATFORM_STD_FREE)
static void platform_free_uninit(void *ptr)
{
    ((void) ptr);
}

#define MBEDTLS_PLATFORM_STD_FREE     platform_free_uninit
#endif

static void * (*mbedtls_calloc_func)(size_t, size_t) = MBEDTLS_PLATFORM_STD_CALLOC;
static void (*mbedtls_free_func)(void *) = MBEDTLS_PLATFORM_STD_FREE;

void *mbedtls_calloc(size_t nmemb, size_t size)
{
    return (*mbedtls_calloc_func)(nmemb, size);
}

void mbedtls_free(void *ptr)
{
    (*mbedtls_free_func)(ptr);
}

int mbedtls_platform_set_calloc_free(void *(*calloc_func)(size_t, size_t),
                                     void (*free_func)(void *))
{
    mbedtls_calloc_func = calloc_func;
    mbedtls_free_func = free_func;
    return 0;
}
#endif

#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)
#include <stdarg.h>
int mbedtls_platform_win32_snprintf(char *s, size_t n, const char *fmt, ...)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    va_list argp;

    va_start(argp, fmt);
    ret = mbedtls_vsnprintf(s, n, fmt, argp);
    va_end(argp);

    return ret;
}
#endif

#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_SNPRINTF)

static int platform_snprintf_uninit(char *s, size_t n,
                                    const char *format, ...)
{
    ((void) s);
    ((void) n);
    ((void) format);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_SNPRINTF    platform_snprintf_uninit
#endif

int (*mbedtls_snprintf)(char *s, size_t n,
                        const char *format,
                        ...) = MBEDTLS_PLATFORM_STD_SNPRINTF;

int mbedtls_platform_set_snprintf(int (*snprintf_func)(char *s, size_t n,
                                                       const char *format,
                                                       ...))
{
    mbedtls_snprintf = snprintf_func;
    return 0;
}
#endif

#if defined(MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#include <stdarg.h>
int mbedtls_platform_win32_vsnprintf(char *s, size_t n, const char *fmt, va_list arg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (s == NULL || n == 0 || fmt == NULL) {
        return -1;
    }

#if defined(_TRUNCATE)
    ret = vsnprintf_s(s, n, _TRUNCATE, fmt, arg);
#else
    ret = vsnprintf(s, n, fmt, arg);
    if (ret < 0 || (size_t) ret == n) {
        s[n-1] = '\0';
        ret = -1;
    }
#endif

    return ret;
}
#endif

#if defined(MBEDTLS_PLATFORM_VSNPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_VSNPRINTF)

static int platform_vsnprintf_uninit(char *s, size_t n,
                                     const char *format, va_list arg)
{
    ((void) s);
    ((void) n);
    ((void) format);
    ((void) arg);
    return -1;
}

#define MBEDTLS_PLATFORM_STD_VSNPRINTF    platform_vsnprintf_uninit
#endif

int (*mbedtls_vsnprintf)(char *s, size_t n,
                         const char *format,
                         va_list arg) = MBEDTLS_PLATFORM_STD_VSNPRINTF;

int mbedtls_platform_set_vsnprintf(int (*vsnprintf_func)(char *s, size_t n,
                                                         const char *format,
                                                         va_list arg))
{
    mbedtls_vsnprintf = vsnprintf_func;
    return 0;
}
#endif

#if defined(MBEDTLS_PLATFORM_PRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_PRINTF)

static int platform_printf_uninit(const char *format, ...)
{
    ((void) format);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_PRINTF    platform_printf_uninit
#endif

int (*mbedtls_printf)(const char *, ...) = MBEDTLS_PLATFORM_STD_PRINTF;

int mbedtls_platform_set_printf(int (*printf_func)(const char *, ...))
{
    mbedtls_printf = printf_func;
    return 0;
}
#endif

#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_FPRINTF)

static int platform_fprintf_uninit(FILE *stream, const char *format, ...)
{
    ((void) stream);
    ((void) format);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_FPRINTF   platform_fprintf_uninit
#endif

int (*mbedtls_fprintf)(FILE *, const char *, ...) =
    MBEDTLS_PLATFORM_STD_FPRINTF;

int mbedtls_platform_set_fprintf(int (*fprintf_func)(FILE *, const char *, ...))
{
    mbedtls_fprintf = fprintf_func;
    return 0;
}
#endif

#if defined(MBEDTLS_PLATFORM_SETBUF_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_SETBUF)

static void platform_setbuf_uninit(FILE *stream, char *buf)
{
    ((void) stream);
    ((void) buf);
}

#define MBEDTLS_PLATFORM_STD_SETBUF   platform_setbuf_uninit
#endif
void (*mbedtls_setbuf)(FILE *stream, char *buf) = MBEDTLS_PLATFORM_STD_SETBUF;

int mbedtls_platform_set_setbuf(void (*setbuf_func)(FILE *stream, char *buf))
{
    mbedtls_setbuf = setbuf_func;
    return 0;
}
#endif

#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_EXIT)

static void platform_exit_uninit(int status)
{
    ((void) status);
}

#define MBEDTLS_PLATFORM_STD_EXIT   platform_exit_uninit
#endif

void (*mbedtls_exit)(int status) = MBEDTLS_PLATFORM_STD_EXIT;

int mbedtls_platform_set_exit(void (*exit_func)(int status))
{
    mbedtls_exit = exit_func;
    return 0;
}
#endif

#if defined(MBEDTLS_HAVE_TIME)

#if defined(MBEDTLS_PLATFORM_TIME_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_TIME)

static mbedtls_time_t platform_time_uninit(mbedtls_time_t *timer)
{
    ((void) timer);
    return 0;
}

#define MBEDTLS_PLATFORM_STD_TIME   platform_time_uninit
#endif

mbedtls_time_t (*mbedtls_time)(mbedtls_time_t *timer) = MBEDTLS_PLATFORM_STD_TIME;

int mbedtls_platform_set_time(mbedtls_time_t (*time_func)(mbedtls_time_t *timer))
{
    mbedtls_time = time_func;
    return 0;
}
#endif

#endif

#if defined(MBEDTLS_ENTROPY_NV_SEED)
#if !defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS) && defined(MBEDTLS_FS_IO)

int mbedtls_platform_std_nv_seed_read(unsigned char *buf, size_t buf_len)
{
    FILE *file;
    size_t n;

    if ((file = fopen(MBEDTLS_PLATFORM_STD_NV_SEED_FILE, "rb")) == NULL) {
        return -1;
    }

    mbedtls_setbuf(file, NULL);

    if ((n = fread(buf, 1, buf_len, file)) != buf_len) {
        fclose(file);
        mbedtls_platform_zeroize(buf, buf_len);
        return -1;
    }

    fclose(file);
    return (int) n;
}

int mbedtls_platform_std_nv_seed_write(unsigned char *buf, size_t buf_len)
{
    FILE *file;
    size_t n;

    if ((file = fopen(MBEDTLS_PLATFORM_STD_NV_SEED_FILE, "w")) == NULL) {
        return -1;
    }

    mbedtls_setbuf(file, NULL);

    if ((n = fwrite(buf, 1, buf_len, file)) != buf_len) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return (int) n;
}
#endif

#if defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
#if !defined(MBEDTLS_PLATFORM_STD_NV_SEED_READ)

static int platform_nv_seed_read_uninit(unsigned char *buf, size_t buf_len)
{
    ((void) buf);
    ((void) buf_len);
    return -1;
}

#define MBEDTLS_PLATFORM_STD_NV_SEED_READ   platform_nv_seed_read_uninit
#endif

#if !defined(MBEDTLS_PLATFORM_STD_NV_SEED_WRITE)

static int platform_nv_seed_write_uninit(unsigned char *buf, size_t buf_len)
{
    ((void) buf);
    ((void) buf_len);
    return -1;
}

#define MBEDTLS_PLATFORM_STD_NV_SEED_WRITE   platform_nv_seed_write_uninit
#endif

int (*mbedtls_nv_seed_read)(unsigned char *buf, size_t buf_len) =
    MBEDTLS_PLATFORM_STD_NV_SEED_READ;
int (*mbedtls_nv_seed_write)(unsigned char *buf, size_t buf_len) =
    MBEDTLS_PLATFORM_STD_NV_SEED_WRITE;

int mbedtls_platform_set_nv_seed(
    int (*nv_seed_read_func)(unsigned char *buf, size_t buf_len),
    int (*nv_seed_write_func)(unsigned char *buf, size_t buf_len))
{
    mbedtls_nv_seed_read = nv_seed_read_func;
    mbedtls_nv_seed_write = nv_seed_write_func;
    return 0;
}
#endif
#endif

#if !defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)

int mbedtls_platform_setup(mbedtls_platform_context *ctx)
{
    (void) ctx;

    return 0;
}

void mbedtls_platform_teardown(mbedtls_platform_context *ctx)
{
    (void) ctx;
}
#endif

#endif
