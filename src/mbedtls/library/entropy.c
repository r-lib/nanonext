/*
 *  Entropy accumulator implementation
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_ENTROPY_C)

#include "mbedtls/entropy.h"
#include "entropy_poll.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_FS_IO)
#include <stdio.h>
#endif

#include "mbedtls/platform.h"

#define ENTROPY_MAX_LOOP    256

void mbedtls_entropy_init(mbedtls_entropy_context *ctx)
{
    ctx->source_count = 0;
    memset(ctx->source, 0, sizeof(ctx->source));

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init(&ctx->mutex);
#endif

    ctx->accumulator_started = 0;
    mbedtls_md_init(&ctx->accumulator);

#if !defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)
    mbedtls_entropy_add_source(ctx, mbedtls_platform_entropy_poll, NULL,
                               MBEDTLS_ENTROPY_MIN_PLATFORM,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif
#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
    mbedtls_entropy_add_source(ctx, mbedtls_hardware_poll, NULL,
                               MBEDTLS_ENTROPY_MIN_HARDWARE,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
#endif
#if defined(MBEDTLS_ENTROPY_NV_SEED)
    mbedtls_entropy_add_source(ctx, mbedtls_nv_seed_poll, NULL,
                               MBEDTLS_ENTROPY_BLOCK_SIZE,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
    ctx->initial_entropy_run = 0;
#endif
#endif
}

void mbedtls_entropy_free(mbedtls_entropy_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->accumulator_started == -1) {
        return;
    }

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_free(&ctx->mutex);
#endif
    mbedtls_md_free(&ctx->accumulator);
#if defined(MBEDTLS_ENTROPY_NV_SEED)
    ctx->initial_entropy_run = 0;
#endif
    ctx->source_count = 0;
    mbedtls_platform_zeroize(ctx->source, sizeof(ctx->source));
    ctx->accumulator_started = -1;
}

int mbedtls_entropy_add_source(mbedtls_entropy_context *ctx,
                               mbedtls_entropy_f_source_ptr f_source, void *p_source,
                               size_t threshold, int strong)
{
    int idx, ret = 0;

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    idx = ctx->source_count;
    if (idx >= MBEDTLS_ENTROPY_MAX_SOURCES) {
        ret = MBEDTLS_ERR_ENTROPY_MAX_SOURCES;
        goto exit;
    }

    ctx->source[idx].f_source  = f_source;
    ctx->source[idx].p_source  = p_source;
    ctx->source[idx].threshold = threshold;
    ctx->source[idx].strong    = strong;

    ctx->source_count++;

exit:
#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

static int entropy_update(mbedtls_entropy_context *ctx, unsigned char source_id,
                          const unsigned char *data, size_t len)
{
    unsigned char header[2];
    unsigned char tmp[MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = len;
    const unsigned char *p = data;
    int ret = 0;

    if (use_len > MBEDTLS_ENTROPY_BLOCK_SIZE) {
        if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_ENTROPY_MD),
                              data, len, tmp)) != 0) {
            goto cleanup;
        }
        p = tmp;
        use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = use_len & 0xFF;

    if (ctx->accumulator_started == 0) {
        ret = mbedtls_md_setup(&ctx->accumulator,
                               mbedtls_md_info_from_type(MBEDTLS_ENTROPY_MD), 0);
        if (ret != 0) {
            goto cleanup;
        }
        ret = mbedtls_md_starts(&ctx->accumulator);
        if (ret != 0) {
            goto cleanup;
        }
        ctx->accumulator_started = 1;
    }
    if ((ret = mbedtls_md_update(&ctx->accumulator, header, 2)) != 0) {
        goto cleanup;
    }
    ret = mbedtls_md_update(&ctx->accumulator, p, use_len);

cleanup:
    mbedtls_platform_zeroize(tmp, sizeof(tmp));

    return ret;
}

int mbedtls_entropy_update_manual(mbedtls_entropy_context *ctx,
                                  const unsigned char *data, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    ret = entropy_update(ctx, MBEDTLS_ENTROPY_SOURCE_MANUAL, data, len);

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

static int entropy_gather_internal(mbedtls_entropy_context *ctx)
{
    int ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    int i;
    int have_one_strong = 0;
    unsigned char buf[MBEDTLS_ENTROPY_MAX_GATHER];
    size_t olen;

    if (ctx->source_count == 0) {
        return MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED;
    }

    for (i = 0; i < ctx->source_count; i++) {
        if (ctx->source[i].strong == MBEDTLS_ENTROPY_SOURCE_STRONG) {
            have_one_strong = 1;
        }

        olen = 0;
        if ((ret = ctx->source[i].f_source(ctx->source[i].p_source,
                                           buf, MBEDTLS_ENTROPY_MAX_GATHER, &olen)) != 0) {
            goto cleanup;
        }

        if (olen > 0) {
            if ((ret = entropy_update(ctx, (unsigned char) i,
                                      buf, olen)) != 0) {
                return ret;
            }
            ctx->source[i].size += olen;
        }
    }

    if (have_one_strong == 0) {
        ret = MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE;
    }

cleanup:
    mbedtls_platform_zeroize(buf, sizeof(buf));

    return ret;
}

int mbedtls_entropy_gather(mbedtls_entropy_context *ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    ret = entropy_gather_internal(ctx);

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

int mbedtls_entropy_func(void *data, unsigned char *output, size_t len)
{
    int ret, count = 0, i, thresholds_reached;
    size_t strong_size;
    mbedtls_entropy_context *ctx = (mbedtls_entropy_context *) data;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];

    if (len > MBEDTLS_ENTROPY_BLOCK_SIZE) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

#if defined(MBEDTLS_ENTROPY_NV_SEED)

    if (ctx->initial_entropy_run == 0) {
        ctx->initial_entropy_run = 1;
        if ((ret = mbedtls_entropy_update_nv_seed(ctx)) != 0) {
            return ret;
        }
    }
#endif

#if defined(MBEDTLS_THREADING_C)
    if ((ret = mbedtls_mutex_lock(&ctx->mutex)) != 0) {
        return ret;
    }
#endif

    do {
        if (count++ > ENTROPY_MAX_LOOP) {
            ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
            goto exit;
        }

        if ((ret = entropy_gather_internal(ctx)) != 0) {
            goto exit;
        }

        thresholds_reached = 1;
        strong_size = 0;
        for (i = 0; i < ctx->source_count; i++) {
            if (ctx->source[i].size < ctx->source[i].threshold) {
                thresholds_reached = 0;
            }
            if (ctx->source[i].strong == MBEDTLS_ENTROPY_SOURCE_STRONG) {
                strong_size += ctx->source[i].size;
            }
        }
    } while (!thresholds_reached || strong_size < MBEDTLS_ENTROPY_BLOCK_SIZE);

    memset(buf, 0, MBEDTLS_ENTROPY_BLOCK_SIZE);

    if ((ret = mbedtls_md_finish(&ctx->accumulator, buf)) != 0) {
        goto exit;
    }

    mbedtls_md_free(&ctx->accumulator);
    mbedtls_md_init(&ctx->accumulator);
    ret = mbedtls_md_setup(&ctx->accumulator,
                           mbedtls_md_info_from_type(MBEDTLS_ENTROPY_MD), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_starts(&ctx->accumulator);
    if (ret != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_update(&ctx->accumulator, buf,
                                 MBEDTLS_ENTROPY_BLOCK_SIZE)) != 0) {
        goto exit;
    }

    if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_ENTROPY_MD),
                          buf, MBEDTLS_ENTROPY_BLOCK_SIZE, buf)) != 0) {
        goto exit;
    }

    for (i = 0; i < ctx->source_count; i++) {
        ctx->source[i].size = 0;
    }

    memcpy(output, buf, len);

    ret = 0;

exit:
    mbedtls_platform_zeroize(buf, sizeof(buf));

#if defined(MBEDTLS_THREADING_C)
    if (mbedtls_mutex_unlock(&ctx->mutex) != 0) {
        return MBEDTLS_ERR_THREADING_MUTEX_ERROR;
    }
#endif

    return ret;
}

#if defined(MBEDTLS_ENTROPY_NV_SEED)
int mbedtls_entropy_update_nv_seed(mbedtls_entropy_context *ctx)
{
    int ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];

    if ((ret = mbedtls_entropy_func(ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE)) != 0) {
        return ret;
    }

    if (mbedtls_nv_seed_write(buf, MBEDTLS_ENTROPY_BLOCK_SIZE) < 0) {
        return MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    }

    memset(buf, 0, MBEDTLS_ENTROPY_BLOCK_SIZE);
    ret = mbedtls_entropy_update_manual(ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE);

    return ret;
}
#endif

#if defined(MBEDTLS_FS_IO)
int mbedtls_entropy_write_seed_file(mbedtls_entropy_context *ctx, const char *path)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    FILE *f = NULL;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];

    if ((ret = mbedtls_entropy_func(ctx, buf, MBEDTLS_ENTROPY_BLOCK_SIZE)) != 0) {
        ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        goto exit;
    }

    if ((f = fopen(path, "wb")) == NULL) {
        ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
        goto exit;
    }

    mbedtls_setbuf(f, NULL);

    if (fwrite(buf, 1, MBEDTLS_ENTROPY_BLOCK_SIZE, f) != MBEDTLS_ENTROPY_BLOCK_SIZE) {
        ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
        goto exit;
    }

    ret = 0;

exit:
    mbedtls_platform_zeroize(buf, sizeof(buf));

    if (f != NULL) {
        fclose(f);
    }

    return ret;
}

int mbedtls_entropy_update_seed_file(mbedtls_entropy_context *ctx, const char *path)
{
    int ret = 0;
    FILE *f;
    size_t n;
    unsigned char buf[MBEDTLS_ENTROPY_MAX_SEED_SIZE];

    if ((f = fopen(path, "rb")) == NULL) {
        return MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    }

    mbedtls_setbuf(f, NULL);

    fseek(f, 0, SEEK_END);
    n = (size_t) ftell(f);
    fseek(f, 0, SEEK_SET);

    if (n > MBEDTLS_ENTROPY_MAX_SEED_SIZE) {
        n = MBEDTLS_ENTROPY_MAX_SEED_SIZE;
    }

    if (fread(buf, 1, n, f) != n) {
        ret = MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR;
    } else {
        ret = mbedtls_entropy_update_manual(ctx, buf, n);
    }

    fclose(f);

    mbedtls_platform_zeroize(buf, sizeof(buf));

    if (ret != 0) {
        return ret;
    }

    return mbedtls_entropy_write_seed_file(ctx, path);
}
#endif

#if defined(MBEDTLS_SELF_TEST)

static int entropy_dummy_source(void *data, unsigned char *output,
                                size_t len, size_t *olen)
{
    ((void) data);

    memset(output, 0x2a, len);
    *olen = len;

    return 0;
}

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

static int mbedtls_entropy_source_self_test_gather(unsigned char *buf, size_t buf_len)
{
    int ret = 0;
    size_t entropy_len = 0;
    size_t olen = 0;
    size_t attempts = buf_len;

    while (attempts > 0 && entropy_len < buf_len) {
        if ((ret = mbedtls_hardware_poll(NULL, buf + entropy_len,
                                         buf_len - entropy_len, &olen)) != 0) {
            return ret;
        }

        entropy_len += olen;
        attempts--;
    }

    if (entropy_len < buf_len) {
        ret = 1;
    }

    return ret;
}

static int mbedtls_entropy_source_self_test_check_bits(const unsigned char *buf,
                                                       size_t buf_len)
{
    unsigned char set = 0xFF;
    unsigned char unset = 0x00;
    size_t i;

    for (i = 0; i < buf_len; i++) {
        set &= buf[i];
        unset |= buf[i];
    }

    return set == 0xFF || unset == 0x00;
}

int mbedtls_entropy_source_self_test(int verbose)
{
    int ret = 0;
    unsigned char buf0[2 * sizeof(unsigned long long int)];
    unsigned char buf1[2 * sizeof(unsigned long long int)];

    if (verbose != 0) {
        mbedtls_printf("  ENTROPY_BIAS test: ");
    }

    memset(buf0, 0x00, sizeof(buf0));
    memset(buf1, 0x00, sizeof(buf1));

    if ((ret = mbedtls_entropy_source_self_test_gather(buf0, sizeof(buf0))) != 0) {
        goto cleanup;
    }
    if ((ret = mbedtls_entropy_source_self_test_gather(buf1, sizeof(buf1))) != 0) {
        goto cleanup;
    }

    if ((ret = mbedtls_entropy_source_self_test_check_bits(buf0, sizeof(buf0))) != 0) {
        goto cleanup;
    }
    if ((ret = mbedtls_entropy_source_self_test_check_bits(buf1, sizeof(buf1))) != 0) {
        goto cleanup;
    }

    ret = memcmp(buf0, buf1, sizeof(buf0)) == 0;

cleanup:
    if (verbose != 0) {
        if (ret != 0) {
            mbedtls_printf("failed\n");
        } else {
            mbedtls_printf("passed\n");
        }

        mbedtls_printf("\n");
    }

    return ret != 0;
}

#endif

int mbedtls_entropy_self_test(int verbose)
{
    int ret = 1;
    mbedtls_entropy_context ctx;
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE] = { 0 };
    unsigned char acc[MBEDTLS_ENTROPY_BLOCK_SIZE] = { 0 };
    size_t i, j;

    if (verbose != 0) {
        mbedtls_printf("  ENTROPY test: ");
    }

    mbedtls_entropy_init(&ctx);

    if ((ret = mbedtls_entropy_gather(&ctx)) != 0) {
        goto cleanup;
    }

    ret = mbedtls_entropy_add_source(&ctx, entropy_dummy_source, NULL, 16,
                                     MBEDTLS_ENTROPY_SOURCE_WEAK);
    if (ret != 0) {
        goto cleanup;
    }

    if ((ret = mbedtls_entropy_update_manual(&ctx, buf, sizeof(buf))) != 0) {
        goto cleanup;
    }

    for (i = 0; i < 8; i++) {
        if ((ret = mbedtls_entropy_func(&ctx, buf, sizeof(buf))) != 0) {
            goto cleanup;
        }

        for (j = 0; j < sizeof(buf); j++) {
            acc[j] |= buf[j];
        }
    }

    for (j = 0; j < sizeof(buf); j++) {
        if (acc[j] == 0) {
            ret = 1;
            goto cleanup;
        }
    }

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
    if ((ret = mbedtls_entropy_source_self_test(0)) != 0) {
        goto cleanup;
    }
#endif

cleanup:
    mbedtls_entropy_free(&ctx);

    if (verbose != 0) {
        if (ret != 0) {
            mbedtls_printf("failed\n");
        } else {
            mbedtls_printf("passed\n");
        }

        mbedtls_printf("\n");
    }

    return ret != 0;
}
#endif

#endif
