/**
 * \file md.h
 *
 * \brief   This file contains the generic functions for message-digest
 *          (hashing) and HMAC.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_MD_H
#define MBEDTLS_MD_H 
#include "mbedtls/private_access.h"
#include <stddef.h>
#include "mbedtls/build_info.h"
#include "mbedtls/platform_util.h"
#define MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE -0x5080
#define MBEDTLS_ERR_MD_BAD_INPUT_DATA -0x5100
#define MBEDTLS_ERR_MD_ALLOC_FAILED -0x5180
#define MBEDTLS_ERR_MD_FILE_IO_ERROR -0x5200
#ifdef __cplusplus
extern "C" {
#endif
typedef enum {
    MBEDTLS_MD_NONE=0,
    MBEDTLS_MD_MD5=0x03,
    MBEDTLS_MD_RIPEMD160=0x04,
    MBEDTLS_MD_SHA1=0x05,
    MBEDTLS_MD_SHA224=0x08,
    MBEDTLS_MD_SHA256=0x09,
    MBEDTLS_MD_SHA384=0x0a,
    MBEDTLS_MD_SHA512=0x0b,
    MBEDTLS_MD_SHA3_224=0x10,
    MBEDTLS_MD_SHA3_256=0x11,
    MBEDTLS_MD_SHA3_384=0x12,
    MBEDTLS_MD_SHA3_512=0x13,
} mbedtls_md_type_t;
#if defined(MBEDTLS_MD_CAN_SHA512) || defined(MBEDTLS_MD_CAN_SHA3_512)
#define MBEDTLS_MD_MAX_SIZE 64
#elif defined(MBEDTLS_MD_CAN_SHA384) || defined(MBEDTLS_MD_CAN_SHA3_384)
#define MBEDTLS_MD_MAX_SIZE 48
#elif defined(MBEDTLS_MD_CAN_SHA256) || defined(MBEDTLS_MD_CAN_SHA3_256)
#define MBEDTLS_MD_MAX_SIZE 32
#elif defined(MBEDTLS_MD_CAN_SHA224) || defined(MBEDTLS_MD_CAN_SHA3_224)
#define MBEDTLS_MD_MAX_SIZE 28
#else
#define MBEDTLS_MD_MAX_SIZE 20
#endif
#if defined(MBEDTLS_MD_CAN_SHA3_224)
#define MBEDTLS_MD_MAX_BLOCK_SIZE 144
#elif defined(MBEDTLS_MD_CAN_SHA3_256)
#define MBEDTLS_MD_MAX_BLOCK_SIZE 136
#elif defined(MBEDTLS_MD_CAN_SHA512) || defined(MBEDTLS_MD_CAN_SHA384)
#define MBEDTLS_MD_MAX_BLOCK_SIZE 128
#elif defined(MBEDTLS_MD_CAN_SHA3_384)
#define MBEDTLS_MD_MAX_BLOCK_SIZE 104
#elif defined(MBEDTLS_MD_CAN_SHA3_512)
#define MBEDTLS_MD_MAX_BLOCK_SIZE 72
#else
#define MBEDTLS_MD_MAX_BLOCK_SIZE 64
#endif
typedef struct mbedtls_md_info_t mbedtls_md_info_t;
typedef enum {
    MBEDTLS_MD_ENGINE_LEGACY = 0,
    MBEDTLS_MD_ENGINE_PSA,
} mbedtls_md_engine_t;
typedef struct mbedtls_md_context_t {
    const mbedtls_md_info_t *MBEDTLS_PRIVATE(md_info);
#if defined(MBEDTLS_MD_SOME_PSA)
    mbedtls_md_engine_t MBEDTLS_PRIVATE(engine);
#endif
    void *MBEDTLS_PRIVATE(md_ctx);
#if defined(MBEDTLS_MD_C)
    void *MBEDTLS_PRIVATE(hmac_ctx);
#endif
} mbedtls_md_context_t;
const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t md_type);
void mbedtls_md_init(mbedtls_md_context_t *ctx);
void mbedtls_md_free(mbedtls_md_context_t *ctx);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_setup(mbedtls_md_context_t *ctx, const mbedtls_md_info_t *md_info, int hmac);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_clone(mbedtls_md_context_t *dst,
                     const mbedtls_md_context_t *src);
unsigned char mbedtls_md_get_size(const mbedtls_md_info_t *md_info);
static inline unsigned char mbedtls_md_get_size_from_type(mbedtls_md_type_t md_type)
{
    return mbedtls_md_get_size(mbedtls_md_info_from_type(md_type));
}
mbedtls_md_type_t mbedtls_md_get_type(const mbedtls_md_info_t *md_info);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_starts(mbedtls_md_context_t *ctx);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_update(mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_finish(mbedtls_md_context_t *ctx, unsigned char *output);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md(const mbedtls_md_info_t *md_info, const unsigned char *input, size_t ilen,
               unsigned char *output);
const int *mbedtls_md_list(void);
const mbedtls_md_info_t *mbedtls_md_info_from_string(const char *md_name);
const char *mbedtls_md_get_name(const mbedtls_md_info_t *md_info);
const mbedtls_md_info_t *mbedtls_md_info_from_ctx(
    const mbedtls_md_context_t *ctx);
#if defined(MBEDTLS_FS_IO)
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_file(const mbedtls_md_info_t *md_info, const char *path,
                    unsigned char *output);
#endif
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_hmac_starts(mbedtls_md_context_t *ctx, const unsigned char *key,
                           size_t keylen);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_hmac_update(mbedtls_md_context_t *ctx, const unsigned char *input,
                           size_t ilen);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_hmac_finish(mbedtls_md_context_t *ctx, unsigned char *output);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_hmac_reset(mbedtls_md_context_t *ctx);
MBEDTLS_CHECK_RETURN_TYPICAL
int mbedtls_md_hmac(const mbedtls_md_info_t *md_info, const unsigned char *key, size_t keylen,
                    const unsigned char *input, size_t ilen,
                    unsigned char *output);
#ifdef __cplusplus
}
#endif
#endif
