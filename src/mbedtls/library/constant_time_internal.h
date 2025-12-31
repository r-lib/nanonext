/**
 *  Constant-time functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef MBEDTLS_CONSTANT_TIME_INTERNAL_H
#define MBEDTLS_CONSTANT_TIME_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

#include "common.h"

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if (SIZE_MAX > 0xffffffffffffffffULL)

typedef size_t    mbedtls_ct_condition_t;
typedef size_t    mbedtls_ct_uint_t;
typedef ptrdiff_t mbedtls_ct_int_t;
#define MBEDTLS_CT_TRUE  ((mbedtls_ct_condition_t) mbedtls_ct_compiler_opaque(SIZE_MAX))
#elif (SIZE_MAX > 0xffffffff) || defined(MBEDTLS_HAVE_INT64)

typedef uint64_t  mbedtls_ct_condition_t;
typedef uint64_t  mbedtls_ct_uint_t;
typedef int64_t   mbedtls_ct_int_t;
#define MBEDTLS_CT_SIZE_64
#define MBEDTLS_CT_TRUE  ((mbedtls_ct_condition_t) mbedtls_ct_compiler_opaque(UINT64_MAX))
#else

typedef uint32_t  mbedtls_ct_condition_t;
typedef uint32_t  mbedtls_ct_uint_t;
typedef int32_t   mbedtls_ct_int_t;
#define MBEDTLS_CT_SIZE_32
#define MBEDTLS_CT_TRUE  ((mbedtls_ct_condition_t) mbedtls_ct_compiler_opaque(UINT32_MAX))
#endif
#define MBEDTLS_CT_FALSE ((mbedtls_ct_condition_t) mbedtls_ct_compiler_opaque(0))

static inline mbedtls_ct_condition_t mbedtls_ct_bool(mbedtls_ct_uint_t x);

static inline mbedtls_ct_condition_t mbedtls_ct_uint_ne(mbedtls_ct_uint_t x, mbedtls_ct_uint_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_uint_eq(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_uint_lt(mbedtls_ct_uint_t x, mbedtls_ct_uint_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_uint_gt(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_uint_ge(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_uint_le(mbedtls_ct_uint_t x,
                                                        mbedtls_ct_uint_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_bool_ne(mbedtls_ct_condition_t x,
                                                        mbedtls_ct_condition_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_bool_and(mbedtls_ct_condition_t x,
                                                         mbedtls_ct_condition_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_bool_or(mbedtls_ct_condition_t x,
                                                        mbedtls_ct_condition_t y);

static inline mbedtls_ct_condition_t mbedtls_ct_bool_not(mbedtls_ct_condition_t x);

static inline size_t mbedtls_ct_size_if(mbedtls_ct_condition_t condition,
                                        size_t if1,
                                        size_t if0);

static inline unsigned mbedtls_ct_uint_if(mbedtls_ct_condition_t condition,
                                          unsigned if1,
                                          unsigned if0);

static inline mbedtls_ct_condition_t mbedtls_ct_bool_if(mbedtls_ct_condition_t condition,
                                                        mbedtls_ct_condition_t if1,
                                                        mbedtls_ct_condition_t if0);

#if defined(MBEDTLS_BIGNUM_C)

static inline mbedtls_mpi_uint mbedtls_ct_mpi_uint_if(mbedtls_ct_condition_t condition, \
                                                      mbedtls_mpi_uint if1, \
                                                      mbedtls_mpi_uint if0);

#endif

static inline unsigned mbedtls_ct_uint_if_else_0(mbedtls_ct_condition_t condition, unsigned if1);

static inline mbedtls_ct_condition_t mbedtls_ct_bool_if_else_0(mbedtls_ct_condition_t condition,
                                                               mbedtls_ct_condition_t if1);

static inline size_t mbedtls_ct_size_if_else_0(mbedtls_ct_condition_t condition, size_t if1);

#if defined(MBEDTLS_BIGNUM_C)

static inline mbedtls_mpi_uint mbedtls_ct_mpi_uint_if_else_0(mbedtls_ct_condition_t condition,
                                                             mbedtls_mpi_uint if1);

#endif

static inline unsigned char mbedtls_ct_uchar_in_range_if(unsigned char low,
                                                         unsigned char high,
                                                         unsigned char c,
                                                         unsigned char t);

static inline int mbedtls_ct_error_if(mbedtls_ct_condition_t condition, int if1, int if0);

static inline int mbedtls_ct_error_if_else_0(mbedtls_ct_condition_t condition, int if1);

#if defined(MBEDTLS_PKCS1_V15) && defined(MBEDTLS_RSA_C) && !defined(MBEDTLS_RSA_ALT)

void mbedtls_ct_zeroize_if(mbedtls_ct_condition_t condition, void *buf, size_t len);

void mbedtls_ct_memmove_left(void *start,
                             size_t total,
                             size_t offset);

#endif

void mbedtls_ct_memcpy_if(mbedtls_ct_condition_t condition,
                          unsigned char *dest,
                          const unsigned char *src1,
                          const unsigned char *src2,
                          size_t len
                          );

void mbedtls_ct_memcpy_offset(unsigned char *dest,
                              const unsigned char *src,
                              size_t offset,
                              size_t offset_min,
                              size_t offset_max,
                              size_t len);

#if defined(MBEDTLS_NIST_KW_C)

int mbedtls_ct_memcmp_partial(const void *a,
                              const void *b,
                              size_t n,
                              size_t skip_head,
                              size_t skip_tail);

#endif

#include "constant_time_impl.h"

#endif
