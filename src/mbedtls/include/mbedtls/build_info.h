/**
 * \file mbedtls/build_info.h
 *
 * \brief Build-time configuration info
 *
 *  Include this file if you need to depend on the
 *  configuration options defined in mbedtls_config.h or MBEDTLS_CONFIG_FILE
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_BUILD_INFO_H
#define MBEDTLS_BUILD_INFO_H 
#define MBEDTLS_VERSION_MAJOR 3
#define MBEDTLS_VERSION_MINOR 6
#define MBEDTLS_VERSION_PATCH 2
#define MBEDTLS_VERSION_NUMBER 0x03060200
#define MBEDTLS_VERSION_STRING "3.6.2"
#define MBEDTLS_VERSION_STRING_FULL "Mbed TLS 3.6.2"
#if !defined(MBEDTLS_ARCH_IS_ARM64) && \
    (defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC))
#define MBEDTLS_ARCH_IS_ARM64 
#endif
#if !defined(MBEDTLS_ARCH_IS_ARM32) && \
    (defined(__arm__) || defined(_M_ARM) || \
    defined(_M_ARMT) || defined(__thumb__) || defined(__thumb2__))
#define MBEDTLS_ARCH_IS_ARM32 
#endif
#if !defined(MBEDTLS_ARCH_IS_X64) && \
    (defined(__amd64__) || defined(__x86_64__) || \
    ((defined(_M_X64) || defined(_M_AMD64)) && !defined(_M_ARM64EC)))
#define MBEDTLS_ARCH_IS_X64 
#endif
#if !defined(MBEDTLS_ARCH_IS_X86) && \
    (defined(__i386__) || defined(_X86_) || \
    (defined(_M_IX86) && !defined(_M_I86)))
#define MBEDTLS_ARCH_IS_X86 
#endif
#if !defined(MBEDTLS_PLATFORM_IS_WINDOWS_ON_ARM64) && \
    (defined(_M_ARM64) || defined(_M_ARM64EC))
#define MBEDTLS_PLATFORM_IS_WINDOWS_ON_ARM64 
#endif
#if !defined(MBEDTLS_ARCH_IS_ARMV8_A)
#if defined(__ARM_ARCH) && defined(__ARM_ARCH_PROFILE)
#if (__ARM_ARCH >= 8) && (__ARM_ARCH_PROFILE == 'A')
#define MBEDTLS_ARCH_IS_ARMV8_A 
#endif
#elif defined(__ARM_ARCH_8A)
#define MBEDTLS_ARCH_IS_ARMV8_A 
#elif defined(_M_ARM64) || defined(_M_ARM64EC)
#define MBEDTLS_ARCH_IS_ARMV8_A 
#endif
#endif
#if defined(__GNUC__) && !defined(__ARMCC_VERSION) && !defined(__clang__) \
    && !defined(__llvm__) && !defined(__INTEL_COMPILER)
#define MBEDTLS_COMPILER_IS_GCC 
#define MBEDTLS_GCC_VERSION \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#endif
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif
#if (defined(__ARMCC_VERSION) || defined(_MSC_VER)) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif
#if defined(MBEDTLS_CONFIG_FILES_READ)
#error "Something went wrong: MBEDTLS_CONFIG_FILES_READ defined before reading the config files!"
#endif
#if defined(MBEDTLS_CONFIG_IS_FINALIZED)
#error "Something went wrong: MBEDTLS_CONFIG_IS_FINALIZED defined before reading the config files!"
#endif
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_CONFIG_VERSION) && ( \
    MBEDTLS_CONFIG_VERSION < 0x03000000 || \
                             MBEDTLS_CONFIG_VERSION > MBEDTLS_VERSION_NUMBER)
#error "Invalid config version, defined value of MBEDTLS_CONFIG_VERSION is unsupported"
#endif
#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_CONFIG_FILE
#else
#include "psa/crypto_config.h"
#endif
#if defined(MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE)
#include MBEDTLS_PSA_CRYPTO_USER_CONFIG_FILE
#endif
#endif
#define MBEDTLS_CONFIG_FILES_READ 
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH) && defined(MBEDTLS_CTR_DRBG_C)
#define MBEDTLS_CTR_DRBG_USE_128_BIT_KEY 
#endif
#if defined(MBEDTLS_PKCS5_C)
#define MBEDTLS_MD_C 
#endif
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG) || \
    defined(MBEDTLS_PSA_CRYPTO_C) || \
    defined(MBEDTLS_PSA_CRYPTO_CLIENT)
#include "mbedtls/config_psa.h"
#endif
#include "mbedtls/config_adjust_legacy_crypto.h"
#include "mbedtls/config_adjust_x509.h"
#include "mbedtls/config_adjust_ssl.h"
#define MBEDTLS_CONFIG_IS_FINALIZED 
#include "mbedtls/check_config.h"
#endif
