/*
 *  Version feature information
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"
#if defined(MBEDTLS_VERSION_C)
#include "mbedtls/version.h"
#include <string.h>
static const char * const features[] = {
#if defined(MBEDTLS_VERSION_FEATURES)
    #if defined(MBEDTLS_HAVE_ASM)
    "HAVE_ASM",
#endif
#if defined(MBEDTLS_NO_UDBL_DIVISION)
    "NO_UDBL_DIVISION",
#endif
#if defined(MBEDTLS_NO_64BIT_MULTIPLICATION)
    "NO_64BIT_MULTIPLICATION",
#endif
#if defined(MBEDTLS_HAVE_SSE2)
    "HAVE_SSE2",
#endif
#if defined(MBEDTLS_HAVE_TIME)
    "HAVE_TIME",
#endif
#if defined(MBEDTLS_HAVE_TIME_DATE)
    "HAVE_TIME_DATE",
#endif
#if defined(MBEDTLS_PLATFORM_MEMORY)
    "PLATFORM_MEMORY",
#endif
#if defined(MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
    "PLATFORM_NO_STD_FUNCTIONS",
#endif
#if defined(MBEDTLS_PLATFORM_SETBUF_ALT)
    "PLATFORM_SETBUF_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
    "PLATFORM_EXIT_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_TIME_ALT)
    "PLATFORM_TIME_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_FPRINTF_ALT)
    "PLATFORM_FPRINTF_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_PRINTF_ALT)
    "PLATFORM_PRINTF_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_SNPRINTF_ALT)
    "PLATFORM_SNPRINTF_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_VSNPRINTF_ALT)
    "PLATFORM_VSNPRINTF_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
    "PLATFORM_NV_SEED_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)
    "PLATFORM_SETUP_TEARDOWN_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_MS_TIME_ALT)
    "PLATFORM_MS_TIME_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)
    "PLATFORM_GMTIME_R_ALT",
#endif
#if defined(MBEDTLS_PLATFORM_ZEROIZE_ALT)
    "PLATFORM_ZEROIZE_ALT",
#endif
#if defined(MBEDTLS_DEPRECATED_WARNING)
    "DEPRECATED_WARNING",
#endif
#if defined(MBEDTLS_DEPRECATED_REMOVED)
    "DEPRECATED_REMOVED",
#endif
#if defined(MBEDTLS_TIMING_ALT)
    "TIMING_ALT",
#endif
#if defined(MBEDTLS_AES_ALT)
    "AES_ALT",
#endif
#if defined(MBEDTLS_ARIA_ALT)
    "ARIA_ALT",
#endif
#if defined(MBEDTLS_CAMELLIA_ALT)
    "CAMELLIA_ALT",
#endif
#if defined(MBEDTLS_CCM_ALT)
    "CCM_ALT",
#endif
#if defined(MBEDTLS_CHACHA20_ALT)
    "CHACHA20_ALT",
#endif
#if defined(MBEDTLS_CHACHAPOLY_ALT)
    "CHACHAPOLY_ALT",
#endif
#if defined(MBEDTLS_CMAC_ALT)
    "CMAC_ALT",
#endif
#if defined(MBEDTLS_DES_ALT)
    "DES_ALT",
#endif
#if defined(MBEDTLS_DHM_ALT)
    "DHM_ALT",
#endif
#if defined(MBEDTLS_ECJPAKE_ALT)
    "ECJPAKE_ALT",
#endif
#if defined(MBEDTLS_GCM_ALT)
    "GCM_ALT",
#endif
#if defined(MBEDTLS_NIST_KW_ALT)
    "NIST_KW_ALT",
#endif
#if defined(MBEDTLS_MD5_ALT)
    "MD5_ALT",
#endif
#if defined(MBEDTLS_POLY1305_ALT)
    "POLY1305_ALT",
#endif
#if defined(MBEDTLS_RIPEMD160_ALT)
    "RIPEMD160_ALT",
#endif
#if defined(MBEDTLS_RSA_ALT)
    "RSA_ALT",
#endif
#if defined(MBEDTLS_SHA1_ALT)
    "SHA1_ALT",
#endif
#if defined(MBEDTLS_SHA256_ALT)
    "SHA256_ALT",
#endif
#if defined(MBEDTLS_SHA512_ALT)
    "SHA512_ALT",
#endif
#if defined(MBEDTLS_ECP_ALT)
    "ECP_ALT",
#endif
#if defined(MBEDTLS_MD5_PROCESS_ALT)
    "MD5_PROCESS_ALT",
#endif
#if defined(MBEDTLS_RIPEMD160_PROCESS_ALT)
    "RIPEMD160_PROCESS_ALT",
#endif
#if defined(MBEDTLS_SHA1_PROCESS_ALT)
    "SHA1_PROCESS_ALT",
#endif
#if defined(MBEDTLS_SHA256_PROCESS_ALT)
    "SHA256_PROCESS_ALT",
#endif
#if defined(MBEDTLS_SHA512_PROCESS_ALT)
    "SHA512_PROCESS_ALT",
#endif
#if defined(MBEDTLS_DES_SETKEY_ALT)
    "DES_SETKEY_ALT",
#endif
#if defined(MBEDTLS_DES_CRYPT_ECB_ALT)
    "DES_CRYPT_ECB_ALT",
#endif
#if defined(MBEDTLS_DES3_CRYPT_ECB_ALT)
    "DES3_CRYPT_ECB_ALT",
#endif
#if defined(MBEDTLS_AES_SETKEY_ENC_ALT)
    "AES_SETKEY_ENC_ALT",
#endif
#if defined(MBEDTLS_AES_SETKEY_DEC_ALT)
    "AES_SETKEY_DEC_ALT",
#endif
#if defined(MBEDTLS_AES_ENCRYPT_ALT)
    "AES_ENCRYPT_ALT",
#endif
#if defined(MBEDTLS_AES_DECRYPT_ALT)
    "AES_DECRYPT_ALT",
#endif
#if defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
    "ECDH_GEN_PUBLIC_ALT",
#endif
#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
    "ECDH_COMPUTE_SHARED_ALT",
#endif
#if defined(MBEDTLS_ECDSA_VERIFY_ALT)
    "ECDSA_VERIFY_ALT",
#endif
#if defined(MBEDTLS_ECDSA_SIGN_ALT)
    "ECDSA_SIGN_ALT",
#endif
#if defined(MBEDTLS_ECDSA_GENKEY_ALT)
    "ECDSA_GENKEY_ALT",
#endif
#if defined(MBEDTLS_ECP_INTERNAL_ALT)
    "ECP_INTERNAL_ALT",
#endif
#if defined(MBEDTLS_ECP_NO_FALLBACK)
    "ECP_NO_FALLBACK",
#endif
#if defined(MBEDTLS_ECP_RANDOMIZE_JAC_ALT)
    "ECP_RANDOMIZE_JAC_ALT",
#endif
#if defined(MBEDTLS_ECP_ADD_MIXED_ALT)
    "ECP_ADD_MIXED_ALT",
#endif
#if defined(MBEDTLS_ECP_DOUBLE_JAC_ALT)
    "ECP_DOUBLE_JAC_ALT",
#endif
#if defined(MBEDTLS_ECP_NORMALIZE_JAC_MANY_ALT)
    "ECP_NORMALIZE_JAC_MANY_ALT",
#endif
#if defined(MBEDTLS_ECP_NORMALIZE_JAC_ALT)
    "ECP_NORMALIZE_JAC_ALT",
#endif
#if defined(MBEDTLS_ECP_DOUBLE_ADD_MXZ_ALT)
    "ECP_DOUBLE_ADD_MXZ_ALT",
#endif
#if defined(MBEDTLS_ECP_RANDOMIZE_MXZ_ALT)
    "ECP_RANDOMIZE_MXZ_ALT",
#endif
#if defined(MBEDTLS_ECP_NORMALIZE_MXZ_ALT)
    "ECP_NORMALIZE_MXZ_ALT",
#endif
#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)
    "ENTROPY_HARDWARE_ALT",
#endif
#if defined(MBEDTLS_AES_ROM_TABLES)
    "AES_ROM_TABLES",
#endif
#if defined(MBEDTLS_AES_FEWER_TABLES)
    "AES_FEWER_TABLES",
#endif
#if defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    "AES_ONLY_128_BIT_KEY_LENGTH",
#endif
#if defined(MBEDTLS_AES_USE_HARDWARE_ONLY)
    "AES_USE_HARDWARE_ONLY",
#endif
#if defined(MBEDTLS_CAMELLIA_SMALL_MEMORY)
    "CAMELLIA_SMALL_MEMORY",
#endif
#if defined(MBEDTLS_CHECK_RETURN_WARNING)
    "CHECK_RETURN_WARNING",
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    "CIPHER_MODE_CBC",
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    "CIPHER_MODE_CFB",
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    "CIPHER_MODE_CTR",
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    "CIPHER_MODE_OFB",
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    "CIPHER_MODE_XTS",
#endif
#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
    "CIPHER_NULL_CIPHER",
#endif
#if defined(MBEDTLS_CIPHER_PADDING_PKCS7)
    "CIPHER_PADDING_PKCS7",
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS)
    "CIPHER_PADDING_ONE_AND_ZEROS",
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN)
    "CIPHER_PADDING_ZEROS_AND_LEN",
#endif
#if defined(MBEDTLS_CIPHER_PADDING_ZEROS)
    "CIPHER_PADDING_ZEROS",
#endif
#if defined(MBEDTLS_CTR_DRBG_USE_128_BIT_KEY)
    "CTR_DRBG_USE_128_BIT_KEY",
#endif
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
    "ECDH_VARIANT_EVEREST_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
    "ECP_DP_SECP192R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
    "ECP_DP_SECP224R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    "ECP_DP_SECP256R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
    "ECP_DP_SECP384R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
    "ECP_DP_SECP521R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
    "ECP_DP_SECP192K1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
    "ECP_DP_SECP224K1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    "ECP_DP_SECP256K1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    "ECP_DP_BP256R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
    "ECP_DP_BP384R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
    "ECP_DP_BP512R1_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
    "ECP_DP_CURVE25519_ENABLED",
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED)
    "ECP_DP_CURVE448_ENABLED",
#endif
#if defined(MBEDTLS_ECP_NIST_OPTIM)
    "ECP_NIST_OPTIM",
#endif
#if defined(MBEDTLS_ECP_RESTARTABLE)
    "ECP_RESTARTABLE",
#endif
#if defined(MBEDTLS_ECP_WITH_MPI_UINT)
    "ECP_WITH_MPI_UINT",
#endif
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
    "ECDSA_DETERMINISTIC",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    "KEY_EXCHANGE_PSK_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    "KEY_EXCHANGE_DHE_PSK_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    "KEY_EXCHANGE_ECDHE_PSK_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    "KEY_EXCHANGE_RSA_PSK_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)
    "KEY_EXCHANGE_RSA_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
    "KEY_EXCHANGE_DHE_RSA_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)
    "KEY_EXCHANGE_ECDHE_RSA_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
    "KEY_EXCHANGE_ECDHE_ECDSA_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
    "KEY_EXCHANGE_ECDH_ECDSA_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)
    "KEY_EXCHANGE_ECDH_RSA_ENABLED",
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    "KEY_EXCHANGE_ECJPAKE_ENABLED",
#endif
#if defined(MBEDTLS_PK_PARSE_EC_EXTENDED)
    "PK_PARSE_EC_EXTENDED",
#endif
#if defined(MBEDTLS_PK_PARSE_EC_COMPRESSED)
    "PK_PARSE_EC_COMPRESSED",
#endif
#if defined(MBEDTLS_ERROR_STRERROR_DUMMY)
    "ERROR_STRERROR_DUMMY",
#endif
#if defined(MBEDTLS_GENPRIME)
    "GENPRIME",
#endif
#if defined(MBEDTLS_FS_IO)
    "FS_IO",
#endif
#if defined(MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES)
    "NO_DEFAULT_ENTROPY_SOURCES",
#endif
#if defined(MBEDTLS_NO_PLATFORM_ENTROPY)
    "NO_PLATFORM_ENTROPY",
#endif
#if defined(MBEDTLS_ENTROPY_FORCE_SHA256)
    "ENTROPY_FORCE_SHA256",
#endif
#if defined(MBEDTLS_ENTROPY_NV_SEED)
    "ENTROPY_NV_SEED",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
    "PSA_CRYPTO_KEY_ID_ENCODES_OWNER",
#endif
#if defined(MBEDTLS_MEMORY_DEBUG)
    "MEMORY_DEBUG",
#endif
#if defined(MBEDTLS_MEMORY_BACKTRACE)
    "MEMORY_BACKTRACE",
#endif
#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
    "PK_RSA_ALT_SUPPORT",
#endif
#if defined(MBEDTLS_PKCS1_V15)
    "PKCS1_V15",
#endif
#if defined(MBEDTLS_PKCS1_V21)
    "PKCS1_V21",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    "PSA_CRYPTO_BUILTIN_KEYS",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_CLIENT)
    "PSA_CRYPTO_CLIENT",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
    "PSA_CRYPTO_EXTERNAL_RNG",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_SPM)
    "PSA_CRYPTO_SPM",
#endif
#if defined(MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    "PSA_KEY_STORE_DYNAMIC",
#endif
#if defined(MBEDTLS_PSA_P256M_DRIVER_ENABLED)
    "PSA_P256M_DRIVER_ENABLED",
#endif
#if defined(MBEDTLS_PSA_INJECT_ENTROPY)
    "PSA_INJECT_ENTROPY",
#endif
#if defined(MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
    "PSA_ASSUME_EXCLUSIVE_BUFFERS",
#endif
#if defined(MBEDTLS_RSA_NO_CRT)
    "RSA_NO_CRT",
#endif
#if defined(MBEDTLS_SELF_TEST)
    "SELF_TEST",
#endif
#if defined(MBEDTLS_SHA256_SMALLER)
    "SHA256_SMALLER",
#endif
#if defined(MBEDTLS_SHA512_SMALLER)
    "SHA512_SMALLER",
#endif
#if defined(MBEDTLS_SSL_ALL_ALERT_MESSAGES)
    "SSL_ALL_ALERT_MESSAGES",
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    "SSL_DTLS_CONNECTION_ID",
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT)
    "SSL_DTLS_CONNECTION_ID_COMPAT",
#endif
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    "SSL_ASYNC_PRIVATE",
#endif
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    "SSL_CONTEXT_SERIALIZATION",
#endif
#if defined(MBEDTLS_SSL_DEBUG_ALL)
    "SSL_DEBUG_ALL",
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    "SSL_ENCRYPT_THEN_MAC",
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    "SSL_EXTENDED_MASTER_SECRET",
#endif
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    "SSL_KEEP_PEER_CERTIFICATE",
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    "SSL_RENEGOTIATION",
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    "SSL_MAX_FRAGMENT_LENGTH",
#endif
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    "SSL_RECORD_SIZE_LIMIT",
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    "SSL_PROTO_TLS1_2",
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    "SSL_PROTO_TLS1_3",
#endif
#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)
    "SSL_TLS1_3_COMPATIBILITY_MODE",
#endif
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED)
    "SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED",
#endif
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    "SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED",
#endif
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED)
    "SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED",
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA)
    "SSL_EARLY_DATA",
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    "SSL_PROTO_DTLS",
#endif
#if defined(MBEDTLS_SSL_ALPN)
    "SSL_ALPN",
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    "SSL_DTLS_ANTI_REPLAY",
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
    "SSL_DTLS_HELLO_VERIFY",
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
    "SSL_DTLS_SRTP",
#endif
#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE)
    "SSL_DTLS_CLIENT_PORT_REUSE",
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    "SSL_SESSION_TICKETS",
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    "SSL_SERVER_NAME_INDICATION",
#endif
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    "SSL_VARIABLE_BUFFER_LENGTH",
#endif
#if defined(MBEDTLS_TEST_CONSTANT_FLOW_MEMSAN)
    "TEST_CONSTANT_FLOW_MEMSAN",
#endif
#if defined(MBEDTLS_TEST_CONSTANT_FLOW_VALGRIND)
    "TEST_CONSTANT_FLOW_VALGRIND",
#endif
#if defined(MBEDTLS_TEST_HOOKS)
    "TEST_HOOKS",
#endif
#if defined(MBEDTLS_THREADING_ALT)
    "THREADING_ALT",
#endif
#if defined(MBEDTLS_THREADING_PTHREAD)
    "THREADING_PTHREAD",
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    "USE_PSA_CRYPTO",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_CONFIG)
    "PSA_CRYPTO_CONFIG",
#endif
#if defined(MBEDTLS_VERSION_FEATURES)
    "VERSION_FEATURES",
#endif
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    "X509_TRUSTED_CERTIFICATE_CALLBACK",
#endif
#if defined(MBEDTLS_X509_REMOVE_INFO)
    "X509_REMOVE_INFO",
#endif
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    "X509_RSASSA_PSS_SUPPORT",
#endif
#if defined(MBEDTLS_AESNI_C)
    "AESNI_C",
#endif
#if defined(MBEDTLS_AESCE_C)
    "AESCE_C",
#endif
#if defined(MBEDTLS_AES_C)
    "AES_C",
#endif
#if defined(MBEDTLS_ASN1_PARSE_C)
    "ASN1_PARSE_C",
#endif
#if defined(MBEDTLS_ASN1_WRITE_C)
    "ASN1_WRITE_C",
#endif
#if defined(MBEDTLS_BASE64_C)
    "BASE64_C",
#endif
#if defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    "BLOCK_CIPHER_NO_DECRYPT",
#endif
#if defined(MBEDTLS_BIGNUM_C)
    "BIGNUM_C",
#endif
#if defined(MBEDTLS_CAMELLIA_C)
    "CAMELLIA_C",
#endif
#if defined(MBEDTLS_ARIA_C)
    "ARIA_C",
#endif
#if defined(MBEDTLS_CCM_C)
    "CCM_C",
#endif
#if defined(MBEDTLS_CHACHA20_C)
    "CHACHA20_C",
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    "CHACHAPOLY_C",
#endif
#if defined(MBEDTLS_CIPHER_C)
    "CIPHER_C",
#endif
#if defined(MBEDTLS_CMAC_C)
    "CMAC_C",
#endif
#if defined(MBEDTLS_CTR_DRBG_C)
    "CTR_DRBG_C",
#endif
#if defined(MBEDTLS_DEBUG_C)
    "DEBUG_C",
#endif
#if defined(MBEDTLS_DES_C)
    "DES_C",
#endif
#if defined(MBEDTLS_DHM_C)
    "DHM_C",
#endif
#if defined(MBEDTLS_ECDH_C)
    "ECDH_C",
#endif
#if defined(MBEDTLS_ECDSA_C)
    "ECDSA_C",
#endif
#if defined(MBEDTLS_ECJPAKE_C)
    "ECJPAKE_C",
#endif
#if defined(MBEDTLS_ECP_C)
    "ECP_C",
#endif
#if defined(MBEDTLS_ENTROPY_C)
    "ENTROPY_C",
#endif
#if defined(MBEDTLS_ERROR_C)
    "ERROR_C",
#endif
#if defined(MBEDTLS_GCM_C)
    "GCM_C",
#endif
#if defined(MBEDTLS_GCM_LARGE_TABLE)
    "GCM_LARGE_TABLE",
#endif
#if defined(MBEDTLS_HKDF_C)
    "HKDF_C",
#endif
#if defined(MBEDTLS_HMAC_DRBG_C)
    "HMAC_DRBG_C",
#endif
#if defined(MBEDTLS_LMS_C)
    "LMS_C",
#endif
#if defined(MBEDTLS_LMS_PRIVATE)
    "LMS_PRIVATE",
#endif
#if defined(MBEDTLS_NIST_KW_C)
    "NIST_KW_C",
#endif
#if defined(MBEDTLS_MD_C)
    "MD_C",
#endif
#if defined(MBEDTLS_MD5_C)
    "MD5_C",
#endif
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    "MEMORY_BUFFER_ALLOC_C",
#endif
#if defined(MBEDTLS_NET_C)
    "NET_C",
#endif
#if defined(MBEDTLS_OID_C)
    "OID_C",
#endif
#if defined(MBEDTLS_PADLOCK_C)
    "PADLOCK_C",
#endif
#if defined(MBEDTLS_PEM_PARSE_C)
    "PEM_PARSE_C",
#endif
#if defined(MBEDTLS_PEM_WRITE_C)
    "PEM_WRITE_C",
#endif
#if defined(MBEDTLS_PK_C)
    "PK_C",
#endif
#if defined(MBEDTLS_PK_PARSE_C)
    "PK_PARSE_C",
#endif
#if defined(MBEDTLS_PK_WRITE_C)
    "PK_WRITE_C",
#endif
#if defined(MBEDTLS_PKCS5_C)
    "PKCS5_C",
#endif
#if defined(MBEDTLS_PKCS7_C)
    "PKCS7_C",
#endif
#if defined(MBEDTLS_PKCS12_C)
    "PKCS12_C",
#endif
#if defined(MBEDTLS_PLATFORM_C)
    "PLATFORM_C",
#endif
#if defined(MBEDTLS_POLY1305_C)
    "POLY1305_C",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_C)
    "PSA_CRYPTO_C",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    "PSA_CRYPTO_SE_C",
#endif
#if defined(MBEDTLS_PSA_CRYPTO_STORAGE_C)
    "PSA_CRYPTO_STORAGE_C",
#endif
#if defined(MBEDTLS_PSA_ITS_FILE_C)
    "PSA_ITS_FILE_C",
#endif
#if defined(MBEDTLS_RIPEMD160_C)
    "RIPEMD160_C",
#endif
#if defined(MBEDTLS_RSA_C)
    "RSA_C",
#endif
#if defined(MBEDTLS_SHA1_C)
    "SHA1_C",
#endif
#if defined(MBEDTLS_SHA224_C)
    "SHA224_C",
#endif
#if defined(MBEDTLS_SHA256_C)
    "SHA256_C",
#endif
#if defined(MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT)
    "SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT",
#endif
#if defined(MBEDTLS_SHA256_USE_A64_CRYPTO_IF_PRESENT)
    "SHA256_USE_A64_CRYPTO_IF_PRESENT",
#endif
#if defined(MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY)
    "SHA256_USE_ARMV8_A_CRYPTO_ONLY",
#endif
#if defined(MBEDTLS_SHA256_USE_A64_CRYPTO_ONLY)
    "SHA256_USE_A64_CRYPTO_ONLY",
#endif
#if defined(MBEDTLS_SHA384_C)
    "SHA384_C",
#endif
#if defined(MBEDTLS_SHA512_C)
    "SHA512_C",
#endif
#if defined(MBEDTLS_SHA3_C)
    "SHA3_C",
#endif
#if defined(MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT)
    "SHA512_USE_A64_CRYPTO_IF_PRESENT",
#endif
#if defined(MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY)
    "SHA512_USE_A64_CRYPTO_ONLY",
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    "SSL_CACHE_C",
#endif
#if defined(MBEDTLS_SSL_COOKIE_C)
    "SSL_COOKIE_C",
#endif
#if defined(MBEDTLS_SSL_TICKET_C)
    "SSL_TICKET_C",
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    "SSL_CLI_C",
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    "SSL_SRV_C",
#endif
#if defined(MBEDTLS_SSL_TLS_C)
    "SSL_TLS_C",
#endif
#if defined(MBEDTLS_THREADING_C)
    "THREADING_C",
#endif
#if defined(MBEDTLS_TIMING_C)
    "TIMING_C",
#endif
#if defined(MBEDTLS_VERSION_C)
    "VERSION_C",
#endif
#if defined(MBEDTLS_X509_USE_C)
    "X509_USE_C",
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    "X509_CRT_PARSE_C",
#endif
#if defined(MBEDTLS_X509_CRL_PARSE_C)
    "X509_CRL_PARSE_C",
#endif
#if defined(MBEDTLS_X509_CSR_PARSE_C)
    "X509_CSR_PARSE_C",
#endif
#if defined(MBEDTLS_X509_CREATE_C)
    "X509_CREATE_C",
#endif
#if defined(MBEDTLS_X509_CRT_WRITE_C)
    "X509_CRT_WRITE_C",
#endif
#if defined(MBEDTLS_X509_CSR_WRITE_C)
    "X509_CSR_WRITE_C",
#endif
#endif
    NULL
};
int mbedtls_version_check_feature(const char *feature)
{
    const char * const *idx = features;
    if (*idx == NULL) {
        return -2;
    }
    if (feature == NULL) {
        return -1;
    }
    if (strncmp(feature, "MBEDTLS_", 8)) {
        return -1;
    }
    feature += 8;
    while (*idx != NULL) {
        if (!strcmp(*idx, feature)) {
            return 0;
        }
        idx++;
    }
    return -1;
}
#endif
