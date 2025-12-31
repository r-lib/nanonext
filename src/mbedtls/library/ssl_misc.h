/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_MISC_H
#define MBEDTLS_SSL_MISC_H

#include "mbedtls/build_info.h"
#include "common.h"

#include "mbedtls/error.h"

#include "mbedtls/ssl.h"
#include "mbedtls/debug.h"
#include "debug_internal.h"

#include "mbedtls/cipher.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
#include "psa/crypto.h"
#include "psa_util_internal.h"
#endif

#if defined(MBEDTLS_MD_CAN_MD5)
#include "mbedtls/md5.h"
#endif

#if defined(MBEDTLS_MD_CAN_SHA1)
#include "mbedtls/sha1.h"
#endif

#if defined(MBEDTLS_MD_CAN_SHA256)
#include "mbedtls/sha256.h"
#endif

#if defined(MBEDTLS_MD_CAN_SHA512)
#include "mbedtls/sha512.h"
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) && \
    !defined(MBEDTLS_USE_PSA_CRYPTO)
#include "mbedtls/ecjpake.h"
#endif

#include "mbedtls/pk.h"
#include "ssl_ciphersuites_internal.h"
#include "x509_internal.h"
#include "pk_internal.h"

#if defined(MBEDTLS_ECP_RESTARTABLE) && \
    defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)
#define MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED
#endif

#define MBEDTLS_SSL_INITIAL_HANDSHAKE           0
#define MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS   1
#define MBEDTLS_SSL_RENEGOTIATION_DONE          2
#define MBEDTLS_SSL_RENEGOTIATION_PENDING       3

#define MBEDTLS_SSL_TLS1_3_HS_HELLO_RETRY_REQUEST (-MBEDTLS_SSL_HS_SERVER_HELLO)

#define MBEDTLS_SSL_EXT_ID_UNRECOGNIZED                0
#define MBEDTLS_SSL_EXT_ID_SERVERNAME                  1
#define MBEDTLS_SSL_EXT_ID_SERVERNAME_HOSTNAME         1
#define MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH         2
#define MBEDTLS_SSL_EXT_ID_STATUS_REQUEST              3
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS            4
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_ELLIPTIC_CURVES   4
#define MBEDTLS_SSL_EXT_ID_SIG_ALG                     5
#define MBEDTLS_SSL_EXT_ID_USE_SRTP                    6
#define MBEDTLS_SSL_EXT_ID_HEARTBEAT                   7
#define MBEDTLS_SSL_EXT_ID_ALPN                        8
#define MBEDTLS_SSL_EXT_ID_SCT                         9
#define MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE              10
#define MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE             11
#define MBEDTLS_SSL_EXT_ID_PADDING                    12
#define MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY             13
#define MBEDTLS_SSL_EXT_ID_EARLY_DATA                 14
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS         15
#define MBEDTLS_SSL_EXT_ID_COOKIE                     16
#define MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES     17
#define MBEDTLS_SSL_EXT_ID_CERT_AUTH                  18
#define MBEDTLS_SSL_EXT_ID_OID_FILTERS                19
#define MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH        20
#define MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT               21
#define MBEDTLS_SSL_EXT_ID_KEY_SHARE                  22
#define MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC             23
#define MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS    24
#define MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC           25
#define MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET     26
#define MBEDTLS_SSL_EXT_ID_SESSION_TICKET             27
#define MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT          28

uint32_t mbedtls_ssl_get_extension_id(unsigned int extension_type);
uint32_t mbedtls_ssl_get_extension_mask(unsigned int extension_type);

#define MBEDTLS_SSL_EXT_MASK(id)       (1ULL << (MBEDTLS_SSL_EXT_ID_##id))

#define MBEDTLS_SSL_EXT_MASK_NONE                                              0

#define MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED                               \
    (MBEDTLS_SSL_EXT_MASK(SUPPORTED_POINT_FORMATS)                | \
     MBEDTLS_SSL_EXT_MASK(ENCRYPT_THEN_MAC)                       | \
     MBEDTLS_SSL_EXT_MASK(EXTENDED_MASTER_SECRET)                 | \
     MBEDTLS_SSL_EXT_MASK(SESSION_TICKET)                         | \
     MBEDTLS_SSL_EXT_MASK(TRUNCATED_HMAC)                         | \
     MBEDTLS_SSL_EXT_MASK(UNRECOGNIZED))

#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CH                                  \
    (MBEDTLS_SSL_EXT_MASK(SERVERNAME)                             | \
     MBEDTLS_SSL_EXT_MASK(MAX_FRAGMENT_LENGTH)                    | \
     MBEDTLS_SSL_EXT_MASK(STATUS_REQUEST)                         | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_GROUPS)                       | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG)                                | \
     MBEDTLS_SSL_EXT_MASK(USE_SRTP)                               | \
     MBEDTLS_SSL_EXT_MASK(HEARTBEAT)                              | \
     MBEDTLS_SSL_EXT_MASK(ALPN)                                   | \
     MBEDTLS_SSL_EXT_MASK(SCT)                                    | \
     MBEDTLS_SSL_EXT_MASK(CLI_CERT_TYPE)                          | \
     MBEDTLS_SSL_EXT_MASK(SERV_CERT_TYPE)                         | \
     MBEDTLS_SSL_EXT_MASK(PADDING)                                | \
     MBEDTLS_SSL_EXT_MASK(KEY_SHARE)                              | \
     MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY)                         | \
     MBEDTLS_SSL_EXT_MASK(PSK_KEY_EXCHANGE_MODES)                 | \
     MBEDTLS_SSL_EXT_MASK(EARLY_DATA)                             | \
     MBEDTLS_SSL_EXT_MASK(COOKIE)                                 | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_VERSIONS)                     | \
     MBEDTLS_SSL_EXT_MASK(CERT_AUTH)                              | \
     MBEDTLS_SSL_EXT_MASK(POST_HANDSHAKE_AUTH)                    | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG_CERT)                           | \
     MBEDTLS_SSL_EXT_MASK(RECORD_SIZE_LIMIT)                      | \
     MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED)

#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_EE                                  \
    (MBEDTLS_SSL_EXT_MASK(SERVERNAME)                             | \
     MBEDTLS_SSL_EXT_MASK(MAX_FRAGMENT_LENGTH)                    | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_GROUPS)                       | \
     MBEDTLS_SSL_EXT_MASK(USE_SRTP)                               | \
     MBEDTLS_SSL_EXT_MASK(HEARTBEAT)                              | \
     MBEDTLS_SSL_EXT_MASK(ALPN)                                   | \
     MBEDTLS_SSL_EXT_MASK(CLI_CERT_TYPE)                          | \
     MBEDTLS_SSL_EXT_MASK(SERV_CERT_TYPE)                         | \
     MBEDTLS_SSL_EXT_MASK(EARLY_DATA)                             | \
     MBEDTLS_SSL_EXT_MASK(RECORD_SIZE_LIMIT))

#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CR                                  \
    (MBEDTLS_SSL_EXT_MASK(STATUS_REQUEST)                         | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG)                                | \
     MBEDTLS_SSL_EXT_MASK(SCT)                                    | \
     MBEDTLS_SSL_EXT_MASK(CERT_AUTH)                              | \
     MBEDTLS_SSL_EXT_MASK(OID_FILTERS)                            | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG_CERT)                           | \
     MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED)

#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CT                                  \
    (MBEDTLS_SSL_EXT_MASK(STATUS_REQUEST)                         | \
     MBEDTLS_SSL_EXT_MASK(SCT))

#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_SH                                  \
    (MBEDTLS_SSL_EXT_MASK(KEY_SHARE)                              | \
     MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY)                         | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_VERSIONS))

#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_HRR                                 \
    (MBEDTLS_SSL_EXT_MASK(KEY_SHARE)                              | \
     MBEDTLS_SSL_EXT_MASK(COOKIE)                                 | \
     MBEDTLS_SSL_EXT_MASK(SUPPORTED_VERSIONS))

#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_NST                                 \
    (MBEDTLS_SSL_EXT_MASK(EARLY_DATA)                             | \
     MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED)

#define MBEDTLS_SSL_PROC_CHK(f)                               \
    do {                                                        \
        ret = (f);                                            \
        if (ret != 0)                                          \
        {                                                       \
            goto cleanup;                                       \
        }                                                       \
    } while (0)

#define MBEDTLS_SSL_PROC_CHK_NEG(f)                           \
    do {                                                        \
        ret = (f);                                            \
        if (ret < 0)                                           \
        {                                                       \
            goto cleanup;                                       \
        }                                                       \
    } while (0)

#define MBEDTLS_SSL_RETRANS_PREPARING       0
#define MBEDTLS_SSL_RETRANS_SENDING         1
#define MBEDTLS_SSL_RETRANS_WAITING         2
#define MBEDTLS_SSL_RETRANS_FINISHED        3

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)

#if defined(MBEDTLS_SSL_HAVE_CBC)      &&                                  \
    (defined(MBEDTLS_SSL_HAVE_AES)     ||                                  \
    defined(MBEDTLS_SSL_HAVE_CAMELLIA) ||                                  \
    defined(MBEDTLS_SSL_HAVE_ARIA))
#define MBEDTLS_SSL_SOME_SUITES_USE_CBC
#endif

#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
#define MBEDTLS_SSL_SOME_SUITES_USE_STREAM
#endif

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_SOME_SUITES_USE_TLS_CBC
#endif

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_STREAM) || \
    defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC)
#define MBEDTLS_SSL_SOME_SUITES_USE_MAC
#endif

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC) && \
    defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
#define MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM
#endif

#endif

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

#if defined(MBEDTLS_MD_CAN_SHA384)
#define MBEDTLS_SSL_MAC_ADD                 48
#elif defined(MBEDTLS_MD_CAN_SHA256)
#define MBEDTLS_SSL_MAC_ADD                 32
#else
#define MBEDTLS_SSL_MAC_ADD                 20
#endif
#else

#define MBEDTLS_SSL_MAC_ADD                 16
#endif

#if defined(MBEDTLS_SSL_HAVE_CBC)
#define MBEDTLS_SSL_PADDING_ADD            256
#else
#define MBEDTLS_SSL_PADDING_ADD              0
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_MAX_CID_EXPANSION      MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY
#else
#define MBEDTLS_SSL_MAX_CID_EXPANSION        0
#endif

#define MBEDTLS_SSL_PAYLOAD_OVERHEAD (MBEDTLS_MAX_IV_LENGTH +          \
                                      MBEDTLS_SSL_MAC_ADD +            \
                                      MBEDTLS_SSL_PADDING_ADD +        \
                                      MBEDTLS_SSL_MAX_CID_EXPANSION    \
                                      )

#define MBEDTLS_SSL_IN_PAYLOAD_LEN (MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                    (MBEDTLS_SSL_IN_CONTENT_LEN))

#define MBEDTLS_SSL_OUT_PAYLOAD_LEN (MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                     (MBEDTLS_SSL_OUT_CONTENT_LEN))

#define MBEDTLS_SSL_MAX_BUFFERED_HS 4

#define MBEDTLS_TLS_EXT_ADV_CONTENT_LEN (                            \
        (MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN)   \
        ? (MBEDTLS_SSL_OUT_CONTENT_LEN)                            \
        : (MBEDTLS_SSL_IN_CONTENT_LEN)                             \
        )

#define MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN       65534

#define MBEDTLS_SSL_MIN_SIG_ALG_LIST_LEN       2

#define MBEDTLS_SSL_MAX_CURVE_LIST_LEN         65535

#define MBEDTLS_RECEIVED_SIG_ALGS_SIZE         20

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

#define MBEDTLS_TLS_SIG_NONE MBEDTLS_TLS1_3_SIG_NONE

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#define MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(sig, hash) ((hash << 8) | sig)
#define MBEDTLS_SSL_TLS12_SIG_ALG_FROM_SIG_AND_HASH_ALG(alg) (alg & 0xFF)
#define MBEDTLS_SSL_TLS12_HASH_ALG_FROM_SIG_AND_HASH_ALG(alg) (alg >> 8)
#endif

#endif

#if MBEDTLS_SSL_IN_CONTENT_LEN > 16384
#error "Bad configuration - incoming record content too large."
#endif

#if MBEDTLS_SSL_OUT_CONTENT_LEN > 16384
#error "Bad configuration - outgoing record content too large."
#endif

#if MBEDTLS_SSL_IN_PAYLOAD_LEN > MBEDTLS_SSL_IN_CONTENT_LEN + 2048
#error "Bad configuration - incoming protected record payload too large."
#endif

#if MBEDTLS_SSL_OUT_PAYLOAD_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN + 2048
#error "Bad configuration - outgoing protected record payload too large."
#endif

#define MBEDTLS_SSL_HEADER_LEN 13

#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN))
#else
#define MBEDTLS_SSL_IN_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_IN_PAYLOAD_LEN) \
     + (MBEDTLS_SSL_CID_IN_LEN_MAX))
#endif

#if !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_OUT_BUFFER_LEN  \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_OUT_PAYLOAD_LEN))
#else
#define MBEDTLS_SSL_OUT_BUFFER_LEN                               \
    ((MBEDTLS_SSL_HEADER_LEN) + (MBEDTLS_SSL_OUT_PAYLOAD_LEN)    \
     + (MBEDTLS_SSL_CID_OUT_LEN_MAX))
#endif

#define MBEDTLS_CLIENT_HELLO_RANDOM_LEN 32
#define MBEDTLS_SERVER_HELLO_RANDOM_LEN 32

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)

size_t mbedtls_ssl_get_output_max_frag_len(const mbedtls_ssl_context *ssl);

size_t mbedtls_ssl_get_input_max_frag_len(const mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)

size_t mbedtls_ssl_get_output_record_size_limit(const mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
static inline size_t mbedtls_ssl_get_output_buflen(const mbedtls_ssl_context *ctx)
{
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return mbedtls_ssl_get_output_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
           + MBEDTLS_SSL_CID_OUT_LEN_MAX;
#else
    return mbedtls_ssl_get_output_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}

static inline size_t mbedtls_ssl_get_input_buflen(const mbedtls_ssl_context *ctx)
{
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    return mbedtls_ssl_get_input_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD
           + MBEDTLS_SSL_CID_IN_LEN_MAX;
#else
    return mbedtls_ssl_get_input_max_frag_len(ctx)
           + MBEDTLS_SSL_HEADER_LEN + MBEDTLS_SSL_PAYLOAD_OVERHEAD;
#endif
}
#endif

#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT (1 << 0)
#define MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK                 (1 << 1)

#if !defined(MBEDTLS_TEST_HOOKS)
static inline int mbedtls_ssl_chk_buf_ptr(const uint8_t *cur,
                                          const uint8_t *end, size_t need)
{
    return (cur > end) || (need > (size_t) (end - cur));
}
#else
typedef struct {
    const uint8_t *cur;
    const uint8_t *end;
    size_t need;
} mbedtls_ssl_chk_buf_ptr_args;

void mbedtls_ssl_set_chk_buf_ptr_fail_args(
    const uint8_t *cur, const uint8_t *end, size_t need);
void mbedtls_ssl_reset_chk_buf_ptr_fail_args(void);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_cmp_chk_buf_ptr_fail_args(mbedtls_ssl_chk_buf_ptr_args *args);

static inline int mbedtls_ssl_chk_buf_ptr(const uint8_t *cur,
                                          const uint8_t *end, size_t need)
{
    if ((cur > end) || (need > (size_t) (end - cur))) {
        mbedtls_ssl_set_chk_buf_ptr_fail_args(cur, end, need);
        return 1;
    }
    return 0;
}
#endif

#define MBEDTLS_SSL_CHK_BUF_PTR(cur, end, need)                        \
    do {                                                                 \
        if (mbedtls_ssl_chk_buf_ptr((cur), (end), (need)) != 0) \
        {                                                                \
            return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;                  \
        }                                                                \
    } while (0)

#define MBEDTLS_SSL_CHK_BUF_READ_PTR(cur, end, need)                          \
    do {                                                                        \
        if (mbedtls_ssl_chk_buf_ptr((cur), (end), (need)) != 0)        \
        {                                                                       \
            MBEDTLS_SSL_DEBUG_MSG(1,                                           \
                                  ("missing input data in %s", __func__));  \
            MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,   \
                                         MBEDTLS_ERR_SSL_DECODE_ERROR);       \
            return MBEDTLS_ERR_SSL_DECODE_ERROR;                             \
        }                                                                       \
    } while (0)

#ifdef __cplusplus
extern "C" {
#endif

typedef int  mbedtls_ssl_tls_prf_cb(const unsigned char *secret, size_t slen,
                                    const char *label,
                                    const unsigned char *random, size_t rlen,
                                    unsigned char *dstbuf, size_t dlen);

#define MBEDTLS_SSL_MAX_BLOCK_LENGTH 16
#define MBEDTLS_SSL_MAX_IV_LENGTH    16
#define MBEDTLS_SSL_MAX_KEY_LENGTH   32

struct mbedtls_ssl_key_set {

    unsigned char client_write_key[MBEDTLS_SSL_MAX_KEY_LENGTH];

    unsigned char server_write_key[MBEDTLS_SSL_MAX_KEY_LENGTH];

    unsigned char client_write_iv[MBEDTLS_SSL_MAX_IV_LENGTH];

    unsigned char server_write_iv[MBEDTLS_SSL_MAX_IV_LENGTH];

    size_t key_len;
    size_t iv_len;
};
typedef struct mbedtls_ssl_key_set mbedtls_ssl_key_set;

typedef struct {
    unsigned char binder_key[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char client_early_traffic_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char early_exporter_master_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
} mbedtls_ssl_tls13_early_secrets;

typedef struct {
    unsigned char client_handshake_traffic_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char server_handshake_traffic_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
} mbedtls_ssl_tls13_handshake_secrets;

struct mbedtls_ssl_handshake_params {

    uint8_t resume;
    uint8_t cli_exts;

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    uint8_t sni_authmode;
#endif

#if defined(MBEDTLS_SSL_SRV_C)

    uint8_t certificate_request_sent;
#if defined(MBEDTLS_SSL_EARLY_DATA)

    uint8_t early_data_accepted;
#endif
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    uint8_t new_session_ticket;
#endif

#if defined(MBEDTLS_SSL_CLI_C)

    mbedtls_ssl_protocol_version min_tls_version;
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    uint8_t extended_ms;
#endif

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    uint8_t async_in_progress;
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned char retransmit_state;
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    unsigned char group_list_heap_allocated;
    unsigned char sig_algs_heap_allocated;
#endif

#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    uint8_t ecrs_enabled;
    enum {
        ssl_ecrs_none = 0,
        ssl_ecrs_crt_verify,
        ssl_ecrs_ske_start_processing,
        ssl_ecrs_cke_ecdh_calc_secret,
        ssl_ecrs_crt_vrfy_sign,
    } ecrs_state;
    mbedtls_x509_crt *ecrs_peer_cert;
    size_t ecrs_n;
#endif

    mbedtls_ssl_ciphersuite_t const *ciphersuite_info;

    MBEDTLS_CHECK_RETURN_CRITICAL
    int (*update_checksum)(mbedtls_ssl_context *, const unsigned char *, size_t);
    MBEDTLS_CHECK_RETURN_CRITICAL
    int (*calc_verify)(const mbedtls_ssl_context *, unsigned char *, size_t *);
    MBEDTLS_CHECK_RETURN_CRITICAL
    int (*calc_finished)(mbedtls_ssl_context *, unsigned char *, int);
    mbedtls_ssl_tls_prf_cb *tls_prf;

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    uint8_t key_exchange_mode;

    uint8_t hello_retry_request_flag;

#if defined(MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE)

    uint8_t ccs_sent;
#endif

#if defined(MBEDTLS_SSL_SRV_C)
#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)
    uint8_t tls13_kex_modes;
#endif

    uint16_t hrr_selected_group;
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    uint16_t new_session_tickets_count;
#endif
#endif

#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    uint16_t received_sig_algs[MBEDTLS_RECEIVED_SIG_ALGS_SIZE];
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    const uint16_t *group_list;
    const uint16_t *sig_algs;
#endif

#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_context dhm_ctx;
#endif

#if !defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED)
    mbedtls_ecdh_context ecdh_ctx;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED)
    psa_key_type_t xxdh_psa_type;
    size_t xxdh_psa_bits;
    mbedtls_svc_key_id_t xxdh_psa_privkey;
    uint8_t xxdh_psa_privkey_is_external;
    unsigned char xxdh_psa_peerkey[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    size_t xxdh_psa_peerkey_len;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_pake_operation_t psa_pake_ctx;
    mbedtls_svc_key_id_t psa_pake_password;
    uint8_t psa_pake_ctx_is_ok;
#else
    mbedtls_ecjpake_context ecjpake_ctx;
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    unsigned char *ecjpake_cache;
    size_t ecjpake_cache_len;
#endif
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    uint16_t *curves_tls_id;
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t psk_opaque;
    uint8_t psk_opaque_is_internal;
#else
    unsigned char *psk;
    size_t psk_len;
#endif
    uint16_t    selected_identity;
#endif

#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    mbedtls_x509_crt_restart_ctx ecrs_ctx;
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_key_cert *key_cert;
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    mbedtls_ssl_key_cert *sni_key_cert;
    mbedtls_x509_crt *sni_ca_chain;
    mbedtls_x509_crl *sni_ca_crl;
#endif
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) &&        \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_pk_context peer_pubkey;
#endif

    struct {
        size_t total_bytes_buffered;

        uint8_t seen_ccs;

        struct mbedtls_ssl_hs_buffer {
            unsigned is_valid      : 1;
            unsigned is_fragmented : 1;
            unsigned is_complete   : 1;
            unsigned char *data;
            size_t data_len;
        } hs[MBEDTLS_SSL_MAX_BUFFERED_HS];

        struct {
            unsigned char *data;
            size_t len;
            unsigned epoch;
        } future_record;

    } buffering;

#if defined(MBEDTLS_SSL_CLI_C) && \
    (defined(MBEDTLS_SSL_PROTO_DTLS) || \
    defined(MBEDTLS_SSL_PROTO_TLS1_3))
    unsigned char *cookie;
#if !defined(MBEDTLS_SSL_PROTO_TLS1_3)

    uint8_t cookie_len;
#else

    uint16_t cookie_len;
#endif
#endif
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned char cookie_verify_result;
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    unsigned int out_msg_seq;
    unsigned int in_msg_seq;

    uint32_t retransmit_timeout;
    mbedtls_ssl_flight_item *flight;
    mbedtls_ssl_flight_item *cur_msg;
    unsigned char *cur_msg_p;
    unsigned int in_flight_start_seq;
    mbedtls_ssl_transform *alt_transform_out;
    unsigned char alt_out_ctr[MBEDTLS_SSL_SEQUENCE_NUMBER_LEN];

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)

    uint8_t cid_in_use;
    unsigned char peer_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX];
    uint8_t peer_cid_len;
#endif

    uint16_t mtu;
#endif

#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_hash_operation_t fin_sha256_psa;
#else
    mbedtls_md_context_t fin_sha256;
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_hash_operation_t fin_sha384_psa;
#else
    mbedtls_md_context_t fin_sha384;
#endif
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    uint16_t offered_group_id;
#endif

#if defined(MBEDTLS_SSL_CLI_C)
    uint8_t client_auth;
#endif

    union {

        struct {
            uint8_t preparation_done;

            unsigned char digest[MBEDTLS_TLS1_3_MD_MAX_SIZE];
            size_t digest_len;
        } finished_out;

        struct {
            uint8_t preparation_done;

            unsigned char digest[MBEDTLS_TLS1_3_MD_MAX_SIZE];
            size_t digest_len;
        } finished_in;

    } state_local;

    unsigned char randbytes[MBEDTLS_CLIENT_HELLO_RANDOM_LEN +
                            MBEDTLS_SERVER_HELLO_RANDOM_LEN];

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    unsigned char premaster[MBEDTLS_PREMASTER_SIZE];

    size_t pmslen;
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    uint32_t sent_extensions;
    uint32_t received_extensions;

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    unsigned char certificate_request_context_len;
    unsigned char *certificate_request_context;
#endif

    mbedtls_ssl_transform *transform_handshake;
    union {
        unsigned char early[MBEDTLS_TLS1_3_MD_MAX_SIZE];
        unsigned char handshake[MBEDTLS_TLS1_3_MD_MAX_SIZE];
        unsigned char app[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    } tls13_master_secrets;

    mbedtls_ssl_tls13_handshake_secrets tls13_hs_secrets;
#if defined(MBEDTLS_SSL_EARLY_DATA)

    mbedtls_ssl_transform *transform_earlydata;
#endif
#endif

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)

    void *user_async_ctx;
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    const unsigned char *sni_name;
    size_t sni_name_len;
#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
    const mbedtls_x509_crt *dn_hints;
#endif
#endif
};

typedef struct mbedtls_ssl_hs_buffer mbedtls_ssl_hs_buffer;

struct mbedtls_ssl_transform {

    size_t minlen;
    size_t ivlen;
    size_t fixed_ivlen;
    size_t maclen;
    size_t taglen;

    unsigned char iv_enc[16];
    unsigned char iv_dec[16];

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t psa_mac_enc;
    mbedtls_svc_key_id_t psa_mac_dec;
    psa_algorithm_t psa_mac_alg;
#else
    mbedtls_md_context_t md_ctx_enc;
    mbedtls_md_context_t md_ctx_dec;
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    int encrypt_then_mac;
#endif

#endif

    mbedtls_ssl_protocol_version tls_version;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_svc_key_id_t psa_key_enc;
    mbedtls_svc_key_id_t psa_key_dec;
    psa_algorithm_t psa_alg;
#else
    mbedtls_cipher_context_t cipher_ctx_enc;
    mbedtls_cipher_context_t cipher_ctx_dec;
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t in_cid_len;
    uint8_t out_cid_len;
    unsigned char in_cid[MBEDTLS_SSL_CID_IN_LEN_MAX];
    unsigned char out_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX];
#endif

#if defined(MBEDTLS_SSL_KEEP_RANDBYTES)

    unsigned char randbytes[MBEDTLS_SERVER_HELLO_RANDOM_LEN +
                            MBEDTLS_CLIENT_HELLO_RANDOM_LEN];

#endif
};

static inline int mbedtls_ssl_transform_uses_aead(
    const mbedtls_ssl_transform *transform)
{
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    return transform->maclen == 0 && transform->taglen != 0;
#else
    (void) transform;
    return 1;
#endif
}

#if MBEDTLS_SSL_CID_OUT_LEN_MAX > MBEDTLS_SSL_CID_IN_LEN_MAX
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_OUT_LEN_MAX
#else
#define MBEDTLS_SSL_CID_LEN_MAX MBEDTLS_SSL_CID_IN_LEN_MAX
#endif

typedef struct {
    uint8_t ctr[MBEDTLS_SSL_SEQUENCE_NUMBER_LEN];
    uint8_t type;
    uint8_t ver[2];

    unsigned char *buf;
    size_t buf_len;
    size_t data_offset;
    size_t data_len;

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t cid_len;
    unsigned char cid[MBEDTLS_SSL_CID_LEN_MAX];
#endif
} mbedtls_record;

#if defined(MBEDTLS_X509_CRT_PARSE_C)

struct mbedtls_ssl_key_cert {
    mbedtls_x509_crt *cert;
    mbedtls_pk_context *key;
    mbedtls_ssl_key_cert *next;
};
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)

struct mbedtls_ssl_flight_item {
    unsigned char *p;
    size_t len;
    unsigned char type;
    mbedtls_ssl_flight_item *next;
};
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls12_write_client_hello_exts(mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              const unsigned char *end,
                                              int uses_ec,
                                              size_t *out_len);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)

unsigned int mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg(
    mbedtls_ssl_context *ssl,
    unsigned int sig_alg);

#endif

void mbedtls_ssl_transform_free(mbedtls_ssl_transform *transform);

void mbedtls_ssl_handshake_free(mbedtls_ssl_context *ssl);

void mbedtls_ssl_set_inbound_transform(mbedtls_ssl_context *ssl,
                                       mbedtls_ssl_transform *transform);

void mbedtls_ssl_set_outbound_transform(mbedtls_ssl_context *ssl,
                                        mbedtls_ssl_transform *transform);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handshake_client_step(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handshake_server_step(mbedtls_ssl_context *ssl);
void mbedtls_ssl_handshake_wrapup(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_DEBUG_C)

const char *mbedtls_ssl_states_str(mbedtls_ssl_states state);
#endif

static inline void mbedtls_ssl_handshake_set_state(mbedtls_ssl_context *ssl,
                                                   mbedtls_ssl_states state)
{
    MBEDTLS_SSL_DEBUG_MSG(3, ("handshake state: %d (%s) -> %d (%s)",
                              ssl->state, mbedtls_ssl_states_str(ssl->state),
                              (int) state, mbedtls_ssl_states_str(state)));
    ssl->state = (int) state;
}

static inline void mbedtls_ssl_handshake_increment_state(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_handshake_set_state(ssl, ssl->state + 1);
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_send_fatal_handshake_failure(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_reset_checksum(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_derive_keys(mbedtls_ssl_context *ssl);
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handle_message_type(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_prepare_handshake_record(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_update_handshake_status(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_read_record(mbedtls_ssl_context *ssl,
                            unsigned update_hs_digest);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_fetch_input(mbedtls_ssl_context *ssl, size_t nb_want);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_start_handshake_msg(mbedtls_ssl_context *ssl, unsigned char hs_type,
                                    unsigned char **buf, size_t *buf_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_handshake_msg_ext(mbedtls_ssl_context *ssl,
                                        int update_checksum,
                                        int force_flush);
static inline int mbedtls_ssl_write_handshake_msg(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_write_handshake_msg_ext(ssl, 1 , 1 );
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_finish_handshake_msg(mbedtls_ssl_context *ssl,
                                     size_t buf_len, size_t msg_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_record(mbedtls_ssl_context *ssl, int force_flush);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_flush_output(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_certificate(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_certificate(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_change_cipher_spec(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_change_cipher_spec(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_finished(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_finished(mbedtls_ssl_context *ssl);

void mbedtls_ssl_optimize_checksum(mbedtls_ssl_context *ssl,
                                   const mbedtls_ssl_ciphersuite_t *ciphersuite_info);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_add_hs_msg_to_checksum(mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       unsigned char const *msg,
                                       size_t msg_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_add_hs_hdr_to_checksum(mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       size_t total_hs_len);

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_psk_derive_premaster(mbedtls_ssl_context *ssl,
                                     mbedtls_key_exchange_type_t key_ex);
#endif
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(MBEDTLS_SSL_CLI_C) || defined(MBEDTLS_SSL_SRV_C)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_conf_has_static_psk(mbedtls_ssl_config const *conf);
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)

static inline mbedtls_svc_key_id_t mbedtls_ssl_get_opaque_psk(
    const mbedtls_ssl_context *ssl)
{
    if (!mbedtls_svc_key_id_is_null(ssl->handshake->psk_opaque)) {
        return ssl->handshake->psk_opaque;
    }

    if (!mbedtls_svc_key_id_is_null(ssl->conf->psk_opaque)) {
        return ssl->conf->psk_opaque;
    }

    return MBEDTLS_SVC_KEY_ID_INIT;
}
#else

static inline int mbedtls_ssl_get_psk(const mbedtls_ssl_context *ssl,
                                      const unsigned char **psk, size_t *psk_len)
{
    if (ssl->handshake->psk != NULL && ssl->handshake->psk_len > 0) {
        *psk = ssl->handshake->psk;
        *psk_len = ssl->handshake->psk_len;
    } else if (ssl->conf->psk != NULL && ssl->conf->psk_len > 0) {
        *psk = ssl->conf->psk;
        *psk_len = ssl->conf->psk_len;
    } else {
        *psk = NULL;
        *psk_len = 0;
        return MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED;
    }

    return 0;
}
#endif

#endif

#if defined(MBEDTLS_PK_C)
unsigned char mbedtls_ssl_sig_from_pk(mbedtls_pk_context *pk);
unsigned char mbedtls_ssl_sig_from_pk_alg(mbedtls_pk_type_t type);
mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig(unsigned char sig);
#endif

mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash(unsigned char hash);
unsigned char mbedtls_ssl_hash_from_md_alg(int md);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_set_calc_verify_md(mbedtls_ssl_context *ssl, int md);
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_check_curve_tls_id(const mbedtls_ssl_context *ssl, uint16_t tls_id);
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_check_curve(const mbedtls_ssl_context *ssl, mbedtls_ecp_group_id grp_id);
#endif

mbedtls_ecp_group_id mbedtls_ssl_get_ecp_group_id_from_tls_id(uint16_t tls_id);

uint16_t mbedtls_ssl_get_tls_id_from_ecp_group_id(mbedtls_ecp_group_id grp_id);

#if defined(MBEDTLS_DEBUG_C)

const char *mbedtls_ssl_get_curve_name_from_tls_id(uint16_t tls_id);
#endif

#if defined(MBEDTLS_SSL_DTLS_SRTP)
static inline mbedtls_ssl_srtp_profile mbedtls_ssl_check_srtp_profile_value
    (const uint16_t srtp_profile_value)
{
    switch (srtp_profile_value) {
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80:
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32:
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80:
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32:
            return srtp_profile_value;
        default: break;
    }
    return MBEDTLS_TLS_SRTP_UNSET;
}
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static inline mbedtls_pk_context *mbedtls_ssl_own_key(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_key_cert *key_cert;

    if (ssl->handshake != NULL && ssl->handshake->key_cert != NULL) {
        key_cert = ssl->handshake->key_cert;
    } else {
        key_cert = ssl->conf->key_cert;
    }

    return key_cert == NULL ? NULL : key_cert->key;
}

static inline mbedtls_x509_crt *mbedtls_ssl_own_cert(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_key_cert *key_cert;

    if (ssl->handshake != NULL && ssl->handshake->key_cert != NULL) {
        key_cert = ssl->handshake->key_cert;
    } else {
        key_cert = ssl->conf->key_cert;
    }

    return key_cert == NULL ? NULL : key_cert->cert;
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_verify_certificate(mbedtls_ssl_context *ssl,
                                   int authmode,
                                   mbedtls_x509_crt *chain,
                                   const mbedtls_ssl_ciphersuite_t *ciphersuite_info,
                                   void *rs_ctx);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_check_cert_usage(const mbedtls_x509_crt *cert,
                                 const mbedtls_ssl_ciphersuite_t *ciphersuite,
                                 int recv_endpoint,
                                 mbedtls_ssl_protocol_version tls_version,
                                 uint32_t *flags);
#endif

void mbedtls_ssl_write_version(unsigned char version[2], int transport,
                               mbedtls_ssl_protocol_version tls_version);
uint16_t mbedtls_ssl_read_version(const unsigned char version[2],
                                  int transport);

static inline size_t mbedtls_ssl_in_hdr_len(const mbedtls_ssl_context *ssl)
{
#if !defined(MBEDTLS_SSL_PROTO_DTLS)
    ((void) ssl);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return 13;
    } else
#endif
    {
        return 5;
    }
}

static inline size_t mbedtls_ssl_out_hdr_len(const mbedtls_ssl_context *ssl)
{
    return (size_t) (ssl->out_iv - ssl->out_hdr);
}

static inline size_t mbedtls_ssl_hs_hdr_len(const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return 12;
    }
#else
    ((void) ssl);
#endif
    return 4;
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_send_flight_completed(mbedtls_ssl_context *ssl);
void mbedtls_ssl_recv_flight_completed(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_resend(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_flight_transmit(mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_dtls_replay_check(mbedtls_ssl_context const *ssl);
void mbedtls_ssl_dtls_replay_update(mbedtls_ssl_context *ssl);
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_copy(mbedtls_ssl_session *dst,
                             const mbedtls_ssl_session *src);

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_get_key_exchange_md_tls1_2(mbedtls_ssl_context *ssl,
                                           unsigned char *hash, size_t *hashlen,
                                           unsigned char *data, size_t data_len,
                                           mbedtls_md_type_t md_alg);
#endif

#ifdef __cplusplus
}
#endif

void mbedtls_ssl_transform_init(mbedtls_ssl_transform *transform);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_encrypt_buf(mbedtls_ssl_context *ssl,
                            mbedtls_ssl_transform *transform,
                            mbedtls_record *rec,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_decrypt_buf(mbedtls_ssl_context const *ssl,
                            mbedtls_ssl_transform *transform,
                            mbedtls_record *rec);

static inline size_t mbedtls_ssl_ep_len(const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return 2;
    }
#else
    ((void) ssl);
#endif
    return 0;
}

#if defined(MBEDTLS_SSL_PROTO_DTLS)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_resend_hello_request(mbedtls_ssl_context *ssl);
#endif

void mbedtls_ssl_set_timer(mbedtls_ssl_context *ssl, uint32_t millisecs);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_check_timer(mbedtls_ssl_context *ssl);

void mbedtls_ssl_reset_in_pointers(mbedtls_ssl_context *ssl);
void mbedtls_ssl_update_in_pointers(mbedtls_ssl_context *ssl);
void mbedtls_ssl_reset_out_pointers(mbedtls_ssl_context *ssl);
void mbedtls_ssl_update_out_pointers(mbedtls_ssl_context *ssl,
                                     mbedtls_ssl_transform *transform);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_reset_int(mbedtls_ssl_context *ssl, int partial);
void mbedtls_ssl_session_reset_msg_layer(mbedtls_ssl_context *ssl,
                                         int partial);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_handle_pending_alert(mbedtls_ssl_context *ssl);

void mbedtls_ssl_pend_fatal_alert(mbedtls_ssl_context *ssl,
                                  unsigned char alert_type,
                                  int alert_reason);

#define MBEDTLS_SSL_PEND_FATAL_ALERT(type, user_return_value)         \
    mbedtls_ssl_pend_fatal_alert(ssl, type, user_return_value)

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
void mbedtls_ssl_dtls_replay_reset(mbedtls_ssl_context *ssl);
#endif

void mbedtls_ssl_handshake_wrapup_free_hs_transform(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_RENEGOTIATION)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_start_renegotiation(mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
size_t mbedtls_ssl_get_current_mtu(const mbedtls_ssl_context *ssl);
void mbedtls_ssl_buffering_free(mbedtls_ssl_context *ssl);
void mbedtls_ssl_flight_free(mbedtls_ssl_flight_item *flight);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
static inline int mbedtls_ssl_conf_is_tls13_only(const mbedtls_ssl_config *conf)
{
    return conf->min_tls_version == MBEDTLS_SSL_VERSION_TLS1_3 &&
           conf->max_tls_version == MBEDTLS_SSL_VERSION_TLS1_3;
}

#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static inline int mbedtls_ssl_conf_is_tls12_only(const mbedtls_ssl_config *conf)
{
    return conf->min_tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
           conf->max_tls_version == MBEDTLS_SSL_VERSION_TLS1_2;
}

#endif

static inline int mbedtls_ssl_conf_is_tls13_enabled(const mbedtls_ssl_config *conf)
{
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    return conf->min_tls_version <= MBEDTLS_SSL_VERSION_TLS1_3 &&
           conf->max_tls_version >= MBEDTLS_SSL_VERSION_TLS1_3;
#else
    ((void) conf);
    return 0;
#endif
}

static inline int mbedtls_ssl_conf_is_tls12_enabled(const mbedtls_ssl_config *conf)
{
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    return conf->min_tls_version <= MBEDTLS_SSL_VERSION_TLS1_2 &&
           conf->max_tls_version >= MBEDTLS_SSL_VERSION_TLS1_2;
#else
    ((void) conf);
    return 0;
#endif
}

#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
static inline int mbedtls_ssl_conf_is_hybrid_tls12_tls13(const mbedtls_ssl_config *conf)
{
    return conf->min_tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
           conf->max_tls_version == MBEDTLS_SSL_VERSION_TLS1_3;
}
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

int mbedtls_ssl_tls13_crypto_init(mbedtls_ssl_context *ssl);

extern const uint8_t mbedtls_ssl_tls13_hello_retry_request_magic[
    MBEDTLS_SERVER_HELLO_RANDOM_LEN];
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_process_finished_message(mbedtls_ssl_context *ssl);
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_finished_message(mbedtls_ssl_context *ssl);
void mbedtls_ssl_tls13_handshake_wrapup(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_client_hello_exts(mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              unsigned char *end,
                                              size_t *out_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_handshake_client_step(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_handshake_server_step(mbedtls_ssl_context *ssl);

static inline int mbedtls_ssl_conf_tls13_is_kex_mode_enabled(mbedtls_ssl_context *ssl,
                                                             int kex_mode_mask)
{
    return (ssl->conf->tls13_kex_modes & kex_mode_mask) != 0;
}

static inline int mbedtls_ssl_conf_tls13_is_psk_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK);
}

static inline int mbedtls_ssl_conf_tls13_is_psk_ephemeral_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);
}

static inline int mbedtls_ssl_conf_tls13_is_ephemeral_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
}

static inline int mbedtls_ssl_conf_tls13_is_some_ephemeral_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL);
}

static inline int mbedtls_ssl_conf_tls13_is_some_psk_enabled(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_conf_tls13_is_kex_mode_enabled(ssl,
                                                      MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL);
}

#if defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)

static inline int mbedtls_ssl_tls13_is_kex_mode_supported(mbedtls_ssl_context *ssl,
                                                          int kex_modes_mask)
{
    return (ssl->handshake->tls13_kex_modes & kex_modes_mask) != 0;
}

static inline int mbedtls_ssl_tls13_is_psk_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK);
}

static inline int mbedtls_ssl_tls13_is_psk_ephemeral_supported(
    mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL);
}

static inline int mbedtls_ssl_tls13_is_ephemeral_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);
}

static inline int mbedtls_ssl_tls13_is_some_ephemeral_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL);
}

static inline int mbedtls_ssl_tls13_is_some_psk_supported(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_is_kex_mode_supported(ssl,
                                                   MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL);
}
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_check_received_extension(
    mbedtls_ssl_context *ssl,
    int hs_msg_type,
    unsigned int received_extension_type,
    uint32_t hs_msg_allowed_extensions_mask);

static inline void mbedtls_ssl_tls13_set_hs_sent_ext_mask(
    mbedtls_ssl_context *ssl, unsigned int extension_type)
{
    ssl->handshake->sent_extensions |=
        mbedtls_ssl_get_extension_mask(extension_type);
}

static inline int mbedtls_ssl_tls13_key_exchange_mode_check(
    mbedtls_ssl_context *ssl, int kex_mask)
{
    return (ssl->handshake->key_exchange_mode & kex_mask) != 0;
}

static inline int mbedtls_ssl_tls13_key_exchange_mode_with_psk(
    mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_key_exchange_mode_check(ssl,
                                                     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL);
}

static inline int mbedtls_ssl_tls13_key_exchange_mode_with_ephemeral(
    mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_tls13_key_exchange_mode_check(ssl,
                                                     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL);
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_fetch_handshake_msg(mbedtls_ssl_context *ssl,
                                          unsigned hs_type,
                                          unsigned char **buf,
                                          size_t *buf_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_is_supported_versions_ext_present_in_exts(
    mbedtls_ssl_context *ssl,
    const unsigned char *buf, const unsigned char *end,
    const unsigned char **supported_versions_data,
    const unsigned char **supported_versions_data_end);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_process_certificate(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_certificate(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_certificate_verify(mbedtls_ssl_context *ssl);

#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_process_certificate_verify(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_change_cipher_spec(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_reset_transcript_for_hrr(mbedtls_ssl_context *ssl);

#if defined(PSA_WANT_ALG_ECDH) || defined(PSA_WANT_ALG_FFDH)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_generate_and_write_xxdh_key_exchange(
    mbedtls_ssl_context *ssl,
    uint16_t named_group,
    unsigned char *buf,
    unsigned char *end,
    size_t *out_len);
#endif

#if defined(MBEDTLS_SSL_EARLY_DATA)
int mbedtls_ssl_tls13_write_early_data_ext(mbedtls_ssl_context *ssl,
                                           int in_new_session_ticket,
                                           unsigned char *buf,
                                           const unsigned char *end,
                                           size_t *out_len);

int mbedtls_ssl_tls13_check_early_data_len(mbedtls_ssl_context *ssl,
                                           size_t early_data_len);

typedef enum {

    MBEDTLS_SSL_EARLY_DATA_STATE_IDLE,

    MBEDTLS_SSL_EARLY_DATA_STATE_NO_IND_SENT,

    MBEDTLS_SSL_EARLY_DATA_STATE_IND_SENT,

    MBEDTLS_SSL_EARLY_DATA_STATE_CAN_WRITE,

    MBEDTLS_SSL_EARLY_DATA_STATE_ACCEPTED,

    MBEDTLS_SSL_EARLY_DATA_STATE_REJECTED,

    MBEDTLS_SSL_EARLY_DATA_STATE_SERVER_FINISHED_RECEIVED,

} mbedtls_ssl_early_data_state;
#endif

#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_sig_alg_ext(mbedtls_ssl_context *ssl, unsigned char *buf,
                                  const unsigned char *end, size_t *out_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_sig_alg_ext(mbedtls_ssl_context *ssl,
                                  const unsigned char *buf,
                                  const unsigned char *end);
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_get_handshake_transcript(mbedtls_ssl_context *ssl,
                                         const mbedtls_md_type_t md,
                                         unsigned char *dst,
                                         size_t dst_len,
                                         size_t *olen);

static inline const void *mbedtls_ssl_get_groups(const mbedtls_ssl_context *ssl)
{
    #if defined(MBEDTLS_DEPRECATED_REMOVED) || !defined(MBEDTLS_ECP_C)
    return ssl->conf->group_list;
    #else
    if ((ssl->handshake != NULL) && (ssl->handshake->group_list != NULL)) {
        return ssl->handshake->group_list;
    } else {
        return ssl->conf->group_list;
    }
    #endif
}

static inline int mbedtls_ssl_tls12_named_group_is_ecdhe(uint16_t named_group)
{

    return named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X25519    ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1   ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1   ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1   ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X448      ||

           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP192K1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP224K1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1;
}

static inline int mbedtls_ssl_tls13_named_group_is_ecdhe(uint16_t named_group)
{
    return named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X25519    ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1 ||
           named_group == MBEDTLS_SSL_IANA_TLS_GROUP_X448;
}

static inline int mbedtls_ssl_tls13_named_group_is_ffdh(uint16_t named_group)
{
    return named_group >= MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048 &&
           named_group <= MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192;
}

static inline int mbedtls_ssl_named_group_is_offered(
    const mbedtls_ssl_context *ssl, uint16_t named_group)
{
    const uint16_t *group_list = mbedtls_ssl_get_groups(ssl);

    if (group_list == NULL) {
        return 0;
    }

    for (; *group_list != 0; group_list++) {
        if (*group_list == named_group) {
            return 1;
        }
    }

    return 0;
}

static inline int mbedtls_ssl_named_group_is_supported(uint16_t named_group)
{
#if defined(PSA_WANT_ALG_ECDH)
    if (mbedtls_ssl_tls13_named_group_is_ecdhe(named_group)) {
        if (mbedtls_ssl_get_ecp_group_id_from_tls_id(named_group) !=
            MBEDTLS_ECP_DP_NONE) {
            return 1;
        }
    }
#endif
#if defined(PSA_WANT_ALG_FFDH)
    if (mbedtls_ssl_tls13_named_group_is_ffdh(named_group)) {
        return 1;
    }
#endif
#if !defined(PSA_WANT_ALG_ECDH) && !defined(PSA_WANT_ALG_FFDH)
    (void) named_group;
#endif
    return 0;
}

static inline const void *mbedtls_ssl_get_sig_algs(
    const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ssl->handshake != NULL &&
        ssl->handshake->sig_algs_heap_allocated == 1 &&
        ssl->handshake->sig_algs != NULL) {
        return ssl->handshake->sig_algs;
    }
#endif
    return ssl->conf->sig_algs;

#else

    ((void) ssl);
    return NULL;
#endif
}

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
static inline int mbedtls_ssl_sig_alg_is_received(const mbedtls_ssl_context *ssl,
                                                  uint16_t own_sig_alg)
{
    const uint16_t *sig_alg = ssl->handshake->received_sig_algs;
    if (sig_alg == NULL) {
        return 0;
    }

    for (; *sig_alg != MBEDTLS_TLS_SIG_NONE; sig_alg++) {
        if (*sig_alg == own_sig_alg) {
            return 1;
        }
    }
    return 0;
}

static inline int mbedtls_ssl_tls13_sig_alg_for_cert_verify_is_supported(
    const uint16_t sig_alg)
{
    switch (sig_alg) {
#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
#if defined(PSA_WANT_ALG_SHA_256) && defined(PSA_WANT_ECC_SECP_R1_256)
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256:
            break;
#endif
#if defined(PSA_WANT_ALG_SHA_384) && defined(PSA_WANT_ECC_SECP_R1_384)
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384:
            break;
#endif
#if defined(PSA_WANT_ALG_SHA_512) && defined(PSA_WANT_ECC_SECP_R1_521)
        case MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512:
            break;
#endif
#endif

#if defined(MBEDTLS_PKCS1_V21)
#if defined(PSA_WANT_ALG_SHA_256)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256:
            break;
#endif
#if defined(PSA_WANT_ALG_SHA_384)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384:
            break;
#endif
#if defined(PSA_WANT_ALG_SHA_512)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512:
            break;
#endif
#endif
        default:
            return 0;
    }
    return 1;

}

static inline int mbedtls_ssl_tls13_sig_alg_is_supported(
    const uint16_t sig_alg)
{
    switch (sig_alg) {
#if defined(MBEDTLS_PKCS1_V15)
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256:
            break;
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384:
            break;
#endif
#if defined(MBEDTLS_MD_CAN_SHA512)
        case MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512:
            break;
#endif
#endif
        default:
            return mbedtls_ssl_tls13_sig_alg_for_cert_verify_is_supported(
                sig_alg);
    }
    return 1;
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_check_sig_alg_cert_key_match(uint16_t sig_alg,
                                                   mbedtls_pk_context *key);
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
static inline int mbedtls_ssl_sig_alg_is_offered(const mbedtls_ssl_context *ssl,
                                                 uint16_t proposed_sig_alg)
{
    const uint16_t *sig_alg = mbedtls_ssl_get_sig_algs(ssl);
    if (sig_alg == NULL) {
        return 0;
    }

    for (; *sig_alg != MBEDTLS_TLS_SIG_NONE; sig_alg++) {
        if (*sig_alg == proposed_sig_alg) {
            return 1;
        }
    }
    return 0;
}

static inline int mbedtls_ssl_get_pk_type_and_md_alg_from_sig_alg(
    uint16_t sig_alg, mbedtls_pk_type_t *pk_type, mbedtls_md_type_t *md_alg)
{
    *pk_type = mbedtls_ssl_pk_alg_from_sig(sig_alg & 0xff);
    *md_alg = mbedtls_ssl_md_alg_from_hash((sig_alg >> 8) & 0xff);

    if (*pk_type != MBEDTLS_PK_NONE && *md_alg != MBEDTLS_MD_NONE) {
        return 0;
    }

    switch (sig_alg) {
#if defined(MBEDTLS_PKCS1_V21)
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256:
            *md_alg = MBEDTLS_MD_SHA256;
            *pk_type = MBEDTLS_PK_RSASSA_PSS;
            break;
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384:
            *md_alg = MBEDTLS_MD_SHA384;
            *pk_type = MBEDTLS_PK_RSASSA_PSS;
            break;
#endif
#if defined(MBEDTLS_MD_CAN_SHA512)
        case MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512:
            *md_alg = MBEDTLS_MD_SHA512;
            *pk_type = MBEDTLS_PK_RSASSA_PSS;
            break;
#endif
#endif
        default:
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    return 0;
}

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static inline int mbedtls_ssl_tls12_sig_alg_is_supported(
    const uint16_t sig_alg)
{

    unsigned char hash = MBEDTLS_BYTE_1(sig_alg);
    unsigned char sig = MBEDTLS_BYTE_0(sig_alg);

    switch (hash) {
#if defined(MBEDTLS_MD_CAN_MD5)
        case MBEDTLS_SSL_HASH_MD5:
            break;
#endif

#if defined(MBEDTLS_MD_CAN_SHA1)
        case MBEDTLS_SSL_HASH_SHA1:
            break;
#endif

#if defined(MBEDTLS_MD_CAN_SHA224)
        case MBEDTLS_SSL_HASH_SHA224:
            break;
#endif

#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_SSL_HASH_SHA256:
            break;
#endif

#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_SSL_HASH_SHA384:
            break;
#endif

#if defined(MBEDTLS_MD_CAN_SHA512)
        case MBEDTLS_SSL_HASH_SHA512:
            break;
#endif

        default:
            return 0;
    }

    switch (sig) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_SSL_SIG_RSA:
            break;
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
        case MBEDTLS_SSL_SIG_ECDSA:
            break;
#endif

        default:
            return 0;
    }

    return 1;
}
#endif

static inline int mbedtls_ssl_sig_alg_is_supported(
    const mbedtls_ssl_context *ssl,
    const uint16_t sig_alg)
{

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2) {
        return mbedtls_ssl_tls12_sig_alg_is_supported(sig_alg);
    }
#endif

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED)
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        return mbedtls_ssl_tls13_sig_alg_is_supported(sig_alg);
    }
#endif
    ((void) ssl);
    ((void) sig_alg);
    return 0;
}
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)

#define MBEDTLS_SSL_NULL_CIPHER 0x04000000

psa_status_t mbedtls_ssl_cipher_to_psa(mbedtls_cipher_type_t mbedtls_cipher_type,
                                       size_t taglen,
                                       psa_algorithm_t *alg,
                                       psa_key_type_t *key_type,
                                       size_t *key_size);

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

static inline MBEDTLS_DEPRECATED int psa_ssl_status_to_mbedtls(psa_status_t status)
{
    switch (status) {
        case PSA_SUCCESS:
            return 0;
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        case PSA_ERROR_NOT_SUPPORTED:
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        case PSA_ERROR_INVALID_SIGNATURE:
            return MBEDTLS_ERR_SSL_INVALID_MAC;
        case PSA_ERROR_INVALID_ARGUMENT:
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        case PSA_ERROR_BAD_STATE:
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        case PSA_ERROR_BUFFER_TOO_SMALL:
            return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
        default:
            return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
}
#endif
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) && \
    defined(MBEDTLS_USE_PSA_CRYPTO)

typedef enum {
    MBEDTLS_ECJPAKE_ROUND_ONE,
    MBEDTLS_ECJPAKE_ROUND_TWO
} mbedtls_ecjpake_rounds_t;

int mbedtls_psa_ecjpake_read_round(
    psa_pake_operation_t *pake_ctx,
    const unsigned char *buf,
    size_t len, mbedtls_ecjpake_rounds_t round);

int mbedtls_psa_ecjpake_write_round(
    psa_pake_operation_t *pake_ctx,
    unsigned char *buf,
    size_t len, size_t *olen,
    mbedtls_ecjpake_rounds_t round);

#endif

typedef enum {
    MBEDTLS_SSL_MODE_STREAM = 0,
    MBEDTLS_SSL_MODE_CBC,
    MBEDTLS_SSL_MODE_CBC_ETM,
    MBEDTLS_SSL_MODE_AEAD
} mbedtls_ssl_mode_t;

mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_transform(
    const mbedtls_ssl_transform *transform);

#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_ciphersuite(
    int encrypt_then_mac,
    const mbedtls_ssl_ciphersuite_t *suite);
#else
mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_ciphersuite(
    const mbedtls_ssl_ciphersuite_t *suite);
#endif

#if defined(PSA_WANT_ALG_ECDH) || defined(PSA_WANT_ALG_FFDH)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_read_public_xxdhe_share(mbedtls_ssl_context *ssl,
                                              const unsigned char *buf,
                                              size_t buf_len);

#endif

static inline int mbedtls_ssl_tls13_cipher_suite_is_offered(
    mbedtls_ssl_context *ssl, int cipher_suite)
{
    const int *ciphersuite_list = ssl->conf->ciphersuite_list;

    for (size_t i = 0; ciphersuite_list[i] != 0; i++) {
        if (ciphersuite_list[i] == cipher_suite) {
            return 1;
        }
    }
    return 0;
}

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_validate_ciphersuite(
    const mbedtls_ssl_context *ssl,
    const mbedtls_ssl_ciphersuite_t *suite_info,
    mbedtls_ssl_protocol_version min_tls_version,
    mbedtls_ssl_protocol_version max_tls_version);

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_server_name_ext(mbedtls_ssl_context *ssl,
                                      const unsigned char *buf,
                                      const unsigned char *end);
#endif

#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
#define MBEDTLS_SSL_RECORD_SIZE_LIMIT_EXTENSION_DATA_LENGTH (2)
#define MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN (64)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_parse_record_size_limit_ext(mbedtls_ssl_context *ssl,
                                                  const unsigned char *buf,
                                                  const unsigned char *end);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_record_size_limit_ext(mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  const unsigned char *end,
                                                  size_t *out_len);
#endif

#if defined(MBEDTLS_SSL_ALPN)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_alpn_ext(mbedtls_ssl_context *ssl,
                               const unsigned char *buf,
                               const unsigned char *end);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_write_alpn_ext(mbedtls_ssl_context *ssl,
                               unsigned char *buf,
                               unsigned char *end,
                               size_t *out_len);
#endif

#if defined(MBEDTLS_TEST_HOOKS)
int mbedtls_ssl_check_dtls_clihlo_cookie(
    mbedtls_ssl_context *ssl,
    const unsigned char *cli_id, size_t cli_id_len,
    const unsigned char *in, size_t in_len,
    unsigned char *obuf, size_t buf_len, size_t *olen);
#endif

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_identities_of_pre_shared_key_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf, unsigned char *end,
    size_t *out_len, size_t *binders_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_write_binders_of_pre_shared_key_ext(
    mbedtls_ssl_context *ssl,
    unsigned char *buf, unsigned char *end);
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)

const char *mbedtls_ssl_get_hostname_pointer(const mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && \
    defined(MBEDTLS_SSL_CLI_C)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_set_hostname(mbedtls_ssl_session *session,
                                     const char *hostname);
#endif

#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_EARLY_DATA) && \
    defined(MBEDTLS_SSL_ALPN)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_session_set_ticket_alpn(mbedtls_ssl_session *session,
                                        const char *alpn);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)

#define MBEDTLS_SSL_TLS1_3_MAX_ALLOWED_TICKET_LIFETIME (604800)

static inline unsigned int mbedtls_ssl_tls13_session_get_ticket_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    return session->ticket_flags &
           (flags & MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK);
}

static inline int mbedtls_ssl_tls13_session_ticket_has_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    return mbedtls_ssl_tls13_session_get_ticket_flags(session, flags) != 0;
}

static inline int mbedtls_ssl_tls13_session_ticket_allow_psk(
    mbedtls_ssl_session *session)
{
    return mbedtls_ssl_tls13_session_ticket_has_flags(
        session, MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_RESUMPTION);
}

static inline int mbedtls_ssl_tls13_session_ticket_allow_psk_ephemeral(
    mbedtls_ssl_session *session)
{
    return mbedtls_ssl_tls13_session_ticket_has_flags(
        session, MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_EPHEMERAL_RESUMPTION);
}

static inline unsigned int mbedtls_ssl_tls13_session_ticket_allow_early_data(
    mbedtls_ssl_session *session)
{
    return mbedtls_ssl_tls13_session_ticket_has_flags(
        session, MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_EARLY_DATA);
}

static inline void mbedtls_ssl_tls13_session_set_ticket_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    session->ticket_flags |= (flags & MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK);
}

static inline void mbedtls_ssl_tls13_session_clear_ticket_flags(
    mbedtls_ssl_session *session, unsigned int flags)
{
    session->ticket_flags &= ~(flags & MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK);
}

#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
#define MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_BIT 0
#define MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_BIT 1

#define MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_MASK \
    (1 << MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_BIT)
#define MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_MASK \
    (1 << MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_BIT)

#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static inline int mbedtls_ssl_conf_get_session_tickets(
    const mbedtls_ssl_config *conf)
{
    return conf->session_tickets & MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_MASK ?
           MBEDTLS_SSL_SESSION_TICKETS_ENABLED :
           MBEDTLS_SSL_SESSION_TICKETS_DISABLED;
}
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
static inline int mbedtls_ssl_conf_is_signal_new_session_tickets_enabled(
    const mbedtls_ssl_config *conf)
{
    return conf->session_tickets & MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_MASK ?
           MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED :
           MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_DISABLED;
}
#endif
#endif

#if defined(MBEDTLS_SSL_CLI_C) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
int mbedtls_ssl_tls13_finalize_client_hello(mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_TEST_HOOKS) && defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)

#if defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_ct_hmac(mbedtls_svc_key_id_t key,
                    psa_algorithm_t mac_alg,
                    const unsigned char *add_data,
                    size_t add_data_len,
                    const unsigned char *data,
                    size_t data_len_secret,
                    size_t min_data_len,
                    size_t max_data_len,
                    unsigned char *output);
#else
int mbedtls_ct_hmac(mbedtls_md_context_t *ctx,
                    const unsigned char *add_data,
                    size_t add_data_len,
                    const unsigned char *data,
                    size_t data_len_secret,
                    size_t min_data_len,
                    size_t max_data_len,
                    unsigned char *output);
#endif
#endif

#endif
