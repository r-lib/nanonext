/*
 *  TLS shared functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */
#include "common.h"
#if defined(MBEDTLS_SSL_TLS_C)
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "ssl_client.h"
#include "ssl_misc.h"
#include "debug_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/version.h"
#include "mbedtls/constant_time.h"
#include <string.h>
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "mbedtls/psa_util.h"
#include "md_psa.h"
#include "psa_util_internal.h"
#include "psa/crypto.h"
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/oid.h"
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int local_err_translation(psa_status_t status)
{
    return psa_status_to_mbedtls(status, psa_to_ssl_errors,
                                 ARRAY_LENGTH(psa_to_ssl_errors),
                                 psa_generic_status_to_mbedtls);
}
#define PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)
#endif
#if defined(MBEDTLS_TEST_HOOKS)
static mbedtls_ssl_chk_buf_ptr_args chk_buf_ptr_fail_args;
void mbedtls_ssl_set_chk_buf_ptr_fail_args(
    const uint8_t *cur, const uint8_t *end, size_t need)
{
    chk_buf_ptr_fail_args.cur = cur;
    chk_buf_ptr_fail_args.end = end;
    chk_buf_ptr_fail_args.need = need;
}
void mbedtls_ssl_reset_chk_buf_ptr_fail_args(void)
{
    memset(&chk_buf_ptr_fail_args, 0, sizeof(chk_buf_ptr_fail_args));
}
int mbedtls_ssl_cmp_chk_buf_ptr_fail_args(mbedtls_ssl_chk_buf_ptr_args *args)
{
    return (chk_buf_ptr_fail_args.cur != args->cur) ||
           (chk_buf_ptr_fail_args.end != args->end) ||
           (chk_buf_ptr_fail_args.need != args->need);
}
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
int mbedtls_ssl_conf_cid(mbedtls_ssl_config *conf,
                         size_t len,
                         int ignore_other_cid)
{
    if (len > MBEDTLS_SSL_CID_IN_LEN_MAX) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ignore_other_cid != MBEDTLS_SSL_UNEXPECTED_CID_FAIL &&
        ignore_other_cid != MBEDTLS_SSL_UNEXPECTED_CID_IGNORE) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    conf->ignore_unexpected_cid = ignore_other_cid;
    conf->cid_len = len;
    return 0;
}
int mbedtls_ssl_set_cid(mbedtls_ssl_context *ssl,
                        int enable,
                        unsigned char const *own_cid,
                        size_t own_cid_len)
{
    if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl->negotiate_cid = enable;
    if (enable == MBEDTLS_SSL_CID_DISABLED) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("Disable use of CID extension."));
        return 0;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("Enable use of CID extension."));
    MBEDTLS_SSL_DEBUG_BUF(3, "Own CID", own_cid, own_cid_len);
    if (own_cid_len != ssl->conf->cid_len) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("CID length %u does not match CID length %u in config",
                                  (unsigned) own_cid_len,
                                  (unsigned) ssl->conf->cid_len));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(ssl->own_cid, own_cid, own_cid_len);
    ssl->own_cid_len = (uint8_t) own_cid_len;
    return 0;
}
int mbedtls_ssl_get_own_cid(mbedtls_ssl_context *ssl,
                            int *enabled,
                            unsigned char own_cid[MBEDTLS_SSL_CID_IN_LEN_MAX],
                            size_t *own_cid_len)
{
    *enabled = MBEDTLS_SSL_CID_DISABLED;
    if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->own_cid_len == 0 || ssl->negotiate_cid == MBEDTLS_SSL_CID_DISABLED) {
        return 0;
    }
    if (own_cid_len != NULL) {
        *own_cid_len = ssl->own_cid_len;
        if (own_cid != NULL) {
            memcpy(own_cid, ssl->own_cid, ssl->own_cid_len);
        }
    }
    *enabled = MBEDTLS_SSL_CID_ENABLED;
    return 0;
}
int mbedtls_ssl_get_peer_cid(mbedtls_ssl_context *ssl,
                             int *enabled,
                             unsigned char peer_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX],
                             size_t *peer_cid_len)
{
    *enabled = MBEDTLS_SSL_CID_DISABLED;
    if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM ||
        mbedtls_ssl_is_handshake_over(ssl) == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->transform_in->in_cid_len == 0 &&
        ssl->transform_in->out_cid_len == 0) {
        return 0;
    }
    if (peer_cid_len != NULL) {
        *peer_cid_len = ssl->transform_in->out_cid_len;
        if (peer_cid != NULL) {
            memcpy(peer_cid, ssl->transform_in->out_cid,
                   ssl->transform_in->out_cid_len);
        }
    }
    *enabled = MBEDTLS_SSL_CID_ENABLED;
    return 0;
}
#endif
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static unsigned int ssl_mfl_code_to_length(int mfl)
{
    switch (mfl) {
        case MBEDTLS_SSL_MAX_FRAG_LEN_NONE:
            return MBEDTLS_TLS_EXT_ADV_CONTENT_LEN;
        case MBEDTLS_SSL_MAX_FRAG_LEN_512:
            return 512;
        case MBEDTLS_SSL_MAX_FRAG_LEN_1024:
            return 1024;
        case MBEDTLS_SSL_MAX_FRAG_LEN_2048:
            return 2048;
        case MBEDTLS_SSL_MAX_FRAG_LEN_4096:
            return 4096;
        default:
            return MBEDTLS_TLS_EXT_ADV_CONTENT_LEN;
    }
}
#endif
int mbedtls_ssl_session_copy(mbedtls_ssl_session *dst,
                             const mbedtls_ssl_session *src)
{
    mbedtls_ssl_session_free(dst);
    memcpy(dst, src, sizeof(mbedtls_ssl_session));
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    dst->ticket = NULL;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    dst->hostname = NULL;
#endif
#endif
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_ALPN) && \
    defined(MBEDTLS_SSL_EARLY_DATA)
    dst->ticket_alpn = NULL;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (src->peer_cert != NULL) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        dst->peer_cert = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
        if (dst->peer_cert == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        mbedtls_x509_crt_init(dst->peer_cert);
        if ((ret = mbedtls_x509_crt_parse_der(dst->peer_cert, src->peer_cert->raw.p,
                                              src->peer_cert->raw.len)) != 0) {
            mbedtls_free(dst->peer_cert);
            dst->peer_cert = NULL;
            return ret;
        }
    }
#else
    if (src->peer_cert_digest != NULL) {
        dst->peer_cert_digest =
            mbedtls_calloc(1, src->peer_cert_digest_len);
        if (dst->peer_cert_digest == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(dst->peer_cert_digest, src->peer_cert_digest,
               src->peer_cert_digest_len);
        dst->peer_cert_digest_type = src->peer_cert_digest_type;
        dst->peer_cert_digest_len = src->peer_cert_digest_len;
    }
#endif
#endif
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_ALPN) && \
    defined(MBEDTLS_SSL_EARLY_DATA)
    {
        int ret = mbedtls_ssl_session_set_ticket_alpn(dst, src->ticket_alpn);
        if (ret != 0) {
            return ret;
        }
    }
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    if (src->ticket != NULL) {
        dst->ticket = mbedtls_calloc(1, src->ticket_len);
        if (dst->ticket == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(dst->ticket, src->ticket, src->ticket_len);
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if (src->endpoint == MBEDTLS_SSL_IS_CLIENT) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        ret = mbedtls_ssl_session_set_hostname(dst, src->hostname);
        if (ret != 0) {
            return ret;
        }
    }
#endif
#endif
    return 0;
}
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
MBEDTLS_CHECK_RETURN_CRITICAL
static int resize_buffer(unsigned char **buffer, size_t len_new, size_t *len_old)
{
    unsigned char *resized_buffer = mbedtls_calloc(1, len_new);
    if (resized_buffer == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    memcpy(resized_buffer, *buffer,
           (len_new < *len_old) ? len_new : *len_old);
    mbedtls_zeroize_and_free(*buffer, *len_old);
    *buffer = resized_buffer;
    *len_old = len_new;
    return 0;
}
static void handle_buffer_resizing(mbedtls_ssl_context *ssl, int downsizing,
                                   size_t in_buf_new_len,
                                   size_t out_buf_new_len)
{
    int modified = 0;
    size_t written_in = 0, iv_offset_in = 0, len_offset_in = 0;
    size_t written_out = 0, iv_offset_out = 0, len_offset_out = 0;
    if (ssl->in_buf != NULL) {
        written_in = ssl->in_msg - ssl->in_buf;
        iv_offset_in = ssl->in_iv - ssl->in_buf;
        len_offset_in = ssl->in_len - ssl->in_buf;
        if (downsizing ?
            ssl->in_buf_len > in_buf_new_len && ssl->in_left < in_buf_new_len :
            ssl->in_buf_len < in_buf_new_len) {
            if (resize_buffer(&ssl->in_buf, in_buf_new_len, &ssl->in_buf_len) != 0) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("input buffer resizing failed - out of memory"));
            } else {
                MBEDTLS_SSL_DEBUG_MSG(2, ("Reallocating in_buf to %" MBEDTLS_PRINTF_SIZET,
                                          in_buf_new_len));
                modified = 1;
            }
        }
    }
    if (ssl->out_buf != NULL) {
        written_out = ssl->out_msg - ssl->out_buf;
        iv_offset_out = ssl->out_iv - ssl->out_buf;
        len_offset_out = ssl->out_len - ssl->out_buf;
        if (downsizing ?
            ssl->out_buf_len > out_buf_new_len && ssl->out_left < out_buf_new_len :
            ssl->out_buf_len < out_buf_new_len) {
            if (resize_buffer(&ssl->out_buf, out_buf_new_len, &ssl->out_buf_len) != 0) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("output buffer resizing failed - out of memory"));
            } else {
                MBEDTLS_SSL_DEBUG_MSG(2, ("Reallocating out_buf to %" MBEDTLS_PRINTF_SIZET,
                                          out_buf_new_len));
                modified = 1;
            }
        }
    }
    if (modified) {
        mbedtls_ssl_reset_in_out_pointers(ssl);
        ssl->out_msg = ssl->out_buf + written_out;
        ssl->out_len = ssl->out_buf + len_offset_out;
        ssl->out_iv = ssl->out_buf + iv_offset_out;
        ssl->in_msg = ssl->in_buf + written_in;
        ssl->in_len = ssl->in_buf + len_offset_in;
        ssl->in_iv = ssl->in_buf + iv_offset_in;
    }
}
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
typedef int (*tls_prf_fn)(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen);
static tls_prf_fn ssl_tls12prf_from_cs(int ciphersuite_id);
#endif
typedef int ssl_tls_prf_t(const unsigned char *, size_t, const char *,
                          const unsigned char *, size_t,
                          unsigned char *, size_t);
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_populate_transform(mbedtls_ssl_transform *transform,
                                        int ciphersuite,
                                        const unsigned char master[48],
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                        int encrypt_then_mac,
#endif
                                        ssl_tls_prf_t tls_prf,
                                        const unsigned char randbytes[64],
                                        mbedtls_ssl_protocol_version tls_version,
                                        unsigned endpoint,
                                        const mbedtls_ssl_context *ssl);
#if defined(MBEDTLS_MD_CAN_SHA256)
MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha256(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen);
static int ssl_calc_verify_tls_sha256(const mbedtls_ssl_context *, unsigned char *, size_t *);
static int ssl_calc_finished_tls_sha256(mbedtls_ssl_context *, unsigned char *, int);
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha384(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen);
static int ssl_calc_verify_tls_sha384(const mbedtls_ssl_context *, unsigned char *, size_t *);
static int ssl_calc_finished_tls_sha384(mbedtls_ssl_context *, unsigned char *, int);
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_session_load(mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t len);
#endif
static int ssl_update_checksum_start(mbedtls_ssl_context *, const unsigned char *, size_t);
#if defined(MBEDTLS_MD_CAN_SHA256)
static int ssl_update_checksum_sha256(mbedtls_ssl_context *, const unsigned char *, size_t);
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
static int ssl_update_checksum_sha384(mbedtls_ssl_context *, const unsigned char *, size_t);
#endif
int mbedtls_ssl_tls_prf(const mbedtls_tls_prf_types prf,
                         const unsigned char *secret, size_t slen,
                         const char *label,
                         const unsigned char *random, size_t rlen,
                         unsigned char *dstbuf, size_t dlen)
{
    mbedtls_ssl_tls_prf_cb *tls_prf = NULL;
    switch (prf) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_SSL_TLS_PRF_SHA384:
            tls_prf = tls_prf_sha384;
            break;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_SSL_TLS_PRF_SHA256:
            tls_prf = tls_prf_sha256;
            break;
#endif
#endif
        default:
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    return tls_prf(secret, slen, label, random, rlen, dstbuf, dlen);
}
#if defined(MBEDTLS_X509_CRT_PARSE_C)
static void ssl_clear_peer_cert(mbedtls_ssl_session *session)
{
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (session->peer_cert != NULL) {
        mbedtls_x509_crt_free(session->peer_cert);
        mbedtls_free(session->peer_cert);
        session->peer_cert = NULL;
    }
#else
    if (session->peer_cert_digest != NULL) {
        mbedtls_free(session->peer_cert_digest);
        session->peer_cert_digest = NULL;
        session->peer_cert_digest_type = MBEDTLS_MD_NONE;
        session->peer_cert_digest_len = 0;
    }
#endif
}
#endif
uint32_t mbedtls_ssl_get_extension_id(unsigned int extension_type)
{
    switch (extension_type) {
        case MBEDTLS_TLS_EXT_SERVERNAME:
            return MBEDTLS_SSL_EXT_ID_SERVERNAME;
        case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
            return MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH;
        case MBEDTLS_TLS_EXT_STATUS_REQUEST:
            return MBEDTLS_SSL_EXT_ID_STATUS_REQUEST;
        case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
            return MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS;
        case MBEDTLS_TLS_EXT_SIG_ALG:
            return MBEDTLS_SSL_EXT_ID_SIG_ALG;
        case MBEDTLS_TLS_EXT_USE_SRTP:
            return MBEDTLS_SSL_EXT_ID_USE_SRTP;
        case MBEDTLS_TLS_EXT_HEARTBEAT:
            return MBEDTLS_SSL_EXT_ID_HEARTBEAT;
        case MBEDTLS_TLS_EXT_ALPN:
            return MBEDTLS_SSL_EXT_ID_ALPN;
        case MBEDTLS_TLS_EXT_SCT:
            return MBEDTLS_SSL_EXT_ID_SCT;
        case MBEDTLS_TLS_EXT_CLI_CERT_TYPE:
            return MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE;
        case MBEDTLS_TLS_EXT_SERV_CERT_TYPE:
            return MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE;
        case MBEDTLS_TLS_EXT_PADDING:
            return MBEDTLS_SSL_EXT_ID_PADDING;
        case MBEDTLS_TLS_EXT_PRE_SHARED_KEY:
            return MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY;
        case MBEDTLS_TLS_EXT_EARLY_DATA:
            return MBEDTLS_SSL_EXT_ID_EARLY_DATA;
        case MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS:
            return MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS;
        case MBEDTLS_TLS_EXT_COOKIE:
            return MBEDTLS_SSL_EXT_ID_COOKIE;
        case MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES:
            return MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES;
        case MBEDTLS_TLS_EXT_CERT_AUTH:
            return MBEDTLS_SSL_EXT_ID_CERT_AUTH;
        case MBEDTLS_TLS_EXT_OID_FILTERS:
            return MBEDTLS_SSL_EXT_ID_OID_FILTERS;
        case MBEDTLS_TLS_EXT_POST_HANDSHAKE_AUTH:
            return MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH;
        case MBEDTLS_TLS_EXT_SIG_ALG_CERT:
            return MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT;
        case MBEDTLS_TLS_EXT_KEY_SHARE:
            return MBEDTLS_SSL_EXT_ID_KEY_SHARE;
        case MBEDTLS_TLS_EXT_TRUNCATED_HMAC:
            return MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC;
        case MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
            return MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS;
        case MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC:
            return MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC;
        case MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
            return MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET;
        case MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT:
            return MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT;
        case MBEDTLS_TLS_EXT_SESSION_TICKET:
            return MBEDTLS_SSL_EXT_ID_SESSION_TICKET;
    }
    return MBEDTLS_SSL_EXT_ID_UNRECOGNIZED;
}
uint32_t mbedtls_ssl_get_extension_mask(unsigned int extension_type)
{
    return 1 << mbedtls_ssl_get_extension_id(extension_type);
}
#if defined(MBEDTLS_DEBUG_C)
static const char *extension_name_table[] = {
    [MBEDTLS_SSL_EXT_ID_UNRECOGNIZED] = "unrecognized",
    [MBEDTLS_SSL_EXT_ID_SERVERNAME] = "server_name",
    [MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH] = "max_fragment_length",
    [MBEDTLS_SSL_EXT_ID_STATUS_REQUEST] = "status_request",
    [MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS] = "supported_groups",
    [MBEDTLS_SSL_EXT_ID_SIG_ALG] = "signature_algorithms",
    [MBEDTLS_SSL_EXT_ID_USE_SRTP] = "use_srtp",
    [MBEDTLS_SSL_EXT_ID_HEARTBEAT] = "heartbeat",
    [MBEDTLS_SSL_EXT_ID_ALPN] = "application_layer_protocol_negotiation",
    [MBEDTLS_SSL_EXT_ID_SCT] = "signed_certificate_timestamp",
    [MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE] = "client_certificate_type",
    [MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE] = "server_certificate_type",
    [MBEDTLS_SSL_EXT_ID_PADDING] = "padding",
    [MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY] = "pre_shared_key",
    [MBEDTLS_SSL_EXT_ID_EARLY_DATA] = "early_data",
    [MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS] = "supported_versions",
    [MBEDTLS_SSL_EXT_ID_COOKIE] = "cookie",
    [MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES] = "psk_key_exchange_modes",
    [MBEDTLS_SSL_EXT_ID_CERT_AUTH] = "certificate_authorities",
    [MBEDTLS_SSL_EXT_ID_OID_FILTERS] = "oid_filters",
    [MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH] = "post_handshake_auth",
    [MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT] = "signature_algorithms_cert",
    [MBEDTLS_SSL_EXT_ID_KEY_SHARE] = "key_share",
    [MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC] = "truncated_hmac",
    [MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS] = "supported_point_formats",
    [MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC] = "encrypt_then_mac",
    [MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET] = "extended_master_secret",
    [MBEDTLS_SSL_EXT_ID_SESSION_TICKET] = "session_ticket",
    [MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT] = "record_size_limit"
};
static const unsigned int extension_type_table[] = {
    [MBEDTLS_SSL_EXT_ID_UNRECOGNIZED] = 0xff,
    [MBEDTLS_SSL_EXT_ID_SERVERNAME] = MBEDTLS_TLS_EXT_SERVERNAME,
    [MBEDTLS_SSL_EXT_ID_MAX_FRAGMENT_LENGTH] = MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH,
    [MBEDTLS_SSL_EXT_ID_STATUS_REQUEST] = MBEDTLS_TLS_EXT_STATUS_REQUEST,
    [MBEDTLS_SSL_EXT_ID_SUPPORTED_GROUPS] = MBEDTLS_TLS_EXT_SUPPORTED_GROUPS,
    [MBEDTLS_SSL_EXT_ID_SIG_ALG] = MBEDTLS_TLS_EXT_SIG_ALG,
    [MBEDTLS_SSL_EXT_ID_USE_SRTP] = MBEDTLS_TLS_EXT_USE_SRTP,
    [MBEDTLS_SSL_EXT_ID_HEARTBEAT] = MBEDTLS_TLS_EXT_HEARTBEAT,
    [MBEDTLS_SSL_EXT_ID_ALPN] = MBEDTLS_TLS_EXT_ALPN,
    [MBEDTLS_SSL_EXT_ID_SCT] = MBEDTLS_TLS_EXT_SCT,
    [MBEDTLS_SSL_EXT_ID_CLI_CERT_TYPE] = MBEDTLS_TLS_EXT_CLI_CERT_TYPE,
    [MBEDTLS_SSL_EXT_ID_SERV_CERT_TYPE] = MBEDTLS_TLS_EXT_SERV_CERT_TYPE,
    [MBEDTLS_SSL_EXT_ID_PADDING] = MBEDTLS_TLS_EXT_PADDING,
    [MBEDTLS_SSL_EXT_ID_PRE_SHARED_KEY] = MBEDTLS_TLS_EXT_PRE_SHARED_KEY,
    [MBEDTLS_SSL_EXT_ID_EARLY_DATA] = MBEDTLS_TLS_EXT_EARLY_DATA,
    [MBEDTLS_SSL_EXT_ID_SUPPORTED_VERSIONS] = MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS,
    [MBEDTLS_SSL_EXT_ID_COOKIE] = MBEDTLS_TLS_EXT_COOKIE,
    [MBEDTLS_SSL_EXT_ID_PSK_KEY_EXCHANGE_MODES] = MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES,
    [MBEDTLS_SSL_EXT_ID_CERT_AUTH] = MBEDTLS_TLS_EXT_CERT_AUTH,
    [MBEDTLS_SSL_EXT_ID_OID_FILTERS] = MBEDTLS_TLS_EXT_OID_FILTERS,
    [MBEDTLS_SSL_EXT_ID_POST_HANDSHAKE_AUTH] = MBEDTLS_TLS_EXT_POST_HANDSHAKE_AUTH,
    [MBEDTLS_SSL_EXT_ID_SIG_ALG_CERT] = MBEDTLS_TLS_EXT_SIG_ALG_CERT,
    [MBEDTLS_SSL_EXT_ID_KEY_SHARE] = MBEDTLS_TLS_EXT_KEY_SHARE,
    [MBEDTLS_SSL_EXT_ID_TRUNCATED_HMAC] = MBEDTLS_TLS_EXT_TRUNCATED_HMAC,
    [MBEDTLS_SSL_EXT_ID_SUPPORTED_POINT_FORMATS] = MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS,
    [MBEDTLS_SSL_EXT_ID_ENCRYPT_THEN_MAC] = MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC,
    [MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET] = MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET,
    [MBEDTLS_SSL_EXT_ID_SESSION_TICKET] = MBEDTLS_TLS_EXT_SESSION_TICKET,
    [MBEDTLS_SSL_EXT_ID_RECORD_SIZE_LIMIT] = MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT
};
const char *mbedtls_ssl_get_extension_name(unsigned int extension_type)
{
    return extension_name_table[
        mbedtls_ssl_get_extension_id(extension_type)];
}
static const char *ssl_tls13_get_hs_msg_name(int hs_msg_type)
{
    switch (hs_msg_type) {
        case MBEDTLS_SSL_HS_CLIENT_HELLO:
            return "ClientHello";
        case MBEDTLS_SSL_HS_SERVER_HELLO:
            return "ServerHello";
        case MBEDTLS_SSL_TLS1_3_HS_HELLO_RETRY_REQUEST:
            return "HelloRetryRequest";
        case MBEDTLS_SSL_HS_NEW_SESSION_TICKET:
            return "NewSessionTicket";
        case MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS:
            return "EncryptedExtensions";
        case MBEDTLS_SSL_HS_CERTIFICATE:
            return "Certificate";
        case MBEDTLS_SSL_HS_CERTIFICATE_REQUEST:
            return "CertificateRequest";
    }
    return "Unknown";
}
void mbedtls_ssl_print_extension(const mbedtls_ssl_context *ssl,
                                 int level, const char *file, int line,
                                 int hs_msg_type, unsigned int extension_type,
                                 const char *extra_msg0, const char *extra_msg1)
{
    const char *extra_msg;
    if (extra_msg0 && extra_msg1) {
        mbedtls_debug_print_msg(
            ssl, level, file, line,
            "%s: %s(%u) extension %s %s.",
            ssl_tls13_get_hs_msg_name(hs_msg_type),
            mbedtls_ssl_get_extension_name(extension_type),
            extension_type,
            extra_msg0, extra_msg1);
        return;
    }
    extra_msg = extra_msg0 ? extra_msg0 : extra_msg1;
    if (extra_msg) {
        mbedtls_debug_print_msg(
            ssl, level, file, line,
            "%s: %s(%u) extension %s.", ssl_tls13_get_hs_msg_name(hs_msg_type),
            mbedtls_ssl_get_extension_name(extension_type), extension_type,
            extra_msg);
        return;
    }
    mbedtls_debug_print_msg(
        ssl, level, file, line,
        "%s: %s(%u) extension.", ssl_tls13_get_hs_msg_name(hs_msg_type),
        mbedtls_ssl_get_extension_name(extension_type), extension_type);
}
void mbedtls_ssl_print_extensions(const mbedtls_ssl_context *ssl,
                                  int level, const char *file, int line,
                                  int hs_msg_type, uint32_t extensions_mask,
                                  const char *extra)
{
    for (unsigned i = 0;
         i < sizeof(extension_name_table) / sizeof(extension_name_table[0]);
         i++) {
        mbedtls_ssl_print_extension(
            ssl, level, file, line, hs_msg_type, extension_type_table[i],
            extensions_mask & (1 << i) ? "exists" : "does not exist", extra);
    }
}
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
static const char *ticket_flag_name_table[] =
{
    [0] = "ALLOW_PSK_RESUMPTION",
    [2] = "ALLOW_PSK_EPHEMERAL_RESUMPTION",
    [3] = "ALLOW_EARLY_DATA",
};
void mbedtls_ssl_print_ticket_flags(const mbedtls_ssl_context *ssl,
                                    int level, const char *file, int line,
                                    unsigned int flags)
{
    size_t i;
    mbedtls_debug_print_msg(ssl, level, file, line,
                            "print ticket_flags (0x%02x)", flags);
    flags = flags & MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK;
    for (i = 0; i < ARRAY_LENGTH(ticket_flag_name_table); i++) {
        if ((flags & (1 << i))) {
            mbedtls_debug_print_msg(ssl, level, file, line, "- %s is set.",
                                    ticket_flag_name_table[i]);
        }
    }
}
#endif
#endif
void mbedtls_ssl_optimize_checksum(mbedtls_ssl_context *ssl,
                                   const mbedtls_ssl_ciphersuite_t *ciphersuite_info)
{
    ((void) ciphersuite_info);
#if defined(MBEDTLS_MD_CAN_SHA384)
    if (ciphersuite_info->mac == MBEDTLS_MD_SHA384) {
        ssl->handshake->update_checksum = ssl_update_checksum_sha384;
    } else
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
    if (ciphersuite_info->mac != MBEDTLS_MD_SHA384) {
        ssl->handshake->update_checksum = ssl_update_checksum_sha256;
    } else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return;
    }
}
int mbedtls_ssl_add_hs_hdr_to_checksum(mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       size_t total_hs_len)
{
    unsigned char hs_hdr[4];
    hs_hdr[0] = MBEDTLS_BYTE_0(hs_type);
    hs_hdr[1] = MBEDTLS_BYTE_2(total_hs_len);
    hs_hdr[2] = MBEDTLS_BYTE_1(total_hs_len);
    hs_hdr[3] = MBEDTLS_BYTE_0(total_hs_len);
    return ssl->handshake->update_checksum(ssl, hs_hdr, sizeof(hs_hdr));
}
int mbedtls_ssl_add_hs_msg_to_checksum(mbedtls_ssl_context *ssl,
                                       unsigned hs_type,
                                       unsigned char const *msg,
                                       size_t msg_len)
{
    int ret;
    ret = mbedtls_ssl_add_hs_hdr_to_checksum(ssl, hs_type, msg_len);
    if (ret != 0) {
        return ret;
    }
    return ssl->handshake->update_checksum(ssl, msg, msg_len);
}
int mbedtls_ssl_reset_checksum(mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_MD_CAN_SHA256) || \
    defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
#else
    ((void) ssl);
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    status = psa_hash_abort(&ssl->handshake->fin_sha256_psa);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
    status = psa_hash_setup(&ssl->handshake->fin_sha256_psa, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
#else
    mbedtls_md_free(&ssl->handshake->fin_sha256);
    mbedtls_md_init(&ssl->handshake->fin_sha256);
    ret = mbedtls_md_setup(&ssl->handshake->fin_sha256,
                           mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                           0);
    if (ret != 0) {
        return ret;
    }
    ret = mbedtls_md_starts(&ssl->handshake->fin_sha256);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    status = psa_hash_abort(&ssl->handshake->fin_sha384_psa);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
    status = psa_hash_setup(&ssl->handshake->fin_sha384_psa, PSA_ALG_SHA_384);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
#else
    mbedtls_md_free(&ssl->handshake->fin_sha384);
    mbedtls_md_init(&ssl->handshake->fin_sha384);
    ret = mbedtls_md_setup(&ssl->handshake->fin_sha384,
                           mbedtls_md_info_from_type(MBEDTLS_MD_SHA384), 0);
    if (ret != 0) {
        return ret;
    }
    ret = mbedtls_md_starts(&ssl->handshake->fin_sha384);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
    return 0;
}
static int ssl_update_checksum_start(mbedtls_ssl_context *ssl,
                                     const unsigned char *buf, size_t len)
{
#if defined(MBEDTLS_MD_CAN_SHA256) || \
    defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
#else
    ((void) ssl);
    (void) buf;
    (void) len;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    status = psa_hash_update(&ssl->handshake->fin_sha256_psa, buf, len);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
#else
    ret = mbedtls_md_update(&ssl->handshake->fin_sha256, buf, len);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    status = psa_hash_update(&ssl->handshake->fin_sha384_psa, buf, len);
    if (status != PSA_SUCCESS) {
        return mbedtls_md_error_from_psa(status);
    }
#else
    ret = mbedtls_md_update(&ssl->handshake->fin_sha384, buf, len);
    if (ret != 0) {
        return ret;
    }
#endif
#endif
    return 0;
}
#if defined(MBEDTLS_MD_CAN_SHA256)
static int ssl_update_checksum_sha256(mbedtls_ssl_context *ssl,
                                      const unsigned char *buf, size_t len)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    return mbedtls_md_error_from_psa(psa_hash_update(
                                         &ssl->handshake->fin_sha256_psa, buf, len));
#else
    return mbedtls_md_update(&ssl->handshake->fin_sha256, buf, len);
#endif
}
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
static int ssl_update_checksum_sha384(mbedtls_ssl_context *ssl,
                                      const unsigned char *buf, size_t len)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    return mbedtls_md_error_from_psa(psa_hash_update(
                                         &ssl->handshake->fin_sha384_psa, buf, len));
#else
    return mbedtls_md_update(&ssl->handshake->fin_sha384, buf, len);
#endif
}
#endif
static void ssl_handshake_params_init(mbedtls_ssl_handshake_params *handshake)
{
    memset(handshake, 0, sizeof(mbedtls_ssl_handshake_params));
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    handshake->fin_sha256_psa = psa_hash_operation_init();
#else
    mbedtls_md_init(&handshake->fin_sha256);
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    handshake->fin_sha384_psa = psa_hash_operation_init();
#else
    mbedtls_md_init(&handshake->fin_sha384);
#endif
#endif
    handshake->update_checksum = ssl_update_checksum_start;
#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_init(&handshake->dhm_ctx);
#endif
#if !defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED)
    mbedtls_ecdh_init(&handshake->ecdh_ctx);
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    handshake->psa_pake_ctx = psa_pake_operation_init();
    handshake->psa_pake_password = MBEDTLS_SVC_KEY_ID_INIT;
#else
    mbedtls_ecjpake_init(&handshake->ecjpake_ctx);
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif
#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    mbedtls_x509_crt_restart_init(&handshake->ecrs_ctx);
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    handshake->sni_authmode = MBEDTLS_SSL_VERIFY_UNSET;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_pk_init(&handshake->peer_pubkey);
#endif
}
void mbedtls_ssl_transform_init(mbedtls_ssl_transform *transform)
{
    memset(transform, 0, sizeof(mbedtls_ssl_transform));
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    transform->psa_key_enc = MBEDTLS_SVC_KEY_ID_INIT;
    transform->psa_key_dec = MBEDTLS_SVC_KEY_ID_INIT;
#else
    mbedtls_cipher_init(&transform->cipher_ctx_enc);
    mbedtls_cipher_init(&transform->cipher_ctx_dec);
#endif
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    transform->psa_mac_enc = MBEDTLS_SVC_KEY_ID_INIT;
    transform->psa_mac_dec = MBEDTLS_SVC_KEY_ID_INIT;
#else
    mbedtls_md_init(&transform->md_ctx_enc);
    mbedtls_md_init(&transform->md_ctx_dec);
#endif
#endif
}
void mbedtls_ssl_session_init(mbedtls_ssl_session *session)
{
    memset(session, 0, sizeof(mbedtls_ssl_session));
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_handshake_init(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform_negotiate) {
        mbedtls_ssl_transform_free(ssl->transform_negotiate);
    }
#endif
    if (ssl->session_negotiate) {
        mbedtls_ssl_session_free(ssl->session_negotiate);
    }
    if (ssl->handshake) {
        mbedtls_ssl_handshake_free(ssl);
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform_negotiate == NULL) {
        ssl->transform_negotiate = mbedtls_calloc(1, sizeof(mbedtls_ssl_transform));
    }
#endif
    if (ssl->session_negotiate == NULL) {
        ssl->session_negotiate = mbedtls_calloc(1, sizeof(mbedtls_ssl_session));
    }
    if (ssl->handshake == NULL) {
        ssl->handshake = mbedtls_calloc(1, sizeof(mbedtls_ssl_handshake_params));
    }
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    handle_buffer_resizing(ssl, 0, MBEDTLS_SSL_IN_BUFFER_LEN,
                           MBEDTLS_SSL_OUT_BUFFER_LEN);
#endif
    if (ssl->handshake == NULL ||
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        ssl->transform_negotiate == NULL ||
#endif
        ssl->session_negotiate == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc() of ssl sub-contexts failed"));
        mbedtls_free(ssl->handshake);
        ssl->handshake = NULL;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        mbedtls_free(ssl->transform_negotiate);
        ssl->transform_negotiate = NULL;
#endif
        mbedtls_free(ssl->session_negotiate);
        ssl->session_negotiate = NULL;
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
#if defined(MBEDTLS_SSL_EARLY_DATA)
#if defined(MBEDTLS_SSL_CLI_C)
    ssl->early_data_state = MBEDTLS_SSL_EARLY_DATA_STATE_IDLE;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    ssl->discard_early_data_record = MBEDTLS_SSL_EARLY_DATA_NO_DISCARD;
#endif
    ssl->total_early_data_size = 0;
#endif
    mbedtls_ssl_session_init(ssl->session_negotiate);
    ssl_handshake_params_init(ssl->handshake);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    mbedtls_ssl_transform_init(ssl->transform_negotiate);
#endif
    ret = mbedtls_ssl_reset_checksum(ssl);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_reset_checksum", ret);
        return ret;
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS)
    ssl->handshake->new_session_tickets_count =
        ssl->conf->new_session_tickets_count;
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        ssl->handshake->alt_transform_out = ssl->transform_out;
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_PREPARING;
        } else {
            ssl->handshake->retransmit_state = MBEDTLS_SSL_RETRANS_WAITING;
        }
        mbedtls_ssl_set_timer(ssl, 0);
    }
#endif
#if defined(MBEDTLS_ECP_C)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ssl->conf->curve_list != NULL) {
        size_t length;
        const mbedtls_ecp_group_id *curve_list = ssl->conf->curve_list;
        for (length = 0; (curve_list[length] != MBEDTLS_ECP_DP_NONE); length++) {
        }
        uint16_t *group_list = mbedtls_calloc(length + 1, sizeof(uint16_t));
        if (group_list == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        for (size_t i = 0; i < length; i++) {
            uint16_t tls_id = mbedtls_ssl_get_tls_id_from_ecp_group_id(
                curve_list[i]);
            if (tls_id == 0) {
                mbedtls_free(group_list);
                return MBEDTLS_ERR_SSL_BAD_CONFIG;
            }
            group_list[i] = tls_id;
        }
        group_list[length] = 0;
        ssl->handshake->group_list = group_list;
        ssl->handshake->group_list_heap_allocated = 1;
    } else {
        ssl->handshake->group_list = ssl->conf->group_list;
        ssl->handshake->group_list_heap_allocated = 0;
    }
#endif
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (mbedtls_ssl_conf_is_tls12_only(ssl->conf) &&
        ssl->conf->sig_hashes != NULL) {
        const int *md;
        const int *sig_hashes = ssl->conf->sig_hashes;
        size_t sig_algs_len = 0;
        uint16_t *p;
        MBEDTLS_STATIC_ASSERT(MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN
                              <= (SIZE_MAX - (2 * sizeof(uint16_t))),
                              "MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN too big");
        for (md = sig_hashes; *md != MBEDTLS_MD_NONE; md++) {
            if (mbedtls_ssl_hash_from_md_alg(*md) == MBEDTLS_SSL_HASH_NONE) {
                continue;
            }
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
            sig_algs_len += sizeof(uint16_t);
#endif
#if defined(MBEDTLS_RSA_C)
            sig_algs_len += sizeof(uint16_t);
#endif
            if (sig_algs_len > MBEDTLS_SSL_MAX_SIG_ALG_LIST_LEN) {
                return MBEDTLS_ERR_SSL_BAD_CONFIG;
            }
        }
        if (sig_algs_len < MBEDTLS_SSL_MIN_SIG_ALG_LIST_LEN) {
            return MBEDTLS_ERR_SSL_BAD_CONFIG;
        }
        ssl->handshake->sig_algs = mbedtls_calloc(1, sig_algs_len +
                                                  sizeof(uint16_t));
        if (ssl->handshake->sig_algs == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        p = (uint16_t *) ssl->handshake->sig_algs;
        for (md = sig_hashes; *md != MBEDTLS_MD_NONE; md++) {
            unsigned char hash = mbedtls_ssl_hash_from_md_alg(*md);
            if (hash == MBEDTLS_SSL_HASH_NONE) {
                continue;
            }
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
            *p = ((hash << 8) | MBEDTLS_SSL_SIG_ECDSA);
            p++;
#endif
#if defined(MBEDTLS_RSA_C)
            *p = ((hash << 8) | MBEDTLS_SSL_SIG_RSA);
            p++;
#endif
        }
        *p = MBEDTLS_TLS_SIG_NONE;
        ssl->handshake->sig_algs_heap_allocated = 1;
    } else
#endif
    {
        ssl->handshake->sig_algs_heap_allocated = 0;
    }
#endif
#endif
    return 0;
}
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_cookie_write_dummy(void *ctx,
                                  unsigned char **p, unsigned char *end,
                                  const unsigned char *cli_id, size_t cli_id_len)
{
    ((void) ctx);
    ((void) p);
    ((void) end);
    ((void) cli_id);
    ((void) cli_id_len);
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_cookie_check_dummy(void *ctx,
                                  const unsigned char *cookie, size_t cookie_len,
                                  const unsigned char *cli_id, size_t cli_id_len)
{
    ((void) ctx);
    ((void) cookie);
    ((void) cookie_len);
    ((void) cli_id);
    ((void) cli_id_len);
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif
void mbedtls_ssl_init(mbedtls_ssl_context *ssl)
{
    memset(ssl, 0, sizeof(mbedtls_ssl_context));
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_version_check(const mbedtls_ssl_context *ssl)
{
    const mbedtls_ssl_config *conf = ssl->conf;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (mbedtls_ssl_conf_is_tls13_only(conf)) {
        if (conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS 1.3 is not yet supported."));
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }
        MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is tls13 only."));
        return 0;
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (mbedtls_ssl_conf_is_tls12_only(conf)) {
        MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is tls12 only."));
        return 0;
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (mbedtls_ssl_conf_is_hybrid_tls12_tls13(conf)) {
        if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS not yet supported in Hybrid TLS 1.3 + TLS 1.2"));
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }
        MBEDTLS_SSL_DEBUG_MSG(4, ("The SSL configuration is TLS 1.3 or TLS 1.2."));
        return 0;
    }
#endif
    MBEDTLS_SSL_DEBUG_MSG(1, ("The SSL configuration is invalid."));
    return MBEDTLS_ERR_SSL_BAD_CONFIG;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_check(const mbedtls_ssl_context *ssl)
{
    int ret;
    ret = ssl_conf_version_check(ssl);
    if (ret != 0) {
        return ret;
    }
    if (ssl->conf->f_rng == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("no RNG provided"));
        return MBEDTLS_ERR_SSL_NO_RNG;
    }
    return 0;
}
int mbedtls_ssl_setup(mbedtls_ssl_context *ssl,
                      const mbedtls_ssl_config *conf)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
    size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;
    ssl->conf = conf;
    if ((ret = ssl_conf_check(ssl)) != 0) {
        return ret;
    }
    ssl->tls_version = ssl->conf->max_tls_version;
    ssl->out_buf = NULL;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->in_buf_len = in_buf_len;
#endif
    ssl->in_buf = mbedtls_calloc(1, in_buf_len);
    if (ssl->in_buf == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" MBEDTLS_PRINTF_SIZET " bytes) failed", in_buf_len));
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto error;
    }
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->out_buf_len = out_buf_len;
#endif
    ssl->out_buf = mbedtls_calloc(1, out_buf_len);
    if (ssl->out_buf == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" MBEDTLS_PRINTF_SIZET " bytes) failed", out_buf_len));
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto error;
    }
    mbedtls_ssl_reset_in_out_pointers(ssl);
#if defined(MBEDTLS_SSL_DTLS_SRTP)
    memset(&ssl->dtls_srtp_info, 0, sizeof(ssl->dtls_srtp_info));
#endif
    if ((ret = ssl_handshake_init(ssl)) != 0) {
        goto error;
    }
    return 0;
error:
    mbedtls_free(ssl->in_buf);
    mbedtls_free(ssl->out_buf);
    ssl->conf = NULL;
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    ssl->in_buf_len = 0;
    ssl->out_buf_len = 0;
#endif
    ssl->in_buf = NULL;
    ssl->out_buf = NULL;
    ssl->in_hdr = NULL;
    ssl->in_ctr = NULL;
    ssl->in_len = NULL;
    ssl->in_iv = NULL;
    ssl->in_msg = NULL;
    ssl->out_hdr = NULL;
    ssl->out_ctr = NULL;
    ssl->out_len = NULL;
    ssl->out_iv = NULL;
    ssl->out_msg = NULL;
    return ret;
}
void mbedtls_ssl_session_reset_msg_layer(mbedtls_ssl_context *ssl,
                                         int partial)
{
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t in_buf_len = ssl->in_buf_len;
    size_t out_buf_len = ssl->out_buf_len;
#else
    size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
    size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif
#if !defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE) || !defined(MBEDTLS_SSL_SRV_C)
    partial = 0;
#endif
    mbedtls_ssl_set_timer(ssl, 0);
    mbedtls_ssl_reset_in_out_pointers(ssl);
    ssl->in_offt = NULL;
    ssl->nb_zero = 0;
    ssl->in_msgtype = 0;
    ssl->in_msglen = 0;
    ssl->in_hslen = 0;
    ssl->keep_current_message = 0;
    ssl->transform_in = NULL;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    ssl->next_record_offset = 0;
    ssl->in_epoch = 0;
#endif
    if (partial == 0) {
        ssl->in_left = 0;
        memset(ssl->in_buf, 0, in_buf_len);
    }
    ssl->send_alert = 0;
    ssl->out_msgtype = 0;
    ssl->out_msglen = 0;
    ssl->out_left = 0;
    memset(ssl->out_buf, 0, out_buf_len);
    memset(ssl->cur_out_ctr, 0, sizeof(ssl->cur_out_ctr));
    ssl->transform_out = NULL;
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    mbedtls_ssl_dtls_replay_reset(ssl);
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->transform) {
        mbedtls_ssl_transform_free(ssl->transform);
        mbedtls_free(ssl->transform);
        ssl->transform = NULL;
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_transform_free(ssl->transform_application);
    mbedtls_free(ssl->transform_application);
    ssl->transform_application = NULL;
    if (ssl->handshake != NULL) {
#if defined(MBEDTLS_SSL_EARLY_DATA)
        mbedtls_ssl_transform_free(ssl->handshake->transform_earlydata);
        mbedtls_free(ssl->handshake->transform_earlydata);
        ssl->handshake->transform_earlydata = NULL;
#endif
        mbedtls_ssl_transform_free(ssl->handshake->transform_handshake);
        mbedtls_free(ssl->handshake->transform_handshake);
        ssl->handshake->transform_handshake = NULL;
    }
#endif
}
int mbedtls_ssl_session_reset_int(mbedtls_ssl_context *ssl, int partial)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ssl->state = MBEDTLS_SSL_HELLO_REQUEST;
    ssl->tls_version = ssl->conf->max_tls_version;
    mbedtls_ssl_session_reset_msg_layer(ssl, partial);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ssl->renego_status = MBEDTLS_SSL_INITIAL_HANDSHAKE;
    ssl->renego_records_seen = 0;
    ssl->verify_data_len = 0;
    memset(ssl->own_verify_data, 0, MBEDTLS_SSL_VERIFY_DATA_MAX_LEN);
    memset(ssl->peer_verify_data, 0, MBEDTLS_SSL_VERIFY_DATA_MAX_LEN);
#endif
    ssl->secure_renegotiation = MBEDTLS_SSL_LEGACY_RENEGOTIATION;
    ssl->session_in = NULL;
    ssl->session_out = NULL;
    if (ssl->session) {
        mbedtls_ssl_session_free(ssl->session);
        mbedtls_free(ssl->session);
        ssl->session = NULL;
    }
#if defined(MBEDTLS_SSL_ALPN)
    ssl->alpn_chosen = NULL;
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    int free_cli_id = 1;
#if defined(MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE)
    free_cli_id = (partial == 0);
#endif
    if (free_cli_id) {
        mbedtls_free(ssl->cli_id);
        ssl->cli_id = NULL;
        ssl->cli_id_len = 0;
    }
#endif
    if ((ret = ssl_handshake_init(ssl)) != 0) {
        return ret;
    }
    return 0;
}
int mbedtls_ssl_session_reset(mbedtls_ssl_context *ssl)
{
    return mbedtls_ssl_session_reset_int(ssl, 0);
}
void mbedtls_ssl_conf_endpoint(mbedtls_ssl_config *conf, int endpoint)
{
    conf->endpoint = endpoint;
}
void mbedtls_ssl_conf_transport(mbedtls_ssl_config *conf, int transport)
{
    conf->transport = transport;
}
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
void mbedtls_ssl_conf_dtls_anti_replay(mbedtls_ssl_config *conf, char mode)
{
    conf->anti_replay = mode;
}
#endif
void mbedtls_ssl_conf_dtls_badmac_limit(mbedtls_ssl_config *conf, unsigned limit)
{
    conf->badmac_limit = limit;
}
#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_set_datagram_packing(mbedtls_ssl_context *ssl,
                                      unsigned allow_packing)
{
    ssl->disable_datagram_packing = !allow_packing;
}
void mbedtls_ssl_conf_handshake_timeout(mbedtls_ssl_config *conf,
                                        uint32_t min, uint32_t max)
{
    conf->hs_timeout_min = min;
    conf->hs_timeout_max = max;
}
#endif
void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode)
{
    conf->authmode = authmode;
}
#if defined(MBEDTLS_X509_CRT_PARSE_C)
void mbedtls_ssl_conf_verify(mbedtls_ssl_config *conf,
                             int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                             void *p_vrfy)
{
    conf->f_vrfy = f_vrfy;
    conf->p_vrfy = p_vrfy;
}
#endif
void mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng)
{
    conf->f_rng = f_rng;
    conf->p_rng = p_rng;
}
void mbedtls_ssl_conf_dbg(mbedtls_ssl_config *conf,
                          void (*f_dbg)(void *, int, const char *, int, const char *),
                          void *p_dbg)
{
    conf->f_dbg = f_dbg;
    conf->p_dbg = p_dbg;
}
void mbedtls_ssl_set_bio(mbedtls_ssl_context *ssl,
                         void *p_bio,
                         mbedtls_ssl_send_t *f_send,
                         mbedtls_ssl_recv_t *f_recv,
                         mbedtls_ssl_recv_timeout_t *f_recv_timeout)
{
    ssl->p_bio = p_bio;
    ssl->f_send = f_send;
    ssl->f_recv = f_recv;
    ssl->f_recv_timeout = f_recv_timeout;
}
#if defined(MBEDTLS_SSL_PROTO_DTLS)
void mbedtls_ssl_set_mtu(mbedtls_ssl_context *ssl, uint16_t mtu)
{
    ssl->mtu = mtu;
}
#endif
void mbedtls_ssl_conf_read_timeout(mbedtls_ssl_config *conf, uint32_t timeout)
{
    conf->read_timeout = timeout;
}
void mbedtls_ssl_set_timer_cb(mbedtls_ssl_context *ssl,
                              void *p_timer,
                              mbedtls_ssl_set_timer_t *f_set_timer,
                              mbedtls_ssl_get_timer_t *f_get_timer)
{
    ssl->p_timer = p_timer;
    ssl->f_set_timer = f_set_timer;
    ssl->f_get_timer = f_get_timer;
    mbedtls_ssl_set_timer(ssl, 0);
}
#if defined(MBEDTLS_SSL_SRV_C)
void mbedtls_ssl_conf_session_cache(mbedtls_ssl_config *conf,
                                    void *p_cache,
                                    mbedtls_ssl_cache_get_t *f_get_cache,
                                    mbedtls_ssl_cache_set_t *f_set_cache)
{
    conf->p_cache = p_cache;
    conf->f_get_cache = f_get_cache;
    conf->f_set_cache = f_set_cache;
}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
int mbedtls_ssl_set_session(mbedtls_ssl_context *ssl, const mbedtls_ssl_session *session)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (ssl == NULL ||
        session == NULL ||
        ssl->session_negotiate == NULL ||
        ssl->conf->endpoint != MBEDTLS_SSL_IS_CLIENT) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->handshake->resume == 1) {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (session->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
        const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
            mbedtls_ssl_ciphersuite_from_id(session->ciphersuite);
        if (mbedtls_ssl_validate_ciphersuite(
                ssl, ciphersuite_info, MBEDTLS_SSL_VERSION_TLS1_3,
                MBEDTLS_SSL_VERSION_TLS1_3) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(4, ("%d is not a valid TLS 1.3 ciphersuite.",
                                      session->ciphersuite));
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
#else
        return 0;
#endif
    }
#endif
    if ((ret = mbedtls_ssl_session_copy(ssl->session_negotiate,
                                        session)) != 0) {
        return ret;
    }
    ssl->handshake->resume = 1;
    return 0;
}
#endif
void mbedtls_ssl_conf_ciphersuites(mbedtls_ssl_config *conf,
                                   const int *ciphersuites)
{
    conf->ciphersuite_list = ciphersuites;
}
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
void mbedtls_ssl_conf_tls13_key_exchange_modes(mbedtls_ssl_config *conf,
                                               const int kex_modes)
{
    conf->tls13_kex_modes = kex_modes & MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL;
}
#if defined(MBEDTLS_SSL_EARLY_DATA)
void mbedtls_ssl_conf_early_data(mbedtls_ssl_config *conf,
                                 int early_data_enabled)
{
    conf->early_data_enabled = early_data_enabled;
}
#if defined(MBEDTLS_SSL_SRV_C)
void mbedtls_ssl_conf_max_early_data_size(
    mbedtls_ssl_config *conf, uint32_t max_early_data_size)
{
    conf->max_early_data_size = max_early_data_size;
}
#endif
#endif
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
void mbedtls_ssl_conf_cert_profile(mbedtls_ssl_config *conf,
                                   const mbedtls_x509_crt_profile *profile)
{
    conf->cert_profile = profile;
}
static void ssl_key_cert_free(mbedtls_ssl_key_cert *key_cert)
{
    mbedtls_ssl_key_cert *cur = key_cert, *next;
    while (cur != NULL) {
        next = cur->next;
        mbedtls_free(cur);
        cur = next;
    }
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_append_key_cert(mbedtls_ssl_key_cert **head,
                               mbedtls_x509_crt *cert,
                               mbedtls_pk_context *key)
{
    mbedtls_ssl_key_cert *new_cert;
    if (cert == NULL) {
        ssl_key_cert_free(*head);
        *head = NULL;
        return 0;
    }
    new_cert = mbedtls_calloc(1, sizeof(mbedtls_ssl_key_cert));
    if (new_cert == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    new_cert->cert = cert;
    new_cert->key = key;
    new_cert->next = NULL;
    if (*head == NULL) {
        *head = new_cert;
    } else {
        mbedtls_ssl_key_cert *cur = *head;
        while (cur->next != NULL) {
            cur = cur->next;
        }
        cur->next = new_cert;
    }
    return 0;
}
int mbedtls_ssl_conf_own_cert(mbedtls_ssl_config *conf,
                              mbedtls_x509_crt *own_cert,
                              mbedtls_pk_context *pk_key)
{
    return ssl_append_key_cert(&conf->key_cert, own_cert, pk_key);
}
void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config *conf,
                               mbedtls_x509_crt *ca_chain,
                               mbedtls_x509_crl *ca_crl)
{
    conf->ca_chain = ca_chain;
    conf->ca_crl = ca_crl;
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    conf->f_ca_cb = NULL;
    conf->p_ca_cb = NULL;
#endif
}
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
void mbedtls_ssl_conf_ca_cb(mbedtls_ssl_config *conf,
                            mbedtls_x509_crt_ca_cb_t f_ca_cb,
                            void *p_ca_cb)
{
    conf->f_ca_cb = f_ca_cb;
    conf->p_ca_cb = p_ca_cb;
    conf->ca_chain = NULL;
    conf->ca_crl = NULL;
}
#endif
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
const unsigned char *mbedtls_ssl_get_hs_sni(mbedtls_ssl_context *ssl,
                                            size_t *name_len)
{
    *name_len = ssl->handshake->sni_name_len;
    return ssl->handshake->sni_name;
}
int mbedtls_ssl_set_hs_own_cert(mbedtls_ssl_context *ssl,
                                mbedtls_x509_crt *own_cert,
                                mbedtls_pk_context *pk_key)
{
    return ssl_append_key_cert(&ssl->handshake->sni_key_cert,
                               own_cert, pk_key);
}
void mbedtls_ssl_set_hs_ca_chain(mbedtls_ssl_context *ssl,
                                 mbedtls_x509_crt *ca_chain,
                                 mbedtls_x509_crl *ca_crl)
{
    ssl->handshake->sni_ca_chain = ca_chain;
    ssl->handshake->sni_ca_crl = ca_crl;
}
#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
void mbedtls_ssl_set_hs_dn_hints(mbedtls_ssl_context *ssl,
                                 const mbedtls_x509_crt *crt)
{
    ssl->handshake->dn_hints = crt;
}
#endif
void mbedtls_ssl_set_hs_authmode(mbedtls_ssl_context *ssl,
                                 int authmode)
{
    ssl->handshake->sni_authmode = authmode;
}
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
void mbedtls_ssl_set_verify(mbedtls_ssl_context *ssl,
                            int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy)
{
    ssl->f_vrfy = f_vrfy;
    ssl->p_vrfy = p_vrfy;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
static const uint8_t jpake_server_id[] = { 's', 'e', 'r', 'v', 'e', 'r' };
static const uint8_t jpake_client_id[] = { 'c', 'l', 'i', 'e', 'n', 't' };
static psa_status_t mbedtls_ssl_set_hs_ecjpake_password_common(
    mbedtls_ssl_context *ssl,
    mbedtls_svc_key_id_t pwd)
{
    psa_status_t status;
    psa_pake_cipher_suite_t cipher_suite = psa_pake_cipher_suite_init();
    const uint8_t *user = NULL;
    size_t user_len = 0;
    const uint8_t *peer = NULL;
    size_t peer_len = 0;
    psa_pake_cs_set_algorithm(&cipher_suite, PSA_ALG_JPAKE);
    psa_pake_cs_set_primitive(&cipher_suite,
                              PSA_PAKE_PRIMITIVE(PSA_PAKE_PRIMITIVE_TYPE_ECC,
                                                 PSA_ECC_FAMILY_SECP_R1,
                                                 256));
    psa_pake_cs_set_hash(&cipher_suite, PSA_ALG_SHA_256);
    status = psa_pake_setup(&ssl->handshake->psa_pake_ctx, &cipher_suite);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
        user = jpake_server_id;
        user_len = sizeof(jpake_server_id);
        peer = jpake_client_id;
        peer_len = sizeof(jpake_client_id);
    } else {
        user = jpake_client_id;
        user_len = sizeof(jpake_client_id);
        peer = jpake_server_id;
        peer_len = sizeof(jpake_server_id);
    }
    status = psa_pake_set_user(&ssl->handshake->psa_pake_ctx, user, user_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_pake_set_peer(&ssl->handshake->psa_pake_ctx, peer, peer_len);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_pake_set_password_key(&ssl->handshake->psa_pake_ctx, pwd);
    if (status != PSA_SUCCESS) {
        return status;
    }
    ssl->handshake->psa_pake_ctx_is_ok = 1;
    return PSA_SUCCESS;
}
int mbedtls_ssl_set_hs_ecjpake_password(mbedtls_ssl_context *ssl,
                                        const unsigned char *pw,
                                        size_t pw_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t status;
    if (ssl->handshake == NULL || ssl->conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if ((pw == NULL) || (pw_len == 0)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_JPAKE);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_PASSWORD);
    status = psa_import_key(&attributes, pw, pw_len,
                            &ssl->handshake->psa_pake_password);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    status = mbedtls_ssl_set_hs_ecjpake_password_common(ssl,
                                                        ssl->handshake->psa_pake_password);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(ssl->handshake->psa_pake_password);
        psa_pake_abort(&ssl->handshake->psa_pake_ctx);
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    return 0;
}
int mbedtls_ssl_set_hs_ecjpake_password_opaque(mbedtls_ssl_context *ssl,
                                               mbedtls_svc_key_id_t pwd)
{
    psa_status_t status;
    if (ssl->handshake == NULL || ssl->conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (mbedtls_svc_key_id_is_null(pwd)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    status = mbedtls_ssl_set_hs_ecjpake_password_common(ssl, pwd);
    if (status != PSA_SUCCESS) {
        psa_pake_abort(&ssl->handshake->psa_pake_ctx);
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    return 0;
}
#else
int mbedtls_ssl_set_hs_ecjpake_password(mbedtls_ssl_context *ssl,
                                        const unsigned char *pw,
                                        size_t pw_len)
{
    mbedtls_ecjpake_role role;
    if (ssl->handshake == NULL || ssl->conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if ((pw == NULL) || (pw_len == 0)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
        role = MBEDTLS_ECJPAKE_SERVER;
    } else {
        role = MBEDTLS_ECJPAKE_CLIENT;
    }
    return mbedtls_ecjpake_setup(&ssl->handshake->ecjpake_ctx,
                                 role,
                                 MBEDTLS_MD_SHA256,
                                 MBEDTLS_ECP_DP_SECP256R1,
                                 pw, pw_len);
}
#endif
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
int mbedtls_ssl_conf_has_static_psk(mbedtls_ssl_config const *conf)
{
    if (conf->psk_identity == NULL ||
        conf->psk_identity_len == 0) {
        return 0;
    }
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (!mbedtls_svc_key_id_is_null(conf->psk_opaque)) {
        return 1;
    }
#endif
    if (conf->psk != NULL && conf->psk_len != 0) {
        return 1;
    }
    return 0;
}
static void ssl_conf_remove_psk(mbedtls_ssl_config *conf)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (!mbedtls_svc_key_id_is_null(conf->psk_opaque)) {
        conf->psk_opaque = MBEDTLS_SVC_KEY_ID_INIT;
    }
#endif
    if (conf->psk != NULL) {
        mbedtls_zeroize_and_free(conf->psk, conf->psk_len);
        conf->psk = NULL;
        conf->psk_len = 0;
    }
    if (conf->psk_identity != NULL) {
        mbedtls_free(conf->psk_identity);
        conf->psk_identity = NULL;
        conf->psk_identity_len = 0;
    }
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_set_psk_identity(mbedtls_ssl_config *conf,
                                     unsigned char const *psk_identity,
                                     size_t psk_identity_len)
{
    if (psk_identity == NULL ||
        psk_identity_len == 0 ||
        (psk_identity_len >> 16) != 0 ||
        psk_identity_len > MBEDTLS_SSL_OUT_CONTENT_LEN) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    conf->psk_identity = mbedtls_calloc(1, psk_identity_len);
    if (conf->psk_identity == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    conf->psk_identity_len = psk_identity_len;
    memcpy(conf->psk_identity, psk_identity, conf->psk_identity_len);
    return 0;
}
int mbedtls_ssl_conf_psk(mbedtls_ssl_config *conf,
                         const unsigned char *psk, size_t psk_len,
                         const unsigned char *psk_identity, size_t psk_identity_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (mbedtls_ssl_conf_has_static_psk(conf)) {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    if (psk == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (psk_len == 0) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (psk_len > MBEDTLS_PSK_MAX_LEN) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if ((conf->psk = mbedtls_calloc(1, psk_len)) == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    conf->psk_len = psk_len;
    memcpy(conf->psk, psk, conf->psk_len);
    ret = ssl_conf_set_psk_identity(conf, psk_identity, psk_identity_len);
    if (ret != 0) {
        ssl_conf_remove_psk(conf);
    }
    return ret;
}
static void ssl_remove_psk(mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (!mbedtls_svc_key_id_is_null(ssl->handshake->psk_opaque)) {
        if (ssl->handshake->psk_opaque_is_internal) {
            psa_destroy_key(ssl->handshake->psk_opaque);
            ssl->handshake->psk_opaque_is_internal = 0;
        }
        ssl->handshake->psk_opaque = MBEDTLS_SVC_KEY_ID_INIT;
    }
#else
    if (ssl->handshake->psk != NULL) {
        mbedtls_zeroize_and_free(ssl->handshake->psk,
                                 ssl->handshake->psk_len);
        ssl->handshake->psk_len = 0;
        ssl->handshake->psk = NULL;
    }
#endif
}
int mbedtls_ssl_set_hs_psk(mbedtls_ssl_context *ssl,
                           const unsigned char *psk, size_t psk_len)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_key_attributes_t key_attributes = psa_key_attributes_init();
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_algorithm_t alg = PSA_ALG_NONE;
    mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
#endif
    if (psk == NULL || ssl->handshake == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (psk_len > MBEDTLS_PSK_MAX_LEN) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl_remove_psk(ssl);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2) {
        if (ssl->handshake->ciphersuite_info->mac == MBEDTLS_MD_SHA384) {
            alg = PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_384);
        } else {
            alg = PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256);
        }
        psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        alg = PSA_ALG_HKDF_EXTRACT(PSA_ALG_ANY_HASH);
        psa_set_key_usage_flags(&key_attributes,
                                PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    }
#endif
    psa_set_key_algorithm(&key_attributes, alg);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_DERIVE);
    status = psa_import_key(&key_attributes, psk, psk_len, &key);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    ssl->handshake->psk_opaque_is_internal = 1;
    return mbedtls_ssl_set_hs_psk_opaque(ssl, key);
#else
    if ((ssl->handshake->psk = mbedtls_calloc(1, psk_len)) == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    ssl->handshake->psk_len = psk_len;
    memcpy(ssl->handshake->psk, psk, ssl->handshake->psk_len);
    return 0;
#endif
}
#if defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_ssl_conf_psk_opaque(mbedtls_ssl_config *conf,
                                mbedtls_svc_key_id_t psk,
                                const unsigned char *psk_identity,
                                size_t psk_identity_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (mbedtls_ssl_conf_has_static_psk(conf)) {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    if (mbedtls_svc_key_id_is_null(psk)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    conf->psk_opaque = psk;
    ret = ssl_conf_set_psk_identity(conf, psk_identity,
                                    psk_identity_len);
    if (ret != 0) {
        ssl_conf_remove_psk(conf);
    }
    return ret;
}
int mbedtls_ssl_set_hs_psk_opaque(mbedtls_ssl_context *ssl,
                                  mbedtls_svc_key_id_t psk)
{
    if ((mbedtls_svc_key_id_is_null(psk)) ||
        (ssl->handshake == NULL)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl_remove_psk(ssl);
    ssl->handshake->psk_opaque = psk;
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_SRV_C)
void mbedtls_ssl_conf_psk_cb(mbedtls_ssl_config *conf,
                             int (*f_psk)(void *, mbedtls_ssl_context *, const unsigned char *,
                                          size_t),
                             void *p_psk)
{
    conf->f_psk = f_psk;
    conf->p_psk = p_psk;
}
#endif
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
static mbedtls_ssl_mode_t mbedtls_ssl_get_base_mode(
    psa_algorithm_t alg)
{
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    if (alg == PSA_ALG_CBC_NO_PADDING) {
        return MBEDTLS_SSL_MODE_CBC;
    }
#endif
    if (PSA_ALG_IS_AEAD(alg)) {
        return MBEDTLS_SSL_MODE_AEAD;
    }
    return MBEDTLS_SSL_MODE_STREAM;
}
#else
static mbedtls_ssl_mode_t mbedtls_ssl_get_base_mode(
    mbedtls_cipher_mode_t mode)
{
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    if (mode == MBEDTLS_MODE_CBC) {
        return MBEDTLS_SSL_MODE_CBC;
    }
#endif
#if defined(MBEDTLS_GCM_C) || \
    defined(MBEDTLS_CCM_C) || \
    defined(MBEDTLS_CHACHAPOLY_C)
    if (mode == MBEDTLS_MODE_GCM ||
        mode == MBEDTLS_MODE_CCM ||
        mode == MBEDTLS_MODE_CHACHAPOLY) {
        return MBEDTLS_SSL_MODE_AEAD;
    }
#endif
    return MBEDTLS_SSL_MODE_STREAM;
}
#endif
static mbedtls_ssl_mode_t mbedtls_ssl_get_actual_mode(
    mbedtls_ssl_mode_t base_mode,
    int encrypt_then_mac)
{
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    if (encrypt_then_mac == MBEDTLS_SSL_ETM_ENABLED &&
        base_mode == MBEDTLS_SSL_MODE_CBC) {
        return MBEDTLS_SSL_MODE_CBC_ETM;
    }
#else
    (void) encrypt_then_mac;
#endif
    return base_mode;
}
mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_transform(
    const mbedtls_ssl_transform *transform)
{
    mbedtls_ssl_mode_t base_mode = mbedtls_ssl_get_base_mode(
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        transform->psa_alg
#else
        mbedtls_cipher_get_cipher_mode(&transform->cipher_ctx_enc)
#endif
        );
    int encrypt_then_mac = 0;
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    encrypt_then_mac = transform->encrypt_then_mac;
#endif
    return mbedtls_ssl_get_actual_mode(base_mode, encrypt_then_mac);
}
mbedtls_ssl_mode_t mbedtls_ssl_get_mode_from_ciphersuite(
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    int encrypt_then_mac,
#endif
    const mbedtls_ssl_ciphersuite_t *suite)
{
    mbedtls_ssl_mode_t base_mode = MBEDTLS_SSL_MODE_STREAM;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status;
    psa_algorithm_t alg;
    psa_key_type_t type;
    size_t size;
    status = mbedtls_ssl_cipher_to_psa((mbedtls_cipher_type_t) suite->cipher,
                                       0, &alg, &type, &size);
    if (status == PSA_SUCCESS) {
        base_mode = mbedtls_ssl_get_base_mode(alg);
    }
#else
    const mbedtls_cipher_info_t *cipher =
        mbedtls_cipher_info_from_type((mbedtls_cipher_type_t) suite->cipher);
    if (cipher != NULL) {
        base_mode =
            mbedtls_ssl_get_base_mode(
                mbedtls_cipher_info_get_mode(cipher));
    }
#endif
#if !defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    int encrypt_then_mac = 0;
#endif
    return mbedtls_ssl_get_actual_mode(base_mode, encrypt_then_mac);
}
#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
psa_status_t mbedtls_ssl_cipher_to_psa(mbedtls_cipher_type_t mbedtls_cipher_type,
                                       size_t taglen,
                                       psa_algorithm_t *alg,
                                       psa_key_type_t *key_type,
                                       size_t *key_size)
{
#if !defined(MBEDTLS_SSL_HAVE_CCM)
    (void) taglen;
#endif
    switch (mbedtls_cipher_type) {
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_CBC)
        case MBEDTLS_CIPHER_AES_128_CBC:
            *alg = PSA_ALG_CBC_NO_PADDING;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_AES_128_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_AES_128_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_AES_192_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 192;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_AES_192_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 192;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_CBC)
        case MBEDTLS_CIPHER_AES_256_CBC:
            *alg = PSA_ALG_CBC_NO_PADDING;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_AES_256_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_AES_256_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_AES;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_CBC)
        case MBEDTLS_CIPHER_ARIA_128_CBC:
            *alg = PSA_ALG_CBC_NO_PADDING;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_ARIA_128_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_ARIA_128_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_ARIA_192_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 192;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_ARIA_192_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 192;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_CBC)
        case MBEDTLS_CIPHER_ARIA_256_CBC:
            *alg = PSA_ALG_CBC_NO_PADDING;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_ARIA_256_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_ARIA) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_ARIA_256_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_ARIA;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_CBC)
        case MBEDTLS_CIPHER_CAMELLIA_128_CBC:
            *alg = PSA_ALG_CBC_NO_PADDING;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_CAMELLIA_128_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_CAMELLIA_128_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 128;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_CAMELLIA_192_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 192;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_CAMELLIA_192_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 192;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_CBC)
        case MBEDTLS_CIPHER_CAMELLIA_256_CBC:
            *alg = PSA_ALG_CBC_NO_PADDING;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_CCM)
        case MBEDTLS_CIPHER_CAMELLIA_256_CCM:
            *alg = taglen ? PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen) : PSA_ALG_CCM;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CAMELLIA) && defined(MBEDTLS_SSL_HAVE_GCM)
        case MBEDTLS_CIPHER_CAMELLIA_256_GCM:
            *alg = PSA_ALG_GCM;
            *key_type = PSA_KEY_TYPE_CAMELLIA;
            *key_size = 256;
            break;
#endif
#if defined(MBEDTLS_SSL_HAVE_CHACHAPOLY)
        case MBEDTLS_CIPHER_CHACHA20_POLY1305:
            *alg = PSA_ALG_CHACHA20_POLY1305;
            *key_type = PSA_KEY_TYPE_CHACHA20;
            *key_size = 256;
            break;
#endif
        case MBEDTLS_CIPHER_NULL:
            *alg = MBEDTLS_SSL_NULL_CIPHER;
            *key_type = 0;
            *key_size = 0;
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}
#endif
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
int mbedtls_ssl_conf_dh_param_bin(mbedtls_ssl_config *conf,
                                  const unsigned char *dhm_P, size_t P_len,
                                  const unsigned char *dhm_G, size_t G_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_free(&conf->dhm_P);
    mbedtls_mpi_free(&conf->dhm_G);
    if ((ret = mbedtls_mpi_read_binary(&conf->dhm_P, dhm_P, P_len)) != 0 ||
        (ret = mbedtls_mpi_read_binary(&conf->dhm_G, dhm_G, G_len)) != 0) {
        mbedtls_mpi_free(&conf->dhm_P);
        mbedtls_mpi_free(&conf->dhm_G);
        return ret;
    }
    return 0;
}
int mbedtls_ssl_conf_dh_param_ctx(mbedtls_ssl_config *conf, mbedtls_dhm_context *dhm_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_free(&conf->dhm_P);
    mbedtls_mpi_free(&conf->dhm_G);
    if ((ret = mbedtls_dhm_get_value(dhm_ctx, MBEDTLS_DHM_PARAM_P,
                                     &conf->dhm_P)) != 0 ||
        (ret = mbedtls_dhm_get_value(dhm_ctx, MBEDTLS_DHM_PARAM_G,
                                     &conf->dhm_G)) != 0) {
        mbedtls_mpi_free(&conf->dhm_P);
        mbedtls_mpi_free(&conf->dhm_G);
        return ret;
    }
    return 0;
}
#endif
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_CLI_C)
void mbedtls_ssl_conf_dhm_min_bitlen(mbedtls_ssl_config *conf,
                                     unsigned int bitlen)
{
    conf->dhm_min_bitlen = bitlen;
}
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && defined(MBEDTLS_SSL_PROTO_TLS1_2)
void mbedtls_ssl_conf_sig_hashes(mbedtls_ssl_config *conf,
                                 const int *hashes)
{
    conf->sig_hashes = hashes;
}
#endif
void mbedtls_ssl_conf_sig_algs(mbedtls_ssl_config *conf,
                               const uint16_t *sig_algs)
{
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    conf->sig_hashes = NULL;
#endif
    conf->sig_algs = sig_algs;
}
#endif
#if defined(MBEDTLS_ECP_C)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_ssl_conf_curves(mbedtls_ssl_config *conf,
                             const mbedtls_ecp_group_id *curve_list)
{
    conf->curve_list = curve_list;
    conf->group_list = NULL;
}
#endif
#endif
void mbedtls_ssl_conf_groups(mbedtls_ssl_config *conf,
                             const uint16_t *group_list)
{
#if defined(MBEDTLS_ECP_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    conf->curve_list = NULL;
#endif
    conf->group_list = group_list;
}
#if defined(MBEDTLS_X509_CRT_PARSE_C)
int mbedtls_ssl_set_hostname(mbedtls_ssl_context *ssl, const char *hostname)
{
    size_t hostname_len = 0;
    if (hostname != NULL) {
        hostname_len = strlen(hostname);
        if (hostname_len > MBEDTLS_SSL_MAX_HOST_NAME_LEN) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }
    if (ssl->hostname != NULL) {
        mbedtls_zeroize_and_free(ssl->hostname, strlen(ssl->hostname));
    }
    if (hostname == NULL) {
        ssl->hostname = NULL;
    } else {
        ssl->hostname = mbedtls_calloc(1, hostname_len + 1);
        if (ssl->hostname == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(ssl->hostname, hostname, hostname_len);
        ssl->hostname[hostname_len] = '\0';
    }
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
void mbedtls_ssl_conf_sni(mbedtls_ssl_config *conf,
                          int (*f_sni)(void *, mbedtls_ssl_context *,
                                       const unsigned char *, size_t),
                          void *p_sni)
{
    conf->f_sni = f_sni;
    conf->p_sni = p_sni;
}
#endif
#if defined(MBEDTLS_SSL_ALPN)
int mbedtls_ssl_conf_alpn_protocols(mbedtls_ssl_config *conf, const char **protos)
{
    size_t cur_len, tot_len;
    const char **p;
    tot_len = 0;
    for (p = protos; *p != NULL; p++) {
        cur_len = strlen(*p);
        tot_len += cur_len;
        if ((cur_len == 0) ||
            (cur_len > MBEDTLS_SSL_MAX_ALPN_NAME_LEN) ||
            (tot_len > MBEDTLS_SSL_MAX_ALPN_LIST_LEN)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }
    conf->alpn_list = protos;
    return 0;
}
const char *mbedtls_ssl_get_alpn_protocol(const mbedtls_ssl_context *ssl)
{
    return ssl->alpn_chosen;
}
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
void mbedtls_ssl_conf_srtp_mki_value_supported(mbedtls_ssl_config *conf,
                                               int support_mki_value)
{
    conf->dtls_srtp_mki_support = support_mki_value;
}
int mbedtls_ssl_dtls_srtp_set_mki_value(mbedtls_ssl_context *ssl,
                                        unsigned char *mki_value,
                                        uint16_t mki_len)
{
    if (mki_len > MBEDTLS_TLS_SRTP_MAX_MKI_LENGTH) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->conf->dtls_srtp_mki_support == MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED) {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    memcpy(ssl->dtls_srtp_info.mki_value, mki_value, mki_len);
    ssl->dtls_srtp_info.mki_len = mki_len;
    return 0;
}
int mbedtls_ssl_conf_dtls_srtp_protection_profiles(mbedtls_ssl_config *conf,
                                                   const mbedtls_ssl_srtp_profile *profiles)
{
    const mbedtls_ssl_srtp_profile *p;
    size_t list_size = 0;
    for (p = profiles; *p != MBEDTLS_TLS_SRTP_UNSET &&
         list_size <= MBEDTLS_TLS_SRTP_MAX_PROFILE_LIST_LENGTH;
         p++) {
        if (mbedtls_ssl_check_srtp_profile_value(*p) != MBEDTLS_TLS_SRTP_UNSET) {
            list_size++;
        } else {
            list_size = MBEDTLS_TLS_SRTP_MAX_PROFILE_LIST_LENGTH + 1;
        }
    }
    if (list_size > MBEDTLS_TLS_SRTP_MAX_PROFILE_LIST_LENGTH) {
        conf->dtls_srtp_profile_list = NULL;
        conf->dtls_srtp_profile_list_len = 0;
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    conf->dtls_srtp_profile_list = profiles;
    conf->dtls_srtp_profile_list_len = list_size;
    return 0;
}
void mbedtls_ssl_get_dtls_srtp_negotiation_result(const mbedtls_ssl_context *ssl,
                                                  mbedtls_dtls_srtp_info *dtls_srtp_info)
{
    dtls_srtp_info->chosen_dtls_srtp_profile = ssl->dtls_srtp_info.chosen_dtls_srtp_profile;
    if (dtls_srtp_info->chosen_dtls_srtp_profile == MBEDTLS_TLS_SRTP_UNSET) {
        dtls_srtp_info->mki_len = 0;
    } else {
        dtls_srtp_info->mki_len = ssl->dtls_srtp_info.mki_len;
        memcpy(dtls_srtp_info->mki_value, ssl->dtls_srtp_info.mki_value,
               ssl->dtls_srtp_info.mki_len);
    }
}
#endif
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_ssl_conf_max_version(mbedtls_ssl_config *conf, int major, int minor)
{
    conf->max_tls_version = (mbedtls_ssl_protocol_version) ((major << 8) | minor);
}
void mbedtls_ssl_conf_min_version(mbedtls_ssl_config *conf, int major, int minor)
{
    conf->min_tls_version = (mbedtls_ssl_protocol_version) ((major << 8) | minor);
}
#endif
#if defined(MBEDTLS_SSL_SRV_C)
void mbedtls_ssl_conf_cert_req_ca_list(mbedtls_ssl_config *conf,
                                       char cert_req_ca_list)
{
    conf->cert_req_ca_list = cert_req_ca_list;
}
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
void mbedtls_ssl_conf_encrypt_then_mac(mbedtls_ssl_config *conf, char etm)
{
    conf->encrypt_then_mac = etm;
}
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
void mbedtls_ssl_conf_extended_master_secret(mbedtls_ssl_config *conf, char ems)
{
    conf->extended_ms = ems;
}
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
int mbedtls_ssl_conf_max_frag_len(mbedtls_ssl_config *conf, unsigned char mfl_code)
{
    if (mfl_code >= MBEDTLS_SSL_MAX_FRAG_LEN_INVALID ||
        ssl_mfl_code_to_length(mfl_code) > MBEDTLS_TLS_EXT_ADV_CONTENT_LEN) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    conf->mfl_code = mfl_code;
    return 0;
}
#endif
void mbedtls_ssl_conf_legacy_renegotiation(mbedtls_ssl_config *conf, int allow_legacy)
{
    conf->allow_legacy_renegotiation = allow_legacy;
}
#if defined(MBEDTLS_SSL_RENEGOTIATION)
void mbedtls_ssl_conf_renegotiation(mbedtls_ssl_config *conf, int renegotiation)
{
    conf->disable_renegotiation = renegotiation;
}
void mbedtls_ssl_conf_renegotiation_enforced(mbedtls_ssl_config *conf, int max_records)
{
    conf->renego_max_records = max_records;
}
void mbedtls_ssl_conf_renegotiation_period(mbedtls_ssl_config *conf,
                                           const unsigned char period[8])
{
    memcpy(conf->renego_period, period, 8);
}
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#if defined(MBEDTLS_SSL_CLI_C)
void mbedtls_ssl_conf_session_tickets(mbedtls_ssl_config *conf, int use_tickets)
{
    conf->session_tickets &= ~MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_MASK;
    conf->session_tickets |= (use_tickets != 0) <<
                             MBEDTLS_SSL_SESSION_TICKETS_TLS1_2_BIT;
}
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
void mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
    mbedtls_ssl_config *conf, int signal_new_session_tickets)
{
    conf->session_tickets &= ~MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_MASK;
    conf->session_tickets |= (signal_new_session_tickets != 0) <<
                             MBEDTLS_SSL_SESSION_TICKETS_TLS1_3_BIT;
}
#endif
#endif
#if defined(MBEDTLS_SSL_SRV_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
void mbedtls_ssl_conf_new_session_tickets(mbedtls_ssl_config *conf,
                                          uint16_t num_tickets)
{
    conf->new_session_tickets_count = num_tickets;
}
#endif
void mbedtls_ssl_conf_session_tickets_cb(mbedtls_ssl_config *conf,
                                         mbedtls_ssl_ticket_write_t *f_ticket_write,
                                         mbedtls_ssl_ticket_parse_t *f_ticket_parse,
                                         void *p_ticket)
{
    conf->f_ticket_write = f_ticket_write;
    conf->f_ticket_parse = f_ticket_parse;
    conf->p_ticket = p_ticket;
}
#endif
#endif
void mbedtls_ssl_set_export_keys_cb(mbedtls_ssl_context *ssl,
                                    mbedtls_ssl_export_keys_t *f_export_keys,
                                    void *p_export_keys)
{
    ssl->f_export_keys = f_export_keys;
    ssl->p_export_keys = p_export_keys;
}
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
void mbedtls_ssl_conf_async_private_cb(
    mbedtls_ssl_config *conf,
    mbedtls_ssl_async_sign_t *f_async_sign,
    mbedtls_ssl_async_decrypt_t *f_async_decrypt,
    mbedtls_ssl_async_resume_t *f_async_resume,
    mbedtls_ssl_async_cancel_t *f_async_cancel,
    void *async_config_data)
{
    conf->f_async_sign_start = f_async_sign;
    conf->f_async_decrypt_start = f_async_decrypt;
    conf->f_async_resume = f_async_resume;
    conf->f_async_cancel = f_async_cancel;
    conf->p_async_config_data = async_config_data;
}
void *mbedtls_ssl_conf_get_async_config_data(const mbedtls_ssl_config *conf)
{
    return conf->p_async_config_data;
}
void *mbedtls_ssl_get_async_operation_data(const mbedtls_ssl_context *ssl)
{
    if (ssl->handshake == NULL) {
        return NULL;
    } else {
        return ssl->handshake->user_async_ctx;
    }
}
void mbedtls_ssl_set_async_operation_data(mbedtls_ssl_context *ssl,
                                          void *ctx)
{
    if (ssl->handshake != NULL) {
        ssl->handshake->user_async_ctx = ctx;
    }
}
#endif
uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context *ssl)
{
    if (ssl->session != NULL) {
        return ssl->session->verify_result;
    }
    if (ssl->session_negotiate != NULL) {
        return ssl->session_negotiate->verify_result;
    }
    return 0xFFFFFFFF;
}
int mbedtls_ssl_get_ciphersuite_id_from_ssl(const mbedtls_ssl_context *ssl)
{
    if (ssl == NULL || ssl->session == NULL) {
        return 0;
    }
    return ssl->session->ciphersuite;
}
const char *mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context *ssl)
{
    if (ssl == NULL || ssl->session == NULL) {
        return NULL;
    }
    return mbedtls_ssl_get_ciphersuite_name(ssl->session->ciphersuite);
}
const char *mbedtls_ssl_get_version(const mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        switch (ssl->tls_version) {
            case MBEDTLS_SSL_VERSION_TLS1_2:
                return "DTLSv1.2";
            default:
                return "unknown (DTLS)";
        }
    }
#endif
    switch (ssl->tls_version) {
        case MBEDTLS_SSL_VERSION_TLS1_2:
            return "TLSv1.2";
        case MBEDTLS_SSL_VERSION_TLS1_3:
            return "TLSv1.3";
        default:
            return "unknown";
    }
}
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
size_t mbedtls_ssl_get_output_record_size_limit(const mbedtls_ssl_context *ssl)
{
    const size_t max_len = MBEDTLS_SSL_OUT_CONTENT_LEN;
    size_t record_size_limit = max_len;
    if (ssl->session != NULL &&
        ssl->session->record_size_limit >= MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN &&
        ssl->session->record_size_limit < max_len) {
        record_size_limit = ssl->session->record_size_limit;
    }
    if (ssl->session_negotiate != NULL &&
        ssl->session_negotiate->record_size_limit >= MBEDTLS_SSL_RECORD_SIZE_LIMIT_MIN &&
        ssl->session_negotiate->record_size_limit < max_len) {
        record_size_limit = ssl->session_negotiate->record_size_limit;
    }
    return record_size_limit;
}
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
size_t mbedtls_ssl_get_input_max_frag_len(const mbedtls_ssl_context *ssl)
{
    size_t max_len = MBEDTLS_SSL_IN_CONTENT_LEN;
    size_t read_mfl;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        ssl->state >= MBEDTLS_SSL_SERVER_HELLO_DONE) {
        return ssl_mfl_code_to_length(ssl->conf->mfl_code);
    }
#endif
    if (ssl->session_out != NULL) {
        read_mfl = ssl_mfl_code_to_length(ssl->session_out->mfl_code);
        if (read_mfl < max_len) {
            max_len = read_mfl;
        }
    }
    if (ssl->session_negotiate != NULL) {
        read_mfl = ssl_mfl_code_to_length(ssl->session_negotiate->mfl_code);
        if (read_mfl < max_len) {
            max_len = read_mfl;
        }
    }
    return max_len;
}
size_t mbedtls_ssl_get_output_max_frag_len(const mbedtls_ssl_context *ssl)
{
    size_t max_len;
    max_len = ssl_mfl_code_to_length(ssl->conf->mfl_code);
    if (ssl->session_out != NULL &&
        ssl_mfl_code_to_length(ssl->session_out->mfl_code) < max_len) {
        max_len = ssl_mfl_code_to_length(ssl->session_out->mfl_code);
    }
    if (ssl->session_negotiate != NULL &&
        ssl_mfl_code_to_length(ssl->session_negotiate->mfl_code) < max_len) {
        max_len = ssl_mfl_code_to_length(ssl->session_negotiate->mfl_code);
    }
    return max_len;
}
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
size_t mbedtls_ssl_get_current_mtu(const mbedtls_ssl_context *ssl)
{
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
        (ssl->state == MBEDTLS_SSL_CLIENT_HELLO ||
         ssl->state == MBEDTLS_SSL_SERVER_HELLO)) {
        return 0;
    }
    if (ssl->handshake == NULL || ssl->handshake->mtu == 0) {
        return ssl->mtu;
    }
    if (ssl->mtu == 0) {
        return ssl->handshake->mtu;
    }
    return ssl->mtu < ssl->handshake->mtu ?
           ssl->mtu : ssl->handshake->mtu;
}
#endif
int mbedtls_ssl_get_max_out_record_payload(const mbedtls_ssl_context *ssl)
{
    size_t max_len = MBEDTLS_SSL_OUT_CONTENT_LEN;
#if !defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) && \
    !defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT) && \
    !defined(MBEDTLS_SSL_PROTO_DTLS)
    (void) ssl;
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    const size_t mfl = mbedtls_ssl_get_output_max_frag_len(ssl);
    if (max_len > mfl) {
        max_len = mfl;
    }
#endif
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    const size_t record_size_limit = mbedtls_ssl_get_output_record_size_limit(ssl);
    if (max_len > record_size_limit) {
        max_len = record_size_limit;
    }
#endif
    if (ssl->transform_out != NULL &&
        ssl->transform_out->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        max_len = ((max_len / MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY) *
                   MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY) - 1;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (mbedtls_ssl_get_current_mtu(ssl) != 0) {
        const size_t mtu = mbedtls_ssl_get_current_mtu(ssl);
        const int ret = mbedtls_ssl_get_record_expansion(ssl);
        const size_t overhead = (size_t) ret;
        if (ret < 0) {
            return ret;
        }
        if (mtu <= overhead) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("MTU too low for record expansion"));
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }
        if (max_len > mtu - overhead) {
            max_len = mtu - overhead;
        }
    }
#endif
#if !defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) && \
    !defined(MBEDTLS_SSL_PROTO_DTLS) && \
    !defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    ((void) ssl);
#endif
    return (int) max_len;
}
int mbedtls_ssl_get_max_in_record_payload(const mbedtls_ssl_context *ssl)
{
    size_t max_len = MBEDTLS_SSL_IN_CONTENT_LEN;
#if !defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    (void) ssl;
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    const size_t mfl = mbedtls_ssl_get_input_max_frag_len(ssl);
    if (max_len > mfl) {
        max_len = mfl;
    }
#endif
    return (int) max_len;
}
#if defined(MBEDTLS_X509_CRT_PARSE_C)
const mbedtls_x509_crt *mbedtls_ssl_get_peer_cert(const mbedtls_ssl_context *ssl)
{
    if (ssl == NULL || ssl->session == NULL) {
        return NULL;
    }
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    return ssl->session->peer_cert;
#else
    return NULL;
#endif
}
#endif
#if defined(MBEDTLS_SSL_CLI_C)
int mbedtls_ssl_get_session(const mbedtls_ssl_context *ssl,
                            mbedtls_ssl_session *dst)
{
    int ret;
    if (ssl == NULL ||
        dst == NULL ||
        ssl->session == NULL ||
        ssl->conf->endpoint != MBEDTLS_SSL_IS_CLIENT) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->session->exported == 1) {
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    ret = mbedtls_ssl_session_copy(dst, ssl->session);
    if (ret != 0) {
        return ret;
    }
    ssl->session->exported = 1;
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static size_t ssl_tls12_session_save(const mbedtls_ssl_session *session,
                                     unsigned char *buf,
                                     size_t buf_len)
{
    unsigned char *p = buf;
    size_t used = 0;
#if defined(MBEDTLS_HAVE_TIME)
    uint64_t start;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    size_t cert_len;
#endif
#endif
#if defined(MBEDTLS_HAVE_TIME)
    used += 8;
    if (used <= buf_len) {
        start = (uint64_t) session->start;
        MBEDTLS_PUT_UINT64_BE(start, p, 0);
        p += 8;
    }
#endif
    used += 1
            + sizeof(session->id)
            + sizeof(session->master)
            + 4;
    if (used <= buf_len) {
        *p++ = MBEDTLS_BYTE_0(session->id_len);
        memcpy(p, session->id, 32);
        p += 32;
        memcpy(p, session->master, 48);
        p += 48;
        MBEDTLS_PUT_UINT32_BE(session->verify_result, p, 0);
        p += 4;
    }
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (session->peer_cert == NULL) {
        cert_len = 0;
    } else {
        cert_len = session->peer_cert->raw.len;
    }
    used += 3 + cert_len;
    if (used <= buf_len) {
        *p++ = MBEDTLS_BYTE_2(cert_len);
        *p++ = MBEDTLS_BYTE_1(cert_len);
        *p++ = MBEDTLS_BYTE_0(cert_len);
        if (session->peer_cert != NULL) {
            memcpy(p, session->peer_cert->raw.p, cert_len);
            p += cert_len;
        }
    }
#else
    if (session->peer_cert_digest != NULL) {
        used += 1 + 1 + session->peer_cert_digest_len;
        if (used <= buf_len) {
            *p++ = (unsigned char) session->peer_cert_digest_type;
            *p++ = (unsigned char) session->peer_cert_digest_len;
            memcpy(p, session->peer_cert_digest,
                   session->peer_cert_digest_len);
            p += session->peer_cert_digest_len;
        }
    } else {
        used += 2;
        if (used <= buf_len) {
            *p++ = (unsigned char) MBEDTLS_MD_NONE;
            *p++ = 0;
        }
    }
#endif
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#if defined(MBEDTLS_SSL_CLI_C)
    if (session->endpoint == MBEDTLS_SSL_IS_CLIENT) {
        used += 3 + session->ticket_len + 4;
        if (used <= buf_len) {
            *p++ = MBEDTLS_BYTE_2(session->ticket_len);
            *p++ = MBEDTLS_BYTE_1(session->ticket_len);
            *p++ = MBEDTLS_BYTE_0(session->ticket_len);
            if (session->ticket != NULL) {
                memcpy(p, session->ticket, session->ticket_len);
                p += session->ticket_len;
            }
            MBEDTLS_PUT_UINT32_BE(session->ticket_lifetime, p, 0);
            p += 4;
        }
    }
#endif
#if defined(MBEDTLS_HAVE_TIME) && defined(MBEDTLS_SSL_SRV_C)
    if (session->endpoint == MBEDTLS_SSL_IS_SERVER) {
        used += 8;
        if (used <= buf_len) {
            MBEDTLS_PUT_UINT64_BE((uint64_t) session->ticket_creation_time, p, 0);
            p += 8;
        }
    }
#endif
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    used += 1;
    if (used <= buf_len) {
        *p++ = session->mfl_code;
    }
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    used += 1;
    if (used <= buf_len) {
        *p++ = MBEDTLS_BYTE_0(session->encrypt_then_mac);
    }
#endif
    return used;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_session_load(mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t len)
{
#if defined(MBEDTLS_HAVE_TIME)
    uint64_t start;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    size_t cert_len;
#endif
#endif
    const unsigned char *p = buf;
    const unsigned char * const end = buf + len;
#if defined(MBEDTLS_HAVE_TIME)
    if (8 > (size_t) (end - p)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    start = MBEDTLS_GET_UINT64_BE(p, 0);
    p += 8;
    session->start = (time_t) start;
#endif
    if (1 + 32 + 48 + 4 > (size_t) (end - p)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->id_len = *p++;
    memcpy(session->id, p, 32);
    p += 32;
    memcpy(session->master, p, 48);
    p += 48;
    session->verify_result = MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    session->peer_cert = NULL;
#else
    session->peer_cert_digest = NULL;
#endif
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    session->ticket = NULL;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (3 > (size_t) (end - p)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    cert_len = MBEDTLS_GET_UINT24_BE(p, 0);
    p += 3;
    if (cert_len != 0) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        if (cert_len > (size_t) (end - p)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->peer_cert = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
        if (session->peer_cert == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        mbedtls_x509_crt_init(session->peer_cert);
        if ((ret = mbedtls_x509_crt_parse_der(session->peer_cert,
                                              p, cert_len)) != 0) {
            mbedtls_x509_crt_free(session->peer_cert);
            mbedtls_free(session->peer_cert);
            session->peer_cert = NULL;
            return ret;
        }
        p += cert_len;
    }
#else
    if (2 > (size_t) (end - p)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->peer_cert_digest_type = (mbedtls_md_type_t) *p++;
    session->peer_cert_digest_len = (size_t) *p++;
    if (session->peer_cert_digest_len != 0) {
        const mbedtls_md_info_t *md_info =
            mbedtls_md_info_from_type(session->peer_cert_digest_type);
        if (md_info == NULL) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (session->peer_cert_digest_len != mbedtls_md_get_size(md_info)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (session->peer_cert_digest_len > (size_t) (end - p)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->peer_cert_digest =
            mbedtls_calloc(1, session->peer_cert_digest_len);
        if (session->peer_cert_digest == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(session->peer_cert_digest, p,
               session->peer_cert_digest_len);
        p += session->peer_cert_digest_len;
    }
#endif
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#if defined(MBEDTLS_SSL_CLI_C)
    if (session->endpoint == MBEDTLS_SSL_IS_CLIENT) {
        if (3 > (size_t) (end - p)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_len = MBEDTLS_GET_UINT24_BE(p, 0);
        p += 3;
        if (session->ticket_len != 0) {
            if (session->ticket_len > (size_t) (end - p)) {
                return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
            }
            session->ticket = mbedtls_calloc(1, session->ticket_len);
            if (session->ticket == NULL) {
                return MBEDTLS_ERR_SSL_ALLOC_FAILED;
            }
            memcpy(session->ticket, p, session->ticket_len);
            p += session->ticket_len;
        }
        if (4 > (size_t) (end - p)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_lifetime = MBEDTLS_GET_UINT32_BE(p, 0);
        p += 4;
    }
#endif
#if defined(MBEDTLS_HAVE_TIME) && defined(MBEDTLS_SSL_SRV_C)
    if (session->endpoint == MBEDTLS_SSL_IS_SERVER) {
        if (8 > (size_t) (end - p)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_creation_time = MBEDTLS_GET_UINT64_BE(p, 0);
        p += 8;
    }
#endif
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if (1 > (size_t) (end - p)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->mfl_code = *p++;
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    if (1 > (size_t) (end - p)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->encrypt_then_mac = *p++;
#endif
    if (p != end) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_session_save(const mbedtls_ssl_session *session,
                                  unsigned char *buf,
                                  size_t buf_len,
                                  size_t *olen)
{
    unsigned char *p = buf;
#if defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    size_t hostname_len = (session->hostname == NULL) ?
                          0 : strlen(session->hostname) + 1;
#endif
#if defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_ALPN)
    const size_t alpn_len = (session->ticket_alpn == NULL) ?
                            0 : strlen(session->ticket_alpn) + 1;
#endif
    size_t needed = 4
                    + 1
                    + 1;
    *olen = 0;
    if (session->resumption_key_len > MBEDTLS_SSL_TLS1_3_TICKET_RESUMPTION_KEY_LEN) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    needed += session->resumption_key_len;
#if defined(MBEDTLS_SSL_EARLY_DATA)
    needed += 4;
#endif
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    needed += 2;
#endif
#if defined(MBEDTLS_HAVE_TIME)
    needed += 8;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if (session->endpoint == MBEDTLS_SSL_IS_SERVER) {
#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_ALPN)
        needed += 2
                  + alpn_len;
#endif
    }
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    if (session->endpoint == MBEDTLS_SSL_IS_CLIENT) {
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        needed += 2
                  + hostname_len;
#endif
        needed += 4
                  + 2;
        if (session->ticket_len > SIZE_MAX - needed) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        needed += session->ticket_len;
    }
#endif
    *olen = needed;
    if (needed > buf_len) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    MBEDTLS_PUT_UINT32_BE(session->ticket_age_add, p, 0);
    p[4] = session->ticket_flags;
    p[5] = session->resumption_key_len;
    p += 6;
    memcpy(p, session->resumption_key, session->resumption_key_len);
    p += session->resumption_key_len;
#if defined(MBEDTLS_SSL_EARLY_DATA)
    MBEDTLS_PUT_UINT32_BE(session->max_early_data_size, p, 0);
    p += 4;
#endif
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    MBEDTLS_PUT_UINT16_BE(session->record_size_limit, p, 0);
    p += 2;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if (session->endpoint == MBEDTLS_SSL_IS_SERVER) {
#if defined(MBEDTLS_HAVE_TIME)
        MBEDTLS_PUT_UINT64_BE((uint64_t) session->ticket_creation_time, p, 0);
        p += 8;
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_ALPN)
        MBEDTLS_PUT_UINT16_BE(alpn_len, p, 0);
        p += 2;
        if (alpn_len > 0) {
            memcpy(p, session->ticket_alpn, alpn_len);
            p += alpn_len;
        }
#endif
    }
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    if (session->endpoint == MBEDTLS_SSL_IS_CLIENT) {
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        MBEDTLS_PUT_UINT16_BE(hostname_len, p, 0);
        p += 2;
        if (hostname_len > 0) {
            memcpy(p, session->hostname, hostname_len);
            p += hostname_len;
        }
#endif
#if defined(MBEDTLS_HAVE_TIME)
        MBEDTLS_PUT_UINT64_BE((uint64_t) session->ticket_reception_time, p, 0);
        p += 8;
#endif
        MBEDTLS_PUT_UINT32_BE(session->ticket_lifetime, p, 0);
        p += 4;
        MBEDTLS_PUT_UINT16_BE(session->ticket_len, p, 0);
        p += 2;
        if (session->ticket != NULL && session->ticket_len > 0) {
            memcpy(p, session->ticket, session->ticket_len);
            p += session->ticket_len;
        }
    }
#endif
    return 0;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_session_load(mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t len)
{
    const unsigned char *p = buf;
    const unsigned char *end = buf + len;
    if (end - p < 6) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->ticket_age_add = MBEDTLS_GET_UINT32_BE(p, 0);
    session->ticket_flags = p[4];
    session->resumption_key_len = p[5];
    p += 6;
    if (end - p < session->resumption_key_len) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (sizeof(session->resumption_key) < session->resumption_key_len) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(session->resumption_key, p, session->resumption_key_len);
    p += session->resumption_key_len;
#if defined(MBEDTLS_SSL_EARLY_DATA)
    if (end - p < 4) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->max_early_data_size = MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;
#endif
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    if (end - p < 2) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->record_size_limit = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if (session->endpoint == MBEDTLS_SSL_IS_SERVER) {
#if defined(MBEDTLS_HAVE_TIME)
        if (end - p < 8) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_creation_time = MBEDTLS_GET_UINT64_BE(p, 0);
        p += 8;
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_ALPN)
        size_t alpn_len;
        if (end - p < 2) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        alpn_len = MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        if (end - p < (long int) alpn_len) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (alpn_len > 0) {
            int ret = mbedtls_ssl_session_set_ticket_alpn(session, (char *) p);
            if (ret != 0) {
                return ret;
            }
            p += alpn_len;
        }
#endif
    }
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    if (session->endpoint == MBEDTLS_SSL_IS_CLIENT) {
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        size_t hostname_len;
        if (end - p < 2) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        hostname_len = MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        if (end - p < (long int) hostname_len) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (hostname_len > 0) {
            session->hostname = mbedtls_calloc(1, hostname_len);
            if (session->hostname == NULL) {
                return MBEDTLS_ERR_SSL_ALLOC_FAILED;
            }
            memcpy(session->hostname, p, hostname_len);
            p += hostname_len;
        }
#endif
#if defined(MBEDTLS_HAVE_TIME)
        if (end - p < 8) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_reception_time = MBEDTLS_GET_UINT64_BE(p, 0);
        p += 8;
#endif
        if (end - p < 4) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_lifetime = MBEDTLS_GET_UINT32_BE(p, 0);
        p += 4;
        if (end - p < 2) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        session->ticket_len = MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        if (end - p < (long int) session->ticket_len) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (session->ticket_len > 0) {
            session->ticket = mbedtls_calloc(1, session->ticket_len);
            if (session->ticket == NULL) {
                return MBEDTLS_ERR_SSL_ALLOC_FAILED;
            }
            memcpy(session->ticket, p, session->ticket_len);
            p += session->ticket_len;
        }
    }
#endif
    return 0;
}
#else
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls13_session_save(const mbedtls_ssl_session *session,
                                  unsigned char *buf,
                                  size_t buf_len,
                                  size_t *olen)
{
    ((void) session);
    ((void) buf);
    ((void) buf_len);
    *olen = 0;
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
static int ssl_tls13_session_load(const mbedtls_ssl_session *session,
                                  const unsigned char *buf,
                                  size_t buf_len)
{
    ((void) session);
    ((void) buf);
    ((void) buf_len);
    return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
}
#endif
#endif
#if defined(MBEDTLS_HAVE_TIME)
#define SSL_SERIALIZED_SESSION_CONFIG_TIME 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_TIME 0
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#define SSL_SERIALIZED_SESSION_CONFIG_CRT 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_CRT 0
#endif
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
#define SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT 0
#endif
#if defined(MBEDTLS_SSL_CLI_C) && defined(MBEDTLS_SSL_SESSION_TICKETS)
#define SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET 0
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
#define SSL_SERIALIZED_SESSION_CONFIG_MFL 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_MFL 0
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
#define SSL_SERIALIZED_SESSION_CONFIG_ETM 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_ETM 0
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
#define SSL_SERIALIZED_SESSION_CONFIG_TICKET 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_TICKET 0
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
#define SSL_SERIALIZED_SESSION_CONFIG_SNI 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_SNI 0
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA)
#define SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA 0
#endif
#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
#define SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE 0
#endif
#if defined(MBEDTLS_SSL_ALPN) && defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_EARLY_DATA)
#define SSL_SERIALIZED_SESSION_CONFIG_ALPN 1
#else
#define SSL_SERIALIZED_SESSION_CONFIG_ALPN 0
#endif
#define SSL_SERIALIZED_SESSION_CONFIG_TIME_BIT 0
#define SSL_SERIALIZED_SESSION_CONFIG_CRT_BIT 1
#define SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET_BIT 2
#define SSL_SERIALIZED_SESSION_CONFIG_MFL_BIT 3
#define SSL_SERIALIZED_SESSION_CONFIG_ETM_BIT 4
#define SSL_SERIALIZED_SESSION_CONFIG_TICKET_BIT 5
#define SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT_BIT 6
#define SSL_SERIALIZED_SESSION_CONFIG_SNI_BIT 7
#define SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA_BIT 8
#define SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE_BIT 9
#define SSL_SERIALIZED_SESSION_CONFIG_ALPN_BIT 10
#define SSL_SERIALIZED_SESSION_CONFIG_BITFLAG \
    ((uint16_t) ( \
         (SSL_SERIALIZED_SESSION_CONFIG_TIME << SSL_SERIALIZED_SESSION_CONFIG_TIME_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_CRT << SSL_SERIALIZED_SESSION_CONFIG_CRT_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET << \
             SSL_SERIALIZED_SESSION_CONFIG_CLIENT_TICKET_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_MFL << SSL_SERIALIZED_SESSION_CONFIG_MFL_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_ETM << SSL_SERIALIZED_SESSION_CONFIG_ETM_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_TICKET << SSL_SERIALIZED_SESSION_CONFIG_TICKET_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT << \
             SSL_SERIALIZED_SESSION_CONFIG_KEEP_PEER_CRT_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_SNI << SSL_SERIALIZED_SESSION_CONFIG_SNI_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA << \
             SSL_SERIALIZED_SESSION_CONFIG_EARLY_DATA_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE << \
             SSL_SERIALIZED_SESSION_CONFIG_RECORD_SIZE_BIT) | \
         (SSL_SERIALIZED_SESSION_CONFIG_ALPN << \
             SSL_SERIALIZED_SESSION_CONFIG_ALPN_BIT)))
static const unsigned char ssl_serialized_session_header[] = {
    MBEDTLS_VERSION_MAJOR,
    MBEDTLS_VERSION_MINOR,
    MBEDTLS_VERSION_PATCH,
    MBEDTLS_BYTE_1(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
    MBEDTLS_BYTE_0(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
};
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_session_save(const mbedtls_ssl_session *session,
                            unsigned char omit_header,
                            unsigned char *buf,
                            size_t buf_len,
                            size_t *olen)
{
    unsigned char *p = buf;
    size_t used = 0;
    size_t remaining_len;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    size_t out_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
    if (session == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    if (!omit_header) {
        used += sizeof(ssl_serialized_session_header);
        if (used <= buf_len) {
            memcpy(p, ssl_serialized_session_header,
                   sizeof(ssl_serialized_session_header));
            p += sizeof(ssl_serialized_session_header);
        }
    }
    used += 1
            + 1
            + 2;
    if (used <= buf_len) {
        *p++ = MBEDTLS_BYTE_0(session->tls_version);
        *p++ = session->endpoint;
        MBEDTLS_PUT_UINT16_BE(session->ciphersuite, p, 0);
        p += 2;
    }
    remaining_len = (buf_len >= used) ? buf_len - used : 0;
    switch (session->tls_version) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        case MBEDTLS_SSL_VERSION_TLS1_2:
            used += ssl_tls12_session_save(session, p, remaining_len);
            break;
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        case MBEDTLS_SSL_VERSION_TLS1_3:
            ret = ssl_tls13_session_save(session, p, remaining_len, &out_len);
            if (ret != 0 && ret != MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
                return ret;
            }
            used += out_len;
            break;
#endif
        default:
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    }
    *olen = used;
    if (used > buf_len) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    return 0;
}
int mbedtls_ssl_session_save(const mbedtls_ssl_session *session,
                             unsigned char *buf,
                             size_t buf_len,
                             size_t *olen)
{
    return ssl_session_save(session, 0, buf, buf_len, olen);
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_session_load(mbedtls_ssl_session *session,
                            unsigned char omit_header,
                            const unsigned char *buf,
                            size_t len)
{
    const unsigned char *p = buf;
    const unsigned char * const end = buf + len;
    size_t remaining_len;
    if (session == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    if (!omit_header) {
        if ((size_t) (end - p) < sizeof(ssl_serialized_session_header)) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if (memcmp(p, ssl_serialized_session_header,
                   sizeof(ssl_serialized_session_header)) != 0) {
            return MBEDTLS_ERR_SSL_VERSION_MISMATCH;
        }
        p += sizeof(ssl_serialized_session_header);
    }
    if (4 > (size_t) (end - p)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session->tls_version = (mbedtls_ssl_protocol_version) (0x0300 | *p++);
    session->endpoint = *p++;
    session->ciphersuite = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    remaining_len = (size_t) (end - p);
    switch (session->tls_version) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        case MBEDTLS_SSL_VERSION_TLS1_2:
            return ssl_tls12_session_load(session, p, remaining_len);
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        case MBEDTLS_SSL_VERSION_TLS1_3:
            return ssl_tls13_session_load(session, p, remaining_len);
#endif
        default:
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
}
int mbedtls_ssl_session_load(mbedtls_ssl_session *session,
                             const unsigned char *buf,
                             size_t len)
{
    int ret = ssl_session_load(session, 0, buf, len);
    if (ret != 0) {
        mbedtls_ssl_session_free(session);
    }
    return ret;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_prepare_handshake_step(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if ((ret = mbedtls_ssl_flush_output(ssl)) != 0) {
        return ret;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake->retransmit_state == MBEDTLS_SSL_RETRANS_SENDING) {
        if ((ret = mbedtls_ssl_flight_transmit(ssl)) != 0) {
            return ret;
        }
    }
#endif
    return ret;
}
int mbedtls_ssl_handshake_step(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (ssl == NULL ||
        ssl->conf == NULL ||
        ssl->handshake == NULL ||
        ssl->state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = ssl_prepare_handshake_step(ssl);
    if (ret != 0) {
        return ret;
    }
    ret = mbedtls_ssl_handle_pending_alert(ssl);
    if (ret != 0) {
        goto cleanup;
    }
    ret = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
#if defined(MBEDTLS_SSL_CLI_C)
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("client state: %s",
                                  mbedtls_ssl_states_str((mbedtls_ssl_states) ssl->state)));
        switch (ssl->state) {
            case MBEDTLS_SSL_HELLO_REQUEST:
                ssl->state = MBEDTLS_SSL_CLIENT_HELLO;
                ret = 0;
                break;
            case MBEDTLS_SSL_CLIENT_HELLO:
                ret = mbedtls_ssl_write_client_hello(ssl);
                break;
            default:
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
                if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
                    ret = mbedtls_ssl_tls13_handshake_client_step(ssl);
                } else {
                    ret = mbedtls_ssl_handshake_client_step(ssl);
                }
#elif defined(MBEDTLS_SSL_PROTO_TLS1_2)
                ret = mbedtls_ssl_handshake_client_step(ssl);
#else
                ret = mbedtls_ssl_tls13_handshake_client_step(ssl);
#endif
        }
    }
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
        if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
            ret = mbedtls_ssl_tls13_handshake_server_step(ssl);
        } else {
            ret = mbedtls_ssl_handshake_server_step(ssl);
        }
#elif defined(MBEDTLS_SSL_PROTO_TLS1_2)
        ret = mbedtls_ssl_handshake_server_step(ssl);
#else
        ret = mbedtls_ssl_tls13_handshake_server_step(ssl);
#endif
    }
#endif
    if (ret != 0) {
        if (ssl->send_alert) {
            ret = mbedtls_ssl_handle_pending_alert(ssl);
            goto cleanup;
        }
    }
cleanup:
    return ret;
}
int mbedtls_ssl_handshake(mbedtls_ssl_context *ssl)
{
    int ret = 0;
    if (ssl == NULL || ssl->conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        (ssl->f_set_timer == NULL || ssl->f_get_timer == NULL)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("You must use "
                                  "mbedtls_ssl_set_timer_cb() for DTLS"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> handshake"));
    while (ssl->state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        ret = mbedtls_ssl_handshake_step(ssl);
        if (ret != 0) {
            break;
        }
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= handshake"));
    return ret;
}
#if defined(MBEDTLS_SSL_RENEGOTIATION)
#if defined(MBEDTLS_SSL_SRV_C)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_hello_request(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write hello request"));
    ssl->out_msglen = 4;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_HELLO_REQUEST;
    if ((ret = mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write hello request"));
    return 0;
}
#endif
int mbedtls_ssl_start_renegotiation(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> renegotiate"));
    if ((ret = ssl_handshake_init(ssl)) != 0) {
        return ret;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_PENDING) {
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
            ssl->handshake->out_msg_seq = 1;
        } else {
            ssl->handshake->in_msg_seq = 1;
        }
    }
#endif
    ssl->state = MBEDTLS_SSL_HELLO_REQUEST;
    ssl->renego_status = MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS;
    if ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_handshake", ret);
        return ret;
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= renegotiate"));
    return 0;
}
int mbedtls_ssl_renegotiate(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    if (ssl == NULL || ssl->conf == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#if defined(MBEDTLS_SSL_SRV_C)
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
        if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        ssl->renego_status = MBEDTLS_SSL_RENEGOTIATION_PENDING;
        if (ssl->out_left != 0) {
            return mbedtls_ssl_flush_output(ssl);
        }
        return ssl_write_hello_request(ssl);
    }
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    if (ssl->renego_status != MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
        if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if ((ret = mbedtls_ssl_start_renegotiation(ssl)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_start_renegotiation", ret);
            return ret;
        }
    } else {
        if ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_handshake", ret);
            return ret;
        }
    }
#endif
    return ret;
}
#endif
void mbedtls_ssl_handshake_free(mbedtls_ssl_context *ssl)
{
    mbedtls_ssl_handshake_params *handshake = ssl->handshake;
    if (handshake == NULL) {
        return;
    }
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ssl->handshake->group_list_heap_allocated) {
        mbedtls_free((void *) handshake->group_list);
    }
    handshake->group_list = NULL;
#endif
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    if (ssl->handshake->sig_algs_heap_allocated) {
        mbedtls_free((void *) handshake->sig_algs);
    }
    handshake->sig_algs = NULL;
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (ssl->handshake->certificate_request_context) {
        mbedtls_free((void *) handshake->certificate_request_context);
    }
#endif
#endif
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    if (ssl->conf->f_async_cancel != NULL && handshake->async_in_progress != 0) {
        ssl->conf->f_async_cancel(ssl);
        handshake->async_in_progress = 0;
    }
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_hash_abort(&handshake->fin_sha256_psa);
#else
    mbedtls_md_free(&handshake->fin_sha256);
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_hash_abort(&handshake->fin_sha384_psa);
#else
    mbedtls_md_free(&handshake->fin_sha384);
#endif
#endif
#if defined(MBEDTLS_DHM_C)
    mbedtls_dhm_free(&handshake->dhm_ctx);
#endif
#if !defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED)
    mbedtls_ecdh_free(&handshake->ecdh_ctx);
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_pake_abort(&handshake->psa_pake_ctx);
    if (!mbedtls_svc_key_id_is_null(handshake->psa_pake_password)) {
        psa_destroy_key(handshake->psa_pake_password);
    }
    handshake->psa_pake_password = MBEDTLS_SVC_KEY_ID_INIT;
#else
    mbedtls_ecjpake_free(&handshake->ecjpake_ctx);
#endif
#if defined(MBEDTLS_SSL_CLI_C)
    mbedtls_free(handshake->ecjpake_cache);
    handshake->ecjpake_cache = NULL;
    handshake->ecjpake_cache_len = 0;
#endif
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_ECDSA_ANY_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    mbedtls_free((void *) handshake->curves_tls_id);
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (!mbedtls_svc_key_id_is_null(ssl->handshake->psk_opaque)) {
        if (ssl->handshake->psk_opaque_is_internal) {
            psa_destroy_key(ssl->handshake->psk_opaque);
            ssl->handshake->psk_opaque_is_internal = 0;
        }
        ssl->handshake->psk_opaque = MBEDTLS_SVC_KEY_ID_INIT;
    }
#else
    if (handshake->psk != NULL) {
        mbedtls_zeroize_and_free(handshake->psk, handshake->psk_len);
    }
#endif
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    ssl_key_cert_free(handshake->sni_key_cert);
#endif
#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    mbedtls_x509_crt_restart_free(&handshake->ecrs_ctx);
    if (handshake->ecrs_peer_cert != NULL) {
        mbedtls_x509_crt_free(handshake->ecrs_peer_cert);
        mbedtls_free(handshake->ecrs_peer_cert);
    }
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C) && \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_pk_free(&handshake->peer_pubkey);
#endif
#if defined(MBEDTLS_SSL_CLI_C) && \
    (defined(MBEDTLS_SSL_PROTO_DTLS) || defined(MBEDTLS_SSL_PROTO_TLS1_3))
    mbedtls_free(handshake->cookie);
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    mbedtls_ssl_flight_free(handshake->flight);
    mbedtls_ssl_buffering_free(ssl);
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_XXDH_PSA_ANY_ENABLED)
    if (handshake->xxdh_psa_privkey_is_external == 0) {
        psa_destroy_key(handshake->xxdh_psa_privkey);
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_transform_free(handshake->transform_handshake);
    mbedtls_free(handshake->transform_handshake);
#if defined(MBEDTLS_SSL_EARLY_DATA)
    mbedtls_ssl_transform_free(handshake->transform_earlydata);
    mbedtls_free(handshake->transform_earlydata);
#endif
#endif
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    handle_buffer_resizing(ssl, 1, mbedtls_ssl_get_input_buflen(ssl),
                           mbedtls_ssl_get_output_buflen(ssl));
#endif
    mbedtls_platform_zeroize(handshake,
                             sizeof(mbedtls_ssl_handshake_params));
}
void mbedtls_ssl_session_free(mbedtls_ssl_session *session)
{
    if (session == NULL) {
        return;
    }
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    ssl_clear_peer_cert(session);
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    mbedtls_free(session->hostname);
#endif
    mbedtls_free(session->ticket);
#endif
#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_ALPN) && \
    defined(MBEDTLS_SSL_SRV_C)
    mbedtls_free(session->ticket_alpn);
#endif
    mbedtls_platform_zeroize(session, sizeof(mbedtls_ssl_session));
}
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID 1u
#else
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID 0u
#endif
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT 1u
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY 1u
#else
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY 0u
#endif
#if defined(MBEDTLS_SSL_ALPN)
#define SSL_SERIALIZED_CONTEXT_CONFIG_ALPN 1u
#else
#define SSL_SERIALIZED_CONTEXT_CONFIG_ALPN 0u
#endif
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID_BIT 0
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT_BIT 1
#define SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY_BIT 2
#define SSL_SERIALIZED_CONTEXT_CONFIG_ALPN_BIT 3
#define SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG \
    ((uint32_t) ( \
         (SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID << \
             SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_CONNECTION_ID_BIT) | \
         (SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT << \
             SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_BADMAC_LIMIT_BIT) | \
         (SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY << \
             SSL_SERIALIZED_CONTEXT_CONFIG_DTLS_ANTI_REPLAY_BIT) | \
         (SSL_SERIALIZED_CONTEXT_CONFIG_ALPN << SSL_SERIALIZED_CONTEXT_CONFIG_ALPN_BIT) | \
         0u))
static const unsigned char ssl_serialized_context_header[] = {
    MBEDTLS_VERSION_MAJOR,
    MBEDTLS_VERSION_MINOR,
    MBEDTLS_VERSION_PATCH,
    MBEDTLS_BYTE_1(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
    MBEDTLS_BYTE_0(SSL_SERIALIZED_SESSION_CONFIG_BITFLAG),
    MBEDTLS_BYTE_2(SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG),
    MBEDTLS_BYTE_1(SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG),
    MBEDTLS_BYTE_0(SSL_SERIALIZED_CONTEXT_CONFIG_BITFLAG),
};
int mbedtls_ssl_context_save(mbedtls_ssl_context *ssl,
                             unsigned char *buf,
                             size_t buf_len,
                             size_t *olen)
{
    unsigned char *p = buf;
    size_t used = 0;
    size_t session_len;
    int ret = 0;
    if (mbedtls_ssl_is_handshake_over(ssl) == 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Initial handshake isn't over"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->handshake != NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Handshake isn't completed"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->transform == NULL || ssl->session == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Serialised structures aren't ready"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (mbedtls_ssl_check_pending(ssl) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("There is pending incoming data"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->out_left != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("There is pending outgoing data"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Only DTLS is supported"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (ssl->tls_version != MBEDTLS_SSL_VERSION_TLS1_2) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Only version 1.2 supported"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (mbedtls_ssl_transform_uses_aead(ssl->transform) != 1) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Only AEAD ciphersuites supported"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->conf->disable_renegotiation != MBEDTLS_SSL_RENEGOTIATION_DISABLED) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("Renegotiation must not be enabled"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif
    used += sizeof(ssl_serialized_context_header);
    if (used <= buf_len) {
        memcpy(p, ssl_serialized_context_header,
               sizeof(ssl_serialized_context_header));
        p += sizeof(ssl_serialized_context_header);
    }
    ret = ssl_session_save(ssl->session, 1, NULL, 0, &session_len);
    if (ret != MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL) {
        return ret;
    }
    used += 4 + session_len;
    if (used <= buf_len) {
        MBEDTLS_PUT_UINT32_BE(session_len, p, 0);
        p += 4;
        ret = ssl_session_save(ssl->session, 1,
                               p, session_len, &session_len);
        if (ret != 0) {
            return ret;
        }
        p += session_len;
    }
    used += sizeof(ssl->transform->randbytes);
    if (used <= buf_len) {
        memcpy(p, ssl->transform->randbytes,
               sizeof(ssl->transform->randbytes));
        p += sizeof(ssl->transform->randbytes);
    }
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    used += 2U + ssl->transform->in_cid_len + ssl->transform->out_cid_len;
    if (used <= buf_len) {
        *p++ = ssl->transform->in_cid_len;
        memcpy(p, ssl->transform->in_cid, ssl->transform->in_cid_len);
        p += ssl->transform->in_cid_len;
        *p++ = ssl->transform->out_cid_len;
        memcpy(p, ssl->transform->out_cid, ssl->transform->out_cid_len);
        p += ssl->transform->out_cid_len;
    }
#endif
    used += 4;
    if (used <= buf_len) {
        MBEDTLS_PUT_UINT32_BE(ssl->badmac_seen, p, 0);
        p += 4;
    }
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    used += 16;
    if (used <= buf_len) {
        MBEDTLS_PUT_UINT64_BE(ssl->in_window_top, p, 0);
        p += 8;
        MBEDTLS_PUT_UINT64_BE(ssl->in_window, p, 0);
        p += 8;
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    used += 1;
    if (used <= buf_len) {
        *p++ = ssl->disable_datagram_packing;
    }
#endif
    used += MBEDTLS_SSL_SEQUENCE_NUMBER_LEN;
    if (used <= buf_len) {
        memcpy(p, ssl->cur_out_ctr, MBEDTLS_SSL_SEQUENCE_NUMBER_LEN);
        p += MBEDTLS_SSL_SEQUENCE_NUMBER_LEN;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    used += 2;
    if (used <= buf_len) {
        MBEDTLS_PUT_UINT16_BE(ssl->mtu, p, 0);
        p += 2;
    }
#endif
#if defined(MBEDTLS_SSL_ALPN)
    {
        const uint8_t alpn_len = ssl->alpn_chosen
                               ? (uint8_t) strlen(ssl->alpn_chosen)
                               : 0;
        used += 1 + alpn_len;
        if (used <= buf_len) {
            *p++ = alpn_len;
            if (ssl->alpn_chosen != NULL) {
                memcpy(p, ssl->alpn_chosen, alpn_len);
                p += alpn_len;
            }
        }
    }
#endif
    *olen = used;
    if (used > buf_len) {
        return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    }
    MBEDTLS_SSL_DEBUG_BUF(4, "saved context", buf, used);
    return mbedtls_ssl_session_reset_int(ssl, 0);
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_context_load(mbedtls_ssl_context *ssl,
                            const unsigned char *buf,
                            size_t len)
{
    const unsigned char *p = buf;
    const unsigned char * const end = buf + len;
    size_t session_len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    tls_prf_fn prf_func = NULL;
#endif
    if (ssl->state != MBEDTLS_SSL_HELLO_REQUEST ||
        ssl->session != NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        ssl->conf->disable_renegotiation != MBEDTLS_SSL_RENEGOTIATION_DISABLED ||
#endif
        ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM ||
        ssl->conf->max_tls_version < MBEDTLS_SSL_VERSION_TLS1_2 ||
        ssl->conf->min_tls_version > MBEDTLS_SSL_VERSION_TLS1_2
        ) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    MBEDTLS_SSL_DEBUG_BUF(4, "context to load", buf, len);
    if ((size_t) (end - p) < sizeof(ssl_serialized_context_header)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if (memcmp(p, ssl_serialized_context_header,
               sizeof(ssl_serialized_context_header)) != 0) {
        return MBEDTLS_ERR_SSL_VERSION_MISMATCH;
    }
    p += sizeof(ssl_serialized_context_header);
    if ((size_t) (end - p) < 4) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    session_len = MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;
    ssl->session = ssl->session_negotiate;
    ssl->session_in = ssl->session;
    ssl->session_out = ssl->session;
    ssl->session_negotiate = NULL;
    if ((size_t) (end - p) < session_len) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = ssl_session_load(ssl->session, 1, p, session_len);
    if (ret != 0) {
        mbedtls_ssl_session_free(ssl->session);
        return ret;
    }
    p += session_len;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    ssl->transform = ssl->transform_negotiate;
    ssl->transform_in = ssl->transform;
    ssl->transform_out = ssl->transform;
    ssl->transform_negotiate = NULL;
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    prf_func = ssl_tls12prf_from_cs(ssl->session->ciphersuite);
    if (prf_func == NULL) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    if ((size_t) (end - p) < sizeof(ssl->transform->randbytes)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ret = ssl_tls12_populate_transform(ssl->transform,
                                       ssl->session->ciphersuite,
                                       ssl->session->master,
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                       ssl->session->encrypt_then_mac,
#endif
                                       prf_func,
                                       p,
                                       MBEDTLS_SSL_VERSION_TLS1_2,
                                       ssl->conf->endpoint,
                                       ssl);
    if (ret != 0) {
        return ret;
    }
#endif
    p += sizeof(ssl->transform->randbytes);
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if ((size_t) (end - p) < 1) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl->transform->in_cid_len = *p++;
    if ((size_t) (end - p) < ssl->transform->in_cid_len + 1u) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(ssl->transform->in_cid, p, ssl->transform->in_cid_len);
    p += ssl->transform->in_cid_len;
    ssl->transform->out_cid_len = *p++;
    if ((size_t) (end - p) < ssl->transform->out_cid_len) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(ssl->transform->out_cid, p, ssl->transform->out_cid_len);
    p += ssl->transform->out_cid_len;
#endif
    if ((size_t) (end - p) < 4) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl->badmac_seen = MBEDTLS_GET_UINT32_BE(p, 0);
    p += 4;
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    if ((size_t) (end - p) < 16) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl->in_window_top = MBEDTLS_GET_UINT64_BE(p, 0);
    p += 8;
    ssl->in_window = MBEDTLS_GET_UINT64_BE(p, 0);
    p += 8;
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if ((size_t) (end - p) < 1) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl->disable_datagram_packing = *p++;
#endif
    if ((size_t) (end - p) < sizeof(ssl->cur_out_ctr)) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(ssl->cur_out_ctr, p, sizeof(ssl->cur_out_ctr));
    p += sizeof(ssl->cur_out_ctr);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if ((size_t) (end - p) < 2) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl->mtu = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
#endif
#if defined(MBEDTLS_SSL_ALPN)
    {
        uint8_t alpn_len;
        const char **cur;
        if ((size_t) (end - p) < 1) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        alpn_len = *p++;
        if (alpn_len != 0 && ssl->conf->alpn_list != NULL) {
            for (cur = ssl->conf->alpn_list; *cur != NULL; cur++) {
                if (strlen(*cur) == alpn_len &&
                    memcmp(p, *cur, alpn_len) == 0) {
                    ssl->alpn_chosen = *cur;
                    break;
                }
            }
        }
        if (alpn_len != 0 && ssl->alpn_chosen == NULL) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        p += alpn_len;
    }
#endif
    ssl->state = MBEDTLS_SSL_HANDSHAKE_OVER;
    ssl->tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
    mbedtls_ssl_update_out_pointers(ssl, ssl->transform);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    ssl->in_epoch = 1;
#endif
    if (ssl->handshake != NULL) {
        mbedtls_ssl_handshake_free(ssl);
        mbedtls_free(ssl->handshake);
        ssl->handshake = NULL;
    }
    if (p != end) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    return 0;
}
int mbedtls_ssl_context_load(mbedtls_ssl_context *context,
                             const unsigned char *buf,
                             size_t len)
{
    int ret = ssl_context_load(context, buf, len);
    if (ret != 0) {
        mbedtls_ssl_free(context);
    }
    return ret;
}
#endif
void mbedtls_ssl_free(mbedtls_ssl_context *ssl)
{
    if (ssl == NULL) {
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> free"));
    if (ssl->out_buf != NULL) {
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        size_t out_buf_len = ssl->out_buf_len;
#else
        size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN;
#endif
        mbedtls_zeroize_and_free(ssl->out_buf, out_buf_len);
        ssl->out_buf = NULL;
    }
    if (ssl->in_buf != NULL) {
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
        size_t in_buf_len = ssl->in_buf_len;
#else
        size_t in_buf_len = MBEDTLS_SSL_IN_BUFFER_LEN;
#endif
        mbedtls_zeroize_and_free(ssl->in_buf, in_buf_len);
        ssl->in_buf = NULL;
    }
    if (ssl->transform) {
        mbedtls_ssl_transform_free(ssl->transform);
        mbedtls_free(ssl->transform);
    }
    if (ssl->handshake) {
        mbedtls_ssl_handshake_free(ssl);
        mbedtls_free(ssl->handshake);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        mbedtls_ssl_transform_free(ssl->transform_negotiate);
        mbedtls_free(ssl->transform_negotiate);
#endif
        mbedtls_ssl_session_free(ssl->session_negotiate);
        mbedtls_free(ssl->session_negotiate);
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_transform_free(ssl->transform_application);
    mbedtls_free(ssl->transform_application);
#endif
    if (ssl->session) {
        mbedtls_ssl_session_free(ssl->session);
        mbedtls_free(ssl->session);
    }
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (ssl->hostname != NULL) {
        mbedtls_zeroize_and_free(ssl->hostname, strlen(ssl->hostname));
    }
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    mbedtls_free(ssl->cli_id);
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= free"));
    mbedtls_platform_zeroize(ssl, sizeof(mbedtls_ssl_context));
}
void mbedtls_ssl_config_init(mbedtls_ssl_config *conf)
{
    memset(conf, 0, sizeof(mbedtls_ssl_config));
}
static const uint16_t ssl_preset_default_groups[] = {
#if defined(MBEDTLS_ECP_HAVE_CURVE25519)
    MBEDTLS_SSL_IANA_TLS_GROUP_X25519,
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1,
#endif
#if defined(MBEDTLS_ECP_HAVE_CURVE448)
    MBEDTLS_SSL_IANA_TLS_GROUP_X448,
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP521R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1,
#endif
#if defined(MBEDTLS_ECP_HAVE_BP256R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1,
#endif
#if defined(MBEDTLS_ECP_HAVE_BP384R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1,
#endif
#if defined(MBEDTLS_ECP_HAVE_BP512R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1,
#endif
#if defined(PSA_WANT_ALG_FFDH)
    MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048,
    MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072,
    MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096,
    MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144,
    MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192,
#endif
    MBEDTLS_SSL_IANA_TLS_GROUP_NONE
};
static const int ssl_preset_suiteb_ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    0
};
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
static const uint16_t ssl_preset_default_sig_algs[] = {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(MBEDTLS_MD_CAN_SHA256) && \
    defined(PSA_WANT_ECC_SECP_R1_256)
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(MBEDTLS_MD_CAN_SHA384) && \
    defined(PSA_WANT_ECC_SECP_R1_384)
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(MBEDTLS_MD_CAN_SHA512) && \
    defined(PSA_WANT_ECC_SECP_R1_521)
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512,
#endif
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT) && defined(MBEDTLS_MD_CAN_SHA512)
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512,
#endif
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT) && defined(MBEDTLS_MD_CAN_SHA384)
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384,
#endif
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT) && defined(MBEDTLS_MD_CAN_SHA256)
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256,
#endif
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_MD_CAN_SHA512)
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512,
#endif
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_MD_CAN_SHA384)
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384,
#endif
#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_MD_CAN_SHA256)
    MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256,
#endif
    MBEDTLS_TLS_SIG_NONE
};
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static uint16_t ssl_tls12_preset_default_sig_algs[] = {
#if defined(MBEDTLS_MD_CAN_SHA512)
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA512),
#endif
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512,
#endif
#if defined(MBEDTLS_RSA_C)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_RSA, MBEDTLS_SSL_HASH_SHA512),
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA384),
#endif
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384,
#endif
#if defined(MBEDTLS_RSA_C)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_RSA, MBEDTLS_SSL_HASH_SHA384),
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA256),
#endif
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256,
#endif
#if defined(MBEDTLS_RSA_C)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_RSA, MBEDTLS_SSL_HASH_SHA256),
#endif
#endif
    MBEDTLS_TLS_SIG_NONE
};
#endif
static const uint16_t ssl_preset_suiteb_sig_algs[] = {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(MBEDTLS_MD_CAN_SHA256) && \
    defined(MBEDTLS_ECP_HAVE_SECP256R1)
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256,
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED) && \
    defined(MBEDTLS_MD_CAN_SHA384) && \
    defined(MBEDTLS_ECP_HAVE_SECP384R1)
    MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384,
#endif
    MBEDTLS_TLS_SIG_NONE
};
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
static uint16_t ssl_tls12_preset_suiteb_sig_algs[] = {
#if defined(MBEDTLS_MD_CAN_SHA256)
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA256),
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA, MBEDTLS_SSL_HASH_SHA384),
#endif
#endif
    MBEDTLS_TLS_SIG_NONE
};
#endif
#endif
static const uint16_t ssl_preset_suiteb_groups[] = {
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1,
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
    MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1,
#endif
    MBEDTLS_SSL_IANA_TLS_GROUP_NONE
};
#if defined(MBEDTLS_DEBUG_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_check_no_sig_alg_duplication(const uint16_t *sig_algs)
{
    size_t i, j;
    int ret = 0;
    for (i = 0; sig_algs[i] != MBEDTLS_TLS_SIG_NONE; i++) {
        for (j = 0; j < i; j++) {
            if (sig_algs[i] != sig_algs[j]) {
                continue;
            }
            mbedtls_printf(" entry(%04x,%" MBEDTLS_PRINTF_SIZET
                           ") is duplicated at %" MBEDTLS_PRINTF_SIZET "\n",
                           sig_algs[i], j, i);
            ret = -1;
        }
    }
    return ret;
}
#endif
int mbedtls_ssl_config_defaults(mbedtls_ssl_config *conf,
                                int endpoint, int transport, int preset)
{
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#endif
#if defined(MBEDTLS_DEBUG_C) && defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
    if (ssl_check_no_sig_alg_duplication(ssl_preset_suiteb_sig_algs)) {
        mbedtls_printf("ssl_preset_suiteb_sig_algs has duplicated entries\n");
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (ssl_check_no_sig_alg_duplication(ssl_preset_default_sig_algs)) {
        mbedtls_printf("ssl_preset_default_sig_algs has duplicated entries\n");
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (ssl_check_no_sig_alg_duplication(ssl_tls12_preset_suiteb_sig_algs)) {
        mbedtls_printf("ssl_tls12_preset_suiteb_sig_algs has duplicated entries\n");
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    if (ssl_check_no_sig_alg_duplication(ssl_tls12_preset_default_sig_algs)) {
        mbedtls_printf("ssl_tls12_preset_default_sig_algs has duplicated entries\n");
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
#endif
#endif
    mbedtls_ssl_conf_endpoint(conf, endpoint);
    mbedtls_ssl_conf_transport(conf, transport);
#if defined(MBEDTLS_SSL_CLI_C)
    if (endpoint == MBEDTLS_SSL_IS_CLIENT) {
        conf->authmode = MBEDTLS_SSL_VERIFY_REQUIRED;
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
        mbedtls_ssl_conf_session_tickets(conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
        mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
            conf, MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_DISABLED);
#endif
#endif
    }
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    conf->encrypt_then_mac = MBEDTLS_SSL_ETM_ENABLED;
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    conf->extended_ms = MBEDTLS_SSL_EXTENDED_MS_ENABLED;
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    conf->f_cookie_write = ssl_cookie_write_dummy;
    conf->f_cookie_check = ssl_cookie_check_dummy;
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    conf->anti_replay = MBEDTLS_SSL_ANTI_REPLAY_ENABLED;
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    conf->cert_req_ca_list = MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED;
    conf->respect_cli_pref = MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_SERVER;
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    conf->hs_timeout_min = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN;
    conf->hs_timeout_max = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX;
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    conf->renego_max_records = MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT;
    memset(conf->renego_period, 0x00, 2);
    memset(conf->renego_period + 2, 0xFF, 6);
#endif
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)
    if (endpoint == MBEDTLS_SSL_IS_SERVER) {
        const unsigned char dhm_p[] =
            MBEDTLS_DHM_RFC3526_MODP_2048_P_BIN;
        const unsigned char dhm_g[] =
            MBEDTLS_DHM_RFC3526_MODP_2048_G_BIN;
        if ((ret = mbedtls_ssl_conf_dh_param_bin(conf,
                                                 dhm_p, sizeof(dhm_p),
                                                 dhm_g, sizeof(dhm_g))) != 0) {
            return ret;
        }
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
#if defined(MBEDTLS_SSL_EARLY_DATA)
    mbedtls_ssl_conf_early_data(conf, MBEDTLS_SSL_EARLY_DATA_DISABLED);
#if defined(MBEDTLS_SSL_SRV_C)
    mbedtls_ssl_conf_max_early_data_size(conf, MBEDTLS_SSL_MAX_EARLY_DATA_SIZE);
#endif
#endif
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_conf_new_session_tickets(
        conf, MBEDTLS_SSL_TLS1_3_DEFAULT_NEW_SESSION_TICKETS);
#endif
    conf->tls13_kex_modes = MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL;
#endif
    if (transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
        conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
#else
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
#endif
    } else {
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_PROTO_TLS1_3)
        conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
        conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
#elif defined(MBEDTLS_SSL_PROTO_TLS1_3)
        conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
        conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_3;
#elif defined(MBEDTLS_SSL_PROTO_TLS1_2)
        conf->min_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
        conf->max_tls_version = MBEDTLS_SSL_VERSION_TLS1_2;
#else
        return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
#endif
    }
    switch (preset) {
        case MBEDTLS_SSL_PRESET_SUITEB:
            conf->ciphersuite_list = ssl_preset_suiteb_ciphersuites;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
            conf->cert_profile = &mbedtls_x509_crt_profile_suiteb;
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
            if (mbedtls_ssl_conf_is_tls12_only(conf)) {
                conf->sig_algs = ssl_tls12_preset_suiteb_sig_algs;
            } else
#endif
            conf->sig_algs = ssl_preset_suiteb_sig_algs;
#endif
#if defined(MBEDTLS_ECP_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
            conf->curve_list = NULL;
#endif
            conf->group_list = ssl_preset_suiteb_groups;
            break;
        default:
            conf->ciphersuite_list = mbedtls_ssl_list_ciphersuites();
#if defined(MBEDTLS_X509_CRT_PARSE_C)
            conf->cert_profile = &mbedtls_x509_crt_profile_default;
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
            if (mbedtls_ssl_conf_is_tls12_only(conf)) {
                conf->sig_algs = ssl_tls12_preset_default_sig_algs;
            } else
#endif
            conf->sig_algs = ssl_preset_default_sig_algs;
#endif
#if defined(MBEDTLS_ECP_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
            conf->curve_list = NULL;
#endif
            conf->group_list = ssl_preset_default_groups;
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_CLI_C)
            conf->dhm_min_bitlen = 1024;
#endif
    }
    return 0;
}
void mbedtls_ssl_config_free(mbedtls_ssl_config *conf)
{
    if (conf == NULL) {
        return;
    }
#if defined(MBEDTLS_DHM_C)
    mbedtls_mpi_free(&conf->dhm_P);
    mbedtls_mpi_free(&conf->dhm_G);
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (!mbedtls_svc_key_id_is_null(conf->psk_opaque)) {
        conf->psk_opaque = MBEDTLS_SVC_KEY_ID_INIT;
    }
#endif
    if (conf->psk != NULL) {
        mbedtls_zeroize_and_free(conf->psk, conf->psk_len);
        conf->psk = NULL;
        conf->psk_len = 0;
    }
    if (conf->psk_identity != NULL) {
        mbedtls_zeroize_and_free(conf->psk_identity, conf->psk_identity_len);
        conf->psk_identity = NULL;
        conf->psk_identity_len = 0;
    }
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    ssl_key_cert_free(conf->key_cert);
#endif
    mbedtls_platform_zeroize(conf, sizeof(mbedtls_ssl_config));
}
#if defined(MBEDTLS_PK_C) && \
    (defined(MBEDTLS_RSA_C) || defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED))
unsigned char mbedtls_ssl_sig_from_pk(mbedtls_pk_context *pk)
{
#if defined(MBEDTLS_RSA_C)
    if (mbedtls_pk_can_do(pk, MBEDTLS_PK_RSA)) {
        return MBEDTLS_SSL_SIG_RSA;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED)
    if (mbedtls_pk_can_do(pk, MBEDTLS_PK_ECDSA)) {
        return MBEDTLS_SSL_SIG_ECDSA;
    }
#endif
    return MBEDTLS_SSL_SIG_ANON;
}
unsigned char mbedtls_ssl_sig_from_pk_alg(mbedtls_pk_type_t type)
{
    switch (type) {
        case MBEDTLS_PK_RSA:
            return MBEDTLS_SSL_SIG_RSA;
        case MBEDTLS_PK_ECDSA:
        case MBEDTLS_PK_ECKEY:
            return MBEDTLS_SSL_SIG_ECDSA;
        default:
            return MBEDTLS_SSL_SIG_ANON;
    }
}
mbedtls_pk_type_t mbedtls_ssl_pk_alg_from_sig(unsigned char sig)
{
    switch (sig) {
#if defined(MBEDTLS_RSA_C)
        case MBEDTLS_SSL_SIG_RSA:
            return MBEDTLS_PK_RSA;
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ANY_ALLOWED_ENABLED)
        case MBEDTLS_SSL_SIG_ECDSA:
            return MBEDTLS_PK_ECDSA;
#endif
        default:
            return MBEDTLS_PK_NONE;
    }
}
#endif
mbedtls_md_type_t mbedtls_ssl_md_alg_from_hash(unsigned char hash)
{
    switch (hash) {
#if defined(MBEDTLS_MD_CAN_MD5)
        case MBEDTLS_SSL_HASH_MD5:
            return MBEDTLS_MD_MD5;
#endif
#if defined(MBEDTLS_MD_CAN_SHA1)
        case MBEDTLS_SSL_HASH_SHA1:
            return MBEDTLS_MD_SHA1;
#endif
#if defined(MBEDTLS_MD_CAN_SHA224)
        case MBEDTLS_SSL_HASH_SHA224:
            return MBEDTLS_MD_SHA224;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_SSL_HASH_SHA256:
            return MBEDTLS_MD_SHA256;
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_SSL_HASH_SHA384:
            return MBEDTLS_MD_SHA384;
#endif
#if defined(MBEDTLS_MD_CAN_SHA512)
        case MBEDTLS_SSL_HASH_SHA512:
            return MBEDTLS_MD_SHA512;
#endif
        default:
            return MBEDTLS_MD_NONE;
    }
}
unsigned char mbedtls_ssl_hash_from_md_alg(int md)
{
    switch (md) {
#if defined(MBEDTLS_MD_CAN_MD5)
        case MBEDTLS_MD_MD5:
            return MBEDTLS_SSL_HASH_MD5;
#endif
#if defined(MBEDTLS_MD_CAN_SHA1)
        case MBEDTLS_MD_SHA1:
            return MBEDTLS_SSL_HASH_SHA1;
#endif
#if defined(MBEDTLS_MD_CAN_SHA224)
        case MBEDTLS_MD_SHA224:
            return MBEDTLS_SSL_HASH_SHA224;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_MD_SHA256:
            return MBEDTLS_SSL_HASH_SHA256;
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_MD_SHA384:
            return MBEDTLS_SSL_HASH_SHA384;
#endif
#if defined(MBEDTLS_MD_CAN_SHA512)
        case MBEDTLS_MD_SHA512:
            return MBEDTLS_SSL_HASH_SHA512;
#endif
        default:
            return MBEDTLS_SSL_HASH_NONE;
    }
}
int mbedtls_ssl_check_curve_tls_id(const mbedtls_ssl_context *ssl, uint16_t tls_id)
{
    const uint16_t *group_list = mbedtls_ssl_get_groups(ssl);
    if (group_list == NULL) {
        return -1;
    }
    for (; *group_list != 0; group_list++) {
        if (*group_list == tls_id) {
            return 0;
        }
    }
    return -1;
}
#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
int mbedtls_ssl_check_curve(const mbedtls_ssl_context *ssl, mbedtls_ecp_group_id grp_id)
{
    uint16_t tls_id = mbedtls_ssl_get_tls_id_from_ecp_group_id(grp_id);
    if (tls_id == 0) {
        return -1;
    }
    return mbedtls_ssl_check_curve_tls_id(ssl, tls_id);
}
#endif
static const struct {
    uint16_t tls_id;
    mbedtls_ecp_group_id ecp_group_id;
    uint16_t bits;
} tls_id_match_table[] =
{
#if defined(MBEDTLS_ECP_HAVE_SECP521R1)
    { 25, MBEDTLS_ECP_DP_SECP521R1, 521 },
#endif
#if defined(MBEDTLS_ECP_HAVE_BP512R1)
    { 28, MBEDTLS_ECP_DP_BP512R1, 512 },
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP384R1)
    { 24, MBEDTLS_ECP_DP_SECP384R1, 384 },
#endif
#if defined(MBEDTLS_ECP_HAVE_BP384R1)
    { 27, MBEDTLS_ECP_DP_BP384R1, 384 },
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP256R1)
    { 23, MBEDTLS_ECP_DP_SECP256R1, 256 },
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP256K1)
    { 22, MBEDTLS_ECP_DP_SECP256K1, 256 },
#endif
#if defined(MBEDTLS_ECP_HAVE_BP256R1)
    { 26, MBEDTLS_ECP_DP_BP256R1, 256 },
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP224R1)
    { 21, MBEDTLS_ECP_DP_SECP224R1, 224 },
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP224K1)
    { 20, MBEDTLS_ECP_DP_SECP224K1, 224 },
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP192R1)
    { 19, MBEDTLS_ECP_DP_SECP192R1, 192 },
#endif
#if defined(MBEDTLS_ECP_HAVE_SECP192K1)
    { 18, MBEDTLS_ECP_DP_SECP192K1, 192 },
#endif
#if defined(MBEDTLS_ECP_HAVE_CURVE25519)
    { 29, MBEDTLS_ECP_DP_CURVE25519, 255 },
#endif
#if defined(MBEDTLS_ECP_HAVE_CURVE448)
    { 30, MBEDTLS_ECP_DP_CURVE448, 448 },
#endif
    { 0, MBEDTLS_ECP_DP_NONE, 0 },
};
mbedtls_ecp_group_id mbedtls_ssl_get_ecp_group_id_from_tls_id(uint16_t tls_id)
{
    for (int i = 0; tls_id_match_table[i].tls_id != 0; i++) {
        if (tls_id_match_table[i].tls_id == tls_id) {
            return tls_id_match_table[i].ecp_group_id;
        }
    }
    return MBEDTLS_ECP_DP_NONE;
}
uint16_t mbedtls_ssl_get_tls_id_from_ecp_group_id(mbedtls_ecp_group_id grp_id)
{
    for (int i = 0; tls_id_match_table[i].ecp_group_id != MBEDTLS_ECP_DP_NONE;
         i++) {
        if (tls_id_match_table[i].ecp_group_id == grp_id) {
            return tls_id_match_table[i].tls_id;
        }
    }
    return 0;
}
#if defined(MBEDTLS_DEBUG_C)
static const struct {
    uint16_t tls_id;
    const char *name;
} tls_id_curve_name_table[] =
{
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1, "secp521r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1, "brainpoolP512r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1, "secp384r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1, "brainpoolP384r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, "secp256r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1, "secp256k1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1, "brainpoolP256r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1, "secp224r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP224K1, "secp224k1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1, "secp192r1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_SECP192K1, "secp192k1" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_X25519, "x25519" },
    { MBEDTLS_SSL_IANA_TLS_GROUP_X448, "x448" },
    { 0, NULL },
};
const char *mbedtls_ssl_get_curve_name_from_tls_id(uint16_t tls_id)
{
    for (int i = 0; tls_id_curve_name_table[i].tls_id != 0; i++) {
        if (tls_id_curve_name_table[i].tls_id == tls_id) {
            return tls_id_curve_name_table[i].name;
        }
    }
    return NULL;
}
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_ssl_get_handshake_transcript(mbedtls_ssl_context *ssl,
                                         const mbedtls_md_type_t md,
                                         unsigned char *dst,
                                         size_t dst_len,
                                         size_t *olen)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_hash_operation_t *hash_operation_to_clone;
    psa_hash_operation_t hash_operation = psa_hash_operation_init();
    *olen = 0;
    switch (md) {
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_MD_SHA384:
            hash_operation_to_clone = &ssl->handshake->fin_sha384_psa;
            break;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_MD_SHA256:
            hash_operation_to_clone = &ssl->handshake->fin_sha256_psa;
            break;
#endif
        default:
            goto exit;
    }
    status = psa_hash_clone(hash_operation_to_clone, &hash_operation);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    status = psa_hash_finish(&hash_operation, dst, dst_len, olen);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
exit:
#if !defined(MBEDTLS_MD_CAN_SHA384) && \
    !defined(MBEDTLS_MD_CAN_SHA256)
    (void) ssl;
#endif
    return PSA_TO_MBEDTLS_ERR(status);
}
#else
#if defined(MBEDTLS_MD_CAN_SHA384)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_get_handshake_transcript_sha384(mbedtls_ssl_context *ssl,
                                               unsigned char *dst,
                                               size_t dst_len,
                                               size_t *olen)
{
    int ret;
    mbedtls_md_context_t sha384;
    if (dst_len < 48) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    mbedtls_md_init(&sha384);
    ret = mbedtls_md_setup(&sha384, mbedtls_md_info_from_type(MBEDTLS_MD_SHA384), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_clone(&sha384, &ssl->handshake->fin_sha384);
    if (ret != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_finish(&sha384, dst)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_finish", ret);
        goto exit;
    }
    *olen = 48;
exit:
    mbedtls_md_free(&sha384);
    return ret;
}
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_get_handshake_transcript_sha256(mbedtls_ssl_context *ssl,
                                               unsigned char *dst,
                                               size_t dst_len,
                                               size_t *olen)
{
    int ret;
    mbedtls_md_context_t sha256;
    if (dst_len < 32) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    mbedtls_md_init(&sha256);
    ret = mbedtls_md_setup(&sha256, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_clone(&sha256, &ssl->handshake->fin_sha256);
    if (ret != 0) {
        goto exit;
    }
    if ((ret = mbedtls_md_finish(&sha256, dst)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_finish", ret);
        goto exit;
    }
    *olen = 32;
exit:
    mbedtls_md_free(&sha256);
    return ret;
}
#endif
int mbedtls_ssl_get_handshake_transcript(mbedtls_ssl_context *ssl,
                                         const mbedtls_md_type_t md,
                                         unsigned char *dst,
                                         size_t dst_len,
                                         size_t *olen)
{
    switch (md) {
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_MD_SHA384:
            return ssl_get_handshake_transcript_sha384(ssl, dst, dst_len, olen);
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_MD_SHA256:
            return ssl_get_handshake_transcript_sha256(ssl, dst, dst_len, olen);
#endif
        default:
#if !defined(MBEDTLS_MD_CAN_SHA384) && \
            !defined(MBEDTLS_MD_CAN_SHA256)
            (void) ssl;
            (void) dst;
            (void) dst_len;
            (void) olen;
#endif
            break;
    }
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
int mbedtls_ssl_parse_sig_alg_ext(mbedtls_ssl_context *ssl,
                                  const unsigned char *buf,
                                  const unsigned char *end)
{
    const unsigned char *p = buf;
    size_t supported_sig_algs_len = 0;
    const unsigned char *supported_sig_algs_end;
    uint16_t sig_alg;
    uint32_t common_idx = 0;
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    supported_sig_algs_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    memset(ssl->handshake->received_sig_algs, 0,
           sizeof(ssl->handshake->received_sig_algs));
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, supported_sig_algs_len);
    supported_sig_algs_end = p + supported_sig_algs_len;
    while (p < supported_sig_algs_end) {
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, supported_sig_algs_end, 2);
        sig_alg = MBEDTLS_GET_UINT16_BE(p, 0);
        p += 2;
        MBEDTLS_SSL_DEBUG_MSG(4, ("received signature algorithm: 0x%x %s",
                                  sig_alg,
                                  mbedtls_ssl_sig_alg_to_str(sig_alg)));
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
        if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
            (!(mbedtls_ssl_sig_alg_is_supported(ssl, sig_alg) &&
               mbedtls_ssl_sig_alg_is_offered(ssl, sig_alg)))) {
            continue;
        }
#endif
        MBEDTLS_SSL_DEBUG_MSG(4, ("valid signature algorithm: %s",
                                  mbedtls_ssl_sig_alg_to_str(sig_alg)));
        if (common_idx + 1 < MBEDTLS_RECEIVED_SIG_ALGS_SIZE) {
            ssl->handshake->received_sig_algs[common_idx] = sig_alg;
            common_idx += 1;
        }
    }
    if (p != end) {
        MBEDTLS_SSL_DEBUG_MSG(1,
                              ("Signature algorithms extension length misaligned"));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR,
                                     MBEDTLS_ERR_SSL_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (common_idx == 0) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("no signature algorithm in common"));
        MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                     MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
    ssl->handshake->received_sig_algs[common_idx] = MBEDTLS_TLS_SIG_NONE;
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
static psa_status_t setup_psa_key_derivation(psa_key_derivation_operation_t *derivation,
                                             mbedtls_svc_key_id_t key,
                                             psa_algorithm_t alg,
                                             const unsigned char *raw_psk, size_t raw_psk_length,
                                             const unsigned char *seed, size_t seed_length,
                                             const unsigned char *label, size_t label_length,
                                             const unsigned char *other_secret,
                                             size_t other_secret_length,
                                             size_t capacity)
{
    psa_status_t status;
    status = psa_key_derivation_setup(derivation, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (PSA_ALG_IS_TLS12_PRF(alg) || PSA_ALG_IS_TLS12_PSK_TO_MS(alg)) {
        status = psa_key_derivation_input_bytes(derivation,
                                                PSA_KEY_DERIVATION_INPUT_SEED,
                                                seed, seed_length);
        if (status != PSA_SUCCESS) {
            return status;
        }
        if (other_secret != NULL) {
            status = psa_key_derivation_input_bytes(derivation,
                                                    PSA_KEY_DERIVATION_INPUT_OTHER_SECRET,
                                                    other_secret, other_secret_length);
            if (status != PSA_SUCCESS) {
                return status;
            }
        }
        if (mbedtls_svc_key_id_is_null(key)) {
            status = psa_key_derivation_input_bytes(
                derivation, PSA_KEY_DERIVATION_INPUT_SECRET,
                raw_psk, raw_psk_length);
        } else {
            status = psa_key_derivation_input_key(
                derivation, PSA_KEY_DERIVATION_INPUT_SECRET, key);
        }
        if (status != PSA_SUCCESS) {
            return status;
        }
        status = psa_key_derivation_input_bytes(derivation,
                                                PSA_KEY_DERIVATION_INPUT_LABEL,
                                                label, label_length);
        if (status != PSA_SUCCESS) {
            return status;
        }
    } else {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = psa_key_derivation_set_capacity(derivation, capacity);
    if (status != PSA_SUCCESS) {
        return status;
    }
    return PSA_SUCCESS;
}
#if defined(PSA_WANT_ALG_SHA_384) || \
    defined(PSA_WANT_ALG_SHA_256)
MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_generic(mbedtls_md_type_t md_type,
                           const unsigned char *secret, size_t slen,
                           const char *label,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen)
{
    psa_status_t status;
    psa_algorithm_t alg;
    mbedtls_svc_key_id_t master_key = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_derivation_operation_t derivation =
        PSA_KEY_DERIVATION_OPERATION_INIT;
    if (md_type == MBEDTLS_MD_SHA384) {
        alg = PSA_ALG_TLS12_PRF(PSA_ALG_SHA_384);
    } else {
        alg = PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256);
    }
    if (slen != 0) {
        psa_key_attributes_t key_attributes = psa_key_attributes_init();
        psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&key_attributes, alg);
        psa_set_key_type(&key_attributes, PSA_KEY_TYPE_DERIVE);
        status = psa_import_key(&key_attributes, secret, slen, &master_key);
        if (status != PSA_SUCCESS) {
            return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }
    }
    status = setup_psa_key_derivation(&derivation,
                                      master_key, alg,
                                      NULL, 0,
                                      random, rlen,
                                      (unsigned char const *) label,
                                      (size_t) strlen(label),
                                      NULL, 0,
                                      dlen);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(&derivation);
        psa_destroy_key(master_key);
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    status = psa_key_derivation_output_bytes(&derivation, dstbuf, dlen);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(&derivation);
        psa_destroy_key(master_key);
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    status = psa_key_derivation_abort(&derivation);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(master_key);
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    if (!mbedtls_svc_key_id_is_null(master_key)) {
        status = psa_destroy_key(master_key);
    }
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
    }
    return 0;
}
#endif
#else
#if defined(MBEDTLS_MD_C) && \
    (defined(MBEDTLS_MD_CAN_SHA256) || \
    defined(MBEDTLS_MD_CAN_SHA384))
MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_generic(mbedtls_md_type_t md_type,
                           const unsigned char *secret, size_t slen,
                           const char *label,
                           const unsigned char *random, size_t rlen,
                           unsigned char *dstbuf, size_t dlen)
{
    size_t nb;
    size_t i, j, k, md_len;
    unsigned char *tmp;
    size_t tmp_len = 0;
    unsigned char h_i[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_init(&md_ctx);
    if ((md_info = mbedtls_md_info_from_type(md_type)) == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    md_len = mbedtls_md_get_size(md_info);
    tmp_len = md_len + strlen(label) + rlen;
    tmp = mbedtls_calloc(1, tmp_len);
    if (tmp == NULL) {
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }
    nb = strlen(label);
    memcpy(tmp + md_len, label, nb);
    memcpy(tmp + md_len + nb, random, rlen);
    nb += rlen;
    if ((ret = mbedtls_md_setup(&md_ctx, md_info, 1)) != 0) {
        goto exit;
    }
    ret = mbedtls_md_hmac_starts(&md_ctx, secret, slen);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_hmac_update(&md_ctx, tmp + md_len, nb);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_hmac_finish(&md_ctx, tmp);
    if (ret != 0) {
        goto exit;
    }
    for (i = 0; i < dlen; i += md_len) {
        ret = mbedtls_md_hmac_reset(&md_ctx);
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_md_hmac_update(&md_ctx, tmp, md_len + nb);
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_md_hmac_finish(&md_ctx, h_i);
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_md_hmac_reset(&md_ctx);
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_md_hmac_update(&md_ctx, tmp, md_len);
        if (ret != 0) {
            goto exit;
        }
        ret = mbedtls_md_hmac_finish(&md_ctx, tmp);
        if (ret != 0) {
            goto exit;
        }
        k = (i + md_len > dlen) ? dlen % md_len : md_len;
        for (j = 0; j < k; j++) {
            dstbuf[i + j] = h_i[j];
        }
    }
exit:
    mbedtls_md_free(&md_ctx);
    if (tmp != NULL) {
        mbedtls_platform_zeroize(tmp, tmp_len);
    }
    mbedtls_platform_zeroize(h_i, sizeof(h_i));
    mbedtls_free(tmp);
    return ret;
}
#endif
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha256(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen)
{
    return tls_prf_generic(MBEDTLS_MD_SHA256, secret, slen,
                           label, random, rlen, dstbuf, dlen);
}
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
MBEDTLS_CHECK_RETURN_CRITICAL
static int tls_prf_sha384(const unsigned char *secret, size_t slen,
                          const char *label,
                          const unsigned char *random, size_t rlen,
                          unsigned char *dstbuf, size_t dlen)
{
    return tls_prf_generic(MBEDTLS_MD_SHA384, secret, slen,
                           label, random, rlen, dstbuf, dlen);
}
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_set_handshake_prfs(mbedtls_ssl_handshake_params *handshake,
                                  mbedtls_md_type_t hash)
{
#if defined(MBEDTLS_MD_CAN_SHA384)
    if (hash == MBEDTLS_MD_SHA384) {
        handshake->tls_prf = tls_prf_sha384;
        handshake->calc_verify = ssl_calc_verify_tls_sha384;
        handshake->calc_finished = ssl_calc_finished_tls_sha384;
    } else
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
    {
        (void) hash;
        handshake->tls_prf = tls_prf_sha256;
        handshake->calc_verify = ssl_calc_verify_tls_sha256;
        handshake->calc_finished = ssl_calc_finished_tls_sha256;
    }
#else
    {
        (void) handshake;
        (void) hash;
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
#endif
    return 0;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_compute_master(mbedtls_ssl_handshake_params *handshake,
                              unsigned char *master,
                              const mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t const master_secret_len = 48;
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    unsigned char session_hash[48];
#endif
    char const *lbl = "master secret";
    unsigned char const *seed = handshake->randbytes;
    size_t seed_len = 64;
#if !defined(MBEDTLS_DEBUG_C) && \
    !defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET) && \
    !(defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED))
    ssl = NULL;
    (void) ssl;
#endif
    if (handshake->resume != 0) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("no premaster (session resumed)"));
        return 0;
    }
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    if (handshake->extended_ms == MBEDTLS_SSL_EXTENDED_MS_ENABLED) {
        lbl = "extended master secret";
        seed = session_hash;
        ret = handshake->calc_verify(ssl, session_hash, &seed_len);
        if (ret != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "calc_verify", ret);
        }
        MBEDTLS_SSL_DEBUG_BUF(3, "session hash for extended master secret",
                              session_hash, seed_len);
    }
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (mbedtls_ssl_ciphersuite_uses_psk(handshake->ciphersuite_info) == 1) {
        psa_status_t status;
        psa_algorithm_t alg;
        mbedtls_svc_key_id_t psk;
        psa_key_derivation_operation_t derivation =
            PSA_KEY_DERIVATION_OPERATION_INIT;
        mbedtls_md_type_t hash_alg = (mbedtls_md_type_t) handshake->ciphersuite_info->mac;
        MBEDTLS_SSL_DEBUG_MSG(2, ("perform PSA-based PSK-to-MS expansion"));
        psk = mbedtls_ssl_get_opaque_psk(ssl);
        if (hash_alg == MBEDTLS_MD_SHA384) {
            alg = PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_384);
        } else {
            alg = PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256);
        }
        size_t other_secret_len = 0;
        unsigned char *other_secret = NULL;
        switch (handshake->ciphersuite_info->key_exchange) {
            case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
                other_secret_len = 48;
                other_secret = handshake->premaster + 2;
                break;
            case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
                other_secret_len = MBEDTLS_GET_UINT16_BE(handshake->premaster, 0);
                other_secret = handshake->premaster + 2;
                break;
            default:
                break;
        }
        status = setup_psa_key_derivation(&derivation, psk, alg,
                                          ssl->conf->psk, ssl->conf->psk_len,
                                          seed, seed_len,
                                          (unsigned char const *) lbl,
                                          (size_t) strlen(lbl),
                                          other_secret, other_secret_len,
                                          master_secret_len);
        if (status != PSA_SUCCESS) {
            psa_key_derivation_abort(&derivation);
            return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }
        status = psa_key_derivation_output_bytes(&derivation,
                                                 master,
                                                 master_secret_len);
        if (status != PSA_SUCCESS) {
            psa_key_derivation_abort(&derivation);
            return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }
        status = psa_key_derivation_abort(&derivation);
        if (status != PSA_SUCCESS) {
            return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        }
    } else
#endif
    {
#if defined(MBEDTLS_USE_PSA_CRYPTO) && \
        defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
        if (handshake->ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE) {
            psa_status_t status;
            psa_algorithm_t alg = PSA_ALG_TLS12_ECJPAKE_TO_PMS;
            psa_key_derivation_operation_t derivation =
                PSA_KEY_DERIVATION_OPERATION_INIT;
            MBEDTLS_SSL_DEBUG_MSG(2, ("perform PSA-based PMS KDF for ECJPAKE"));
            handshake->pmslen = PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE;
            status = psa_key_derivation_setup(&derivation, alg);
            if (status != PSA_SUCCESS) {
                return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }
            status = psa_key_derivation_set_capacity(&derivation,
                                                     PSA_TLS12_ECJPAKE_TO_PMS_DATA_SIZE);
            if (status != PSA_SUCCESS) {
                psa_key_derivation_abort(&derivation);
                return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }
            status = psa_pake_get_implicit_key(&handshake->psa_pake_ctx,
                                               &derivation);
            if (status != PSA_SUCCESS) {
                psa_key_derivation_abort(&derivation);
                return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }
            status = psa_key_derivation_output_bytes(&derivation,
                                                     handshake->premaster,
                                                     handshake->pmslen);
            if (status != PSA_SUCCESS) {
                psa_key_derivation_abort(&derivation);
                return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }
            status = psa_key_derivation_abort(&derivation);
            if (status != PSA_SUCCESS) {
                return MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
            }
        }
#endif
        ret = handshake->tls_prf(handshake->premaster, handshake->pmslen,
                                 lbl, seed, seed_len,
                                 master,
                                 master_secret_len);
        if (ret != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "prf", ret);
            return ret;
        }
        MBEDTLS_SSL_DEBUG_BUF(3, "premaster secret",
                              handshake->premaster,
                              handshake->pmslen);
        mbedtls_platform_zeroize(handshake->premaster,
                                 sizeof(handshake->premaster));
    }
    return 0;
}
int mbedtls_ssl_derive_keys(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_ssl_ciphersuite_t * const ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> derive keys"));
    ret = ssl_set_handshake_prfs(ssl->handshake,
                                 (mbedtls_md_type_t) ciphersuite_info->mac);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "ssl_set_handshake_prfs", ret);
        return ret;
    }
    ret = ssl_compute_master(ssl->handshake,
                             ssl->session_negotiate->master,
                             ssl);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "ssl_compute_master", ret);
        return ret;
    }
    {
        unsigned char tmp[64];
        memcpy(tmp, ssl->handshake->randbytes, 64);
        memcpy(ssl->handshake->randbytes, tmp + 32, 32);
        memcpy(ssl->handshake->randbytes + 32, tmp, 32);
        mbedtls_platform_zeroize(tmp, sizeof(tmp));
    }
    ret = ssl_tls12_populate_transform(ssl->transform_negotiate,
                                       ssl->session_negotiate->ciphersuite,
                                       ssl->session_negotiate->master,
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                       ssl->session_negotiate->encrypt_then_mac,
#endif
                                       ssl->handshake->tls_prf,
                                       ssl->handshake->randbytes,
                                       ssl->tls_version,
                                       ssl->conf->endpoint,
                                       ssl);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "ssl_tls12_populate_transform", ret);
        return ret;
    }
    mbedtls_platform_zeroize(ssl->handshake->randbytes,
                             sizeof(ssl->handshake->randbytes));
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= derive keys"));
    return 0;
}
int mbedtls_ssl_set_calc_verify_md(mbedtls_ssl_context *ssl, int md)
{
    switch (md) {
#if defined(MBEDTLS_MD_CAN_SHA384)
        case MBEDTLS_SSL_HASH_SHA384:
            ssl->handshake->calc_verify = ssl_calc_verify_tls_sha384;
            break;
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
        case MBEDTLS_SSL_HASH_SHA256:
            ssl->handshake->calc_verify = ssl_calc_verify_tls_sha256;
            break;
#endif
        default:
            return -1;
    }
#if !defined(MBEDTLS_MD_CAN_SHA384) && \
    !defined(MBEDTLS_MD_CAN_SHA256)
    (void) ssl;
#endif
    return 0;
}
#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int ssl_calc_verify_tls_psa(const mbedtls_ssl_context *ssl,
                                   const psa_hash_operation_t *hs_op,
                                   size_t buffer_size,
                                   unsigned char *hash,
                                   size_t *hlen)
{
    psa_status_t status;
    psa_hash_operation_t cloned_op = psa_hash_operation_init();
#if !defined(MBEDTLS_DEBUG_C)
    (void) ssl;
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> PSA calc verify"));
    status = psa_hash_clone(hs_op, &cloned_op);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    status = psa_hash_finish(&cloned_op, hash, buffer_size, hlen);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    MBEDTLS_SSL_DEBUG_BUF(3, "PSA calculated verify result", hash, *hlen);
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= PSA calc verify"));
exit:
    psa_hash_abort(&cloned_op);
    return mbedtls_md_error_from_psa(status);
}
#else
static int ssl_calc_verify_tls_legacy(const mbedtls_ssl_context *ssl,
                                      const mbedtls_md_context_t *hs_ctx,
                                      unsigned char *hash,
                                      size_t *hlen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_context_t cloned_ctx;
    mbedtls_md_init(&cloned_ctx);
#if !defined(MBEDTLS_DEBUG_C)
    (void) ssl;
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc verify"));
    ret = mbedtls_md_setup(&cloned_ctx, mbedtls_md_info_from_ctx(hs_ctx), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_clone(&cloned_ctx, hs_ctx);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_finish(&cloned_ctx, hash);
    if (ret != 0) {
        goto exit;
    }
    *hlen = mbedtls_md_get_size(mbedtls_md_info_from_ctx(hs_ctx));
    MBEDTLS_SSL_DEBUG_BUF(3, "calculated verify result", hash, *hlen);
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= calc verify"));
exit:
    mbedtls_md_free(&cloned_ctx);
    return ret;
}
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
int ssl_calc_verify_tls_sha256(const mbedtls_ssl_context *ssl,
                               unsigned char *hash,
                               size_t *hlen)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    return ssl_calc_verify_tls_psa(ssl, &ssl->handshake->fin_sha256_psa, 32,
                                   hash, hlen);
#else
    return ssl_calc_verify_tls_legacy(ssl, &ssl->handshake->fin_sha256,
                                      hash, hlen);
#endif
}
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
int ssl_calc_verify_tls_sha384(const mbedtls_ssl_context *ssl,
                               unsigned char *hash,
                               size_t *hlen)
{
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    return ssl_calc_verify_tls_psa(ssl, &ssl->handshake->fin_sha384_psa, 48,
                                   hash, hlen);
#else
    return ssl_calc_verify_tls_legacy(ssl, &ssl->handshake->fin_sha384,
                                      hash, hlen);
#endif
}
#endif
#if !defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int mbedtls_ssl_psk_derive_premaster(mbedtls_ssl_context *ssl, mbedtls_key_exchange_type_t key_ex)
{
    unsigned char *p = ssl->handshake->premaster;
    unsigned char *end = p + sizeof(ssl->handshake->premaster);
    const unsigned char *psk = NULL;
    size_t psk_len = 0;
    int psk_ret = mbedtls_ssl_get_psk(ssl, &psk, &psk_len);
    if (psk_ret == MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED) {
        if (key_ex != MBEDTLS_KEY_EXCHANGE_DHE_PSK) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    }
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    if (key_ex == MBEDTLS_KEY_EXCHANGE_PSK) {
        if (end - p < 2) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        MBEDTLS_PUT_UINT16_BE(psk_len, p, 0);
        p += 2;
        if (end < p || (size_t) (end - p) < psk_len) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        memset(p, 0, psk_len);
        p += psk_len;
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    if (key_ex == MBEDTLS_KEY_EXCHANGE_RSA_PSK) {
        if (end - p < 2) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        *p++ = 0;
        *p++ = 48;
        p += 48;
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if (key_ex == MBEDTLS_KEY_EXCHANGE_DHE_PSK) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t len;
        if ((ret = mbedtls_dhm_calc_secret(&ssl->handshake->dhm_ctx,
                                           p + 2, (size_t) (end - (p + 2)), &len,
                                           ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_dhm_calc_secret", ret);
            return ret;
        }
        MBEDTLS_PUT_UINT16_BE(len, p, 0);
        p += 2 + len;
        MBEDTLS_SSL_DEBUG_MPI(3, "DHM: K ", &ssl->handshake->dhm_ctx.K);
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    if (key_ex == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t zlen;
        if ((ret = mbedtls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx, &zlen,
                                            p + 2, (size_t) (end - (p + 2)),
                                            ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_calc_secret", ret);
            return ret;
        }
        MBEDTLS_PUT_UINT16_BE(zlen, p, 0);
        p += 2 + zlen;
        MBEDTLS_SSL_DEBUG_ECDH(3, &ssl->handshake->ecdh_ctx,
                               MBEDTLS_DEBUG_ECDH_Z);
    } else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    if (end - p < 2) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    MBEDTLS_PUT_UINT16_BE(psk_len, p, 0);
    p += 2;
    if (end < p || (size_t) (end - p) < psk_len) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    memcpy(p, psk, psk_len);
    p += psk_len;
    ssl->handshake->pmslen = (size_t) (p - ssl->handshake->premaster);
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_RENEGOTIATION)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_hello_request(mbedtls_ssl_context *ssl);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
int mbedtls_ssl_resend_hello_request(mbedtls_ssl_context *ssl)
{
    if (ssl->conf->renego_max_records < 0) {
        uint32_t ratio = ssl->conf->hs_timeout_max / ssl->conf->hs_timeout_min + 1;
        unsigned char doublings = 1;
        while (ratio != 0) {
            ++doublings;
            ratio >>= 1;
        }
        if (++ssl->renego_records_seen > doublings) {
            MBEDTLS_SSL_DEBUG_MSG(2, ("no longer retransmitting hello request"));
            return 0;
        }
    }
    return ssl_write_hello_request(ssl);
}
#endif
#endif
#if !defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
int mbedtls_ssl_write_certificate(mbedtls_ssl_context *ssl)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate"));
    if (!mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate"));
        ssl->state++;
        return 0;
    }
    MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
int mbedtls_ssl_parse_certificate(mbedtls_ssl_context *ssl)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));
    if (!mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate"));
        ssl->state++;
        return 0;
    }
    MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
#else
int mbedtls_ssl_write_certificate(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, n;
    const mbedtls_x509_crt *crt;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate"));
    if (!mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate"));
        ssl->state++;
        return 0;
    }
#if defined(MBEDTLS_SSL_CLI_C)
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
        if (ssl->handshake->client_auth == 0) {
            MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate"));
            ssl->state++;
            return 0;
        }
    }
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
        if (mbedtls_ssl_own_cert(ssl) == NULL) {
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
    }
#endif
    MBEDTLS_SSL_DEBUG_CRT(3, "own certificate", mbedtls_ssl_own_cert(ssl));
    i = 7;
    crt = mbedtls_ssl_own_cert(ssl);
    while (crt != NULL) {
        n = crt->raw.len;
        if (n > MBEDTLS_SSL_OUT_CONTENT_LEN - 3 - i) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("certificate too large, %" MBEDTLS_PRINTF_SIZET
                                      " > %" MBEDTLS_PRINTF_SIZET,
                                      i + 3 + n, (size_t) MBEDTLS_SSL_OUT_CONTENT_LEN));
            return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
        }
        ssl->out_msg[i] = MBEDTLS_BYTE_2(n);
        ssl->out_msg[i + 1] = MBEDTLS_BYTE_1(n);
        ssl->out_msg[i + 2] = MBEDTLS_BYTE_0(n);
        i += 3; memcpy(ssl->out_msg + i, crt->raw.p, n);
        i += n; crt = crt->next;
    }
    ssl->out_msg[4] = MBEDTLS_BYTE_2(i - 7);
    ssl->out_msg[5] = MBEDTLS_BYTE_1(i - 7);
    ssl->out_msg[6] = MBEDTLS_BYTE_0(i - 7);
    ssl->out_msglen = i;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_CERTIFICATE;
    ssl->state++;
    if ((ret = mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate"));
    return ret;
}
#if defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CLI_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_check_peer_crt_unchanged(mbedtls_ssl_context *ssl,
                                        unsigned char *crt_buf,
                                        size_t crt_buf_len)
{
    mbedtls_x509_crt const * const peer_crt = ssl->session->peer_cert;
    if (peer_crt == NULL) {
        return -1;
    }
    if (peer_crt->raw.len != crt_buf_len) {
        return -1;
    }
    return memcmp(peer_crt->raw.p, crt_buf, peer_crt->raw.len);
}
#else
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_check_peer_crt_unchanged(mbedtls_ssl_context *ssl,
                                        unsigned char *crt_buf,
                                        size_t crt_buf_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char const * const peer_cert_digest =
        ssl->session->peer_cert_digest;
    mbedtls_md_type_t const peer_cert_digest_type =
        ssl->session->peer_cert_digest_type;
    mbedtls_md_info_t const * const digest_info =
        mbedtls_md_info_from_type(peer_cert_digest_type);
    unsigned char tmp_digest[MBEDTLS_SSL_PEER_CERT_DIGEST_MAX_LEN];
    size_t digest_len;
    if (peer_cert_digest == NULL || digest_info == NULL) {
        return -1;
    }
    digest_len = mbedtls_md_get_size(digest_info);
    if (digest_len > MBEDTLS_SSL_PEER_CERT_DIGEST_MAX_LEN) {
        return -1;
    }
    ret = mbedtls_md(digest_info, crt_buf, crt_buf_len, tmp_digest);
    if (ret != 0) {
        return -1;
    }
    return memcmp(tmp_digest, peer_cert_digest, digest_len);
}
#endif
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_certificate_chain(mbedtls_ssl_context *ssl,
                                       mbedtls_x509_crt *chain)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CLI_C)
    int crt_cnt = 0;
#endif
    size_t i, n;
    uint8_t alert;
    if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }
    if (ssl->in_msg[0] != MBEDTLS_SSL_HS_CERTIFICATE) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }
    if (ssl->in_hslen < mbedtls_ssl_hs_hdr_len(ssl) + 3 + 3) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    i = mbedtls_ssl_hs_hdr_len(ssl);
    n = MBEDTLS_GET_UINT16_BE(ssl->in_msg, i + 1);
    if (ssl->in_msg[i] != 0 ||
        ssl->in_hslen != n + 3 + mbedtls_ssl_hs_hdr_len(ssl)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    i += 3;
    while (i < ssl->in_hslen) {
        if (i + 3 > ssl->in_hslen) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
            mbedtls_ssl_send_alert_message(ssl,
                                           MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        if (ssl->in_msg[i] != 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
            mbedtls_ssl_send_alert_message(ssl,
                                           MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT);
            return MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
        }
        n = MBEDTLS_GET_UINT16_BE(ssl->in_msg, i + 1);
        i += 3;
        if (n < 128 || i + n > ssl->in_hslen) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate message"));
            mbedtls_ssl_send_alert_message(ssl,
                                           MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
#if defined(MBEDTLS_SSL_RENEGOTIATION) && defined(MBEDTLS_SSL_CLI_C)
        if (crt_cnt++ == 0 &&
            ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT &&
            ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("Check that peer CRT hasn't changed during renegotiation"));
            if (ssl_check_peer_crt_unchanged(ssl,
                                             &ssl->in_msg[i],
                                             n) != 0) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("new server cert during renegotiation"));
                mbedtls_ssl_send_alert_message(ssl,
                                               MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                               MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED);
                return MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
            }
            ssl_clear_peer_cert(ssl->session);
        }
#endif
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
        ret = mbedtls_x509_crt_parse_der(chain, ssl->in_msg + i, n);
#else
        ret = mbedtls_x509_crt_parse_der_nocopy(chain, ssl->in_msg + i, n);
#endif
        switch (ret) {
            case 0:
            case MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND:
                break;
            case MBEDTLS_ERR_X509_ALLOC_FAILED:
                alert = MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR;
                goto crt_parse_der_failed;
            case MBEDTLS_ERR_X509_UNKNOWN_VERSION:
                alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
                goto crt_parse_der_failed;
            default:
                alert = MBEDTLS_SSL_ALERT_MSG_BAD_CERT;
crt_parse_der_failed:
                mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, alert);
                MBEDTLS_SSL_DEBUG_RET(1, " mbedtls_x509_crt_parse_der", ret);
                return ret;
        }
        i += n;
    }
    MBEDTLS_SSL_DEBUG_CRT(3, "peer certificate", chain);
    return 0;
}
#if defined(MBEDTLS_SSL_SRV_C)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_srv_check_client_no_crt_notification(mbedtls_ssl_context *ssl)
{
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
        return -1;
    }
    if (ssl->in_hslen == 3 + mbedtls_ssl_hs_hdr_len(ssl) &&
        ssl->in_msgtype == MBEDTLS_SSL_MSG_HANDSHAKE &&
        ssl->in_msg[0] == MBEDTLS_SSL_HS_CERTIFICATE &&
        memcmp(ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl), "\0\0\0", 3) == 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("peer has no certificate"));
        return 0;
    }
    return -1;
}
#endif
#define SSL_CERTIFICATE_EXPECTED 0
#define SSL_CERTIFICATE_SKIP 1
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_certificate_coordinate(mbedtls_ssl_context *ssl,
                                            int authmode)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    if (!mbedtls_ssl_ciphersuite_uses_srv_cert(ciphersuite_info)) {
        return SSL_CERTIFICATE_SKIP;
    }
#if defined(MBEDTLS_SSL_SRV_C)
    if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
        if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_RSA_PSK) {
            return SSL_CERTIFICATE_SKIP;
        }
        if (authmode == MBEDTLS_SSL_VERIFY_NONE) {
            ssl->session_negotiate->verify_result =
                MBEDTLS_X509_BADCERT_SKIP_VERIFY;
            return SSL_CERTIFICATE_SKIP;
        }
    }
#else
    ((void) authmode);
#endif
    return SSL_CERTIFICATE_EXPECTED;
}
#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_remember_peer_crt_digest(mbedtls_ssl_context *ssl,
                                        unsigned char *start, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ssl->session_negotiate->peer_cert_digest =
        mbedtls_calloc(1, MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN);
    if (ssl->session_negotiate->peer_cert_digest == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%d bytes) failed",
                                  MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN));
        mbedtls_ssl_send_alert_message(ssl,
                                       MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    ret = mbedtls_md(mbedtls_md_info_from_type(
                         MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE),
                     start, len,
                     ssl->session_negotiate->peer_cert_digest);
    ssl->session_negotiate->peer_cert_digest_type =
        MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE;
    ssl->session_negotiate->peer_cert_digest_len =
        MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN;
    return ret;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_remember_peer_pubkey(mbedtls_ssl_context *ssl,
                                    unsigned char *start, size_t len)
{
    unsigned char *end = start + len;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_pk_init(&ssl->handshake->peer_pubkey);
    ret = mbedtls_pk_parse_subpubkey(&start, end,
                                     &ssl->handshake->peer_pubkey);
    if (ret != 0) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    return 0;
}
#endif
int mbedtls_ssl_parse_certificate(mbedtls_ssl_context *ssl)
{
    int ret = 0;
    int crt_expected;
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    const int authmode = ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET
                       ? ssl->handshake->sni_authmode
                       : ssl->conf->authmode;
#else
    const int authmode = ssl->conf->authmode;
#endif
    void *rs_ctx = NULL;
    mbedtls_x509_crt *chain = NULL;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate"));
    crt_expected = ssl_parse_certificate_coordinate(ssl, authmode);
    if (crt_expected == SSL_CERTIFICATE_SKIP) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate"));
        goto exit;
    }
#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ssl->handshake->ecrs_enabled &&
        ssl->handshake->ecrs_state == ssl_ecrs_crt_verify) {
        chain = ssl->handshake->ecrs_peer_cert;
        ssl->handshake->ecrs_peer_cert = NULL;
        goto crt_verify;
    }
#endif
    if ((ret = mbedtls_ssl_read_record(ssl, 1)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        goto exit;
    }
#if defined(MBEDTLS_SSL_SRV_C)
    if (ssl_srv_check_client_no_crt_notification(ssl) == 0) {
        ssl->session_negotiate->verify_result = MBEDTLS_X509_BADCERT_MISSING;
        if (authmode != MBEDTLS_SSL_VERIFY_OPTIONAL) {
            ret = MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;
        }
        goto exit;
    }
#endif
    ssl_clear_peer_cert(ssl->session_negotiate);
    chain = mbedtls_calloc(1, sizeof(mbedtls_x509_crt));
    if (chain == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("alloc(%" MBEDTLS_PRINTF_SIZET " bytes) failed",
                                  sizeof(mbedtls_x509_crt)));
        mbedtls_ssl_send_alert_message(ssl,
                                       MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
        ret = MBEDTLS_ERR_SSL_ALLOC_FAILED;
        goto exit;
    }
    mbedtls_x509_crt_init(chain);
    ret = ssl_parse_certificate_chain(ssl, chain);
    if (ret != 0) {
        goto exit;
    }
#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ssl->handshake->ecrs_enabled) {
        ssl->handshake->ecrs_state = ssl_ecrs_crt_verify;
    }
crt_verify:
    if (ssl->handshake->ecrs_enabled) {
        rs_ctx = &ssl->handshake->ecrs_ctx;
    }
#endif
    ret = mbedtls_ssl_verify_certificate(ssl, authmode, chain,
                                         ssl->handshake->ciphersuite_info,
                                         rs_ctx);
    if (ret != 0) {
        goto exit;
    }
#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    {
        unsigned char *crt_start, *pk_start;
        size_t crt_len, pk_len;
        crt_start = chain->raw.p;
        crt_len = chain->raw.len;
        pk_start = chain->pk_raw.p;
        pk_len = chain->pk_raw.len;
        mbedtls_x509_crt_free(chain);
        mbedtls_free(chain);
        chain = NULL;
        ret = ssl_remember_peer_crt_digest(ssl, crt_start, crt_len);
        if (ret != 0) {
            goto exit;
        }
        ret = ssl_remember_peer_pubkey(ssl, pk_start, pk_len);
        if (ret != 0) {
            goto exit;
        }
    }
#else
    ssl->session_negotiate->peer_cert = chain;
    chain = NULL;
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate"));
exit:
    if (ret == 0) {
        ssl->state++;
    }
#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
        ssl->handshake->ecrs_peer_cert = chain;
        chain = NULL;
    }
#endif
    if (chain != NULL) {
        mbedtls_x509_crt_free(chain);
        mbedtls_free(chain);
    }
    return ret;
}
#endif
static int ssl_calc_finished_tls_generic(mbedtls_ssl_context *ssl, void *ctx,
                                         unsigned char *padbuf, size_t hlen,
                                         unsigned char *buf, int from)
{
    unsigned int len = 12;
    const char *sender;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status;
    psa_hash_operation_t *hs_op = ctx;
    psa_hash_operation_t cloned_op = PSA_HASH_OPERATION_INIT;
    size_t hash_size;
#else
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_md_context_t *hs_ctx = ctx;
    mbedtls_md_context_t cloned_ctx;
    mbedtls_md_init(&cloned_ctx);
#endif
    mbedtls_ssl_session *session = ssl->session_negotiate;
    if (!session) {
        session = ssl->session;
    }
    sender = (from == MBEDTLS_SSL_IS_CLIENT)
             ? "client finished"
             : "server finished";
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc PSA finished tls"));
    status = psa_hash_clone(hs_op, &cloned_op);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    status = psa_hash_finish(&cloned_op, padbuf, hlen, &hash_size);
    if (status != PSA_SUCCESS) {
        goto exit;
    }
    MBEDTLS_SSL_DEBUG_BUF(3, "PSA calculated padbuf", padbuf, hlen);
#else
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> calc finished tls"));
    ret = mbedtls_md_setup(&cloned_ctx, mbedtls_md_info_from_ctx(hs_ctx), 0);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_clone(&cloned_ctx, hs_ctx);
    if (ret != 0) {
        goto exit;
    }
    ret = mbedtls_md_finish(&cloned_ctx, padbuf);
    if (ret != 0) {
        goto exit;
    }
#endif
    MBEDTLS_SSL_DEBUG_BUF(4, "finished output", padbuf, hlen);
    ssl->handshake->tls_prf(session->master, 48, sender,
                            padbuf, hlen, buf, len);
    MBEDTLS_SSL_DEBUG_BUF(3, "calc finished result", buf, len);
    mbedtls_platform_zeroize(padbuf, hlen);
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= calc finished"));
exit:
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_hash_abort(&cloned_op);
    return mbedtls_md_error_from_psa(status);
#else
    mbedtls_md_free(&cloned_ctx);
    return ret;
#endif
}
#if defined(MBEDTLS_MD_CAN_SHA256)
static int ssl_calc_finished_tls_sha256(
    mbedtls_ssl_context *ssl, unsigned char *buf, int from)
{
    unsigned char padbuf[32];
    return ssl_calc_finished_tls_generic(ssl,
#if defined(MBEDTLS_USE_PSA_CRYPTO)
                                         &ssl->handshake->fin_sha256_psa,
#else
                                         &ssl->handshake->fin_sha256,
#endif
                                         padbuf, sizeof(padbuf),
                                         buf, from);
}
#endif
#if defined(MBEDTLS_MD_CAN_SHA384)
static int ssl_calc_finished_tls_sha384(
    mbedtls_ssl_context *ssl, unsigned char *buf, int from)
{
    unsigned char padbuf[48];
    return ssl_calc_finished_tls_generic(ssl,
#if defined(MBEDTLS_USE_PSA_CRYPTO)
                                         &ssl->handshake->fin_sha384_psa,
#else
                                         &ssl->handshake->fin_sha384,
#endif
                                         padbuf, sizeof(padbuf),
                                         buf, from);
}
#endif
void mbedtls_ssl_handshake_wrapup_free_hs_transform(mbedtls_ssl_context *ssl)
{
    MBEDTLS_SSL_DEBUG_MSG(3, ("=> handshake wrapup: final free"));
    mbedtls_ssl_handshake_free(ssl);
    mbedtls_free(ssl->handshake);
    ssl->handshake = NULL;
    if (ssl->transform) {
        mbedtls_ssl_transform_free(ssl->transform);
        mbedtls_free(ssl->transform);
    }
    ssl->transform = ssl->transform_negotiate;
    ssl->transform_negotiate = NULL;
    MBEDTLS_SSL_DEBUG_MSG(3, ("<= handshake wrapup: final free"));
}
void mbedtls_ssl_handshake_wrapup(mbedtls_ssl_context *ssl)
{
    int resume = ssl->handshake->resume;
    MBEDTLS_SSL_DEBUG_MSG(3, ("=> handshake wrapup"));
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
        ssl->renego_status = MBEDTLS_SSL_RENEGOTIATION_DONE;
        ssl->renego_records_seen = 0;
    }
#endif
    if (ssl->session) {
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
        ssl->session_negotiate->encrypt_then_mac =
            ssl->session->encrypt_then_mac;
#endif
        mbedtls_ssl_session_free(ssl->session);
        mbedtls_free(ssl->session);
    }
    ssl->session = ssl->session_negotiate;
    ssl->session_negotiate = NULL;
    if (ssl->conf->f_set_cache != NULL &&
        ssl->session->id_len != 0 &&
        resume == 0) {
        if (ssl->conf->f_set_cache(ssl->conf->p_cache,
                                   ssl->session->id,
                                   ssl->session->id_len,
                                   ssl->session) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("cache did not store session"));
        }
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake->flight != NULL) {
        mbedtls_ssl_set_timer(ssl, 0);
        MBEDTLS_SSL_DEBUG_MSG(3, ("skip freeing handshake and transform"));
    } else
#endif
    mbedtls_ssl_handshake_wrapup_free_hs_transform(ssl);
    ssl->state = MBEDTLS_SSL_HANDSHAKE_OVER;
    MBEDTLS_SSL_DEBUG_MSG(3, ("<= handshake wrapup"));
}
int mbedtls_ssl_write_finished(mbedtls_ssl_context *ssl)
{
    int ret;
    unsigned int hash_len;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write finished"));
    mbedtls_ssl_update_out_pointers(ssl, ssl->transform_negotiate);
    ret = ssl->handshake->calc_finished(ssl, ssl->out_msg + 4, ssl->conf->endpoint);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "calc_finished", ret);
    }
    hash_len = 12;
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy(ssl->own_verify_data, ssl->out_msg + 4, hash_len);
#endif
    ssl->out_msglen = 4 + hash_len;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_FINISHED;
    if (ssl->handshake->resume != 0) {
#if defined(MBEDTLS_SSL_CLI_C)
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
        }
#endif
#if defined(MBEDTLS_SSL_SRV_C)
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
            ssl->state = MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
        }
#endif
    } else {
        ssl->state++;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("switching to new transform spec for outbound data"));
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        unsigned char i;
        ssl->handshake->alt_transform_out = ssl->transform_out;
        memcpy(ssl->handshake->alt_out_ctr, ssl->cur_out_ctr,
               sizeof(ssl->handshake->alt_out_ctr));
        memset(&ssl->cur_out_ctr[2], 0, sizeof(ssl->cur_out_ctr) - 2);
        for (i = 2; i > 0; i--) {
            if (++ssl->cur_out_ctr[i - 1] != 0) {
                break;
            }
        }
        if (i == 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("DTLS epoch would wrap"));
            return MBEDTLS_ERR_SSL_COUNTER_WRAPPING;
        }
    } else
#endif
    memset(ssl->cur_out_ctr, 0, sizeof(ssl->cur_out_ctr));
    ssl->transform_out = ssl->transform_negotiate;
    ssl->session_out = ssl->session_negotiate;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        mbedtls_ssl_send_flight_completed(ssl);
    }
#endif
    if ((ret = mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        (ret = mbedtls_ssl_flight_transmit(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_flight_transmit", ret);
        return ret;
    }
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write finished"));
    return 0;
}
#define SSL_MAX_HASH_LEN 12
int mbedtls_ssl_parse_finished(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned int hash_len = 12;
    unsigned char buf[SSL_MAX_HASH_LEN];
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse finished"));
    ret = ssl->handshake->calc_finished(ssl, buf, ssl->conf->endpoint ^ 1);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "calc_finished", ret);
    }
    if ((ret = mbedtls_ssl_read_record(ssl, 1)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        goto exit;
    }
    if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto exit;
    }
    if (ssl->in_msg[0] != MBEDTLS_SSL_HS_FINISHED) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE);
        ret = MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
        goto exit;
    }
    if (ssl->in_hslen != mbedtls_ssl_hs_hdr_len(ssl) + hash_len) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        ret = MBEDTLS_ERR_SSL_DECODE_ERROR;
        goto exit;
    }
    if (mbedtls_ct_memcmp(ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl),
                          buf, hash_len) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad finished message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR);
        ret = MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        goto exit;
    }
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    ssl->verify_data_len = hash_len;
    memcpy(ssl->peer_verify_data, buf, hash_len);
#endif
    if (ssl->handshake->resume != 0) {
#if defined(MBEDTLS_SSL_CLI_C)
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_CLIENT) {
            ssl->state = MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
        }
#endif
#if defined(MBEDTLS_SSL_SRV_C)
        if (ssl->conf->endpoint == MBEDTLS_SSL_IS_SERVER) {
            ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
        }
#endif
    } else {
        ssl->state++;
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        mbedtls_ssl_recv_flight_completed(ssl);
    }
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse finished"));
exit:
    mbedtls_platform_zeroize(buf, hash_len);
    return ret;
}
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
static tls_prf_fn ssl_tls12prf_from_cs(int ciphersuite_id)
{
    const mbedtls_ssl_ciphersuite_t * const ciphersuite_info =
        mbedtls_ssl_ciphersuite_from_id(ciphersuite_id);
#if defined(MBEDTLS_MD_CAN_SHA384)
    if (ciphersuite_info != NULL && ciphersuite_info->mac == MBEDTLS_MD_SHA384) {
        return tls_prf_sha384;
    } else
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
    {
        if (ciphersuite_info != NULL && ciphersuite_info->mac == MBEDTLS_MD_SHA256) {
            return tls_prf_sha256;
        }
    }
#endif
#if !defined(MBEDTLS_MD_CAN_SHA384) && \
    !defined(MBEDTLS_MD_CAN_SHA256)
    (void) ciphersuite_info;
#endif
    return NULL;
}
#endif
static mbedtls_tls_prf_types tls_prf_get_type(mbedtls_ssl_tls_prf_cb *tls_prf)
{
    ((void) tls_prf);
#if defined(MBEDTLS_MD_CAN_SHA384)
    if (tls_prf == tls_prf_sha384) {
        return MBEDTLS_SSL_TLS_PRF_SHA384;
    } else
#endif
#if defined(MBEDTLS_MD_CAN_SHA256)
    if (tls_prf == tls_prf_sha256) {
        return MBEDTLS_SSL_TLS_PRF_SHA256;
    } else
#endif
    return MBEDTLS_SSL_TLS_PRF_NONE;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_tls12_populate_transform(mbedtls_ssl_transform *transform,
                                        int ciphersuite,
                                        const unsigned char master[48],
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
                                        int encrypt_then_mac,
#endif
                                        ssl_tls_prf_t tls_prf,
                                        const unsigned char randbytes[64],
                                        mbedtls_ssl_protocol_version tls_version,
                                        unsigned endpoint,
                                        const mbedtls_ssl_context *ssl)
{
    int ret = 0;
    unsigned char keyblk[256];
    unsigned char *key1;
    unsigned char *key2;
    unsigned char *mac_enc;
    unsigned char *mac_dec;
    size_t mac_key_len = 0;
    size_t iv_copy_len;
    size_t keylen;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    mbedtls_ssl_mode_t ssl_mode;
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
    const mbedtls_cipher_info_t *cipher_info;
    const mbedtls_md_info_t *md_info;
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_key_type_t key_type;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg;
    psa_algorithm_t mac_alg = 0;
    size_t key_bits;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
#endif
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    transform->encrypt_then_mac = encrypt_then_mac;
#endif
    transform->tls_version = tls_version;
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    memcpy(transform->randbytes, randbytes, sizeof(transform->randbytes));
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_3) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
#endif
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id(ciphersuite);
    if (ciphersuite_info == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("ciphersuite info for %d not found",
                                  ciphersuite));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    ssl_mode = mbedtls_ssl_get_mode_from_ciphersuite(
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
        encrypt_then_mac,
#endif
        ciphersuite_info);
    if (ssl_mode == MBEDTLS_SSL_MODE_AEAD) {
        transform->taglen =
            ciphersuite_info->flags & MBEDTLS_CIPHERSUITE_SHORT_TAG ? 8 : 16;
    }
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if ((status = mbedtls_ssl_cipher_to_psa((mbedtls_cipher_type_t) ciphersuite_info->cipher,
                                            transform->taglen,
                                            &alg,
                                            &key_type,
                                            &key_bits)) != PSA_SUCCESS) {
        ret = PSA_TO_MBEDTLS_ERR(status);
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_cipher_to_psa", ret);
        goto end;
    }
#else
    cipher_info = mbedtls_cipher_info_from_type((mbedtls_cipher_type_t) ciphersuite_info->cipher);
    if (cipher_info == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("cipher info for %u not found",
                                  ciphersuite_info->cipher));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mac_alg = mbedtls_md_psa_alg_from_type((mbedtls_md_type_t) ciphersuite_info->mac);
    if (mac_alg == 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_md_psa_alg_from_type for %u not found",
                                  (unsigned) ciphersuite_info->mac));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#else
    md_info = mbedtls_md_info_from_type((mbedtls_md_type_t) ciphersuite_info->mac);
    if (md_info == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("mbedtls_md info for %u not found",
                                  (unsigned) ciphersuite_info->mac));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    if (ssl->handshake->cid_in_use == MBEDTLS_SSL_CID_ENABLED) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("Copy CIDs into SSL transform"));
        transform->in_cid_len = ssl->own_cid_len;
        memcpy(transform->in_cid, ssl->own_cid, ssl->own_cid_len);
        MBEDTLS_SSL_DEBUG_BUF(3, "Incoming CID", transform->in_cid,
                              transform->in_cid_len);
        transform->out_cid_len = ssl->handshake->peer_cid_len;
        memcpy(transform->out_cid, ssl->handshake->peer_cid,
               ssl->handshake->peer_cid_len);
        MBEDTLS_SSL_DEBUG_BUF(3, "Outgoing CID", transform->out_cid,
                              transform->out_cid_len);
    }
#endif
    ret = tls_prf(master, 48, "key expansion", randbytes, 64, keyblk, 256);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "prf", ret);
        return ret;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite = %s",
                              mbedtls_ssl_get_ciphersuite_name(ciphersuite)));
    MBEDTLS_SSL_DEBUG_BUF(3, "master secret", master, 48);
    MBEDTLS_SSL_DEBUG_BUF(4, "random bytes", randbytes, 64);
    MBEDTLS_SSL_DEBUG_BUF(4, "key block", keyblk, 256);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    keylen = PSA_BITS_TO_BYTES(key_bits);
#else
    keylen = mbedtls_cipher_info_get_key_bitlen(cipher_info) / 8;
#endif
#if defined(MBEDTLS_SSL_HAVE_AEAD)
    if (ssl_mode == MBEDTLS_SSL_MODE_AEAD) {
        size_t explicit_ivlen;
        transform->maclen = 0;
        mac_key_len = 0;
        transform->ivlen = 12;
        int is_chachapoly = 0;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        is_chachapoly = (key_type == PSA_KEY_TYPE_CHACHA20);
#else
        is_chachapoly = (mbedtls_cipher_info_get_mode(cipher_info)
                         == MBEDTLS_MODE_CHACHAPOLY);
#endif
        if (is_chachapoly) {
            transform->fixed_ivlen = 12;
        } else {
            transform->fixed_ivlen = 4;
        }
        explicit_ivlen = transform->ivlen - transform->fixed_ivlen;
        transform->minlen = explicit_ivlen + transform->taglen;
    } else
#endif
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    if (ssl_mode == MBEDTLS_SSL_MODE_STREAM ||
        ssl_mode == MBEDTLS_SSL_MODE_CBC ||
        ssl_mode == MBEDTLS_SSL_MODE_CBC_ETM) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        size_t block_size = PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type);
#else
        size_t block_size = mbedtls_cipher_info_get_block_size(cipher_info);
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        mac_key_len = PSA_HASH_LENGTH(mac_alg);
#else
        if ((ret = mbedtls_md_setup(&transform->md_ctx_enc, md_info, 1)) != 0 ||
            (ret = mbedtls_md_setup(&transform->md_ctx_dec, md_info, 1)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_setup", ret);
            goto end;
        }
        mac_key_len = mbedtls_md_get_size(md_info);
#endif
        transform->maclen = mac_key_len;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        transform->ivlen = PSA_CIPHER_IV_LENGTH(key_type, alg);
#else
        transform->ivlen = mbedtls_cipher_info_get_iv_size(cipher_info);
#endif
        if (ssl_mode == MBEDTLS_SSL_MODE_STREAM) {
            transform->minlen = transform->maclen;
        } else {
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
            if (ssl_mode == MBEDTLS_SSL_MODE_CBC_ETM) {
                transform->minlen = transform->maclen
                                    + block_size;
            } else
#endif
            {
                transform->minlen = transform->maclen
                                    + block_size
                                    - transform->maclen % block_size;
            }
            if (tls_version == MBEDTLS_SSL_VERSION_TLS1_2) {
                transform->minlen += transform->ivlen;
            } else {
                MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
                ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
                goto end;
            }
        }
    } else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("keylen: %u, minlen: %u, ivlen: %u, maclen: %u",
                              (unsigned) keylen,
                              (unsigned) transform->minlen,
                              (unsigned) transform->ivlen,
                              (unsigned) transform->maclen));
#if defined(MBEDTLS_SSL_CLI_C)
    if (endpoint == MBEDTLS_SSL_IS_CLIENT) {
        key1 = keyblk + mac_key_len * 2;
        key2 = keyblk + mac_key_len * 2 + keylen;
        mac_enc = keyblk;
        mac_dec = keyblk + mac_key_len;
        iv_copy_len = (transform->fixed_ivlen) ?
                      transform->fixed_ivlen : transform->ivlen;
        memcpy(transform->iv_enc, key2 + keylen, iv_copy_len);
        memcpy(transform->iv_dec, key2 + keylen + iv_copy_len,
               iv_copy_len);
    } else
#endif
#if defined(MBEDTLS_SSL_SRV_C)
    if (endpoint == MBEDTLS_SSL_IS_SERVER) {
        key1 = keyblk + mac_key_len * 2 + keylen;
        key2 = keyblk + mac_key_len * 2;
        mac_enc = keyblk + mac_key_len;
        mac_dec = keyblk;
        iv_copy_len = (transform->fixed_ivlen) ?
                      transform->fixed_ivlen : transform->ivlen;
        memcpy(transform->iv_dec, key1 + keylen, iv_copy_len);
        memcpy(transform->iv_enc, key1 + keylen + iv_copy_len,
               iv_copy_len);
    } else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto end;
    }
    if (ssl->f_export_keys != NULL) {
        ssl->f_export_keys(ssl->p_export_keys,
                           MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET,
                           master, 48,
                           randbytes + 32,
                           randbytes,
                           tls_prf_get_type(tls_prf));
    }
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    transform->psa_alg = alg;
    if (alg != MBEDTLS_SSL_NULL_CIPHER) {
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
        psa_set_key_algorithm(&attributes, alg);
        psa_set_key_type(&attributes, key_type);
        if ((status = psa_import_key(&attributes,
                                     key1,
                                     PSA_BITS_TO_BYTES(key_bits),
                                     &transform->psa_key_enc)) != PSA_SUCCESS) {
            MBEDTLS_SSL_DEBUG_RET(3, "psa_import_key", (int) status);
            ret = PSA_TO_MBEDTLS_ERR(status);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_import_key", ret);
            goto end;
        }
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
        if ((status = psa_import_key(&attributes,
                                     key2,
                                     PSA_BITS_TO_BYTES(key_bits),
                                     &transform->psa_key_dec)) != PSA_SUCCESS) {
            ret = PSA_TO_MBEDTLS_ERR(status);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_import_key", ret);
            goto end;
        }
    }
#else
    if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_enc,
                                    cipher_info)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
        goto end;
    }
    if ((ret = mbedtls_cipher_setup(&transform->cipher_ctx_dec,
                                    cipher_info)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setup", ret);
        goto end;
    }
    if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_enc, key1,
                                     (int) mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                     MBEDTLS_ENCRYPT)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
        goto end;
    }
    if ((ret = mbedtls_cipher_setkey(&transform->cipher_ctx_dec, key2,
                                     (int) mbedtls_cipher_info_get_key_bitlen(cipher_info),
                                     MBEDTLS_DECRYPT)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_setkey", ret);
        goto end;
    }
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    if (mbedtls_cipher_info_get_mode(cipher_info) == MBEDTLS_MODE_CBC) {
        if ((ret = mbedtls_cipher_set_padding_mode(&transform->cipher_ctx_enc,
                                                   MBEDTLS_PADDING_NONE)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_set_padding_mode", ret);
            goto end;
        }
        if ((ret = mbedtls_cipher_set_padding_mode(&transform->cipher_ctx_dec,
                                                   MBEDTLS_PADDING_NONE)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_cipher_set_padding_mode", ret);
            goto end;
        }
    }
#endif
#endif
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_MAC)
    if (mac_key_len != 0) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        transform->psa_mac_alg = PSA_ALG_HMAC(mac_alg);
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(mac_alg));
        psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
        if ((status = psa_import_key(&attributes,
                                     mac_enc, mac_key_len,
                                     &transform->psa_mac_enc)) != PSA_SUCCESS) {
            ret = PSA_TO_MBEDTLS_ERR(status);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_import_mac_key", ret);
            goto end;
        }
        if ((transform->psa_alg == MBEDTLS_SSL_NULL_CIPHER) ||
            ((transform->psa_alg == PSA_ALG_CBC_NO_PADDING)
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
             && (transform->encrypt_then_mac == MBEDTLS_SSL_ETM_DISABLED)
#endif
            )) {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT |
                                    PSA_KEY_USAGE_VERIFY_HASH);
        } else {
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
        }
        if ((status = psa_import_key(&attributes,
                                     mac_dec, mac_key_len,
                                     &transform->psa_mac_dec)) != PSA_SUCCESS) {
            ret = PSA_TO_MBEDTLS_ERR(status);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_import_mac_key", ret);
            goto end;
        }
#else
        ret = mbedtls_md_hmac_starts(&transform->md_ctx_enc, mac_enc, mac_key_len);
        if (ret != 0) {
            goto end;
        }
        ret = mbedtls_md_hmac_starts(&transform->md_ctx_dec, mac_dec, mac_key_len);
        if (ret != 0) {
            goto end;
        }
#endif
    }
#endif
    ((void) mac_dec);
    ((void) mac_enc);
end:
    mbedtls_platform_zeroize(keyblk, sizeof(keyblk));
    return ret;
}
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED) && \
    defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_psa_ecjpake_read_round(
    psa_pake_operation_t *pake_ctx,
    const unsigned char *buf,
    size_t len, mbedtls_ecjpake_rounds_t round)
{
    psa_status_t status;
    size_t input_offset = 0;
    unsigned int remaining_steps = (round == MBEDTLS_ECJPAKE_ROUND_ONE) ? 2 : 1;
    for (; remaining_steps > 0; remaining_steps--) {
        for (psa_pake_step_t step = PSA_PAKE_STEP_KEY_SHARE;
             step <= PSA_PAKE_STEP_ZK_PROOF;
             ++step) {
            size_t length = buf[input_offset];
            input_offset += 1;
            if (input_offset + length > len) {
                return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            }
            status = psa_pake_input(pake_ctx, step,
                                    buf + input_offset, length);
            if (status != PSA_SUCCESS) {
                return PSA_TO_MBEDTLS_ERR(status);
            }
            input_offset += length;
        }
    }
    if (input_offset != len) {
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
    return 0;
}
int mbedtls_psa_ecjpake_write_round(
    psa_pake_operation_t *pake_ctx,
    unsigned char *buf,
    size_t len, size_t *olen,
    mbedtls_ecjpake_rounds_t round)
{
    psa_status_t status;
    size_t output_offset = 0;
    size_t output_len;
    unsigned int remaining_steps = (round == MBEDTLS_ECJPAKE_ROUND_ONE) ? 2 : 1;
    for (; remaining_steps > 0; remaining_steps--) {
        for (psa_pake_step_t step = PSA_PAKE_STEP_KEY_SHARE;
             step <= PSA_PAKE_STEP_ZK_PROOF;
             ++step) {
            status = psa_pake_output(pake_ctx, step,
                                     buf + output_offset + 1,
                                     len - output_offset - 1,
                                     &output_len);
            if (status != PSA_SUCCESS) {
                return PSA_TO_MBEDTLS_ERR(status);
            }
            *(buf + output_offset) = (uint8_t) output_len;
            output_offset += output_len + 1;
        }
    }
    *olen = output_offset;
    return 0;
}
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
int mbedtls_ssl_get_key_exchange_md_tls1_2(mbedtls_ssl_context *ssl,
                                           unsigned char *hash, size_t *hashlen,
                                           unsigned char *data, size_t data_len,
                                           mbedtls_md_type_t md_alg)
{
    psa_status_t status;
    psa_hash_operation_t hash_operation = PSA_HASH_OPERATION_INIT;
    psa_algorithm_t hash_alg = mbedtls_md_psa_alg_from_type(md_alg);
    MBEDTLS_SSL_DEBUG_MSG(3, ("Perform PSA-based computation of digest of ServerKeyExchange"));
    if ((status = psa_hash_setup(&hash_operation,
                                 hash_alg)) != PSA_SUCCESS) {
        MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_setup", status);
        goto exit;
    }
    if ((status = psa_hash_update(&hash_operation, ssl->handshake->randbytes,
                                  64)) != PSA_SUCCESS) {
        MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_update", status);
        goto exit;
    }
    if ((status = psa_hash_update(&hash_operation,
                                  data, data_len)) != PSA_SUCCESS) {
        MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_update", status);
        goto exit;
    }
    if ((status = psa_hash_finish(&hash_operation, hash, PSA_HASH_MAX_SIZE,
                                  hashlen)) != PSA_SUCCESS) {
        MBEDTLS_SSL_DEBUG_RET(1, "psa_hash_finish", status);
        goto exit;
    }
exit:
    if (status != PSA_SUCCESS) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
        switch (status) {
            case PSA_ERROR_NOT_SUPPORTED:
                return MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE;
            case PSA_ERROR_BAD_STATE:
            case PSA_ERROR_BUFFER_TOO_SMALL:
                return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
            case PSA_ERROR_INSUFFICIENT_MEMORY:
                return MBEDTLS_ERR_MD_ALLOC_FAILED;
            default:
                return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
        }
    }
    return 0;
}
#else
int mbedtls_ssl_get_key_exchange_md_tls1_2(mbedtls_ssl_context *ssl,
                                           unsigned char *hash, size_t *hashlen,
                                           unsigned char *data, size_t data_len,
                                           mbedtls_md_type_t md_alg)
{
    int ret = 0;
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_alg);
    *hashlen = mbedtls_md_get_size(md_info);
    MBEDTLS_SSL_DEBUG_MSG(3, ("Perform mbedtls-based computation of digest of ServerKeyExchange"));
    mbedtls_md_init(&ctx);
    if ((ret = mbedtls_md_setup(&ctx, md_info, 0)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_setup", ret);
        goto exit;
    }
    if ((ret = mbedtls_md_starts(&ctx)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_starts", ret);
        goto exit;
    }
    if ((ret = mbedtls_md_update(&ctx, ssl->handshake->randbytes, 64)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_update", ret);
        goto exit;
    }
    if ((ret = mbedtls_md_update(&ctx, data, data_len)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_update", ret);
        goto exit;
    }
    if ((ret = mbedtls_md_finish(&ctx, hash)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_md_finish", ret);
        goto exit;
    }
exit:
    mbedtls_md_free(&ctx);
    if (ret != 0) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
    }
    return ret;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
unsigned int mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg(
    mbedtls_ssl_context *ssl,
    unsigned int sig_alg)
{
    unsigned int i;
    uint16_t *received_sig_algs = ssl->handshake->received_sig_algs;
    if (sig_alg == MBEDTLS_SSL_SIG_ANON) {
        return MBEDTLS_SSL_HASH_NONE;
    }
    for (i = 0; received_sig_algs[i] != MBEDTLS_TLS_SIG_NONE; i++) {
        unsigned int hash_alg_received =
            MBEDTLS_SSL_TLS12_HASH_ALG_FROM_SIG_AND_HASH_ALG(
                received_sig_algs[i]);
        unsigned int sig_alg_received =
            MBEDTLS_SSL_TLS12_SIG_ALG_FROM_SIG_AND_HASH_ALG(
                received_sig_algs[i]);
        mbedtls_md_type_t md_alg =
            mbedtls_ssl_md_alg_from_hash((unsigned char) hash_alg_received);
        if (md_alg == MBEDTLS_MD_NONE) {
            continue;
        }
        if (sig_alg == sig_alg_received) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
            if (ssl->handshake->key_cert && ssl->handshake->key_cert->key) {
                psa_algorithm_t psa_hash_alg =
                    mbedtls_md_psa_alg_from_type(md_alg);
                if (sig_alg_received == MBEDTLS_SSL_SIG_ECDSA &&
                    !mbedtls_pk_can_do_ext(ssl->handshake->key_cert->key,
                                           PSA_ALG_ECDSA(psa_hash_alg),
                                           PSA_KEY_USAGE_SIGN_HASH)) {
                    continue;
                }
                if (sig_alg_received == MBEDTLS_SSL_SIG_RSA &&
                    !mbedtls_pk_can_do_ext(ssl->handshake->key_cert->key,
                                           PSA_ALG_RSA_PKCS1V15_SIGN(
                                               psa_hash_alg),
                                           PSA_KEY_USAGE_SIGN_HASH)) {
                    continue;
                }
            }
#endif
            return hash_alg_received;
        }
    }
    return MBEDTLS_SSL_HASH_NONE;
}
#endif
#endif
int mbedtls_ssl_validate_ciphersuite(
    const mbedtls_ssl_context *ssl,
    const mbedtls_ssl_ciphersuite_t *suite_info,
    mbedtls_ssl_protocol_version min_tls_version,
    mbedtls_ssl_protocol_version max_tls_version)
{
    (void) ssl;
    if (suite_info == NULL) {
        return -1;
    }
    if ((suite_info->min_tls_version > max_tls_version) ||
        (suite_info->max_tls_version < min_tls_version)) {
        return -1;
    }
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && defined(MBEDTLS_SSL_CLI_C)
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (suite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE &&
        ssl->handshake->psa_pake_ctx_is_ok != 1)
#else
    if (suite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE &&
        mbedtls_ecjpake_check(&ssl->handshake->ecjpake_ctx) != 0)
#endif
    {
        return -1;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (mbedtls_ssl_ciphersuite_uses_psk(suite_info) &&
        mbedtls_ssl_conf_has_static_psk(ssl->conf) == 0) {
        return -1;
    }
#endif
#endif
    return 0;
}
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
int mbedtls_ssl_write_sig_alg_ext(mbedtls_ssl_context *ssl, unsigned char *buf,
                                  const unsigned char *end, size_t *out_len)
{
    unsigned char *p = buf;
    unsigned char *supported_sig_alg;
    size_t supported_sig_alg_len = 0;
    *out_len = 0;
    MBEDTLS_SSL_DEBUG_MSG(3, ("adding signature_algorithms extension"));
    MBEDTLS_SSL_CHK_BUF_PTR(p, end, 6);
    p += 6;
    supported_sig_alg = p;
    const uint16_t *sig_alg = mbedtls_ssl_get_sig_algs(ssl);
    if (sig_alg == NULL) {
        return MBEDTLS_ERR_SSL_BAD_CONFIG;
    }
    for (; *sig_alg != MBEDTLS_TLS1_3_SIG_NONE; sig_alg++) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("got signature scheme [%x] %s",
                                  *sig_alg,
                                  mbedtls_ssl_sig_alg_to_str(*sig_alg)));
        if (!mbedtls_ssl_sig_alg_is_supported(ssl, *sig_alg)) {
            continue;
        }
        MBEDTLS_SSL_CHK_BUF_PTR(p, end, 2);
        MBEDTLS_PUT_UINT16_BE(*sig_alg, p, 0);
        p += 2;
        MBEDTLS_SSL_DEBUG_MSG(3, ("sent signature scheme [%x] %s",
                                  *sig_alg,
                                  mbedtls_ssl_sig_alg_to_str(*sig_alg)));
    }
    supported_sig_alg_len = (size_t) (p - supported_sig_alg);
    if (supported_sig_alg_len == 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("No signature algorithms defined."));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_SIG_ALG, buf, 0);
    MBEDTLS_PUT_UINT16_BE(supported_sig_alg_len + 2, buf, 2);
    MBEDTLS_PUT_UINT16_BE(supported_sig_alg_len, buf, 4);
    *out_len = (size_t) (p - buf);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, MBEDTLS_TLS_EXT_SIG_ALG);
#endif
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_server_name_ext(mbedtls_ssl_context *ssl,
                                      const unsigned char *buf,
                                      const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;
    size_t server_name_list_len, hostname_len;
    const unsigned char *server_name_list_end;
    MBEDTLS_SSL_DEBUG_MSG(3, ("parse ServerName extension"));
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 2);
    server_name_list_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, server_name_list_len);
    server_name_list_end = p + server_name_list_len;
    while (p < server_name_list_end) {
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, server_name_list_end, 3);
        hostname_len = MBEDTLS_GET_UINT16_BE(p, 1);
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, server_name_list_end,
                                     hostname_len + 3);
        if (p[0] == MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME) {
            ssl->handshake->sni_name = p + 3;
            ssl->handshake->sni_name_len = hostname_len;
            if (ssl->conf->f_sni == NULL) {
                return 0;
            }
            ret = ssl->conf->f_sni(ssl->conf->p_sni,
                                   ssl, p + 3, hostname_len);
            if (ret != 0) {
                MBEDTLS_SSL_DEBUG_RET(1, "ssl_sni_wrapper", ret);
                MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME,
                                             MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME);
                return MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME;
            }
            return 0;
        }
        p += hostname_len + 3;
    }
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_ALPN)
MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_parse_alpn_ext(mbedtls_ssl_context *ssl,
                               const unsigned char *buf,
                               const unsigned char *end)
{
    const unsigned char *p = buf;
    size_t protocol_name_list_len;
    const unsigned char *protocol_name_list;
    const unsigned char *protocol_name_list_end;
    size_t protocol_name_len;
    if (ssl->conf->alpn_list == NULL) {
        return 0;
    }
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, 4);
    protocol_name_list_len = MBEDTLS_GET_UINT16_BE(p, 0);
    p += 2;
    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, end, protocol_name_list_len);
    protocol_name_list = p;
    protocol_name_list_end = p + protocol_name_list_len;
    while (p < protocol_name_list_end) {
        protocol_name_len = *p++;
        MBEDTLS_SSL_CHK_BUF_READ_PTR(p, protocol_name_list_end,
                                     protocol_name_len);
        if (protocol_name_len == 0) {
            MBEDTLS_SSL_PEND_FATAL_ALERT(
                MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
                MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
            return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }
        p += protocol_name_len;
    }
    for (const char **alpn = ssl->conf->alpn_list; *alpn != NULL; alpn++) {
        size_t const alpn_len = strlen(*alpn);
        p = protocol_name_list;
        while (p < protocol_name_list_end) {
            protocol_name_len = *p++;
            if (protocol_name_len == alpn_len &&
                memcmp(p, *alpn, alpn_len) == 0) {
                ssl->alpn_chosen = *alpn;
                return 0;
            }
            p += protocol_name_len;
        }
    }
    MBEDTLS_SSL_PEND_FATAL_ALERT(
        MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL,
        MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL);
    return MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL;
}
int mbedtls_ssl_write_alpn_ext(mbedtls_ssl_context *ssl,
                               unsigned char *buf,
                               unsigned char *end,
                               size_t *out_len)
{
    unsigned char *p = buf;
    size_t protocol_name_len;
    *out_len = 0;
    if (ssl->alpn_chosen == NULL) {
        return 0;
    }
    protocol_name_len = strlen(ssl->alpn_chosen);
    MBEDTLS_SSL_CHK_BUF_PTR(p, end, 7 + protocol_name_len);
    MBEDTLS_SSL_DEBUG_MSG(3, ("server side, adding alpn extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_ALPN, p, 0);
    *out_len = 7 + protocol_name_len;
    MBEDTLS_PUT_UINT16_BE(protocol_name_len + 3, p, 2);
    MBEDTLS_PUT_UINT16_BE(protocol_name_len + 1, p, 4);
    p[6] = MBEDTLS_BYTE_0(protocol_name_len);
    memcpy(p + 7, ssl->alpn_chosen, protocol_name_len);
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_tls13_set_hs_sent_ext_mask(ssl, MBEDTLS_TLS_EXT_ALPN);
#endif
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && \
    defined(MBEDTLS_SSL_CLI_C)
int mbedtls_ssl_session_set_hostname(mbedtls_ssl_session *session,
                                     const char *hostname)
{
    size_t hostname_len = 0;
    if (hostname != NULL) {
        hostname_len = strlen(hostname);
        if (hostname_len > MBEDTLS_SSL_MAX_HOST_NAME_LEN) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }
    if (session->hostname != NULL) {
        mbedtls_zeroize_and_free(session->hostname,
                                 strlen(session->hostname));
    }
    if (hostname == NULL) {
        session->hostname = NULL;
    } else {
        session->hostname = mbedtls_calloc(1, hostname_len + 1);
        if (session->hostname == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(session->hostname, hostname, hostname_len);
    }
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_EARLY_DATA) && \
    defined(MBEDTLS_SSL_ALPN)
int mbedtls_ssl_session_set_ticket_alpn(mbedtls_ssl_session *session,
                                        const char *alpn)
{
    size_t alpn_len = 0;
    if (alpn != NULL) {
        alpn_len = strlen(alpn);
        if (alpn_len > MBEDTLS_SSL_MAX_ALPN_NAME_LEN) {
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
    }
    if (session->ticket_alpn != NULL) {
        mbedtls_zeroize_and_free(session->ticket_alpn,
                                 strlen(session->ticket_alpn));
        session->ticket_alpn = NULL;
    }
    if (alpn != NULL) {
        session->ticket_alpn = mbedtls_calloc(alpn_len + 1, 1);
        if (session->ticket_alpn == NULL) {
            return MBEDTLS_ERR_SSL_ALLOC_FAILED;
        }
        memcpy(session->ticket_alpn, alpn, alpn_len);
    }
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
int mbedtls_ssl_check_cert_usage(const mbedtls_x509_crt *cert,
                                 const mbedtls_ssl_ciphersuite_t *ciphersuite,
                                 int recv_endpoint,
                                 mbedtls_ssl_protocol_version tls_version,
                                 uint32_t *flags)
{
    int ret = 0;
    unsigned int usage = 0;
    const char *ext_oid;
    size_t ext_len;
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    if (tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
        recv_endpoint == MBEDTLS_SSL_IS_CLIENT) {
        switch (ciphersuite->key_exchange) {
            case MBEDTLS_KEY_EXCHANGE_RSA:
            case MBEDTLS_KEY_EXCHANGE_RSA_PSK:
                usage = MBEDTLS_X509_KU_KEY_ENCIPHERMENT;
                break;
            case MBEDTLS_KEY_EXCHANGE_DHE_RSA:
            case MBEDTLS_KEY_EXCHANGE_ECDHE_RSA:
            case MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA:
                usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
                break;
            case MBEDTLS_KEY_EXCHANGE_ECDH_RSA:
            case MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA:
                usage = MBEDTLS_X509_KU_KEY_AGREEMENT;
                break;
            case MBEDTLS_KEY_EXCHANGE_NONE:
            case MBEDTLS_KEY_EXCHANGE_PSK:
            case MBEDTLS_KEY_EXCHANGE_DHE_PSK:
            case MBEDTLS_KEY_EXCHANGE_ECDHE_PSK:
            case MBEDTLS_KEY_EXCHANGE_ECJPAKE:
                usage = 0;
        }
    } else
#endif
    {
        (void) tls_version;
        (void) ciphersuite;
        usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    }
    if (mbedtls_x509_crt_check_key_usage(cert, usage) != 0) {
        *flags |= MBEDTLS_X509_BADCERT_KEY_USAGE;
        ret = -1;
    }
    if (recv_endpoint == MBEDTLS_SSL_IS_CLIENT) {
        ext_oid = MBEDTLS_OID_SERVER_AUTH;
        ext_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
    } else {
        ext_oid = MBEDTLS_OID_CLIENT_AUTH;
        ext_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH);
    }
    if (mbedtls_x509_crt_check_extended_key_usage(cert, ext_oid, ext_len) != 0) {
        *flags |= MBEDTLS_X509_BADCERT_EXT_KEY_USAGE;
        ret = -1;
    }
    return ret;
}
int mbedtls_ssl_verify_certificate(mbedtls_ssl_context *ssl,
                                   int authmode,
                                   mbedtls_x509_crt *chain,
                                   const mbedtls_ssl_ciphersuite_t *ciphersuite_info,
                                   void *rs_ctx)
{
    if (authmode == MBEDTLS_SSL_VERIFY_NONE) {
        return 0;
    }
    int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *);
    void *p_vrfy;
    if (ssl->f_vrfy != NULL) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("Use context-specific verification callback"));
        f_vrfy = ssl->f_vrfy;
        p_vrfy = ssl->p_vrfy;
    } else {
        MBEDTLS_SSL_DEBUG_MSG(3, ("Use configuration-specific verification callback"));
        f_vrfy = ssl->conf->f_vrfy;
        p_vrfy = ssl->conf->p_vrfy;
    }
    int ret = 0;
    int have_ca_chain_or_callback = 0;
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    if (ssl->conf->f_ca_cb != NULL) {
        ((void) rs_ctx);
        have_ca_chain_or_callback = 1;
        MBEDTLS_SSL_DEBUG_MSG(3, ("use CA callback for X.509 CRT verification"));
        ret = mbedtls_x509_crt_verify_with_ca_cb(
            chain,
            ssl->conf->f_ca_cb,
            ssl->conf->p_ca_cb,
            ssl->conf->cert_profile,
            ssl->hostname,
            &ssl->session_negotiate->verify_result,
            f_vrfy, p_vrfy);
    } else
#endif
    {
        mbedtls_x509_crt *ca_chain;
        mbedtls_x509_crl *ca_crl;
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if (ssl->handshake->sni_ca_chain != NULL) {
            ca_chain = ssl->handshake->sni_ca_chain;
            ca_crl = ssl->handshake->sni_ca_crl;
        } else
#endif
        {
            ca_chain = ssl->conf->ca_chain;
            ca_crl = ssl->conf->ca_crl;
        }
        if (ca_chain != NULL) {
            have_ca_chain_or_callback = 1;
        }
        ret = mbedtls_x509_crt_verify_restartable(
            chain,
            ca_chain, ca_crl,
            ssl->conf->cert_profile,
            ssl->hostname,
            &ssl->session_negotiate->verify_result,
            f_vrfy, p_vrfy, rs_ctx);
    }
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "x509_verify_cert", ret);
    }
#if defined(MBEDTLS_SSL_ECP_RESTARTABLE_ENABLED)
    if (ret == MBEDTLS_ERR_ECP_IN_PROGRESS) {
        return MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS;
    }
#endif
#if defined(MBEDTLS_SSL_PROTO_TLS1_2) && \
    defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    if (ssl->tls_version == MBEDTLS_SSL_VERSION_TLS1_2 &&
        mbedtls_pk_can_do(&chain->pk, MBEDTLS_PK_ECKEY)) {
        if (mbedtls_ssl_check_curve(ssl, mbedtls_pk_get_ec_group_id(&chain->pk)) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate (EC key curve)"));
            ssl->session_negotiate->verify_result |= MBEDTLS_X509_BADCERT_BAD_KEY;
            if (ret == 0) {
                ret = MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
            }
        }
    }
#endif
    if (mbedtls_ssl_check_cert_usage(chain,
                                     ciphersuite_info,
                                     ssl->conf->endpoint,
                                     ssl->tls_version,
                                     &ssl->session_negotiate->verify_result) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate (usage extensions)"));
        if (ret == 0) {
            ret = MBEDTLS_ERR_SSL_BAD_CERTIFICATE;
        }
    }
    if (authmode == MBEDTLS_SSL_VERIFY_OPTIONAL &&
        (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ||
         ret == MBEDTLS_ERR_SSL_BAD_CERTIFICATE)) {
        ret = 0;
    }
    if (have_ca_chain_or_callback == 0 && authmode == MBEDTLS_SSL_VERIFY_REQUIRED) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("got no CA chain"));
        ret = MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED;
    }
    if (ret != 0) {
        uint8_t alert;
        if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_OTHER) {
            alert = MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_CN_MISMATCH) {
            alert = MBEDTLS_SSL_ALERT_MSG_BAD_CERT;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_KEY_USAGE) {
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_EXT_KEY_USAGE) {
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_BAD_PK) {
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_BAD_KEY) {
            alert = MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_EXPIRED) {
            alert = MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_REVOKED) {
            alert = MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED;
        } else if (ssl->session_negotiate->verify_result & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
            alert = MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA;
        } else {
            alert = MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN;
        }
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       alert);
    }
#if defined(MBEDTLS_DEBUG_C)
    if (ssl->session_negotiate->verify_result != 0) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("! Certificate verification flags %08x",
                                  (unsigned int) ssl->session_negotiate->verify_result));
    } else {
        MBEDTLS_SSL_DEBUG_MSG(3, ("Certificate verification flags clear"));
    }
#endif
    return ret;
}
#endif
#endif
