/*
 *  TLS server-side functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"
#if defined(MBEDTLS_SSL_SRV_C) && defined(MBEDTLS_SSL_PROTO_TLS1_2)
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "ssl_misc.h"
#include "debug_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/platform_util.h"
#include "constant_time_internal.h"
#include "mbedtls/constant_time.h"
#include <string.h>
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
static int local_err_translation(psa_status_t status)
{
    return psa_status_to_mbedtls(status, psa_to_ssl_errors,
                                 ARRAY_LENGTH(psa_to_ssl_errors),
                                 psa_generic_status_to_mbedtls);
}
#define PSA_TO_MBEDTLS_ERR(status) local_err_translation(status)
#endif
#endif
#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif
#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
int mbedtls_ssl_set_client_transport_id(mbedtls_ssl_context *ssl,
                                        const unsigned char *info,
                                        size_t ilen)
{
    if (ssl->conf->endpoint != MBEDTLS_SSL_IS_SERVER) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    mbedtls_free(ssl->cli_id);
    if ((ssl->cli_id = mbedtls_calloc(1, ilen)) == NULL) {
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    memcpy(ssl->cli_id, info, ilen);
    ssl->cli_id_len = ilen;
    return 0;
}
void mbedtls_ssl_conf_dtls_cookies(mbedtls_ssl_config *conf,
                                   mbedtls_ssl_cookie_write_t *f_cookie_write,
                                   mbedtls_ssl_cookie_check_t *f_cookie_check,
                                   void *p_cookie)
{
    conf->f_cookie_write = f_cookie_write;
    conf->f_cookie_check = f_cookie_check;
    conf->p_cookie = p_cookie;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_conf_has_psk_or_cb(mbedtls_ssl_config const *conf)
{
    if (conf->f_psk != NULL) {
        return 1;
    }
    if (conf->psk_identity_len == 0 || conf->psk_identity == NULL) {
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
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_renegotiation_info(mbedtls_ssl_context *ssl,
                                        const unsigned char *buf,
                                        size_t len)
{
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE) {
        if (len != 1 + ssl->verify_data_len ||
            buf[0] != ssl->verify_data_len ||
            mbedtls_ct_memcmp(buf + 1, ssl->peer_verify_data,
                              ssl->verify_data_len) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("non-matching renegotiation info"));
            mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
    } else
#endif
    {
        if (len != 1 || buf[0] != 0x0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("non-zero length renegotiation info"));
            mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
        ssl->secure_renegotiation = MBEDTLS_SSL_SECURE_RENEGOTIATION;
    }
    return 0;
}
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_supported_groups_ext(mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          size_t len)
{
    size_t list_size, our_size;
    const unsigned char *p;
    uint16_t *curves_tls_id;
    if (len < 2) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    list_size = MBEDTLS_GET_UINT16_BE(buf, 0);
    if (list_size + 2 != len ||
        list_size % 2 != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (ssl->handshake->curves_tls_id != NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    our_size = list_size / 2 + 1;
    if (our_size > MBEDTLS_ECP_DP_MAX) {
        our_size = MBEDTLS_ECP_DP_MAX;
    }
    if ((curves_tls_id = mbedtls_calloc(our_size,
                                        sizeof(*curves_tls_id))) == NULL) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
        return MBEDTLS_ERR_SSL_ALLOC_FAILED;
    }
    ssl->handshake->curves_tls_id = curves_tls_id;
    p = buf + 2;
    while (list_size > 0 && our_size > 1) {
        uint16_t curr_tls_id = MBEDTLS_GET_UINT16_BE(p, 0);
        if (mbedtls_ssl_get_ecp_group_id_from_tls_id(curr_tls_id) !=
            MBEDTLS_ECP_DP_NONE) {
            *curves_tls_id++ = curr_tls_id;
            our_size--;
        }
        list_size -= 2;
        p += 2;
    }
    return 0;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_supported_point_formats(mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             size_t len)
{
    size_t list_size;
    const unsigned char *p;
    if (len == 0 || (size_t) (buf[0] + 1) != len) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    list_size = buf[0];
    p = buf + 1;
    while (list_size > 0) {
        if (p[0] == MBEDTLS_ECP_PF_UNCOMPRESSED ||
            p[0] == MBEDTLS_ECP_PF_COMPRESSED) {
#if !defined(MBEDTLS_USE_PSA_CRYPTO) && \
            defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED)
            ssl->handshake->ecdh_ctx.point_format = p[0];
#endif
#if !defined(MBEDTLS_USE_PSA_CRYPTO) && \
            defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
            mbedtls_ecjpake_set_point_format(&ssl->handshake->ecjpake_ctx,
                                             p[0]);
#endif
            MBEDTLS_SSL_DEBUG_MSG(4, ("point format selected: %d", p[0]));
            return 0;
        }
        list_size--;
        p++;
    }
    return 0;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_ecjpake_kkpp(mbedtls_ssl_context *ssl,
                                  const unsigned char *buf,
                                  size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (ssl->handshake->psa_pake_ctx_is_ok != 1)
#else
    if (mbedtls_ecjpake_check(&ssl->handshake->ecjpake_ctx) != 0)
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG(3, ("skip ecjpake kkpp extension"));
        return 0;
    }
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if ((ret = mbedtls_psa_ecjpake_read_round(
             &ssl->handshake->psa_pake_ctx, buf, len,
             MBEDTLS_ECJPAKE_ROUND_ONE)) != 0) {
        psa_destroy_key(ssl->handshake->psa_pake_password);
        psa_pake_abort(&ssl->handshake->psa_pake_ctx);
        MBEDTLS_SSL_DEBUG_RET(1, "psa_pake_input round one", ret);
        mbedtls_ssl_send_alert_message(
            ssl,
            MBEDTLS_SSL_ALERT_LEVEL_FATAL,
            MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
        return ret;
    }
#else
    if ((ret = mbedtls_ecjpake_read_round_one(&ssl->handshake->ecjpake_ctx,
                                              buf, len)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecjpake_read_round_one", ret);
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
        return ret;
    }
#endif
    ssl->handshake->cli_exts |= MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK;
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_max_fragment_length_ext(mbedtls_ssl_context *ssl,
                                             const unsigned char *buf,
                                             size_t len)
{
    if (len != 1 || buf[0] >= MBEDTLS_SSL_MAX_FRAG_LEN_INVALID) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    ssl->session_negotiate->mfl_code = buf[0];
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_cid_ext(mbedtls_ssl_context *ssl,
                             const unsigned char *buf,
                             size_t len)
{
    size_t peer_cid_len;
    if (ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    if (len < 1) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    peer_cid_len = *buf++;
    len--;
    if (len != peer_cid_len) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (ssl->negotiate_cid == MBEDTLS_SSL_CID_DISABLED) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("Client sent CID extension, but CID disabled"));
        return 0;
    }
    if (peer_cid_len > MBEDTLS_SSL_CID_OUT_LEN_MAX) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER);
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    ssl->handshake->cid_in_use = MBEDTLS_SSL_CID_ENABLED;
    ssl->handshake->peer_cid_len = (uint8_t) peer_cid_len;
    memcpy(ssl->handshake->peer_cid, buf, peer_cid_len);
    MBEDTLS_SSL_DEBUG_MSG(3, ("Use of CID extension negotiated"));
    MBEDTLS_SSL_DEBUG_BUF(3, "Client CID", buf, peer_cid_len);
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_encrypt_then_mac_ext(mbedtls_ssl_context *ssl,
                                          const unsigned char *buf,
                                          size_t len)
{
    if (len != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    ((void) buf);
    if (ssl->conf->encrypt_then_mac == MBEDTLS_SSL_ETM_ENABLED) {
        ssl->session_negotiate->encrypt_then_mac = MBEDTLS_SSL_ETM_ENABLED;
    }
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_extended_ms_ext(mbedtls_ssl_context *ssl,
                                     const unsigned char *buf,
                                     size_t len)
{
    if (len != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    ((void) buf);
    if (ssl->conf->extended_ms == MBEDTLS_SSL_EXTENDED_MS_ENABLED) {
        ssl->handshake->extended_ms = MBEDTLS_SSL_EXTENDED_MS_ENABLED;
    }
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_session_ticket_ext(mbedtls_ssl_context *ssl,
                                        unsigned char *buf,
                                        size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ssl_session session;
    mbedtls_ssl_session_init(&session);
    if (ssl->conf->f_ticket_parse == NULL ||
        ssl->conf->f_ticket_write == NULL) {
        return 0;
    }
    ssl->handshake->new_session_ticket = 1;
    MBEDTLS_SSL_DEBUG_MSG(3, ("ticket length: %" MBEDTLS_PRINTF_SIZET, len));
    if (len == 0) {
        return 0;
    }
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("ticket rejected: renegotiating"));
        return 0;
    }
#endif
    if ((ret = ssl->conf->f_ticket_parse(ssl->conf->p_ticket, &session,
                                         buf, len)) != 0) {
        mbedtls_ssl_session_free(&session);
        if (ret == MBEDTLS_ERR_SSL_INVALID_MAC) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("ticket is not authentic"));
        } else if (ret == MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("ticket is expired"));
        } else {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_ticket_parse", ret);
        }
        return 0;
    }
    session.id_len = ssl->session_negotiate->id_len;
    memcpy(&session.id, ssl->session_negotiate->id, session.id_len);
    mbedtls_ssl_session_free(ssl->session_negotiate);
    memcpy(ssl->session_negotiate, &session, sizeof(mbedtls_ssl_session));
    mbedtls_platform_zeroize(&session, sizeof(mbedtls_ssl_session));
    MBEDTLS_SSL_DEBUG_MSG(3, ("session successfully restored from ticket"));
    ssl->handshake->resume = 1;
    ssl->handshake->new_session_ticket = 0;
    return 0;
}
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_use_srtp_ext(mbedtls_ssl_context *ssl,
                                  const unsigned char *buf,
                                  size_t len)
{
    mbedtls_ssl_srtp_profile client_protection = MBEDTLS_TLS_SRTP_UNSET;
    size_t i, j;
    size_t profile_length;
    uint16_t mki_length;
    const size_t size_of_lengths = 3;
    if ((ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) ||
        (ssl->conf->dtls_srtp_profile_list == NULL) ||
        (ssl->conf->dtls_srtp_profile_list_len == 0)) {
        return 0;
    }
    if (len < size_of_lengths) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    ssl->dtls_srtp_info.chosen_dtls_srtp_profile = MBEDTLS_TLS_SRTP_UNSET;
    profile_length = (buf[0] << 8) | buf[1];
    buf += 2;
    if (profile_length > len - size_of_lengths ||
        profile_length % 2 != 0) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    for (j = 0; j < profile_length; j += 2) {
        uint16_t protection_profile_value = buf[j] << 8 | buf[j + 1];
        client_protection = mbedtls_ssl_check_srtp_profile_value(protection_profile_value);
        if (client_protection != MBEDTLS_TLS_SRTP_UNSET) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("found srtp profile: %s",
                                      mbedtls_ssl_get_srtp_profile_as_string(
                                          client_protection)));
        } else {
            continue;
        }
        for (i = 0; i < ssl->conf->dtls_srtp_profile_list_len; i++) {
            if (client_protection == ssl->conf->dtls_srtp_profile_list[i]) {
                ssl->dtls_srtp_info.chosen_dtls_srtp_profile = ssl->conf->dtls_srtp_profile_list[i];
                MBEDTLS_SSL_DEBUG_MSG(3, ("selected srtp profile: %s",
                                          mbedtls_ssl_get_srtp_profile_as_string(
                                              client_protection)));
                break;
            }
        }
        if (ssl->dtls_srtp_info.chosen_dtls_srtp_profile != MBEDTLS_TLS_SRTP_UNSET) {
            break;
        }
    }
    buf += profile_length;
    mki_length = *buf;
    buf++;
    if (mki_length > MBEDTLS_TLS_SRTP_MAX_MKI_LENGTH ||
        mki_length + profile_length + size_of_lengths != len) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (ssl->conf->dtls_srtp_mki_support == MBEDTLS_SSL_DTLS_SRTP_MKI_SUPPORTED &&
        mki_length > 0) {
        ssl->dtls_srtp_info.mki_len = mki_length;
        memcpy(ssl->dtls_srtp_info.mki_value, buf, mki_length);
        MBEDTLS_SSL_DEBUG_BUF(3, "using mki", ssl->dtls_srtp_info.mki_value,
                              ssl->dtls_srtp_info.mki_len);
    }
    return 0;
}
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_check_key_curve(mbedtls_pk_context *pk,
                               uint16_t *curves_tls_id)
{
    uint16_t *curr_tls_id = curves_tls_id;
    mbedtls_ecp_group_id grp_id = mbedtls_pk_get_ec_group_id(pk);
    mbedtls_ecp_group_id curr_grp_id;
    while (*curr_tls_id != 0) {
        curr_grp_id = mbedtls_ssl_get_ecp_group_id_from_tls_id(*curr_tls_id);
        if (curr_grp_id == grp_id) {
            return 0;
        }
        curr_tls_id++;
    }
    return -1;
}
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_pick_cert(mbedtls_ssl_context *ssl,
                         const mbedtls_ssl_ciphersuite_t *ciphersuite_info)
{
    mbedtls_ssl_key_cert *cur, *list;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_algorithm_t pk_alg =
        mbedtls_ssl_get_ciphersuite_sig_pk_psa_alg(ciphersuite_info);
    psa_key_usage_t pk_usage =
        mbedtls_ssl_get_ciphersuite_sig_pk_psa_usage(ciphersuite_info);
#else
    mbedtls_pk_type_t pk_alg =
        mbedtls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);
#endif
    uint32_t flags;
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if (ssl->handshake->sni_key_cert != NULL) {
        list = ssl->handshake->sni_key_cert;
    } else
#endif
    list = ssl->conf->key_cert;
    int pk_alg_is_none = 0;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    pk_alg_is_none = (pk_alg == PSA_ALG_NONE);
#else
    pk_alg_is_none = (pk_alg == MBEDTLS_PK_NONE);
#endif
    if (pk_alg_is_none) {
        return 0;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite requires certificate"));
    if (list == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("server has no certificate"));
        return -1;
    }
    for (cur = list; cur != NULL; cur = cur->next) {
        flags = 0;
        MBEDTLS_SSL_DEBUG_CRT(3, "candidate certificate chain, certificate",
                              cur->cert);
        int key_type_matches = 0;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
        key_type_matches = ((ssl->conf->f_async_sign_start != NULL ||
                             ssl->conf->f_async_decrypt_start != NULL ||
                             mbedtls_pk_can_do_ext(cur->key, pk_alg, pk_usage)) &&
                            mbedtls_pk_can_do_ext(&cur->cert->pk, pk_alg, pk_usage));
#else
        key_type_matches = (
            mbedtls_pk_can_do_ext(cur->key, pk_alg, pk_usage));
#endif
#else
        key_type_matches = mbedtls_pk_can_do(&cur->cert->pk, pk_alg);
#endif
        if (!key_type_matches) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("certificate mismatch: key type"));
            continue;
        }
        if (mbedtls_ssl_check_cert_usage(cur->cert, ciphersuite_info,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_VERSION_TLS1_2,
                                         &flags) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("certificate mismatch: "
                                      "(extended) key usage extension"));
            continue;
        }
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
        if (pk_alg == MBEDTLS_PK_ECDSA &&
            ssl_check_key_curve(&cur->cert->pk,
                                ssl->handshake->curves_tls_id) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("certificate mismatch: elliptic curve"));
            continue;
        }
#endif
        break;
    }
    if (cur != NULL) {
        ssl->handshake->key_cert = cur;
        MBEDTLS_SSL_DEBUG_CRT(3, "selected certificate chain, certificate",
                              ssl->handshake->key_cert->cert);
        return 0;
    }
    return -1;
}
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_ciphersuite_match(mbedtls_ssl_context *ssl, int suite_id,
                                 const mbedtls_ssl_ciphersuite_t **ciphersuite_info)
{
    const mbedtls_ssl_ciphersuite_t *suite_info;
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    mbedtls_pk_type_t sig_type;
#endif
    suite_info = mbedtls_ssl_ciphersuite_from_id(suite_id);
    if (suite_info == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("trying ciphersuite: %#04x (%s)",
                              (unsigned int) suite_id, suite_info->name));
    if (suite_info->min_tls_version > ssl->tls_version ||
        suite_info->max_tls_version < ssl->tls_version) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: version"));
        return 0;
    }
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    if (suite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE &&
        (ssl->handshake->cli_exts & MBEDTLS_TLS_EXT_ECJPAKE_KKPP_OK) == 0) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: ecjpake "
                                  "not configured or ext missing"));
        return 0;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    if (mbedtls_ssl_ciphersuite_uses_ec(suite_info) &&
        (ssl->handshake->curves_tls_id == NULL ||
         ssl->handshake->curves_tls_id[0] == 0)) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: "
                                  "no common elliptic curve"));
        return 0;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
    if (mbedtls_ssl_ciphersuite_uses_psk(suite_info) &&
        ssl_conf_has_psk_or_cb(ssl->conf) == 0) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: no pre-shared key"));
        return 0;
    }
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if (ssl_pick_cert(ssl, suite_info) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: "
                                  "no suitable certificate"));
        return 0;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    sig_type = mbedtls_ssl_get_ciphersuite_sig_alg(suite_info);
    if (sig_type != MBEDTLS_PK_NONE &&
        mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg(
            ssl, mbedtls_ssl_sig_from_pk_alg(sig_type)) == MBEDTLS_SSL_HASH_NONE) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("ciphersuite mismatch: no suitable hash algorithm "
                                  "for signature algorithm %u", (unsigned) sig_type));
        return 0;
    }
#endif
    *ciphersuite_info = suite_info;
    return 0;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_client_hello(mbedtls_ssl_context *ssl)
{
    int ret, got_common_suite;
    size_t i, j;
    size_t ciph_offset, comp_offset, ext_offset;
    size_t msg_len, ciph_len, sess_len, comp_len, ext_len;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    size_t cookie_offset, cookie_len;
#endif
    unsigned char *buf, *p, *ext;
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    int renegotiation_info_seen = 0;
#endif
    int handshake_failure = 0;
    const int *ciphersuites;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    int sig_hash_alg_ext_present = 0;
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse client hello"));
    int renegotiating;
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
read_record_header:
#endif
    renegotiating = 0;
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    renegotiating = (ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE);
#endif
    if (!renegotiating && !ssl->keep_current_message) {
        if ((ret = mbedtls_ssl_fetch_input(ssl, 5)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_fetch_input", ret);
            return ret;
        }
    }
    buf = ssl->in_hdr;
    MBEDTLS_SSL_DEBUG_BUF(4, "record header", buf, mbedtls_ssl_in_hdr_len(ssl));
    MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, message type: %d",
                              buf[0]));
    if (buf[0] != MBEDTLS_SSL_MSG_HANDSHAKE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, message len.: %d",
                              MBEDTLS_GET_UINT16_BE(ssl->in_len, 0)));
    MBEDTLS_SSL_DEBUG_MSG(3, ("client hello, protocol version: [%d:%d]",
                              buf[1], buf[2]));
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        && ssl->renego_status == MBEDTLS_SSL_INITIAL_HANDSHAKE
#endif
        ) {
        if (ssl->in_ctr[0] != 0 || ssl->in_ctr[1] != 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
            return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }
        memcpy(&ssl->cur_out_ctr[2], ssl->in_ctr + 2,
               sizeof(ssl->cur_out_ctr) - 2);
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
        if (mbedtls_ssl_dtls_replay_check(ssl) != 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("replayed record, discarding"));
            ssl->next_record_offset = 0;
            ssl->in_left = 0;
            goto read_record_header;
        }
        mbedtls_ssl_dtls_replay_update(ssl);
#endif
    }
#endif
    msg_len = MBEDTLS_GET_UINT16_BE(ssl->in_len, 0);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE) {
        msg_len = ssl->in_hslen;
    } else
#endif
    {
        if (ssl->keep_current_message) {
            ssl->keep_current_message = 0;
        } else {
            if (msg_len > MBEDTLS_SSL_IN_CONTENT_LEN) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
                return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
            }
            if ((ret = mbedtls_ssl_fetch_input(ssl,
                                               mbedtls_ssl_in_hdr_len(ssl) + msg_len)) != 0) {
                MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_fetch_input", ret);
                return ret;
            }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
            if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
                ssl->next_record_offset = msg_len + mbedtls_ssl_in_hdr_len(ssl);
            } else
#endif
            ssl->in_left = 0;
        }
    }
    buf = ssl->in_msg;
    MBEDTLS_SSL_DEBUG_BUF(4, "record contents", buf, msg_len);
    ret = ssl->handshake->update_checksum(ssl, buf, msg_len);
    if (0 != ret) {
        MBEDTLS_SSL_DEBUG_RET(1, ("update_checksum"), ret);
        return ret;
    }
    if (msg_len < mbedtls_ssl_hs_hdr_len(ssl)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("client hello v3, handshake type: %d", buf[0]));
    if (buf[0] != MBEDTLS_SSL_HS_CLIENT_HELLO) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }
    {
        size_t handshake_len = MBEDTLS_GET_UINT24_BE(buf, 1);
        MBEDTLS_SSL_DEBUG_MSG(3, ("client hello v3, handshake len.: %u",
                                  (unsigned) handshake_len));
        if (buf[1] != 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message: %u != 0",
                                      (unsigned) buf[1]));
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        if (msg_len != mbedtls_ssl_hs_hdr_len(ssl) + handshake_len) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message: %u != %u + %u",
                                      (unsigned) msg_len,
                                      (unsigned) mbedtls_ssl_hs_hdr_len(ssl),
                                      (unsigned) handshake_len));
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
    }
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
#if defined(MBEDTLS_SSL_RENEGOTIATION)
        if (ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
            unsigned int cli_msg_seq = (unsigned int) MBEDTLS_GET_UINT16_BE(ssl->in_msg, 4);
            if (cli_msg_seq != ssl->handshake->in_msg_seq) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message_seq: "
                                          "%u (expected %u)", cli_msg_seq,
                                          ssl->handshake->in_msg_seq));
                return MBEDTLS_ERR_SSL_DECODE_ERROR;
            }
            ssl->handshake->in_msg_seq++;
        } else
#endif
        {
            unsigned int cli_msg_seq = (unsigned int) MBEDTLS_GET_UINT16_BE(ssl->in_msg, 4);
            ssl->handshake->out_msg_seq = cli_msg_seq;
            ssl->handshake->in_msg_seq = cli_msg_seq + 1;
        }
        {
            size_t fragment_offset, fragment_length, length;
            fragment_offset = MBEDTLS_GET_UINT24_BE(ssl->in_msg, 6);
            fragment_length = MBEDTLS_GET_UINT24_BE(ssl->in_msg, 9);
            length = MBEDTLS_GET_UINT24_BE(ssl->in_msg, 1);
            MBEDTLS_SSL_DEBUG_MSG(
                4, ("fragment_offset=%u fragment_length=%u length=%u",
                    (unsigned) fragment_offset, (unsigned) fragment_length,
                    (unsigned) length));
            if (fragment_offset != 0 || length != fragment_length) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("ClientHello fragmentation not supported"));
                return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
            }
        }
    }
#endif
    buf += mbedtls_ssl_hs_hdr_len(ssl);
    msg_len -= mbedtls_ssl_hs_hdr_len(ssl);
    if (msg_len < 38) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    MBEDTLS_SSL_DEBUG_BUF(3, "client hello, version", buf, 2);
    ssl->tls_version = (mbedtls_ssl_protocol_version) mbedtls_ssl_read_version(buf,
                                                                               ssl->conf->transport);
    ssl->session_negotiate->tls_version = ssl->tls_version;
    ssl->session_negotiate->endpoint = ssl->conf->endpoint;
    if (ssl->tls_version != MBEDTLS_SSL_VERSION_TLS1_2) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("server only supports TLS 1.2"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION);
        return MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION;
    }
    MBEDTLS_SSL_DEBUG_BUF(3, "client hello, random bytes", buf + 2, 32);
    memcpy(ssl->handshake->randbytes, buf + 2, 32);
    sess_len = buf[34];
    if (sess_len > sizeof(ssl->session_negotiate->id) ||
        sess_len + 34 + 2 > msg_len) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    MBEDTLS_SSL_DEBUG_BUF(3, "client hello, session id", buf + 35, sess_len);
    ssl->session_negotiate->id_len = sess_len;
    memset(ssl->session_negotiate->id, 0,
           sizeof(ssl->session_negotiate->id));
    memcpy(ssl->session_negotiate->id, buf + 35,
           ssl->session_negotiate->id_len);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        cookie_offset = 35 + sess_len;
        cookie_len = buf[cookie_offset];
        if (cookie_offset + 1 + cookie_len + 2 > msg_len) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
            mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        MBEDTLS_SSL_DEBUG_BUF(3, "client hello, cookie",
                              buf + cookie_offset + 1, cookie_len);
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
        if (ssl->conf->f_cookie_check != NULL
#if defined(MBEDTLS_SSL_RENEGOTIATION)
            && ssl->renego_status == MBEDTLS_SSL_INITIAL_HANDSHAKE
#endif
            ) {
            if (ssl->conf->f_cookie_check(ssl->conf->p_cookie,
                                          buf + cookie_offset + 1, cookie_len,
                                          ssl->cli_id, ssl->cli_id_len) != 0) {
                MBEDTLS_SSL_DEBUG_MSG(2, ("cookie verification failed"));
                ssl->handshake->cookie_verify_result = 1;
            } else {
                MBEDTLS_SSL_DEBUG_MSG(2, ("cookie verification passed"));
                ssl->handshake->cookie_verify_result = 0;
            }
        } else
#endif
        {
            if (cookie_len != 0) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
                return MBEDTLS_ERR_SSL_DECODE_ERROR;
            }
            MBEDTLS_SSL_DEBUG_MSG(2, ("cookie verification skipped"));
        }
        ciph_offset = cookie_offset + 1 + cookie_len;
    } else
#endif
    ciph_offset = 35 + sess_len;
    ciph_len = MBEDTLS_GET_UINT16_BE(buf, ciph_offset);
    if (ciph_len < 2 ||
        ciph_len + 2 + ciph_offset + 1 > msg_len ||
        (ciph_len % 2) != 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    MBEDTLS_SSL_DEBUG_BUF(3, "client hello, ciphersuitelist",
                          buf + ciph_offset + 2, ciph_len);
    comp_offset = ciph_offset + 2 + ciph_len;
    comp_len = buf[comp_offset];
    if (comp_len < 1 ||
        comp_len > 16 ||
        comp_len + comp_offset + 1 > msg_len) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    MBEDTLS_SSL_DEBUG_BUF(3, "client hello, compression",
                          buf + comp_offset + 1, comp_len);
    ext_offset = comp_offset + 1 + comp_len;
    if (msg_len > ext_offset) {
        if (msg_len < ext_offset + 2) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
            mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        ext_len = MBEDTLS_GET_UINT16_BE(buf, ext_offset);
        if (msg_len != ext_offset + 2 + ext_len) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
            mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
    } else {
        ext_len = 0;
    }
    ext = buf + ext_offset + 2;
    MBEDTLS_SSL_DEBUG_BUF(3, "client hello extensions", ext, ext_len);
    while (ext_len != 0) {
        unsigned int ext_id;
        unsigned int ext_size;
        if (ext_len < 4) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
            mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        ext_id = MBEDTLS_GET_UINT16_BE(ext, 0);
        ext_size = MBEDTLS_GET_UINT16_BE(ext, 2);
        if (ext_size + 4 > ext_len) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client hello message"));
            mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                           MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        switch (ext_id) {
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
            case MBEDTLS_TLS_EXT_SERVERNAME:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found ServerName extension"));
                ret = mbedtls_ssl_parse_server_name_ext(ssl, ext + 4,
                                                        ext + 4 + ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
            case MBEDTLS_TLS_EXT_RENEGOTIATION_INFO:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found renegotiation extension"));
#if defined(MBEDTLS_SSL_RENEGOTIATION)
                renegotiation_info_seen = 1;
#endif
                ret = ssl_parse_renegotiation_info(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
            case MBEDTLS_TLS_EXT_SIG_ALG:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found signature_algorithms extension"));
                ret = mbedtls_ssl_parse_sig_alg_ext(ssl, ext + 4, ext + 4 + ext_size);
                if (ret != 0) {
                    return ret;
                }
                sig_hash_alg_ext_present = 1;
                break;
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) || \
                defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED) || \
                defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
            case MBEDTLS_TLS_EXT_SUPPORTED_GROUPS:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found supported elliptic curves extension"));
                ret = ssl_parse_supported_groups_ext(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
            case MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found supported point formats extension"));
                ssl->handshake->cli_exts |= MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT;
                ret = ssl_parse_supported_point_formats(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
            case MBEDTLS_TLS_EXT_ECJPAKE_KKPP:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found ecjpake kkpp extension"));
                ret = ssl_parse_ecjpake_kkpp(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
            case MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found max fragment length extension"));
                ret = ssl_parse_max_fragment_length_ext(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
            case MBEDTLS_TLS_EXT_CID:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found CID extension"));
                ret = ssl_parse_cid_ext(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
            case MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found encrypt then mac extension"));
                ret = ssl_parse_encrypt_then_mac_ext(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
            case MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found extended master secret extension"));
                ret = ssl_parse_extended_ms_ext(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
            case MBEDTLS_TLS_EXT_SESSION_TICKET:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found session ticket extension"));
                ret = ssl_parse_session_ticket_ext(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_SSL_ALPN)
            case MBEDTLS_TLS_EXT_ALPN:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found alpn extension"));
                ret = mbedtls_ssl_parse_alpn_ext(ssl, ext + 4,
                                                 ext + 4 + ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
            case MBEDTLS_TLS_EXT_USE_SRTP:
                MBEDTLS_SSL_DEBUG_MSG(3, ("found use_srtp extension"));
                ret = ssl_parse_use_srtp_ext(ssl, ext + 4, ext_size);
                if (ret != 0) {
                    return ret;
                }
                break;
#endif
            default:
                MBEDTLS_SSL_DEBUG_MSG(3, ("unknown extension found: %u (ignoring)",
                                          ext_id));
        }
        ext_len -= 4 + ext_size;
        ext += 4 + ext_size;
    }
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    if (!sig_hash_alg_ext_present) {
        uint16_t *received_sig_algs = ssl->handshake->received_sig_algs;
        const uint16_t default_sig_algs[] = {
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
            MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_ECDSA,
                                               MBEDTLS_SSL_HASH_SHA1),
#endif
#if defined(MBEDTLS_RSA_C)
            MBEDTLS_SSL_TLS12_SIG_AND_HASH_ALG(MBEDTLS_SSL_SIG_RSA,
                                               MBEDTLS_SSL_HASH_SHA1),
#endif
            MBEDTLS_TLS_SIG_NONE
        };
        MBEDTLS_STATIC_ASSERT(sizeof(default_sig_algs) / sizeof(default_sig_algs[0])
                              <= MBEDTLS_RECEIVED_SIG_ALGS_SIZE,
                              "default_sig_algs is too big");
        memcpy(received_sig_algs, default_sig_algs, sizeof(default_sig_algs));
    }
#endif
    for (i = 0, p = buf + ciph_offset + 2; i < ciph_len; i += 2, p += 2) {
        if (p[0] == 0 && p[1] == MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("received TLS_EMPTY_RENEGOTIATION_INFO "));
#if defined(MBEDTLS_SSL_RENEGOTIATION)
            if (ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("received RENEGOTIATION SCSV "
                                          "during renegotiation"));
                mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                               MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
                return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            }
#endif
            ssl->secure_renegotiation = MBEDTLS_SSL_SECURE_RENEGOTIATION;
            break;
        }
    }
    if (ssl->secure_renegotiation != MBEDTLS_SSL_SECURE_RENEGOTIATION &&
        ssl->conf->allow_legacy_renegotiation == MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("legacy renegotiation, breaking off handshake"));
        handshake_failure = 1;
    }
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    else if (ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS &&
             ssl->secure_renegotiation == MBEDTLS_SSL_SECURE_RENEGOTIATION &&
             renegotiation_info_seen == 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("renegotiation_info extension missing (secure)"));
        handshake_failure = 1;
    } else if (ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS &&
               ssl->secure_renegotiation == MBEDTLS_SSL_LEGACY_RENEGOTIATION &&
               ssl->conf->allow_legacy_renegotiation == MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("legacy renegotiation not allowed"));
        handshake_failure = 1;
    } else if (ssl->renego_status == MBEDTLS_SSL_RENEGOTIATION_IN_PROGRESS &&
               ssl->secure_renegotiation == MBEDTLS_SSL_LEGACY_RENEGOTIATION &&
               renegotiation_info_seen == 1) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("renegotiation_info extension present (legacy)"));
        handshake_failure = 1;
    }
#endif
    if (handshake_failure == 1) {
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
    if (ssl->conf->f_cert_cb && (ret = ssl->conf->f_cert_cb(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "f_cert_cb", ret);
        return ret;
    }
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    ssl->handshake->sni_name = NULL;
    ssl->handshake->sni_name_len = 0;
#endif
    got_common_suite = 0;
    ciphersuites = ssl->conf->ciphersuite_list;
    ciphersuite_info = NULL;
    if (ssl->conf->respect_cli_pref == MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_CLIENT) {
        for (j = 0, p = buf + ciph_offset + 2; j < ciph_len; j += 2, p += 2) {
            for (i = 0; ciphersuites[i] != 0; i++) {
                if (MBEDTLS_GET_UINT16_BE(p, 0) != ciphersuites[i]) {
                    continue;
                }
                got_common_suite = 1;
                if ((ret = ssl_ciphersuite_match(ssl, ciphersuites[i],
                                                 &ciphersuite_info)) != 0) {
                    return ret;
                }
                if (ciphersuite_info != NULL) {
                    goto have_ciphersuite;
                }
            }
        }
    } else {
        for (i = 0; ciphersuites[i] != 0; i++) {
            for (j = 0, p = buf + ciph_offset + 2; j < ciph_len; j += 2, p += 2) {
                if (MBEDTLS_GET_UINT16_BE(p, 0) != ciphersuites[i]) {
                    continue;
                }
                got_common_suite = 1;
                if ((ret = ssl_ciphersuite_match(ssl, ciphersuites[i],
                                                 &ciphersuite_info)) != 0) {
                    return ret;
                }
                if (ciphersuite_info != NULL) {
                    goto have_ciphersuite;
                }
            }
        }
    }
    if (got_common_suite) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("got ciphersuites in common, "
                                  "but none of them usable"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    } else {
        MBEDTLS_SSL_DEBUG_MSG(1, ("got no ciphersuites in common"));
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE);
        return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
    }
have_ciphersuite:
    MBEDTLS_SSL_DEBUG_MSG(2, ("selected ciphersuite: %s", ciphersuite_info->name));
    ssl->session_negotiate->ciphersuite = ciphersuites[i];
    ssl->handshake->ciphersuite_info = ciphersuite_info;
    ssl->state++;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
        mbedtls_ssl_recv_flight_completed(ssl);
    }
#endif
#if defined(MBEDTLS_DEBUG_C) && \
    defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED)
    mbedtls_pk_type_t sig_alg = mbedtls_ssl_get_ciphersuite_sig_alg(ciphersuite_info);
    if (sig_alg != MBEDTLS_PK_NONE) {
        unsigned int sig_hash = mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg(
            ssl, mbedtls_ssl_sig_from_pk_alg(sig_alg));
        MBEDTLS_SSL_DEBUG_MSG(3, ("client hello v3, signature_algorithm ext: %u",
                                  sig_hash));
    } else {
        MBEDTLS_SSL_DEBUG_MSG(3, ("no hash algorithm for signature algorithm "
                                  "%u - should not happen", (unsigned) sig_alg));
    }
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse client hello"));
    return 0;
}
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
static void ssl_write_cid_ext(mbedtls_ssl_context *ssl,
                              unsigned char *buf,
                              size_t *olen)
{
    unsigned char *p = buf;
    size_t ext_len;
    const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN;
    *olen = 0;
    if (ssl->handshake->cid_in_use == MBEDTLS_SSL_CID_DISABLED) {
        return;
    }
    if (end < p || (size_t) (end - p) < (unsigned) (ssl->own_cid_len + 5)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, adding CID extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_CID, p, 0);
    p += 2;
    ext_len = (size_t) ssl->own_cid_len + 1;
    MBEDTLS_PUT_UINT16_BE(ext_len, p, 0);
    p += 2;
    *p++ = (uint8_t) ssl->own_cid_len;
    memcpy(p, ssl->own_cid, ssl->own_cid_len);
    *olen = ssl->own_cid_len + 5;
}
#endif
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
static void ssl_write_encrypt_then_mac_ext(mbedtls_ssl_context *ssl,
                                           unsigned char *buf,
                                           size_t *olen)
{
    unsigned char *p = buf;
    const mbedtls_ssl_ciphersuite_t *suite = NULL;
    suite = mbedtls_ssl_ciphersuite_from_id(
        ssl->session_negotiate->ciphersuite);
    if (suite == NULL) {
        ssl->session_negotiate->encrypt_then_mac = MBEDTLS_SSL_ETM_DISABLED;
    } else {
        mbedtls_ssl_mode_t ssl_mode =
            mbedtls_ssl_get_mode_from_ciphersuite(
                ssl->session_negotiate->encrypt_then_mac,
                suite);
        if (ssl_mode != MBEDTLS_SSL_MODE_CBC_ETM) {
            ssl->session_negotiate->encrypt_then_mac = MBEDTLS_SSL_ETM_DISABLED;
        }
    }
    if (ssl->session_negotiate->encrypt_then_mac == MBEDTLS_SSL_ETM_DISABLED) {
        *olen = 0;
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, adding encrypt then mac extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC, p, 0);
    p += 2;
    *p++ = 0x00;
    *p++ = 0x00;
    *olen = 4;
}
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
static void ssl_write_extended_ms_ext(mbedtls_ssl_context *ssl,
                                      unsigned char *buf,
                                      size_t *olen)
{
    unsigned char *p = buf;
    if (ssl->handshake->extended_ms == MBEDTLS_SSL_EXTENDED_MS_DISABLED) {
        *olen = 0;
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, adding extended master secret "
                              "extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET, p, 0);
    p += 2;
    *p++ = 0x00;
    *p++ = 0x00;
    *olen = 4;
}
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
static void ssl_write_session_ticket_ext(mbedtls_ssl_context *ssl,
                                         unsigned char *buf,
                                         size_t *olen)
{
    unsigned char *p = buf;
    if (ssl->handshake->new_session_ticket == 0) {
        *olen = 0;
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, adding session ticket extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_SESSION_TICKET, p, 0);
    p += 2;
    *p++ = 0x00;
    *p++ = 0x00;
    *olen = 4;
}
#endif
static void ssl_write_renegotiation_ext(mbedtls_ssl_context *ssl,
                                        unsigned char *buf,
                                        size_t *olen)
{
    unsigned char *p = buf;
    if (ssl->secure_renegotiation != MBEDTLS_SSL_SECURE_RENEGOTIATION) {
        *olen = 0;
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, secure renegotiation extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_RENEGOTIATION_INFO, p, 0);
    p += 2;
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE) {
        *p++ = 0x00;
        *p++ = (ssl->verify_data_len * 2 + 1) & 0xFF;
        *p++ = ssl->verify_data_len * 2 & 0xFF;
        memcpy(p, ssl->peer_verify_data, ssl->verify_data_len);
        p += ssl->verify_data_len;
        memcpy(p, ssl->own_verify_data, ssl->verify_data_len);
        p += ssl->verify_data_len;
    } else
#endif
    {
        *p++ = 0x00;
        *p++ = 0x01;
        *p++ = 0x00;
    }
    *olen = (size_t) (p - buf);
}
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
static void ssl_write_max_fragment_length_ext(mbedtls_ssl_context *ssl,
                                              unsigned char *buf,
                                              size_t *olen)
{
    unsigned char *p = buf;
    if (ssl->session_negotiate->mfl_code == MBEDTLS_SSL_MAX_FRAG_LEN_NONE) {
        *olen = 0;
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, max_fragment_length extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH, p, 0);
    p += 2;
    *p++ = 0x00;
    *p++ = 1;
    *p++ = ssl->session_negotiate->mfl_code;
    *olen = 5;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static void ssl_write_supported_point_formats_ext(mbedtls_ssl_context *ssl,
                                                  unsigned char *buf,
                                                  size_t *olen)
{
    unsigned char *p = buf;
    ((void) ssl);
    if ((ssl->handshake->cli_exts &
         MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS_PRESENT) == 0) {
        *olen = 0;
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, supported_point_formats extension"));
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS, p, 0);
    p += 2;
    *p++ = 0x00;
    *p++ = 2;
    *p++ = 1;
    *p++ = MBEDTLS_ECP_PF_UNCOMPRESSED;
    *olen = 6;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
static void ssl_write_ecjpake_kkpp_ext(mbedtls_ssl_context *ssl,
                                       unsigned char *buf,
                                       size_t *olen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = buf;
    const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN;
    size_t kkpp_len;
    *olen = 0;
    if (ssl->handshake->ciphersuite_info->key_exchange !=
        MBEDTLS_KEY_EXCHANGE_ECJPAKE) {
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, ecjpake kkpp extension"));
    if (end - p < 4) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
        return;
    }
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_ECJPAKE_KKPP, p, 0);
    p += 2;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    ret = mbedtls_psa_ecjpake_write_round(&ssl->handshake->psa_pake_ctx,
                                          p + 2, (size_t) (end - p - 2), &kkpp_len,
                                          MBEDTLS_ECJPAKE_ROUND_ONE);
    if (ret != 0) {
        psa_destroy_key(ssl->handshake->psa_pake_password);
        psa_pake_abort(&ssl->handshake->psa_pake_ctx);
        MBEDTLS_SSL_DEBUG_RET(1, "psa_pake_output", ret);
        return;
    }
#else
    ret = mbedtls_ecjpake_write_round_one(&ssl->handshake->ecjpake_ctx,
                                          p + 2, (size_t) (end - p - 2), &kkpp_len,
                                          ssl->conf->f_rng, ssl->conf->p_rng);
    if (ret != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecjpake_write_round_one", ret);
        return;
    }
#endif
    MBEDTLS_PUT_UINT16_BE(kkpp_len, p, 0);
    p += 2;
    *olen = kkpp_len + 4;
}
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP) && defined(MBEDTLS_SSL_PROTO_DTLS)
static void ssl_write_use_srtp_ext(mbedtls_ssl_context *ssl,
                                   unsigned char *buf,
                                   size_t *olen)
{
    size_t mki_len = 0, ext_len = 0;
    uint16_t profile_value = 0;
    const unsigned char *end = ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN;
    *olen = 0;
    if ((ssl->conf->transport != MBEDTLS_SSL_TRANSPORT_DATAGRAM) ||
        (ssl->dtls_srtp_info.chosen_dtls_srtp_profile == MBEDTLS_TLS_SRTP_UNSET)) {
        return;
    }
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, adding use_srtp extension"));
    if (ssl->conf->dtls_srtp_mki_support == MBEDTLS_SSL_DTLS_SRTP_MKI_SUPPORTED) {
        mki_len = ssl->dtls_srtp_info.mki_len;
    }
    if ((size_t) (end - buf) < mki_len + 9) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("buffer too small"));
        return;
    }
    MBEDTLS_PUT_UINT16_BE(MBEDTLS_TLS_EXT_USE_SRTP, buf, 0);
    ext_len = 5 + mki_len;
    MBEDTLS_PUT_UINT16_BE(ext_len, buf, 2);
    buf[4] = 0x00;
    buf[5] = 0x02;
    profile_value = mbedtls_ssl_check_srtp_profile_value(
        ssl->dtls_srtp_info.chosen_dtls_srtp_profile);
    if (profile_value != MBEDTLS_TLS_SRTP_UNSET) {
        MBEDTLS_PUT_UINT16_BE(profile_value, buf, 6);
    } else {
        MBEDTLS_SSL_DEBUG_MSG(1, ("use_srtp extension invalid profile"));
        return;
    }
    buf[8] = mki_len & 0xFF;
    memcpy(&buf[9], ssl->dtls_srtp_info.mki_value, mki_len);
    *olen = 9 + mki_len;
}
#endif
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_hello_verify_request(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *p = ssl->out_msg + 4;
    unsigned char *cookie_len_byte;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write hello verify request"));
    mbedtls_ssl_write_version(p, ssl->conf->transport, ssl->tls_version);
    MBEDTLS_SSL_DEBUG_BUF(3, "server version", p, 2);
    p += 2;
    if (ssl->conf->f_cookie_write == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("inconsistent cookie callbacks"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    cookie_len_byte = p++;
    if ((ret = ssl->conf->f_cookie_write(ssl->conf->p_cookie,
                                         &p, ssl->out_buf + MBEDTLS_SSL_OUT_BUFFER_LEN,
                                         ssl->cli_id, ssl->cli_id_len)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "f_cookie_write", ret);
        return ret;
    }
    *cookie_len_byte = (unsigned char) (p - (cookie_len_byte + 1));
    MBEDTLS_SSL_DEBUG_BUF(3, "cookie sent", cookie_len_byte + 1, *cookie_len_byte);
    ssl->out_msglen = (size_t) (p - ssl->out_msg);
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST;
    ssl->state = MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT;
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
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write hello verify request"));
    return 0;
}
#endif
static void ssl_handle_id_based_session_resumption(mbedtls_ssl_context *ssl)
{
    int ret;
    mbedtls_ssl_session session_tmp;
    mbedtls_ssl_session * const session = ssl->session_negotiate;
    if (ssl->handshake->resume == 1) {
        return;
    }
    if (session->id_len == 0) {
        return;
    }
    if (ssl->conf->f_get_cache == NULL) {
        return;
    }
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    if (ssl->renego_status != MBEDTLS_SSL_INITIAL_HANDSHAKE) {
        return;
    }
#endif
    mbedtls_ssl_session_init(&session_tmp);
    ret = ssl->conf->f_get_cache(ssl->conf->p_cache,
                                 session->id,
                                 session->id_len,
                                 &session_tmp);
    if (ret != 0) {
        goto exit;
    }
    if (session->ciphersuite != session_tmp.ciphersuite) {
        goto exit;
    }
    mbedtls_ssl_session_free(session);
    *session = session_tmp;
    memset(&session_tmp, 0, sizeof(session_tmp));
    MBEDTLS_SSL_DEBUG_MSG(3, ("session successfully restored from cache"));
    ssl->handshake->resume = 1;
exit:
    mbedtls_ssl_session_free(&session_tmp);
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_server_hello(mbedtls_ssl_context *ssl)
{
#if defined(MBEDTLS_HAVE_TIME)
    mbedtls_time_t t;
#endif
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen, ext_len = 0, n;
    unsigned char *buf, *p;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write server hello"));
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
    if (ssl->conf->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
        ssl->handshake->cookie_verify_result != 0) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("client hello was not authenticated"));
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= write server hello"));
        return ssl_write_hello_verify_request(ssl);
    }
#endif
    buf = ssl->out_msg;
    p = buf + 4;
    mbedtls_ssl_write_version(p, ssl->conf->transport, ssl->tls_version);
    p += 2;
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, chosen version: [%d:%d]",
                              buf[4], buf[5]));
#if defined(MBEDTLS_HAVE_TIME)
    t = mbedtls_time(NULL);
    MBEDTLS_PUT_UINT32_BE(t, p, 0);
    p += 4;
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, current time: %" MBEDTLS_PRINTF_LONGLONG,
                              (long long) t));
#else
    if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 4)) != 0) {
        return ret;
    }
    p += 4;
#endif
    if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 20)) != 0) {
        return ret;
    }
    p += 20;
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    if (mbedtls_ssl_conf_is_tls13_enabled(ssl->conf)) {
        static const unsigned char magic_tls12_downgrade_string[] =
        { 'D', 'O', 'W', 'N', 'G', 'R', 'D', 1 };
        MBEDTLS_STATIC_ASSERT(
            sizeof(magic_tls12_downgrade_string) == 8,
            "magic_tls12_downgrade_string does not have the expected size");
        memcpy(p, magic_tls12_downgrade_string,
               sizeof(magic_tls12_downgrade_string));
    } else
#endif
    {
        if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, p, 8)) != 0) {
            return ret;
        }
    }
    p += 8;
    memcpy(ssl->handshake->randbytes + 32, buf + 6, 32);
    MBEDTLS_SSL_DEBUG_BUF(3, "server hello, random bytes", buf + 6, 32);
    ssl_handle_id_based_session_resumption(ssl);
    if (ssl->handshake->resume == 0) {
        ssl->state++;
#if defined(MBEDTLS_HAVE_TIME)
        ssl->session_negotiate->start = mbedtls_time(NULL);
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
        if (ssl->handshake->new_session_ticket != 0) {
            ssl->session_negotiate->id_len = n = 0;
            memset(ssl->session_negotiate->id, 0, 32);
        } else
#endif
        {
            ssl->session_negotiate->id_len = n = 32;
            if ((ret = ssl->conf->f_rng(ssl->conf->p_rng, ssl->session_negotiate->id,
                                        n)) != 0) {
                return ret;
            }
        }
    } else {
        n = ssl->session_negotiate->id_len;
        ssl->state = MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC;
        if ((ret = mbedtls_ssl_derive_keys(ssl)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_derive_keys", ret);
            return ret;
        }
    }
    *p++ = (unsigned char) ssl->session_negotiate->id_len;
    memcpy(p, ssl->session_negotiate->id, ssl->session_negotiate->id_len);
    p += ssl->session_negotiate->id_len;
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, session id len.: %" MBEDTLS_PRINTF_SIZET, n));
    MBEDTLS_SSL_DEBUG_BUF(3, "server hello, session id", buf + 39, n);
    MBEDTLS_SSL_DEBUG_MSG(3, ("%s session has been resumed",
                              ssl->handshake->resume ? "a" : "no"));
    MBEDTLS_PUT_UINT16_BE(ssl->session_negotiate->ciphersuite, p, 0);
    p += 2;
    *p++ = MBEDTLS_BYTE_0(MBEDTLS_SSL_COMPRESS_NULL);
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, chosen ciphersuite: %s",
                              mbedtls_ssl_get_ciphersuite_name(ssl->session_negotiate->ciphersuite)));
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, compress alg.: 0x%02X",
                              (unsigned int) MBEDTLS_SSL_COMPRESS_NULL));
    ssl_write_renegotiation_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    ssl_write_max_fragment_length_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    ssl_write_cid_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#endif
#if defined(MBEDTLS_SSL_SOME_SUITES_USE_CBC_ETM)
    ssl_write_encrypt_then_mac_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    ssl_write_extended_ms_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    ssl_write_session_ticket_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_1_2_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    const mbedtls_ssl_ciphersuite_t *suite =
        mbedtls_ssl_ciphersuite_from_id(ssl->session_negotiate->ciphersuite);
    if (suite != NULL && mbedtls_ssl_ciphersuite_uses_ec(suite)) {
        ssl_write_supported_point_formats_ext(ssl, p + 2 + ext_len, &olen);
        ext_len += olen;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    ssl_write_ecjpake_kkpp_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#endif
#if defined(MBEDTLS_SSL_ALPN)
    unsigned char *end = buf + MBEDTLS_SSL_OUT_CONTENT_LEN - 4;
    if ((ret = mbedtls_ssl_write_alpn_ext(ssl, p + 2 + ext_len, end, &olen))
        != 0) {
        return ret;
    }
    ext_len += olen;
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
    ssl_write_use_srtp_ext(ssl, p + 2 + ext_len, &olen);
    ext_len += olen;
#endif
    MBEDTLS_SSL_DEBUG_MSG(3, ("server hello, total extension length: %" MBEDTLS_PRINTF_SIZET,
                              ext_len));
    if (ext_len > 0) {
        MBEDTLS_PUT_UINT16_BE(ext_len, p, 0);
        p += 2 + ext_len;
    }
    ssl->out_msglen = (size_t) (p - buf);
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_SERVER_HELLO;
    ret = mbedtls_ssl_write_handshake_msg(ssl);
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write server hello"));
    return ret;
}
#if !defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_certificate_request(mbedtls_ssl_context *ssl)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate request"));
    if (!mbedtls_ssl_ciphersuite_cert_req_allowed(ciphersuite_info)) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate request"));
        ssl->state++;
        return 0;
    }
    MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
#else
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_certificate_request(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    uint16_t dn_size, total_dn_size;
    size_t ct_len, sa_len;
    unsigned char *buf, *p;
    const unsigned char * const end = ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN;
    const mbedtls_x509_crt *crt;
    int authmode;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write certificate request"));
    ssl->state++;
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
    if (ssl->handshake->sni_authmode != MBEDTLS_SSL_VERIFY_UNSET) {
        authmode = ssl->handshake->sni_authmode;
    } else
#endif
    authmode = ssl->conf->authmode;
    if (!mbedtls_ssl_ciphersuite_cert_req_allowed(ciphersuite_info) ||
        authmode == MBEDTLS_SSL_VERIFY_NONE) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write certificate request"));
        return 0;
    }
    buf = ssl->out_msg;
    p = buf + 4;
    ct_len = 0;
#if defined(MBEDTLS_RSA_C)
    p[1 + ct_len++] = MBEDTLS_SSL_CERT_TYPE_RSA_SIGN;
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDSA_CERT_REQ_ALLOWED_ENABLED)
    p[1 + ct_len++] = MBEDTLS_SSL_CERT_TYPE_ECDSA_SIGN;
#endif
    p[0] = (unsigned char) ct_len++;
    p += ct_len;
    sa_len = 0;
    const uint16_t *sig_alg = mbedtls_ssl_get_sig_algs(ssl);
    if (sig_alg == NULL) {
        return MBEDTLS_ERR_SSL_BAD_CONFIG;
    }
    for (; *sig_alg != MBEDTLS_TLS_SIG_NONE; sig_alg++) {
        unsigned char hash = MBEDTLS_BYTE_1(*sig_alg);
        if (mbedtls_ssl_set_calc_verify_md(ssl, hash)) {
            continue;
        }
        if (!mbedtls_ssl_sig_alg_is_supported(ssl, *sig_alg)) {
            continue;
        }
        sa_len += 2;
        MBEDTLS_PUT_UINT16_BE(*sig_alg, p, sa_len);
    }
    MBEDTLS_PUT_UINT16_BE(sa_len, p, 0);
    sa_len += 2;
    p += sa_len;
    p += 2;
    total_dn_size = 0;
    if (ssl->conf->cert_req_ca_list == MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED) {
#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if (ssl->handshake->dn_hints != NULL) {
            crt = ssl->handshake->dn_hints;
        } else
#endif
        if (ssl->conf->dn_hints != NULL) {
            crt = ssl->conf->dn_hints;
        } else
#endif
#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)
        if (ssl->handshake->sni_ca_chain != NULL) {
            crt = ssl->handshake->sni_ca_chain;
        } else
#endif
        crt = ssl->conf->ca_chain;
        while (crt != NULL && crt->version != 0) {
            dn_size = (uint16_t) crt->subject_raw.len;
            if (end < p || (size_t) (end - p) < 2 + (size_t) dn_size) {
                MBEDTLS_SSL_DEBUG_MSG(1, ("skipping CAs: buffer too short"));
                break;
            }
            MBEDTLS_PUT_UINT16_BE(dn_size, p, 0);
            p += 2;
            memcpy(p, crt->subject_raw.p, dn_size);
            p += dn_size;
            MBEDTLS_SSL_DEBUG_BUF(3, "requested DN", p - dn_size, dn_size);
            total_dn_size += (unsigned short) (2 + dn_size);
            crt = crt->next;
        }
    }
    ssl->out_msglen = (size_t) (p - buf);
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_CERTIFICATE_REQUEST;
    MBEDTLS_PUT_UINT16_BE(total_dn_size, ssl->out_msg, 4 + ct_len + sa_len);
    ret = mbedtls_ssl_write_handshake_msg(ssl);
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write certificate request"));
    return ret;
}
#endif
#if (defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED))
#if defined(MBEDTLS_USE_PSA_CRYPTO)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_get_ecdh_params_from_cert(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    mbedtls_pk_context *pk;
    mbedtls_pk_type_t pk_type;
    psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
    unsigned char buf[PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)];
    size_t key_len;
#if !defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    uint16_t tls_id = 0;
    psa_key_type_t key_type = PSA_KEY_TYPE_NONE;
    mbedtls_ecp_group_id grp_id;
    mbedtls_ecp_keypair *key;
#endif
    pk = mbedtls_ssl_own_key(ssl);
    if (pk == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    pk_type = mbedtls_pk_get_type(pk);
    switch (pk_type) {
        case MBEDTLS_PK_OPAQUE:
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
#endif
            if (!mbedtls_pk_can_do(pk, MBEDTLS_PK_ECKEY)) {
                return MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH;
            }
            status = psa_get_key_attributes(pk->priv_id, &key_attributes);
            if (status != PSA_SUCCESS) {
                ret = PSA_TO_MBEDTLS_ERR(status);
                goto exit;
            }
            ssl->handshake->xxdh_psa_type = psa_get_key_type(&key_attributes);
            ssl->handshake->xxdh_psa_bits = psa_get_key_bits(&key_attributes);
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
            if (pk_type != MBEDTLS_PK_OPAQUE) {
                key_attributes = psa_key_attributes_init();
                psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
                psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
                psa_set_key_type(&key_attributes,
                                 PSA_KEY_TYPE_ECC_KEY_PAIR(ssl->handshake->xxdh_psa_type));
                psa_set_key_bits(&key_attributes, ssl->handshake->xxdh_psa_bits);
                status = psa_export_key(pk->priv_id, buf, sizeof(buf), &key_len);
                if (status != PSA_SUCCESS) {
                    ret = PSA_TO_MBEDTLS_ERR(status);
                    goto exit;
                }
                status = psa_import_key(&key_attributes, buf, key_len,
                                        &ssl->handshake->xxdh_psa_privkey);
                if (status != PSA_SUCCESS) {
                    ret = PSA_TO_MBEDTLS_ERR(status);
                    goto exit;
                }
                ssl->handshake->xxdh_psa_privkey_is_external = 0;
                ret = 0;
                break;
            }
#endif
            ssl->handshake->xxdh_psa_privkey = pk->priv_id;
            ssl->handshake->xxdh_psa_privkey_is_external = 1;
            ret = 0;
            break;
#if !defined(MBEDTLS_PK_USE_PSA_EC_DATA)
        case MBEDTLS_PK_ECKEY:
        case MBEDTLS_PK_ECKEY_DH:
        case MBEDTLS_PK_ECDSA:
            key = mbedtls_pk_ec_rw(*pk);
            grp_id = mbedtls_pk_get_ec_group_id(pk);
            if (grp_id == MBEDTLS_ECP_DP_NONE) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            tls_id = mbedtls_ssl_get_tls_id_from_ecp_group_id(grp_id);
            if (tls_id == 0) {
                return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
            }
            mbedtls_ssl_get_psa_curve_info_from_tls_id(tls_id, &key_type,
                                                       &ssl->handshake->xxdh_psa_bits);
            ssl->handshake->xxdh_psa_type = key_type;
            key_attributes = psa_key_attributes_init();
            psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
            psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
            psa_set_key_type(&key_attributes,
                             PSA_KEY_TYPE_ECC_KEY_PAIR(ssl->handshake->xxdh_psa_type));
            psa_set_key_bits(&key_attributes, ssl->handshake->xxdh_psa_bits);
            ret = mbedtls_ecp_write_key_ext(key, &key_len, buf, sizeof(buf));
            if (ret != 0) {
                mbedtls_platform_zeroize(buf, sizeof(buf));
                break;
            }
            status = psa_import_key(&key_attributes, buf, key_len,
                                    &ssl->handshake->xxdh_psa_privkey);
            if (status != PSA_SUCCESS) {
                ret = PSA_TO_MBEDTLS_ERR(status);
                mbedtls_platform_zeroize(buf, sizeof(buf));
                break;
            }
            mbedtls_platform_zeroize(buf, sizeof(buf));
            ret = 0;
            break;
#endif
        default:
            ret = MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH;
    }
exit:
    psa_reset_key_attributes(&key_attributes);
    mbedtls_platform_zeroize(buf, sizeof(buf));
    return ret;
}
#else
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_get_ecdh_params_from_cert(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_pk_context *private_key = mbedtls_ssl_own_key(ssl);
    if (private_key == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("got no server private key"));
        return MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED;
    }
    if (!mbedtls_pk_can_do(private_key, MBEDTLS_PK_ECKEY)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("server key not ECDH capable"));
        return MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH;
    }
    if ((ret = mbedtls_ecdh_get_params(&ssl->handshake->ecdh_ctx,
                                       mbedtls_pk_ec_ro(*mbedtls_ssl_own_key(ssl)),
                                       MBEDTLS_ECDH_OURS)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, ("mbedtls_ecdh_get_params"), ret);
        return ret;
    }
    return 0;
}
#endif
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED) && \
    defined(MBEDTLS_SSL_ASYNC_PRIVATE)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_resume_server_key_exchange(mbedtls_ssl_context *ssl,
                                          size_t *signature_len)
{
    unsigned char *sig_start = ssl->out_msg + ssl->out_msglen + 2;
    size_t sig_max_len = (ssl->out_buf + MBEDTLS_SSL_OUT_CONTENT_LEN
                          - sig_start);
    int ret = ssl->conf->f_async_resume(ssl,
                                        sig_start, signature_len, sig_max_len);
    if (ret != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
        ssl->handshake->async_in_progress = 0;
        mbedtls_ssl_set_async_operation_data(ssl, NULL);
    }
    MBEDTLS_SSL_DEBUG_RET(2, "ssl_resume_server_key_exchange", ret);
    return ret;
}
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_prepare_server_key_exchange(mbedtls_ssl_context *ssl,
                                           size_t *signature_len)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PFS_ENABLED)
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
    unsigned char *dig_signed = NULL;
#endif
#endif
    (void) ciphersuite_info;
#if !defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
    (void) signature_len;
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t out_buf_len = ssl->out_buf_len - (size_t) (ssl->out_msg - ssl->out_buf);
#else
    size_t out_buf_len = MBEDTLS_SSL_OUT_BUFFER_LEN - (size_t) (ssl->out_msg - ssl->out_buf);
#endif
#endif
    ssl->out_msglen = 4;
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        unsigned char *out_p = ssl->out_msg + ssl->out_msglen;
        unsigned char *end_p = ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN -
                               ssl->out_msglen;
        size_t output_offset = 0;
        size_t output_len = 0;
        uint16_t tls_id = mbedtls_ssl_get_tls_id_from_ecp_group_id(
            MBEDTLS_ECP_DP_SECP256R1);
        if (tls_id == 0) {
            return MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
        }
        *out_p = MBEDTLS_ECP_TLS_NAMED_CURVE;
        MBEDTLS_PUT_UINT16_BE(tls_id, out_p, 1);
        output_offset += 3;
        ret = mbedtls_psa_ecjpake_write_round(&ssl->handshake->psa_pake_ctx,
                                              out_p + output_offset,
                                              end_p - out_p - output_offset, &output_len,
                                              MBEDTLS_ECJPAKE_ROUND_TWO);
        if (ret != 0) {
            psa_destroy_key(ssl->handshake->psa_pake_password);
            psa_pake_abort(&ssl->handshake->psa_pake_ctx);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_pake_output", ret);
            return ret;
        }
        output_offset += output_len;
        ssl->out_msglen += output_offset;
#else
        size_t len = 0;
        ret = mbedtls_ecjpake_write_round_two(
            &ssl->handshake->ecjpake_ctx,
            ssl->out_msg + ssl->out_msglen,
            MBEDTLS_SSL_OUT_CONTENT_LEN - ssl->out_msglen, &len,
            ssl->conf->f_rng, ssl->conf->p_rng);
        if (ret != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecjpake_write_round_two", ret);
            return ret;
        }
        ssl->out_msglen += len;
#endif
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_DHE_PSK ||
        ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK) {
        ssl->out_msg[ssl->out_msglen++] = 0x00;
        ssl->out_msg[ssl->out_msglen++] = 0x00;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_DHE_ENABLED)
    if (mbedtls_ssl_ciphersuite_uses_dhe(ciphersuite_info)) {
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t len = 0;
        if (ssl->conf->dhm_P.p == NULL || ssl->conf->dhm_G.p == NULL) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("no DH parameters set"));
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
        }
        if ((ret = mbedtls_dhm_set_group(&ssl->handshake->dhm_ctx,
                                         &ssl->conf->dhm_P,
                                         &ssl->conf->dhm_G)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_dhm_set_group", ret);
            return ret;
        }
        if ((ret = mbedtls_dhm_make_params(
                 &ssl->handshake->dhm_ctx,
                 (int) mbedtls_dhm_get_len(&ssl->handshake->dhm_ctx),
                 ssl->out_msg + ssl->out_msglen, &len,
                 ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_dhm_make_params", ret);
            return ret;
        }
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
        dig_signed = ssl->out_msg + ssl->out_msglen;
#endif
        ssl->out_msglen += len;
        MBEDTLS_SSL_DEBUG_MPI(3, "DHM: X ", &ssl->handshake->dhm_ctx.X);
        MBEDTLS_SSL_DEBUG_MPI(3, "DHM: P ", &ssl->handshake->dhm_ctx.P);
        MBEDTLS_SSL_DEBUG_MPI(3, "DHM: G ", &ssl->handshake->dhm_ctx.G);
        MBEDTLS_SSL_DEBUG_MPI(3, "DHM: GX", &ssl->handshake->dhm_ctx.GX);
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDHE_ENABLED)
    if (mbedtls_ssl_ciphersuite_uses_ecdhe(ciphersuite_info)) {
        uint16_t *curr_tls_id = ssl->handshake->curves_tls_id;
        const uint16_t *group_list = mbedtls_ssl_get_groups(ssl);
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        size_t len = 0;
        if ((group_list == NULL) || (curr_tls_id == NULL)) {
            return MBEDTLS_ERR_SSL_BAD_CONFIG;
        }
        for (; *group_list != 0; group_list++) {
            for (curr_tls_id = ssl->handshake->curves_tls_id;
                 *curr_tls_id != 0; curr_tls_id++) {
                if (*curr_tls_id == *group_list) {
                    goto curve_matching_done;
                }
            }
        }
curve_matching_done:
        if (*curr_tls_id == 0) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("no matching curve for ECDHE"));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
        MBEDTLS_SSL_DEBUG_MSG(2, ("ECDHE curve: %s",
                                  mbedtls_ssl_get_curve_name_from_tls_id(*curr_tls_id)));
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        psa_status_t status = PSA_ERROR_GENERIC_ERROR;
        psa_key_attributes_t key_attributes;
        mbedtls_ssl_handshake_params *handshake = ssl->handshake;
        uint8_t *p = ssl->out_msg + ssl->out_msglen;
        const size_t header_size = 4;
        const size_t data_length_size = 1;
        psa_key_type_t key_type = PSA_KEY_TYPE_NONE;
        size_t ec_bits = 0;
        MBEDTLS_SSL_DEBUG_MSG(1, ("Perform PSA-based ECDH computation."));
        if (mbedtls_ssl_get_psa_curve_info_from_tls_id(*curr_tls_id,
                                                       &key_type,
                                                       &ec_bits) == PSA_ERROR_NOT_SUPPORTED) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid ecc group parse."));
            return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
        }
        handshake->xxdh_psa_type = key_type;
        handshake->xxdh_psa_bits = ec_bits;
        key_attributes = psa_key_attributes_init();
        psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
        psa_set_key_type(&key_attributes, handshake->xxdh_psa_type);
        psa_set_key_bits(&key_attributes, handshake->xxdh_psa_bits);
        *p++ = MBEDTLS_ECP_TLS_NAMED_CURVE;
        MBEDTLS_PUT_UINT16_BE(*curr_tls_id, p, 0);
        p += 2;
        status = psa_generate_key(&key_attributes,
                                  &handshake->xxdh_psa_privkey);
        if (status != PSA_SUCCESS) {
            ret = PSA_TO_MBEDTLS_ERR(status);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_generate_key", ret);
            return ret;
        }
        unsigned char *own_pubkey = p + data_length_size;
        size_t own_pubkey_max_len = (size_t) (MBEDTLS_SSL_OUT_CONTENT_LEN
                                              - (own_pubkey - ssl->out_msg));
        status = psa_export_public_key(handshake->xxdh_psa_privkey,
                                       own_pubkey, own_pubkey_max_len,
                                       &len);
        if (status != PSA_SUCCESS) {
            ret = PSA_TO_MBEDTLS_ERR(status);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_export_public_key", ret);
            (void) psa_destroy_key(handshake->xxdh_psa_privkey);
            handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
            return ret;
        }
        *p = (uint8_t) len;
        len += header_size;
#else
        mbedtls_ecp_group_id curr_grp_id =
            mbedtls_ssl_get_ecp_group_id_from_tls_id(*curr_tls_id);
        if ((ret = mbedtls_ecdh_setup(&ssl->handshake->ecdh_ctx,
                                      curr_grp_id)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecp_group_load", ret);
            return ret;
        }
        if ((ret = mbedtls_ecdh_make_params(
                 &ssl->handshake->ecdh_ctx, &len,
                 ssl->out_msg + ssl->out_msglen,
                 MBEDTLS_SSL_OUT_CONTENT_LEN - ssl->out_msglen,
                 ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_make_params", ret);
            return ret;
        }
        MBEDTLS_SSL_DEBUG_ECDH(3, &ssl->handshake->ecdh_ctx,
                               MBEDTLS_DEBUG_ECDH_Q);
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
        dig_signed = ssl->out_msg + ssl->out_msglen;
#endif
        ssl->out_msglen += len;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
    if (mbedtls_ssl_ciphersuite_uses_server_signature(ciphersuite_info)) {
        if (dig_signed == NULL) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        size_t dig_signed_len = (size_t) (ssl->out_msg + ssl->out_msglen - dig_signed);
        size_t hashlen = 0;
        unsigned char hash[MBEDTLS_MD_MAX_SIZE];
        int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
        mbedtls_pk_type_t sig_alg =
            mbedtls_ssl_get_ciphersuite_sig_pk_alg(ciphersuite_info);
        unsigned char sig_hash =
            (unsigned char) mbedtls_ssl_tls12_get_preferred_hash_for_sig_alg(
                ssl, mbedtls_ssl_sig_from_pk_alg(sig_alg));
        mbedtls_md_type_t md_alg = mbedtls_ssl_md_alg_from_hash(sig_hash);
        if (sig_alg == MBEDTLS_PK_NONE || md_alg == MBEDTLS_MD_NONE) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        MBEDTLS_SSL_DEBUG_MSG(3, ("pick hash algorithm %u for signing", (unsigned) md_alg));
        if (md_alg != MBEDTLS_MD_NONE) {
            ret = mbedtls_ssl_get_key_exchange_md_tls1_2(ssl, hash, &hashlen,
                                                         dig_signed,
                                                         dig_signed_len,
                                                         md_alg);
            if (ret != 0) {
                return ret;
            }
        } else {
            MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        MBEDTLS_SSL_DEBUG_BUF(3, "parameters hash", hash, hashlen);
        ssl->out_msg[ssl->out_msglen++] = mbedtls_ssl_hash_from_md_alg(md_alg);
        ssl->out_msg[ssl->out_msglen++] = mbedtls_ssl_sig_from_pk_alg(sig_alg);
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
        if (ssl->conf->f_async_sign_start != NULL) {
            ret = ssl->conf->f_async_sign_start(ssl,
                                                mbedtls_ssl_own_cert(ssl),
                                                md_alg, hash, hashlen);
            switch (ret) {
                case MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH:
                    break;
                case 0:
                    ssl->handshake->async_in_progress = 1;
                    return ssl_resume_server_key_exchange(ssl, signature_len);
                case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
                    ssl->handshake->async_in_progress = 1;
                    return MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS;
                default:
                    MBEDTLS_SSL_DEBUG_RET(1, "f_async_sign_start", ret);
                    return ret;
            }
        }
#endif
        if (mbedtls_ssl_own_key(ssl) == NULL) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("got no private key"));
            return MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED;
        }
        if ((ret = mbedtls_pk_sign(mbedtls_ssl_own_key(ssl),
                                   md_alg, hash, hashlen,
                                   ssl->out_msg + ssl->out_msglen + 2,
                                   out_buf_len - ssl->out_msglen - 2,
                                   signature_len,
                                   ssl->conf->f_rng,
                                   ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_pk_sign", ret);
            return ret;
        }
    }
#endif
    return 0;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_server_key_exchange(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t signature_len = 0;
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED)
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
#endif
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write server key exchange"));
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_NON_PFS_ENABLED)
    if (mbedtls_ssl_ciphersuite_no_pfs(ciphersuite_info)) {
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_ENABLED)
        if (mbedtls_ssl_ciphersuite_uses_ecdh(ciphersuite_info)) {
            ret = ssl_get_ecdh_params_from_cert(ssl);
            if (ret != 0) {
                MBEDTLS_SSL_DEBUG_RET(1, "ssl_get_ecdh_params_from_cert", ret);
                return ret;
            }
        }
#endif
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip write server key exchange"));
        ssl->state++;
        return 0;
    }
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED) && \
    defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    if (ssl->handshake->async_in_progress != 0) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("resuming signature operation"));
        ret = ssl_resume_server_key_exchange(ssl, &signature_len);
    } else
#endif
    {
        ret = ssl_prepare_server_key_exchange(ssl, &signature_len);
    }
    if (ret != 0) {
        if (ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
            MBEDTLS_SSL_DEBUG_MSG(2, ("<= write server key exchange (pending)"));
        } else {
            ssl->out_msglen = 0;
        }
        return ret;
    }
#if defined(MBEDTLS_KEY_EXCHANGE_WITH_SERVER_SIGNATURE_ENABLED)
    if (signature_len != 0) {
        ssl->out_msg[ssl->out_msglen++] = MBEDTLS_BYTE_1(signature_len);
        ssl->out_msg[ssl->out_msglen++] = MBEDTLS_BYTE_0(signature_len);
        MBEDTLS_SSL_DEBUG_BUF(3, "my signature",
                              ssl->out_msg + ssl->out_msglen,
                              signature_len);
        ssl->out_msglen += signature_len;
    }
#endif
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE;
    ssl->state++;
    if ((ret = mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write server key exchange"));
    return 0;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_server_hello_done(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write server hello done"));
    ssl->out_msglen = 4;
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_SERVER_HELLO_DONE;
    ssl->state++;
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
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write server hello done"));
    return 0;
}
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_client_dh_public(mbedtls_ssl_context *ssl, unsigned char **p,
                                      const unsigned char *end)
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t n;
    if (*p + 2 > end) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    n = MBEDTLS_GET_UINT16_BE(*p, 0);
    *p += 2;
    if (*p + n > end) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if ((ret = mbedtls_dhm_read_public(&ssl->handshake->dhm_ctx, *p, n)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_dhm_read_public", ret);
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    *p += n;
    MBEDTLS_SSL_DEBUG_MPI(3, "DHM: GY", &ssl->handshake->dhm_ctx.GY);
    return ret;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_resume_decrypt_pms(mbedtls_ssl_context *ssl,
                                  unsigned char *peer_pms,
                                  size_t *peer_pmslen,
                                  size_t peer_pmssize)
{
    int ret = ssl->conf->f_async_resume(ssl,
                                        peer_pms, peer_pmslen, peer_pmssize);
    if (ret != MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
        ssl->handshake->async_in_progress = 0;
        mbedtls_ssl_set_async_operation_data(ssl, NULL);
    }
    MBEDTLS_SSL_DEBUG_RET(2, "ssl_decrypt_encrypted_pms", ret);
    return ret;
}
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_decrypt_encrypted_pms(mbedtls_ssl_context *ssl,
                                     const unsigned char *p,
                                     const unsigned char *end,
                                     unsigned char *peer_pms,
                                     size_t *peer_pmslen,
                                     size_t peer_pmssize)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_x509_crt *own_cert = mbedtls_ssl_own_cert(ssl);
    if (own_cert == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("got no local certificate"));
        return MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE;
    }
    mbedtls_pk_context *public_key = &own_cert->pk;
    mbedtls_pk_context *private_key = mbedtls_ssl_own_key(ssl);
    size_t len = mbedtls_pk_get_len(public_key);
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    if (ssl->handshake->async_in_progress != 0) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("resuming decryption operation"));
        return ssl_resume_decrypt_pms(ssl,
                                      peer_pms, peer_pmslen, peer_pmssize);
    }
#endif
    if (p + 2 > end) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (*p++ != MBEDTLS_BYTE_1(len) ||
        *p++ != MBEDTLS_BYTE_0(len)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (p + len != end) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    if (ssl->conf->f_async_decrypt_start != NULL) {
        ret = ssl->conf->f_async_decrypt_start(ssl,
                                               mbedtls_ssl_own_cert(ssl),
                                               p, len);
        switch (ret) {
            case MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH:
                break;
            case 0:
                ssl->handshake->async_in_progress = 1;
                return ssl_resume_decrypt_pms(ssl,
                                              peer_pms,
                                              peer_pmslen,
                                              peer_pmssize);
            case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
                ssl->handshake->async_in_progress = 1;
                return MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS;
            default:
                MBEDTLS_SSL_DEBUG_RET(1, "f_async_decrypt_start", ret);
                return ret;
        }
    }
#endif
    if (!mbedtls_pk_can_do(private_key, MBEDTLS_PK_RSA)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("got no RSA private key"));
        return MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED;
    }
    ret = mbedtls_pk_decrypt(private_key, p, len,
                             peer_pms, peer_pmslen, peer_pmssize,
                             ssl->conf->f_rng, ssl->conf->p_rng);
    return ret;
}
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_encrypted_pms(mbedtls_ssl_context *ssl,
                                   const unsigned char *p,
                                   const unsigned char *end,
                                   size_t pms_offset)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char *pms = ssl->handshake->premaster + pms_offset;
    unsigned char ver[2];
    unsigned char fake_pms[48], peer_pms[48];
    size_t peer_pmslen;
    mbedtls_ct_condition_t diff;
    peer_pms[0] = peer_pms[1] = ~0;
    peer_pmslen = 0;
    ret = ssl_decrypt_encrypted_pms(ssl, p, end,
                                    peer_pms,
                                    &peer_pmslen,
                                    sizeof(peer_pms));
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
    if (ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS) {
        return ret;
    }
#endif
    mbedtls_ssl_write_version(ver, ssl->conf->transport,
                              ssl->session_negotiate->tls_version);
    diff = mbedtls_ct_bool(ret);
    diff = mbedtls_ct_bool_or(diff, mbedtls_ct_uint_ne(peer_pmslen, 48));
    diff = mbedtls_ct_bool_or(diff, mbedtls_ct_uint_ne(peer_pms[0], ver[0]));
    diff = mbedtls_ct_bool_or(diff, mbedtls_ct_uint_ne(peer_pms[1], ver[1]));
    ret = ssl->conf->f_rng(ssl->conf->p_rng, fake_pms, sizeof(fake_pms));
    if (ret != 0) {
        return ret;
    }
#if defined(MBEDTLS_SSL_DEBUG_ALL)
    if (diff != MBEDTLS_CT_FALSE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
    }
#endif
    if (sizeof(ssl->handshake->premaster) < pms_offset ||
        sizeof(ssl->handshake->premaster) - pms_offset < 48) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    ssl->handshake->pmslen = 48;
    mbedtls_ct_memcpy_if(diff, pms, fake_pms, peer_pms, ssl->handshake->pmslen);
    return 0;
}
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_client_psk_identity(mbedtls_ssl_context *ssl, unsigned char **p,
                                         const unsigned char *end)
{
    int ret = 0;
    uint16_t n;
    if (ssl_conf_has_psk_or_cb(ssl->conf) == 0) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("got no pre-shared key"));
        return MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED;
    }
    if (end - *p < 2) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    n = MBEDTLS_GET_UINT16_BE(*p, 0);
    *p += 2;
    if (n == 0 || n > end - *p) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    if (ssl->conf->f_psk != NULL) {
        if (ssl->conf->f_psk(ssl->conf->p_psk, ssl, *p, n) != 0) {
            ret = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
        }
    } else {
        if (n != ssl->conf->psk_identity_len ||
            mbedtls_ct_memcmp(ssl->conf->psk_identity, *p, n) != 0) {
            ret = MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
        }
    }
    if (ret == MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY) {
        MBEDTLS_SSL_DEBUG_BUF(3, "Unknown PSK identity", *p, n);
        mbedtls_ssl_send_alert_message(ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
                                       MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY);
        return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
    }
    *p += n;
    return 0;
}
#endif
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_client_key_exchange(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    unsigned char *p, *end;
    ciphersuite_info = ssl->handshake->ciphersuite_info;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse client key exchange"));
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE) && \
    (defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED))
    if ((ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_RSA_PSK ||
         ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_RSA) &&
        (ssl->handshake->async_in_progress != 0)) {
        MBEDTLS_SSL_DEBUG_MSG(3, ("will resume decryption of previously-read record"));
    } else
#endif
    if ((ret = mbedtls_ssl_read_record(ssl, 1)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_read_record", ret);
        return ret;
    }
    p = ssl->in_msg + mbedtls_ssl_hs_hdr_len(ssl);
    end = ssl->in_msg + ssl->in_hslen;
    if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }
    if (ssl->in_msg[0] != MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange message"));
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_DHE_RSA) {
        if ((ret = ssl_parse_client_dh_public(ssl, &p, end)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_dh_public"), ret);
            return ret;
        }
        if (p != end) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        if ((ret = mbedtls_dhm_calc_secret(&ssl->handshake->dhm_ctx,
                                           ssl->handshake->premaster,
                                           MBEDTLS_PREMASTER_SIZE,
                                           &ssl->handshake->pmslen,
                                           ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_dhm_calc_secret", ret);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        MBEDTLS_SSL_DEBUG_MPI(3, "DHM: K ", &ssl->handshake->dhm_ctx.K);
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED) || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_RSA ||
        ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA ||
        ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDH_RSA ||
        ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        size_t data_len = (size_t) (*p++);
        size_t buf_len = (size_t) (end - p);
        psa_status_t status = PSA_ERROR_GENERIC_ERROR;
        mbedtls_ssl_handshake_params *handshake = ssl->handshake;
        MBEDTLS_SSL_DEBUG_MSG(3, ("Read the peer's public key."));
        if (buf_len < 2) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid buffer length: %" MBEDTLS_PRINTF_SIZET,
                                      buf_len));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
        if (data_len < 1 || data_len > buf_len) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid data length: %" MBEDTLS_PRINTF_SIZET
                                      " > %" MBEDTLS_PRINTF_SIZET,
                                      data_len, buf_len));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
        if (data_len > sizeof(handshake->xxdh_psa_peerkey)) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("Invalid public key length: %" MBEDTLS_PRINTF_SIZET
                                      " > %" MBEDTLS_PRINTF_SIZET,
                                      data_len,
                                      sizeof(handshake->xxdh_psa_peerkey)));
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
        memcpy(handshake->xxdh_psa_peerkey, p, data_len);
        handshake->xxdh_psa_peerkey_len = data_len;
        status = psa_raw_key_agreement(
            PSA_ALG_ECDH, handshake->xxdh_psa_privkey,
            handshake->xxdh_psa_peerkey, handshake->xxdh_psa_peerkey_len,
            handshake->premaster, sizeof(handshake->premaster),
            &handshake->pmslen);
        if (status != PSA_SUCCESS) {
            ret = PSA_TO_MBEDTLS_ERR(status);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_raw_key_agreement", ret);
            if (handshake->xxdh_psa_privkey_is_external == 0) {
                (void) psa_destroy_key(handshake->xxdh_psa_privkey);
            }
            handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
            return ret;
        }
        if (handshake->xxdh_psa_privkey_is_external == 0) {
            status = psa_destroy_key(handshake->xxdh_psa_privkey);
            if (status != PSA_SUCCESS) {
                ret = PSA_TO_MBEDTLS_ERR(status);
                MBEDTLS_SSL_DEBUG_RET(1, "psa_destroy_key", ret);
                return ret;
            }
        }
        handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
#else
        if ((ret = mbedtls_ecdh_read_public(&ssl->handshake->ecdh_ctx,
                                            p, (size_t) (end - p))) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_read_public", ret);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        MBEDTLS_SSL_DEBUG_ECDH(3, &ssl->handshake->ecdh_ctx,
                               MBEDTLS_DEBUG_ECDH_QP);
        if ((ret = mbedtls_ecdh_calc_secret(&ssl->handshake->ecdh_ctx,
                                            &ssl->handshake->pmslen,
                                            ssl->handshake->premaster,
                                            MBEDTLS_MPI_MAX_SIZE,
                                            ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_calc_secret", ret);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        MBEDTLS_SSL_DEBUG_ECDH(3, &ssl->handshake->ecdh_ctx,
                               MBEDTLS_DEBUG_ECDH_Z);
#endif
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_PSK) {
        if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
            return ret;
        }
        if (p != end) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
        if ((ret = mbedtls_ssl_psk_derive_premaster(ssl,
                                                    (mbedtls_key_exchange_type_t) ciphersuite_info->
                                                    key_exchange)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_psk_derive_premaster", ret);
            return ret;
        }
#endif
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_RSA_PSK) {
#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
        if (ssl->handshake->async_in_progress != 0) {
            MBEDTLS_SSL_DEBUG_MSG(3, ("PSK identity already parsed"));
            p += ssl->conf->psk_identity_len + 2;
        } else
#endif
        if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
            return ret;
        }
        if ((ret = ssl_parse_encrypted_pms(ssl, p, end, 2)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_encrypted_pms"), ret);
            return ret;
        }
#if !defined(MBEDTLS_USE_PSA_CRYPTO)
        if ((ret = mbedtls_ssl_psk_derive_premaster(ssl,
                                                    (mbedtls_key_exchange_type_t) ciphersuite_info->
                                                    key_exchange)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_psk_derive_premaster", ret);
            return ret;
        }
#endif
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_DHE_PSK) {
        if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
            return ret;
        }
        if ((ret = ssl_parse_client_dh_public(ssl, &p, end)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_dh_public"), ret);
            return ret;
        }
        if (p != end) {
            MBEDTLS_SSL_DEBUG_MSG(1, ("bad client key exchange"));
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        unsigned char *pms = ssl->handshake->premaster;
        unsigned char *pms_end = pms + sizeof(ssl->handshake->premaster);
        size_t pms_len;
        if ((ret = mbedtls_dhm_calc_secret(&ssl->handshake->dhm_ctx,
                                           pms + 2, pms_end - (pms + 2), &pms_len,
                                           ssl->conf->f_rng, ssl->conf->p_rng)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_dhm_calc_secret", ret);
            return ret;
        }
        MBEDTLS_PUT_UINT16_BE(pms_len, pms, 0);
        pms += 2 + pms_len;
        MBEDTLS_SSL_DEBUG_MPI(3, "DHM: K ", &ssl->handshake->dhm_ctx.K);
#else
        if ((ret = mbedtls_ssl_psk_derive_premaster(ssl,
                                                    (mbedtls_key_exchange_type_t) ciphersuite_info->
                                                    key_exchange)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_psk_derive_premaster", ret);
            return ret;
        }
#endif
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECDHE_PSK) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
        psa_status_t destruction_status = PSA_ERROR_CORRUPTION_DETECTED;
        size_t ecpoint_len;
        mbedtls_ssl_handshake_params *handshake = ssl->handshake;
        if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
            psa_destroy_key(handshake->xxdh_psa_privkey);
            handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
            return ret;
        }
        if (p >= end) {
            psa_destroy_key(handshake->xxdh_psa_privkey);
            handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        ecpoint_len = *(p++);
        if ((size_t) (end - p) < ecpoint_len) {
            psa_destroy_key(handshake->xxdh_psa_privkey);
            handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
#if !defined(PSA_WANT_ALG_FFDH)
        if (ecpoint_len > sizeof(handshake->xxdh_psa_peerkey)) {
            psa_destroy_key(handshake->xxdh_psa_privkey);
            handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
            return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
        }
#else
        MBEDTLS_STATIC_ASSERT(sizeof(handshake->xxdh_psa_peerkey) >= UINT8_MAX,
                              "peer key buffer too small");
#endif
        memcpy(handshake->xxdh_psa_peerkey, p, ecpoint_len);
        handshake->xxdh_psa_peerkey_len = ecpoint_len;
        p += ecpoint_len;
        unsigned char *psm = ssl->handshake->premaster;
        const unsigned char * const psm_end =
            psm + sizeof(ssl->handshake->premaster);
        const size_t zlen_size = 2;
        size_t zlen = 0;
        status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                       handshake->xxdh_psa_privkey,
                                       handshake->xxdh_psa_peerkey,
                                       handshake->xxdh_psa_peerkey_len,
                                       psm + zlen_size,
                                       psm_end - (psm + zlen_size),
                                       &zlen);
        destruction_status = psa_destroy_key(handshake->xxdh_psa_privkey);
        handshake->xxdh_psa_privkey = MBEDTLS_SVC_KEY_ID_INIT;
        if (status != PSA_SUCCESS) {
            return PSA_TO_MBEDTLS_ERR(status);
        } else if (destruction_status != PSA_SUCCESS) {
            return PSA_TO_MBEDTLS_ERR(destruction_status);
        }
        MBEDTLS_PUT_UINT16_BE(zlen, psm, 0);
        psm += zlen_size + zlen;
#else
        if ((ret = ssl_parse_client_psk_identity(ssl, &p, end)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_client_psk_identity"), ret);
            return ret;
        }
        if ((ret = mbedtls_ecdh_read_public(&ssl->handshake->ecdh_ctx,
                                            p, (size_t) (end - p))) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecdh_read_public", ret);
            return MBEDTLS_ERR_SSL_DECODE_ERROR;
        }
        MBEDTLS_SSL_DEBUG_ECDH(3, &ssl->handshake->ecdh_ctx,
                               MBEDTLS_DEBUG_ECDH_QP);
        if ((ret = mbedtls_ssl_psk_derive_premaster(ssl,
                                                    (mbedtls_key_exchange_type_t) ciphersuite_info->
                                                    key_exchange)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_psk_derive_premaster", ret);
            return ret;
        }
#endif
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_RSA) {
        if ((ret = ssl_parse_encrypted_pms(ssl, p, end, 0)) != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, ("ssl_parse_parse_encrypted_pms_secret"), ret);
            return ret;
        }
    } else
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    if (ciphersuite_info->key_exchange == MBEDTLS_KEY_EXCHANGE_ECJPAKE) {
#if defined(MBEDTLS_USE_PSA_CRYPTO)
        if ((ret = mbedtls_psa_ecjpake_read_round(
                 &ssl->handshake->psa_pake_ctx, p, (size_t) (end - p),
                 MBEDTLS_ECJPAKE_ROUND_TWO)) != 0) {
            psa_destroy_key(ssl->handshake->psa_pake_password);
            psa_pake_abort(&ssl->handshake->psa_pake_ctx);
            MBEDTLS_SSL_DEBUG_RET(1, "psa_pake_input round two", ret);
            return ret;
        }
#else
        ret = mbedtls_ecjpake_read_round_two(&ssl->handshake->ecjpake_ctx,
                                             p, (size_t) (end - p));
        if (ret != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecjpake_read_round_two", ret);
            return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        }
        ret = mbedtls_ecjpake_derive_secret(&ssl->handshake->ecjpake_ctx,
                                            ssl->handshake->premaster, 32, &ssl->handshake->pmslen,
                                            ssl->conf->f_rng, ssl->conf->p_rng);
        if (ret != 0) {
            MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ecjpake_derive_secret", ret);
            return ret;
        }
#endif
    } else
#endif
    {
        MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    if ((ret = mbedtls_ssl_derive_keys(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_derive_keys", ret);
        return ret;
    }
    ssl->state++;
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse client key exchange"));
    return 0;
}
#if !defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_certificate_verify(mbedtls_ssl_context *ssl)
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));
    if (!mbedtls_ssl_ciphersuite_cert_req_allowed(ciphersuite_info)) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
        ssl->state++;
        return 0;
    }
    MBEDTLS_SSL_DEBUG_MSG(1, ("should never happen"));
    return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
#else
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_parse_certificate_verify(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    size_t i, sig_len;
    unsigned char hash[48];
    unsigned char *hash_start = hash;
    size_t hashlen;
    mbedtls_pk_type_t pk_alg;
    mbedtls_md_type_t md_alg;
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info =
        ssl->handshake->ciphersuite_info;
    mbedtls_pk_context *peer_pk;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> parse certificate verify"));
    if (!mbedtls_ssl_ciphersuite_cert_req_allowed(ciphersuite_info)) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
        ssl->state++;
        return 0;
    }
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    if (ssl->session_negotiate->peer_cert == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
        ssl->state++;
        return 0;
    }
#else
    if (ssl->session_negotiate->peer_cert_digest == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("<= skip parse certificate verify"));
        ssl->state++;
        return 0;
    }
#endif
    ret = mbedtls_ssl_read_record(ssl, 0 );
    if (0 != ret) {
        MBEDTLS_SSL_DEBUG_RET(1, ("mbedtls_ssl_read_record"), ret);
        return ret;
    }
    ssl->state++;
    if (ssl->in_msgtype != MBEDTLS_SSL_MSG_HANDSHAKE ||
        ssl->in_msg[0] != MBEDTLS_SSL_HS_CERTIFICATE_VERIFY) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
        return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
    }
    i = mbedtls_ssl_hs_hdr_len(ssl);
#if !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    peer_pk = &ssl->handshake->peer_pubkey;
#else
    if (ssl->session_negotiate->peer_cert == NULL) {
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    peer_pk = &ssl->session_negotiate->peer_cert->pk;
#endif
    if (i + 2 > ssl->in_hslen) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    md_alg = mbedtls_ssl_md_alg_from_hash(ssl->in_msg[i]);
    if (md_alg == MBEDTLS_MD_NONE || mbedtls_ssl_set_calc_verify_md(ssl, ssl->in_msg[i])) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
                                  " for verify message"));
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
#if !defined(MBEDTLS_MD_SHA1)
    if (MBEDTLS_MD_SHA1 == md_alg) {
        hash_start += 16;
    }
#endif
    hashlen = 0;
    i++;
    if ((pk_alg = mbedtls_ssl_pk_alg_from_sig(ssl->in_msg[i]))
        == MBEDTLS_PK_NONE) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("peer not adhering to requested sig_alg"
                                  " for verify message"));
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    if (!mbedtls_pk_can_do(peer_pk, pk_alg)) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("sig_alg doesn't match cert key"));
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }
    i++;
    if (i + 2 > ssl->in_hslen) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    sig_len = MBEDTLS_GET_UINT16_BE(ssl->in_msg, i);
    i += 2;
    if (i + sig_len != ssl->in_hslen) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("bad certificate verify message"));
        return MBEDTLS_ERR_SSL_DECODE_ERROR;
    }
    {
        size_t dummy_hlen;
        ret = ssl->handshake->calc_verify(ssl, hash, &dummy_hlen);
        if (0 != ret) {
            MBEDTLS_SSL_DEBUG_RET(1, ("calc_verify"), ret);
            return ret;
        }
    }
    if ((ret = mbedtls_pk_verify(peer_pk,
                                 md_alg, hash_start, hashlen,
                                 ssl->in_msg + i, sig_len)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_pk_verify", ret);
        return ret;
    }
    ret = mbedtls_ssl_update_handshake_status(ssl);
    if (0 != ret) {
        MBEDTLS_SSL_DEBUG_RET(1, ("mbedtls_ssl_update_handshake_status"), ret);
        return ret;
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= parse certificate verify"));
    return ret;
}
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
MBEDTLS_CHECK_RETURN_CRITICAL
static int ssl_write_new_session_ticket(mbedtls_ssl_context *ssl)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t tlen;
    uint32_t lifetime;
    MBEDTLS_SSL_DEBUG_MSG(2, ("=> write new session ticket"));
    ssl->out_msgtype = MBEDTLS_SSL_MSG_HANDSHAKE;
    ssl->out_msg[0] = MBEDTLS_SSL_HS_NEW_SESSION_TICKET;
#if defined(MBEDTLS_HAVE_TIME)
    ssl->session_negotiate->ticket_creation_time = mbedtls_ms_time();
#endif
    if ((ret = ssl->conf->f_ticket_write(ssl->conf->p_ticket,
                                         ssl->session_negotiate,
                                         ssl->out_msg + 10,
                                         ssl->out_msg + MBEDTLS_SSL_OUT_CONTENT_LEN,
                                         &tlen, &lifetime)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_ticket_write", ret);
        tlen = 0;
    }
    MBEDTLS_PUT_UINT32_BE(lifetime, ssl->out_msg, 4);
    MBEDTLS_PUT_UINT16_BE(tlen, ssl->out_msg, 8);
    ssl->out_msglen = 10 + tlen;
    ssl->handshake->new_session_ticket = 0;
    if ((ret = mbedtls_ssl_write_handshake_msg(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "mbedtls_ssl_write_handshake_msg", ret);
        return ret;
    }
    MBEDTLS_SSL_DEBUG_MSG(2, ("<= write new session ticket"));
    return 0;
}
#endif
int mbedtls_ssl_handshake_server_step(mbedtls_ssl_context *ssl)
{
    int ret = 0;
    MBEDTLS_SSL_DEBUG_MSG(2, ("server state: %d", ssl->state));
    switch (ssl->state) {
        case MBEDTLS_SSL_HELLO_REQUEST:
            ssl->state = MBEDTLS_SSL_CLIENT_HELLO;
            break;
        case MBEDTLS_SSL_CLIENT_HELLO:
            ret = ssl_parse_client_hello(ssl);
            break;
#if defined(MBEDTLS_SSL_PROTO_DTLS)
        case MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT:
            return MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED;
#endif
        case MBEDTLS_SSL_SERVER_HELLO:
            ret = ssl_write_server_hello(ssl);
            break;
        case MBEDTLS_SSL_SERVER_CERTIFICATE:
            ret = mbedtls_ssl_write_certificate(ssl);
            break;
        case MBEDTLS_SSL_SERVER_KEY_EXCHANGE:
            ret = ssl_write_server_key_exchange(ssl);
            break;
        case MBEDTLS_SSL_CERTIFICATE_REQUEST:
            ret = ssl_write_certificate_request(ssl);
            break;
        case MBEDTLS_SSL_SERVER_HELLO_DONE:
            ret = ssl_write_server_hello_done(ssl);
            break;
        case MBEDTLS_SSL_CLIENT_CERTIFICATE:
            ret = mbedtls_ssl_parse_certificate(ssl);
            break;
        case MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:
            ret = ssl_parse_client_key_exchange(ssl);
            break;
        case MBEDTLS_SSL_CERTIFICATE_VERIFY:
            ret = ssl_parse_certificate_verify(ssl);
            break;
        case MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
            ret = mbedtls_ssl_parse_change_cipher_spec(ssl);
            break;
        case MBEDTLS_SSL_CLIENT_FINISHED:
            ret = mbedtls_ssl_parse_finished(ssl);
            break;
        case MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
            if (ssl->handshake->new_session_ticket != 0) {
                ret = ssl_write_new_session_ticket(ssl);
            } else
#endif
            ret = mbedtls_ssl_write_change_cipher_spec(ssl);
            break;
        case MBEDTLS_SSL_SERVER_FINISHED:
            ret = mbedtls_ssl_write_finished(ssl);
            break;
        case MBEDTLS_SSL_FLUSH_BUFFERS:
            MBEDTLS_SSL_DEBUG_MSG(2, ("handshake: done"));
            ssl->state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
            break;
        case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
            mbedtls_ssl_handshake_wrapup(ssl);
            break;
        default:
            MBEDTLS_SSL_DEBUG_MSG(1, ("invalid state %d", ssl->state));
            return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    return ret;
}
void mbedtls_ssl_conf_preference_order(mbedtls_ssl_config *conf, int order)
{
    conf->respect_cli_pref = order;
}
#endif
