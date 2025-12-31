/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#if !defined(MBEDTLS_SSL_TLS1_3_KEYS_H)
#define MBEDTLS_SSL_TLS1_3_KEYS_H

#define MBEDTLS_SSL_TLS1_3_LABEL_LIST                                             \
    MBEDTLS_SSL_TLS1_3_LABEL(finished, "finished") \
    MBEDTLS_SSL_TLS1_3_LABEL(resumption, "resumption") \
    MBEDTLS_SSL_TLS1_3_LABEL(traffic_upd, "traffic upd") \
    MBEDTLS_SSL_TLS1_3_LABEL(exporter, "exporter") \
    MBEDTLS_SSL_TLS1_3_LABEL(key, "key") \
    MBEDTLS_SSL_TLS1_3_LABEL(iv, "iv") \
    MBEDTLS_SSL_TLS1_3_LABEL(c_hs_traffic, "c hs traffic") \
    MBEDTLS_SSL_TLS1_3_LABEL(c_ap_traffic, "c ap traffic") \
    MBEDTLS_SSL_TLS1_3_LABEL(c_e_traffic, "c e traffic") \
    MBEDTLS_SSL_TLS1_3_LABEL(s_hs_traffic, "s hs traffic") \
    MBEDTLS_SSL_TLS1_3_LABEL(s_ap_traffic, "s ap traffic") \
    MBEDTLS_SSL_TLS1_3_LABEL(s_e_traffic, "s e traffic") \
    MBEDTLS_SSL_TLS1_3_LABEL(e_exp_master, "e exp master") \
    MBEDTLS_SSL_TLS1_3_LABEL(res_master, "res master") \
    MBEDTLS_SSL_TLS1_3_LABEL(exp_master, "exp master") \
    MBEDTLS_SSL_TLS1_3_LABEL(ext_binder, "ext binder") \
    MBEDTLS_SSL_TLS1_3_LABEL(res_binder, "res binder") \
    MBEDTLS_SSL_TLS1_3_LABEL(derived, "derived") \
    MBEDTLS_SSL_TLS1_3_LABEL(client_cv, "TLS 1.3, client CertificateVerify") \
    MBEDTLS_SSL_TLS1_3_LABEL(server_cv, "TLS 1.3, server CertificateVerify")

#define MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED 0
#define MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED   1

#define MBEDTLS_SSL_TLS1_3_PSK_EXTERNAL   0
#define MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION 1

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

#define MBEDTLS_SSL_TLS1_3_LABEL(name, string)       \
    const unsigned char name    [sizeof(string) - 1] MBEDTLS_ATTRIBUTE_UNTERMINATED_STRING;

union mbedtls_ssl_tls13_labels_union {
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
struct mbedtls_ssl_tls13_labels_struct {
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};
#undef MBEDTLS_SSL_TLS1_3_LABEL

extern const struct mbedtls_ssl_tls13_labels_struct mbedtls_ssl_tls13_labels;

#define MBEDTLS_SSL_TLS1_3_LBL_LEN(LABEL)  \
    sizeof(mbedtls_ssl_tls13_labels.LABEL)

#define MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN(LABEL)  \
    mbedtls_ssl_tls13_labels.LABEL,              \
    MBEDTLS_SSL_TLS1_3_LBL_LEN(LABEL)

#define MBEDTLS_SSL_TLS1_3_HKDF_LABEL_MAX_LABEL_LEN 249

#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN  \
    PSA_HASH_MAX_SIZE

#define MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN \
    (255 * MBEDTLS_TLS1_3_MD_MAX_SIZE)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_hkdf_expand_label(
    psa_algorithm_t hash_alg,
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label, size_t label_len,
    const unsigned char *ctx, size_t ctx_len,
    unsigned char *buf, size_t buf_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_make_traffic_keys(
    psa_algorithm_t hash_alg,
    const unsigned char *client_secret,
    const unsigned char *server_secret, size_t secret_len,
    size_t key_len, size_t iv_len,
    mbedtls_ssl_key_set *keys);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_derive_secret(
    psa_algorithm_t hash_alg,
    const unsigned char *secret, size_t secret_len,
    const unsigned char *label, size_t label_len,
    const unsigned char *ctx, size_t ctx_len,
    int ctx_hashed,
    unsigned char *dstbuf, size_t dstbuf_len);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_derive_early_secrets(
    psa_algorithm_t hash_alg,
    unsigned char const *early_secret,
    unsigned char const *transcript, size_t transcript_len,
    mbedtls_ssl_tls13_early_secrets *derived);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_derive_handshake_secrets(
    psa_algorithm_t hash_alg,
    unsigned char const *handshake_secret,
    unsigned char const *transcript, size_t transcript_len,
    mbedtls_ssl_tls13_handshake_secrets *derived);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_derive_application_secrets(
    psa_algorithm_t hash_alg,
    unsigned char const *master_secret,
    unsigned char const *transcript, size_t transcript_len,
    mbedtls_ssl_tls13_application_secrets *derived);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_derive_resumption_master_secret(
    psa_algorithm_t hash_alg,
    unsigned char const *application_secret,
    unsigned char const *transcript, size_t transcript_len,
    mbedtls_ssl_tls13_application_secrets *derived);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_evolve_secret(
    psa_algorithm_t hash_alg,
    const unsigned char *secret_old,
    const unsigned char *input, size_t input_len,
    unsigned char *secret_new);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_create_psk_binder(mbedtls_ssl_context *ssl,
                                        const psa_algorithm_t hash_alg,
                                        unsigned char const *psk, size_t psk_len,
                                        int psk_type,
                                        unsigned char const *transcript,
                                        unsigned char *result);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_populate_transform(mbedtls_ssl_transform *transform,
                                         int endpoint,
                                         int ciphersuite,
                                         mbedtls_ssl_key_set const *traffic_keys,
                                         mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_key_schedule_stage_early(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_compute_resumption_master_secret(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_calculate_verify_data(mbedtls_ssl_context *ssl,
                                            unsigned char *dst,
                                            size_t dst_len,
                                            size_t *actual_len,
                                            int which);

#if defined(MBEDTLS_SSL_EARLY_DATA)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_compute_early_transform(mbedtls_ssl_context *ssl);
#endif

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_compute_handshake_transform(mbedtls_ssl_context *ssl);

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_compute_application_transform(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_SOME_PSK_ENABLED)

MBEDTLS_CHECK_RETURN_CRITICAL
int mbedtls_ssl_tls13_export_handshake_psk(mbedtls_ssl_context *ssl,
                                           unsigned char **psk,
                                           size_t *psk_len);
#endif

int mbedtls_ssl_tls13_exporter(const psa_algorithm_t hash_alg,
                               const unsigned char *secret, const size_t secret_len,
                               const unsigned char *label, const size_t label_len,
                               const unsigned char *context_value, const size_t context_len,
                               uint8_t *out, const size_t out_len);

#endif

#endif
