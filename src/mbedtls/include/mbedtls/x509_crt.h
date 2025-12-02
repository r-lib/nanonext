/**
 * \file x509_crt.h
 *
 * \brief X.509 certificate parsing and writing
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_X509_CRT_H
#define MBEDTLS_X509_CRT_H 
#include "mbedtls/private_access.h"
#include "mbedtls/build_info.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/bignum.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct mbedtls_x509_crt {
    int MBEDTLS_PRIVATE(own_buffer);
    mbedtls_x509_buf raw;
    mbedtls_x509_buf tbs;
    int version;
    mbedtls_x509_buf serial;
    mbedtls_x509_buf sig_oid;
    mbedtls_x509_buf issuer_raw;
    mbedtls_x509_buf subject_raw;
    mbedtls_x509_name issuer;
    mbedtls_x509_name subject;
    mbedtls_x509_time valid_from;
    mbedtls_x509_time valid_to;
    mbedtls_x509_buf pk_raw;
    mbedtls_pk_context pk;
    mbedtls_x509_buf issuer_id;
    mbedtls_x509_buf subject_id;
    mbedtls_x509_buf v3_ext;
    mbedtls_x509_sequence subject_alt_names;
    mbedtls_x509_buf subject_key_id;
    mbedtls_x509_authority authority_key_id;
    mbedtls_x509_sequence certificate_policies;
    int MBEDTLS_PRIVATE(ext_types);
    int MBEDTLS_PRIVATE(ca_istrue);
    int MBEDTLS_PRIVATE(max_pathlen);
    unsigned int MBEDTLS_PRIVATE(key_usage);
    mbedtls_x509_sequence ext_key_usage;
    unsigned char MBEDTLS_PRIVATE(ns_cert_type);
    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);
    mbedtls_md_type_t MBEDTLS_PRIVATE(sig_md);
    mbedtls_pk_type_t MBEDTLS_PRIVATE(sig_pk);
    void *MBEDTLS_PRIVATE(sig_opts);
    struct mbedtls_x509_crt *next;
}
mbedtls_x509_crt;
#define MBEDTLS_X509_ID_FLAG(id) (1 << ((id) - 1))
typedef struct mbedtls_x509_crt_profile {
    uint32_t allowed_mds;
    uint32_t allowed_pks;
    uint32_t allowed_curves;
    uint32_t rsa_min_bitlen;
}
mbedtls_x509_crt_profile;
#define MBEDTLS_X509_CRT_VERSION_1 0
#define MBEDTLS_X509_CRT_VERSION_2 1
#define MBEDTLS_X509_CRT_VERSION_3 2
#define MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN 20
#define MBEDTLS_X509_RFC5280_UTC_TIME_LEN 15
#if !defined(MBEDTLS_X509_MAX_FILE_PATH_LEN)
#define MBEDTLS_X509_MAX_FILE_PATH_LEN 512
#endif
#define MBEDTLS_X509_CRT_ERROR_INFO_LIST \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_EXPIRED, \
                        "MBEDTLS_X509_BADCERT_EXPIRED", \
                        "The certificate validity has expired") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_REVOKED, \
                        "MBEDTLS_X509_BADCERT_REVOKED", \
                        "The certificate has been revoked (is on a CRL)") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_CN_MISMATCH, \
                        "MBEDTLS_X509_BADCERT_CN_MISMATCH", \
                        "The certificate Common Name (CN) does not match with the expected CN") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_NOT_TRUSTED, \
                        "MBEDTLS_X509_BADCERT_NOT_TRUSTED", \
                        "The certificate is not correctly signed by the trusted CA") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_NOT_TRUSTED, \
                        "MBEDTLS_X509_BADCRL_NOT_TRUSTED", \
                        "The CRL is not correctly signed by the trusted CA") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_EXPIRED, \
                        "MBEDTLS_X509_BADCRL_EXPIRED", \
                        "The CRL is expired") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_MISSING, \
                        "MBEDTLS_X509_BADCERT_MISSING", \
                        "Certificate was missing") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_SKIP_VERIFY, \
                        "MBEDTLS_X509_BADCERT_SKIP_VERIFY", \
                        "Certificate verification was skipped") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_OTHER, \
                        "MBEDTLS_X509_BADCERT_OTHER", \
                        "Other reason (can be used by verify callback)") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_FUTURE, \
                        "MBEDTLS_X509_BADCERT_FUTURE", \
                        "The certificate validity starts in the future") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_FUTURE, \
                        "MBEDTLS_X509_BADCRL_FUTURE", \
                        "The CRL is from the future") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_KEY_USAGE, \
                        "MBEDTLS_X509_BADCERT_KEY_USAGE", \
                        "Usage does not match the keyUsage extension") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_EXT_KEY_USAGE, \
                        "MBEDTLS_X509_BADCERT_EXT_KEY_USAGE", \
                        "Usage does not match the extendedKeyUsage extension") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_NS_CERT_TYPE, \
                        "MBEDTLS_X509_BADCERT_NS_CERT_TYPE", \
                        "Usage does not match the nsCertType extension") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_BAD_MD, \
                        "MBEDTLS_X509_BADCERT_BAD_MD", \
                        "The certificate is signed with an unacceptable hash.") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_BAD_PK, \
                        "MBEDTLS_X509_BADCERT_BAD_PK", \
                        "The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA).") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCERT_BAD_KEY, \
                        "MBEDTLS_X509_BADCERT_BAD_KEY", \
                        "The certificate is signed with an unacceptable key (eg bad curve, RSA too short).") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_BAD_MD, \
                        "MBEDTLS_X509_BADCRL_BAD_MD", \
                        "The CRL is signed with an unacceptable hash.") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_BAD_PK, \
                        "MBEDTLS_X509_BADCRL_BAD_PK", \
                        "The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA).") \
    X509_CRT_ERROR_INFO(MBEDTLS_X509_BADCRL_BAD_KEY, \
                        "MBEDTLS_X509_BADCRL_BAD_KEY", \
                        "The CRL is signed with an unacceptable key (eg bad curve, RSA too short).")
typedef struct mbedtls_x509write_cert {
    int MBEDTLS_PRIVATE(version);
    unsigned char MBEDTLS_PRIVATE(serial)[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
    size_t MBEDTLS_PRIVATE(serial_len);
    mbedtls_pk_context *MBEDTLS_PRIVATE(subject_key);
    mbedtls_pk_context *MBEDTLS_PRIVATE(issuer_key);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(subject);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(issuer);
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_alg);
    char MBEDTLS_PRIVATE(not_before)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    char MBEDTLS_PRIVATE(not_after)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(extensions);
}
mbedtls_x509write_cert;
int mbedtls_x509write_crt_set_subject_alternative_name(mbedtls_x509write_cert *ctx,
                                                       const mbedtls_x509_san_list *san_list);
typedef struct {
    mbedtls_x509_crt *MBEDTLS_PRIVATE(crt);
    uint32_t MBEDTLS_PRIVATE(flags);
} mbedtls_x509_crt_verify_chain_item;
#define MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE (MBEDTLS_X509_MAX_INTERMEDIATE_CA + 2)
typedef struct {
    mbedtls_x509_crt_verify_chain_item MBEDTLS_PRIVATE(items)[MBEDTLS_X509_MAX_VERIFY_CHAIN_SIZE];
    unsigned MBEDTLS_PRIVATE(len);
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    mbedtls_x509_crt *MBEDTLS_PRIVATE(trust_ca_cb_result);
#endif
} mbedtls_x509_crt_verify_chain;
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
typedef struct {
    mbedtls_pk_restart_ctx MBEDTLS_PRIVATE(pk);
    mbedtls_x509_crt *MBEDTLS_PRIVATE(parent);
    mbedtls_x509_crt *MBEDTLS_PRIVATE(fallback_parent);
    int MBEDTLS_PRIVATE(fallback_signature_is_good);
    int MBEDTLS_PRIVATE(parent_is_trusted);
    enum {
        x509_crt_rs_none,
        x509_crt_rs_find_parent,
    } MBEDTLS_PRIVATE(in_progress);
    int MBEDTLS_PRIVATE(self_cnt);
    mbedtls_x509_crt_verify_chain MBEDTLS_PRIVATE(ver_chain);
} mbedtls_x509_crt_restart_ctx;
#else
typedef void mbedtls_x509_crt_restart_ctx;
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
extern const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_default;
extern const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_next;
extern const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_suiteb;
extern const mbedtls_x509_crt_profile mbedtls_x509_crt_profile_none;
int mbedtls_x509_crt_parse_der(mbedtls_x509_crt *chain,
                               const unsigned char *buf,
                               size_t buflen);
typedef int (*mbedtls_x509_crt_ext_cb_t)(void *p_ctx,
                                         mbedtls_x509_crt const *crt,
                                         mbedtls_x509_buf const *oid,
                                         int critical,
                                         const unsigned char *p,
                                         const unsigned char *end);
int mbedtls_x509_crt_parse_der_with_ext_cb(mbedtls_x509_crt *chain,
                                           const unsigned char *buf,
                                           size_t buflen,
                                           int make_copy,
                                           mbedtls_x509_crt_ext_cb_t cb,
                                           void *p_ctx);
int mbedtls_x509_crt_parse_der_nocopy(mbedtls_x509_crt *chain,
                                      const unsigned char *buf,
                                      size_t buflen);
int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain, const unsigned char *buf, size_t buflen);
#if defined(MBEDTLS_FS_IO)
int mbedtls_x509_crt_parse_file(mbedtls_x509_crt *chain, const char *path);
int mbedtls_x509_crt_parse_path(mbedtls_x509_crt *chain, const char *path);
#endif
#if !defined(MBEDTLS_X509_REMOVE_INFO)
int mbedtls_x509_crt_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_crt *crt);
int mbedtls_x509_crt_verify_info(char *buf, size_t size, const char *prefix,
                                 uint32_t flags);
#endif
int mbedtls_x509_crt_verify(mbedtls_x509_crt *crt,
                            mbedtls_x509_crt *trust_ca,
                            mbedtls_x509_crl *ca_crl,
                            const char *cn, uint32_t *flags,
                            int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy);
int mbedtls_x509_crt_verify_with_profile(mbedtls_x509_crt *crt,
                                         mbedtls_x509_crt *trust_ca,
                                         mbedtls_x509_crl *ca_crl,
                                         const mbedtls_x509_crt_profile *profile,
                                         const char *cn, uint32_t *flags,
                                         int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                                         void *p_vrfy);
int mbedtls_x509_crt_verify_restartable(mbedtls_x509_crt *crt,
                                        mbedtls_x509_crt *trust_ca,
                                        mbedtls_x509_crl *ca_crl,
                                        const mbedtls_x509_crt_profile *profile,
                                        const char *cn, uint32_t *flags,
                                        int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                                        void *p_vrfy,
                                        mbedtls_x509_crt_restart_ctx *rs_ctx);
typedef int (*mbedtls_x509_crt_ca_cb_t)(void *p_ctx,
                                        mbedtls_x509_crt const *child,
                                        mbedtls_x509_crt **candidate_cas);
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
int mbedtls_x509_crt_verify_with_ca_cb(mbedtls_x509_crt *crt,
                                       mbedtls_x509_crt_ca_cb_t f_ca_cb,
                                       void *p_ca_cb,
                                       const mbedtls_x509_crt_profile *profile,
                                       const char *cn, uint32_t *flags,
                                       int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                                       void *p_vrfy);
#endif
int mbedtls_x509_crt_check_key_usage(const mbedtls_x509_crt *crt,
                                     unsigned int usage);
int mbedtls_x509_crt_check_extended_key_usage(const mbedtls_x509_crt *crt,
                                              const char *usage_oid,
                                              size_t usage_len);
#if defined(MBEDTLS_X509_CRL_PARSE_C)
int mbedtls_x509_crt_is_revoked(const mbedtls_x509_crt *crt, const mbedtls_x509_crl *crl);
#endif
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt);
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt);
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
void mbedtls_x509_crt_restart_init(mbedtls_x509_crt_restart_ctx *ctx);
void mbedtls_x509_crt_restart_free(mbedtls_x509_crt_restart_ctx *ctx);
#endif
#endif
static inline int mbedtls_x509_crt_has_ext_type(const mbedtls_x509_crt *ctx,
                                                int ext_type)
{
    return ctx->MBEDTLS_PRIVATE(ext_types) & ext_type;
}
int mbedtls_x509_crt_get_ca_istrue(const mbedtls_x509_crt *crt);
#if defined(MBEDTLS_X509_CRT_WRITE_C)
void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx);
void mbedtls_x509write_crt_set_version(mbedtls_x509write_cert *ctx, int version);
#if defined(MBEDTLS_BIGNUM_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
int MBEDTLS_DEPRECATED mbedtls_x509write_crt_set_serial(
    mbedtls_x509write_cert *ctx, const mbedtls_mpi *serial);
#endif
int mbedtls_x509write_crt_set_serial_raw(mbedtls_x509write_cert *ctx,
                                         unsigned char *serial, size_t serial_len);
int mbedtls_x509write_crt_set_validity(mbedtls_x509write_cert *ctx, const char *not_before,
                                       const char *not_after);
int mbedtls_x509write_crt_set_issuer_name(mbedtls_x509write_cert *ctx,
                                          const char *issuer_name);
int mbedtls_x509write_crt_set_subject_name(mbedtls_x509write_cert *ctx,
                                           const char *subject_name);
void mbedtls_x509write_crt_set_subject_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);
void mbedtls_x509write_crt_set_issuer_key(mbedtls_x509write_cert *ctx, mbedtls_pk_context *key);
void mbedtls_x509write_crt_set_md_alg(mbedtls_x509write_cert *ctx, mbedtls_md_type_t md_alg);
int mbedtls_x509write_crt_set_extension(mbedtls_x509write_cert *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len);
int mbedtls_x509write_crt_set_basic_constraints(mbedtls_x509write_cert *ctx,
                                                int is_ca, int max_pathlen);
#if defined(MBEDTLS_MD_CAN_SHA1)
int mbedtls_x509write_crt_set_subject_key_identifier(mbedtls_x509write_cert *ctx);
int mbedtls_x509write_crt_set_authority_key_identifier(mbedtls_x509write_cert *ctx);
#endif
int mbedtls_x509write_crt_set_key_usage(mbedtls_x509write_cert *ctx,
                                        unsigned int key_usage);
int mbedtls_x509write_crt_set_ext_key_usage(mbedtls_x509write_cert *ctx,
                                            const mbedtls_asn1_sequence *exts);
int mbedtls_x509write_crt_set_ns_cert_type(mbedtls_x509write_cert *ctx,
                                           unsigned char ns_cert_type);
void mbedtls_x509write_crt_free(mbedtls_x509write_cert *ctx);
int mbedtls_x509write_crt_der(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
#if defined(MBEDTLS_PEM_WRITE_C)
int mbedtls_x509write_crt_pem(mbedtls_x509write_cert *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
#endif
#endif
#ifdef __cplusplus
}
#endif
#endif
