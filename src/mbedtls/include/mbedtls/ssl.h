/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_SSL_H
#define MBEDTLS_SSL_H
#include "mbedtls/platform_util.h"
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

#include "mbedtls/ssl_ciphersuites.h"

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#endif

#if defined(MBEDTLS_DHM_C)
#include "mbedtls/dhm.h"
#endif

#include "mbedtls/md.h"

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED)
#include "mbedtls/ecdh.h"
#endif

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif

#define MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS                -0x7000

#define MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE               -0x7080

#define MBEDTLS_ERR_SSL_BAD_INPUT_DATA                    -0x7100

#define MBEDTLS_ERR_SSL_INVALID_MAC                       -0x7180

#define MBEDTLS_ERR_SSL_INVALID_RECORD                    -0x7200

#define MBEDTLS_ERR_SSL_CONN_EOF                          -0x7280

#define MBEDTLS_ERR_SSL_DECODE_ERROR                      -0x7300

#define MBEDTLS_ERR_SSL_NO_RNG                            -0x7400

#define MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE             -0x7480

#define MBEDTLS_ERR_SSL_UNSUPPORTED_EXTENSION             -0x7500

#define MBEDTLS_ERR_SSL_NO_APPLICATION_PROTOCOL           -0x7580

#define MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED              -0x7600

#define MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED                 -0x7680

#define MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE                -0x7700

#define MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE               -0x7780

#define MBEDTLS_ERR_SSL_UNRECOGNIZED_NAME                 -0x7800

#define MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY                 -0x7880

#define MBEDTLS_ERR_SSL_BAD_CERTIFICATE                   -0x7A00

#define MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET       -0x7B00

#define MBEDTLS_ERR_SSL_CANNOT_READ_EARLY_DATA            -0x7B80

#define MBEDTLS_ERR_SSL_RECEIVED_EARLY_DATA               -0x7C00

#define MBEDTLS_ERR_SSL_CANNOT_WRITE_EARLY_DATA           -0x7C80

#define MBEDTLS_ERR_SSL_CACHE_ENTRY_NOT_FOUND             -0x7E80

#define MBEDTLS_ERR_SSL_ALLOC_FAILED                      -0x7F00

#define MBEDTLS_ERR_SSL_HW_ACCEL_FAILED                   -0x7F80

#define MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH              -0x6F80

#define MBEDTLS_ERR_SSL_BAD_PROTOCOL_VERSION              -0x6E80

#define MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE                 -0x6E00

#define MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED            -0x6D80

#define MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH                  -0x6D00

#define MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY                  -0x6C80

#define MBEDTLS_ERR_SSL_INTERNAL_ERROR                    -0x6C00

#define MBEDTLS_ERR_SSL_COUNTER_WRAPPING                  -0x6B80

#define MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO       -0x6B00

#define MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED             -0x6A80

#define MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL                  -0x6A00

#define MBEDTLS_ERR_SSL_WANT_READ                         -0x6900

#define MBEDTLS_ERR_SSL_WANT_WRITE                        -0x6880

#define MBEDTLS_ERR_SSL_TIMEOUT                           -0x6800

#define MBEDTLS_ERR_SSL_CLIENT_RECONNECT                  -0x6780

#define MBEDTLS_ERR_SSL_UNEXPECTED_RECORD                 -0x6700

#define MBEDTLS_ERR_SSL_NON_FATAL                         -0x6680

#define MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER                 -0x6600

#define MBEDTLS_ERR_SSL_CONTINUE_PROCESSING               -0x6580

#define MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS                 -0x6500

#define MBEDTLS_ERR_SSL_EARLY_MESSAGE                     -0x6480

#define MBEDTLS_ERR_SSL_UNEXPECTED_CID                    -0x6000

#define MBEDTLS_ERR_SSL_VERSION_MISMATCH                  -0x5F00

#define MBEDTLS_ERR_SSL_BAD_CONFIG                        -0x5E80

#define MBEDTLS_ERR_SSL_CERTIFICATE_VERIFICATION_WITHOUT_HOSTNAME  -0x5D80

#define MBEDTLS_SSL_TLS1_3_PSK_MODE_PURE  0
#define MBEDTLS_SSL_TLS1_3_PSK_MODE_ECDHE 1

#define MBEDTLS_SSL_IANA_TLS_GROUP_NONE               0
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP192K1     0x0012
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP192R1     0x0013
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP224K1     0x0014
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP224R1     0x0015
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP256K1     0x0016
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1     0x0017
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP384R1     0x0018
#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP521R1     0x0019
#define MBEDTLS_SSL_IANA_TLS_GROUP_BP256R1       0x001A
#define MBEDTLS_SSL_IANA_TLS_GROUP_BP384R1       0x001B
#define MBEDTLS_SSL_IANA_TLS_GROUP_BP512R1       0x001C
#define MBEDTLS_SSL_IANA_TLS_GROUP_X25519        0x001D
#define MBEDTLS_SSL_IANA_TLS_GROUP_X448          0x001E

#define MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE2048     0x0100
#define MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE3072     0x0101
#define MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE4096     0x0102
#define MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE6144     0x0103
#define MBEDTLS_SSL_IANA_TLS_GROUP_FFDHE8192     0x0104

#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK            (1u << 0)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL      (1u << 1)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL  (1u << 2)

#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_ALL                         \
    (MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK              |            \
     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL    |            \
     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ALL                     \
    (MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK              |            \
     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL)
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ALL               \
    (MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL        |            \
     MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL)

#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_NONE   (0)

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

#define MBEDTLS_SSL_MAJOR_VERSION_3             3
#define MBEDTLS_SSL_MINOR_VERSION_3             3
#define MBEDTLS_SSL_MINOR_VERSION_4             4
#endif

#define MBEDTLS_SSL_TRANSPORT_STREAM            0
#define MBEDTLS_SSL_TRANSPORT_DATAGRAM          1

#define MBEDTLS_SSL_MAX_HOST_NAME_LEN           255
#define MBEDTLS_SSL_MAX_ALPN_NAME_LEN           255

#define MBEDTLS_SSL_MAX_ALPN_LIST_LEN           65535

#define MBEDTLS_SSL_MAX_FRAG_LEN_NONE           0
#define MBEDTLS_SSL_MAX_FRAG_LEN_512            1
#define MBEDTLS_SSL_MAX_FRAG_LEN_1024           2
#define MBEDTLS_SSL_MAX_FRAG_LEN_2048           3
#define MBEDTLS_SSL_MAX_FRAG_LEN_4096           4
#define MBEDTLS_SSL_MAX_FRAG_LEN_INVALID        5

#define MBEDTLS_SSL_IS_CLIENT                   0
#define MBEDTLS_SSL_IS_SERVER                   1

#define MBEDTLS_SSL_EXTENDED_MS_DISABLED        0
#define MBEDTLS_SSL_EXTENDED_MS_ENABLED         1

#define MBEDTLS_SSL_CID_DISABLED                0
#define MBEDTLS_SSL_CID_ENABLED                 1

#define MBEDTLS_SSL_ETM_DISABLED                0
#define MBEDTLS_SSL_ETM_ENABLED                 1

#define MBEDTLS_SSL_COMPRESS_NULL               0

#define MBEDTLS_SSL_VERIFY_NONE                 0
#define MBEDTLS_SSL_VERIFY_OPTIONAL             1
#define MBEDTLS_SSL_VERIFY_REQUIRED             2
#define MBEDTLS_SSL_VERIFY_UNSET                3

#define MBEDTLS_SSL_LEGACY_RENEGOTIATION        0
#define MBEDTLS_SSL_SECURE_RENEGOTIATION        1

#define MBEDTLS_SSL_RENEGOTIATION_DISABLED      0
#define MBEDTLS_SSL_RENEGOTIATION_ENABLED       1

#define MBEDTLS_SSL_ANTI_REPLAY_DISABLED        0
#define MBEDTLS_SSL_ANTI_REPLAY_ENABLED         1

#define MBEDTLS_SSL_RENEGOTIATION_NOT_ENFORCED  -1
#define MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT  16

#define MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION     0
#define MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION  1
#define MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE      2

#define MBEDTLS_SSL_TRUNC_HMAC_DISABLED         0
#define MBEDTLS_SSL_TRUNC_HMAC_ENABLED          1
#define MBEDTLS_SSL_TRUNCATED_HMAC_LEN          10

#define MBEDTLS_SSL_SESSION_TICKETS_DISABLED     0
#define MBEDTLS_SSL_SESSION_TICKETS_ENABLED      1

#define MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_DISABLED  0
#define MBEDTLS_SSL_TLS1_3_SIGNAL_NEW_SESSION_TICKETS_ENABLED   1

#define MBEDTLS_SSL_PRESET_DEFAULT              0
#define MBEDTLS_SSL_PRESET_SUITEB               2

#define MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED       1
#define MBEDTLS_SSL_CERT_REQ_CA_LIST_DISABLED      0

#define MBEDTLS_SSL_EARLY_DATA_DISABLED        0
#define MBEDTLS_SSL_EARLY_DATA_ENABLED         1

#define MBEDTLS_SSL_DTLS_SRTP_MKI_UNSUPPORTED    0
#define MBEDTLS_SSL_DTLS_SRTP_MKI_SUPPORTED      1

#define MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_CLIENT  1
#define MBEDTLS_SSL_SRV_CIPHERSUITE_ORDER_SERVER  0

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
#if defined(MBEDTLS_MD_CAN_SHA384)
#define MBEDTLS_SSL_TLS1_3_TICKET_RESUMPTION_KEY_LEN        48
#elif defined(MBEDTLS_MD_CAN_SHA256)
#define MBEDTLS_SSL_TLS1_3_TICKET_RESUMPTION_KEY_LEN        32
#endif
#endif

#define MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN    1000
#define MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX   60000

#define MBEDTLS_SSL_EARLY_DATA_NO_DISCARD 0
#define MBEDTLS_SSL_EARLY_DATA_TRY_TO_DEPROTECT_AND_DISCARD 1
#define MBEDTLS_SSL_EARLY_DATA_DISCARD 2

#if !defined(MBEDTLS_SSL_IN_CONTENT_LEN)
#define MBEDTLS_SSL_IN_CONTENT_LEN 16384
#endif

#if !defined(MBEDTLS_SSL_OUT_CONTENT_LEN)
#define MBEDTLS_SSL_OUT_CONTENT_LEN 16384
#endif

#if !defined(MBEDTLS_SSL_DTLS_MAX_BUFFERING)
#define MBEDTLS_SSL_DTLS_MAX_BUFFERING 32768
#endif

#if !defined(MBEDTLS_SSL_CID_IN_LEN_MAX)
#define MBEDTLS_SSL_CID_IN_LEN_MAX          32
#endif

#if !defined(MBEDTLS_SSL_CID_OUT_LEN_MAX)
#define MBEDTLS_SSL_CID_OUT_LEN_MAX         32
#endif

#if !defined(MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY)
#define MBEDTLS_SSL_CID_TLS1_3_PADDING_GRANULARITY 16
#endif

#if !defined(MBEDTLS_SSL_MAX_EARLY_DATA_SIZE)
#define MBEDTLS_SSL_MAX_EARLY_DATA_SIZE        1024
#endif

#if !defined(MBEDTLS_SSL_TLS1_3_TICKET_AGE_TOLERANCE)
#define MBEDTLS_SSL_TLS1_3_TICKET_AGE_TOLERANCE 6000
#endif

#if !defined(MBEDTLS_SSL_TLS1_3_TICKET_NONCE_LENGTH)
#define MBEDTLS_SSL_TLS1_3_TICKET_NONCE_LENGTH 32
#endif

#if !defined(MBEDTLS_SSL_TLS1_3_DEFAULT_NEW_SESSION_TICKETS)
#define MBEDTLS_SSL_TLS1_3_DEFAULT_NEW_SESSION_TICKETS 1
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID) && \
    !defined(MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT)
#define MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT 0
#endif

#define MBEDTLS_SSL_VERIFY_DATA_MAX_LEN 12

#define MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO    0xFF

#define MBEDTLS_SSL_HASH_NONE                0
#define MBEDTLS_SSL_HASH_MD5                 1
#define MBEDTLS_SSL_HASH_SHA1                2
#define MBEDTLS_SSL_HASH_SHA224              3
#define MBEDTLS_SSL_HASH_SHA256              4
#define MBEDTLS_SSL_HASH_SHA384              5
#define MBEDTLS_SSL_HASH_SHA512              6

#define MBEDTLS_SSL_SIG_ANON                 0
#define MBEDTLS_SSL_SIG_RSA                  1
#define MBEDTLS_SSL_SIG_ECDSA                3

#define MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA256 0x0401
#define MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA384 0x0501
#define MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA512 0x0601

#define MBEDTLS_TLS1_3_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define MBEDTLS_TLS1_3_SIG_ECDSA_SECP384R1_SHA384 0x0503
#define MBEDTLS_TLS1_3_SIG_ECDSA_SECP521R1_SHA512 0x0603

#define MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA256 0x0804
#define MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA384 0x0805
#define MBEDTLS_TLS1_3_SIG_RSA_PSS_RSAE_SHA512 0x0806

#define MBEDTLS_TLS1_3_SIG_ED25519 0x0807
#define MBEDTLS_TLS1_3_SIG_ED448 0x0808

#define MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA256 0x0809
#define MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA384 0x080A
#define MBEDTLS_TLS1_3_SIG_RSA_PSS_PSS_SHA512 0x080B

#define MBEDTLS_TLS1_3_SIG_RSA_PKCS1_SHA1 0x0201
#define MBEDTLS_TLS1_3_SIG_ECDSA_SHA1     0x0203

#define MBEDTLS_TLS1_3_SIG_NONE 0x0

#define MBEDTLS_SSL_CERT_TYPE_RSA_SIGN       1
#define MBEDTLS_SSL_CERT_TYPE_ECDSA_SIGN    64

#define MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC     20
#define MBEDTLS_SSL_MSG_ALERT                  21
#define MBEDTLS_SSL_MSG_HANDSHAKE              22
#define MBEDTLS_SSL_MSG_APPLICATION_DATA       23
#define MBEDTLS_SSL_MSG_CID                    25

#define MBEDTLS_SSL_ALERT_LEVEL_WARNING         1
#define MBEDTLS_SSL_ALERT_LEVEL_FATAL           2

#define MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY           0
#define MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE    10
#define MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC        20
#define MBEDTLS_SSL_ALERT_MSG_DECRYPTION_FAILED     21
#define MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW       22
#define MBEDTLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE 30
#define MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE     40
#define MBEDTLS_SSL_ALERT_MSG_NO_CERT               41
#define MBEDTLS_SSL_ALERT_MSG_BAD_CERT              42
#define MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT      43
#define MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED          44
#define MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED          45
#define MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN          46
#define MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER     47
#define MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA            48
#define MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED         49
#define MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR          50
#define MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR         51
#define MBEDTLS_SSL_ALERT_MSG_EXPORT_RESTRICTION    60
#define MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION      70
#define MBEDTLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY 71
#define MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR        80
#define MBEDTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK 86
#define MBEDTLS_SSL_ALERT_MSG_USER_CANCELED         90
#define MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION     100
#define MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION    109
#define MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT      110
#define MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME    112
#define MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY 115
#define MBEDTLS_SSL_ALERT_MSG_CERT_REQUIRED        116
#define MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL 120

#define MBEDTLS_SSL_HS_HELLO_REQUEST            0
#define MBEDTLS_SSL_HS_CLIENT_HELLO             1
#define MBEDTLS_SSL_HS_SERVER_HELLO             2
#define MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST     3
#define MBEDTLS_SSL_HS_NEW_SESSION_TICKET       4
#define MBEDTLS_SSL_HS_END_OF_EARLY_DATA        5
#define MBEDTLS_SSL_HS_ENCRYPTED_EXTENSIONS     8
#define MBEDTLS_SSL_HS_CERTIFICATE             11
#define MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE     12
#define MBEDTLS_SSL_HS_CERTIFICATE_REQUEST     13
#define MBEDTLS_SSL_HS_SERVER_HELLO_DONE       14
#define MBEDTLS_SSL_HS_CERTIFICATE_VERIFY      15
#define MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE     16
#define MBEDTLS_SSL_HS_FINISHED                20
#define MBEDTLS_SSL_HS_MESSAGE_HASH           254

#define MBEDTLS_TLS_EXT_SERVERNAME                   0
#define MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME          0

#define MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH          1

#define MBEDTLS_TLS_EXT_TRUNCATED_HMAC               4
#define MBEDTLS_TLS_EXT_STATUS_REQUEST               5

#define MBEDTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES   10
#define MBEDTLS_TLS_EXT_SUPPORTED_GROUPS            10
#define MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS     11

#define MBEDTLS_TLS_EXT_SIG_ALG                     13
#define MBEDTLS_TLS_EXT_USE_SRTP                    14
#define MBEDTLS_TLS_EXT_HEARTBEAT                   15
#define MBEDTLS_TLS_EXT_ALPN                        16

#define MBEDTLS_TLS_EXT_SCT                         18
#define MBEDTLS_TLS_EXT_CLI_CERT_TYPE               19
#define MBEDTLS_TLS_EXT_SERV_CERT_TYPE              20
#define MBEDTLS_TLS_EXT_PADDING                     21
#define MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC            22
#define MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET  0x0017

#define MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT           28

#define MBEDTLS_TLS_EXT_SESSION_TICKET              35

#define MBEDTLS_TLS_EXT_PRE_SHARED_KEY              41
#define MBEDTLS_TLS_EXT_EARLY_DATA                  42
#define MBEDTLS_TLS_EXT_SUPPORTED_VERSIONS          43
#define MBEDTLS_TLS_EXT_COOKIE                      44
#define MBEDTLS_TLS_EXT_PSK_KEY_EXCHANGE_MODES      45

#define MBEDTLS_TLS_EXT_CERT_AUTH                   47
#define MBEDTLS_TLS_EXT_OID_FILTERS                 48
#define MBEDTLS_TLS_EXT_POST_HANDSHAKE_AUTH         49
#define MBEDTLS_TLS_EXT_SIG_ALG_CERT                50
#define MBEDTLS_TLS_EXT_KEY_SHARE                   51

#if MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT == 0
#define MBEDTLS_TLS_EXT_CID                         54
#else
#define MBEDTLS_TLS_EXT_CID                        254
#endif

#define MBEDTLS_TLS_EXT_ECJPAKE_KKPP               256

#define MBEDTLS_TLS_EXT_RENEGOTIATION_INFO      0xFF01

#if !defined(MBEDTLS_PSK_MAX_LEN)

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && \
    defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_HAVE_AES) && defined(MBEDTLS_SSL_HAVE_GCM) && \
    defined(MBEDTLS_MD_CAN_SHA384)
#define MBEDTLS_PSK_MAX_LEN 48
#else
#define MBEDTLS_PSK_MAX_LEN 32
#endif
#endif

union mbedtls_ssl_premaster_secret {
    unsigned char dummy;
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_ENABLED)
    unsigned char _pms_rsa[48];
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED)
    unsigned char _pms_dhm[MBEDTLS_MPI_MAX_SIZE];
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED)    || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED)  || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED)     || \
    defined(MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED)
    unsigned char _pms_ecdh[MBEDTLS_ECP_MAX_BYTES];
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    unsigned char _pms_psk[4 + 2 * MBEDTLS_PSK_MAX_LEN];
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED)
    unsigned char _pms_dhe_psk[4 + MBEDTLS_MPI_MAX_SIZE
                               + MBEDTLS_PSK_MAX_LEN];
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED)
    unsigned char _pms_rsa_psk[52 + MBEDTLS_PSK_MAX_LEN];
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED)
    unsigned char _pms_ecdhe_psk[4 + MBEDTLS_ECP_MAX_BYTES
                                 + MBEDTLS_PSK_MAX_LEN];
#endif
#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)
    unsigned char _pms_ecjpake[32];
#endif
};

#define MBEDTLS_PREMASTER_SIZE     sizeof(union mbedtls_ssl_premaster_secret)

#define MBEDTLS_TLS1_3_MD_MAX_SIZE         MBEDTLS_MD_MAX_SIZE

#define MBEDTLS_SSL_SEQUENCE_NUMBER_LEN 8

#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION) || \
    (defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT) && defined(MBEDTLS_SSL_PROTO_TLS1_2))
#define MBEDTLS_SSL_KEEP_RANDBYTES
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MBEDTLS_SSL_HELLO_REQUEST,
    MBEDTLS_SSL_CLIENT_HELLO,
    MBEDTLS_SSL_SERVER_HELLO,
    MBEDTLS_SSL_SERVER_CERTIFICATE,
    MBEDTLS_SSL_SERVER_KEY_EXCHANGE,
    MBEDTLS_SSL_CERTIFICATE_REQUEST,
    MBEDTLS_SSL_SERVER_HELLO_DONE,
    MBEDTLS_SSL_CLIENT_CERTIFICATE,
    MBEDTLS_SSL_CLIENT_KEY_EXCHANGE,
    MBEDTLS_SSL_CERTIFICATE_VERIFY,
    MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC,
    MBEDTLS_SSL_CLIENT_FINISHED,
    MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC,
    MBEDTLS_SSL_SERVER_FINISHED,
    MBEDTLS_SSL_FLUSH_BUFFERS,
    MBEDTLS_SSL_HANDSHAKE_WRAPUP,
    MBEDTLS_SSL_NEW_SESSION_TICKET,
    MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT,
    MBEDTLS_SSL_HELLO_RETRY_REQUEST,
    MBEDTLS_SSL_ENCRYPTED_EXTENSIONS,
    MBEDTLS_SSL_END_OF_EARLY_DATA,
    MBEDTLS_SSL_CLIENT_CERTIFICATE_VERIFY,
    MBEDTLS_SSL_CLIENT_CCS_AFTER_SERVER_FINISHED,
    MBEDTLS_SSL_CLIENT_CCS_BEFORE_2ND_CLIENT_HELLO,
    MBEDTLS_SSL_SERVER_CCS_AFTER_SERVER_HELLO,
    MBEDTLS_SSL_CLIENT_CCS_AFTER_CLIENT_HELLO,
    MBEDTLS_SSL_SERVER_CCS_AFTER_HELLO_RETRY_REQUEST,
    MBEDTLS_SSL_HANDSHAKE_OVER,
    MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET,
    MBEDTLS_SSL_TLS1_3_NEW_SESSION_TICKET_FLUSH,
}
mbedtls_ssl_states;

#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_CLI_C)
typedef enum {

    MBEDTLS_SSL_EARLY_DATA_STATUS_NOT_INDICATED,
    MBEDTLS_SSL_EARLY_DATA_STATUS_ACCEPTED,
    MBEDTLS_SSL_EARLY_DATA_STATUS_REJECTED,
} mbedtls_ssl_early_data_status;
#endif

typedef int mbedtls_ssl_send_t(void *ctx,
                               const unsigned char *buf,
                               size_t len);

typedef int mbedtls_ssl_recv_t(void *ctx,
                               unsigned char *buf,
                               size_t len);

typedef int mbedtls_ssl_recv_timeout_t(void *ctx,
                                       unsigned char *buf,
                                       size_t len,
                                       uint32_t timeout);

typedef void mbedtls_ssl_set_timer_t(void *ctx,
                                     uint32_t int_ms,
                                     uint32_t fin_ms);

typedef int mbedtls_ssl_get_timer_t(void *ctx);

typedef struct mbedtls_ssl_session mbedtls_ssl_session;
typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct mbedtls_ssl_config  mbedtls_ssl_config;

typedef struct mbedtls_ssl_transform mbedtls_ssl_transform;
typedef struct mbedtls_ssl_handshake_params mbedtls_ssl_handshake_params;
typedef struct mbedtls_ssl_sig_hash_set_t mbedtls_ssl_sig_hash_set_t;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
typedef struct mbedtls_ssl_key_cert mbedtls_ssl_key_cert;
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
typedef struct mbedtls_ssl_flight_item mbedtls_ssl_flight_item;
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
#define MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_RESUMPTION                          \
    MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK
#define MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_EPHEMERAL_RESUMPTION                \
    MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL
#define MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_EARLY_DATA                  (1U << 3)

#define MBEDTLS_SSL_TLS1_3_TICKET_FLAGS_MASK                                    \
    (MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_RESUMPTION             |      \
     MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_PSK_EPHEMERAL_RESUMPTION   |      \
     MBEDTLS_SSL_TLS1_3_TICKET_ALLOW_EARLY_DATA)
#endif

typedef int mbedtls_ssl_cache_get_t(void *data,
                                    unsigned char const *session_id,
                                    size_t session_id_len,
                                    mbedtls_ssl_session *session);

typedef int mbedtls_ssl_cache_set_t(void *data,
                                    unsigned char const *session_id,
                                    size_t session_id_len,
                                    const mbedtls_ssl_session *session);

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
#if defined(MBEDTLS_X509_CRT_PARSE_C)

typedef int mbedtls_ssl_async_sign_t(mbedtls_ssl_context *ssl,
                                     mbedtls_x509_crt *cert,
                                     mbedtls_md_type_t md_alg,
                                     const unsigned char *hash,
                                     size_t hash_len);

typedef int mbedtls_ssl_async_decrypt_t(mbedtls_ssl_context *ssl,
                                        mbedtls_x509_crt *cert,
                                        const unsigned char *input,
                                        size_t input_len);
#endif

typedef int mbedtls_ssl_async_resume_t(mbedtls_ssl_context *ssl,
                                       unsigned char *output,
                                       size_t *output_len,
                                       size_t output_size);

typedef void mbedtls_ssl_async_cancel_t(mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_WITH_CERT_ENABLED) &&        \
    !defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
#define MBEDTLS_SSL_PEER_CERT_DIGEST_MAX_LEN  48
#if defined(MBEDTLS_MD_CAN_SHA256)
#define MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE MBEDTLS_MD_SHA256
#define MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN  32
#elif defined(MBEDTLS_MD_CAN_SHA384)
#define MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE MBEDTLS_MD_SHA384
#define MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN  48
#elif defined(MBEDTLS_MD_CAN_SHA1)
#define MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_TYPE MBEDTLS_MD_SHA1
#define MBEDTLS_SSL_PEER_CERT_DIGEST_DFL_LEN  20
#else

#error "Bad configuration - need SHA-1, SHA-256 or SHA-512 enabled to compute digest of peer CRT."
#endif
#endif

typedef struct {
    unsigned char client_application_traffic_secret_N[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char server_application_traffic_secret_N[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char exporter_master_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
    unsigned char resumption_master_secret[MBEDTLS_TLS1_3_MD_MAX_SIZE];
} mbedtls_ssl_tls13_application_secrets;

#if defined(MBEDTLS_SSL_DTLS_SRTP)

#define MBEDTLS_TLS_SRTP_MAX_MKI_LENGTH             255
#define MBEDTLS_TLS_SRTP_MAX_PROFILE_LIST_LENGTH    4

#define MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80     ((uint16_t) 0x0001)
#define MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32     ((uint16_t) 0x0002)
#define MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80          ((uint16_t) 0x0005)
#define MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32          ((uint16_t) 0x0006)

#define MBEDTLS_TLS_SRTP_UNSET                      ((uint16_t) 0x0000)

typedef uint16_t mbedtls_ssl_srtp_profile;

typedef struct mbedtls_dtls_srtp_info_t {

    mbedtls_ssl_srtp_profile MBEDTLS_PRIVATE(chosen_dtls_srtp_profile);

    uint16_t MBEDTLS_PRIVATE(mki_len);

    unsigned char MBEDTLS_PRIVATE(mki_value)[MBEDTLS_TLS_SRTP_MAX_MKI_LENGTH];
}
mbedtls_dtls_srtp_info;

#endif

typedef enum {
    MBEDTLS_SSL_VERSION_UNKNOWN,
    MBEDTLS_SSL_VERSION_TLS1_2 = 0x0303,
    MBEDTLS_SSL_VERSION_TLS1_3 = 0x0304,
} mbedtls_ssl_protocol_version;

struct mbedtls_ssl_session {
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    unsigned char MBEDTLS_PRIVATE(mfl_code);
#endif

#if defined(MBEDTLS_SSL_RECORD_SIZE_LIMIT)
    uint16_t MBEDTLS_PRIVATE(record_size_limit);
#endif

    unsigned char MBEDTLS_PRIVATE(exported);
    uint8_t MBEDTLS_PRIVATE(endpoint);

    mbedtls_ssl_protocol_version MBEDTLS_PRIVATE(tls_version);

#if defined(MBEDTLS_HAVE_TIME)
    mbedtls_time_t MBEDTLS_PRIVATE(start);
#endif
    int MBEDTLS_PRIVATE(ciphersuite);
    size_t MBEDTLS_PRIVATE(id_len);
    unsigned char MBEDTLS_PRIVATE(id)[32];
    unsigned char MBEDTLS_PRIVATE(master)[48];

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_SSL_KEEP_PEER_CERTIFICATE)
    mbedtls_x509_crt *MBEDTLS_PRIVATE(peer_cert);
#else

    unsigned char *MBEDTLS_PRIVATE(peer_cert_digest);
    size_t MBEDTLS_PRIVATE(peer_cert_digest_len);
    mbedtls_md_type_t MBEDTLS_PRIVATE(peer_cert_digest_type);
#endif
#endif
    uint32_t MBEDTLS_PRIVATE(verify_result);

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)
    unsigned char *MBEDTLS_PRIVATE(ticket);
    size_t MBEDTLS_PRIVATE(ticket_len);
    uint32_t MBEDTLS_PRIVATE(ticket_lifetime);
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_HAVE_TIME)

    mbedtls_ms_time_t MBEDTLS_PRIVATE(ticket_creation_time);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3) && defined(MBEDTLS_SSL_SESSION_TICKETS)
    uint32_t MBEDTLS_PRIVATE(ticket_age_add);
    uint8_t MBEDTLS_PRIVATE(ticket_flags);
    uint8_t MBEDTLS_PRIVATE(resumption_key_len);
    unsigned char MBEDTLS_PRIVATE(resumption_key)[MBEDTLS_SSL_TLS1_3_TICKET_RESUMPTION_KEY_LEN];

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION) && defined(MBEDTLS_SSL_CLI_C)
    char *MBEDTLS_PRIVATE(hostname);
#endif

#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_ALPN) && defined(MBEDTLS_SSL_SRV_C)
    char *ticket_alpn;
#endif

#if defined(MBEDTLS_HAVE_TIME) && defined(MBEDTLS_SSL_CLI_C)

    mbedtls_ms_time_t MBEDTLS_PRIVATE(ticket_reception_time);
#endif
#endif

#if defined(MBEDTLS_SSL_EARLY_DATA)
    uint32_t MBEDTLS_PRIVATE(max_early_data_size);
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    int MBEDTLS_PRIVATE(encrypt_then_mac);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    mbedtls_ssl_tls13_application_secrets MBEDTLS_PRIVATE(app_secrets);
#endif
};

typedef enum {
    MBEDTLS_SSL_TLS_PRF_NONE,
    MBEDTLS_SSL_TLS_PRF_SHA384,
    MBEDTLS_SSL_TLS_PRF_SHA256,
    MBEDTLS_SSL_HKDF_EXPAND_SHA384,
    MBEDTLS_SSL_HKDF_EXPAND_SHA256
}
mbedtls_tls_prf_types;

typedef enum {
    MBEDTLS_SSL_KEY_EXPORT_TLS12_MASTER_SECRET = 0,
#if defined(MBEDTLS_SSL_PROTO_TLS1_3)
    MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_EARLY_SECRET,
    MBEDTLS_SSL_KEY_EXPORT_TLS1_3_EARLY_EXPORTER_SECRET,
    MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_HANDSHAKE_TRAFFIC_SECRET,
    MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_HANDSHAKE_TRAFFIC_SECRET,
    MBEDTLS_SSL_KEY_EXPORT_TLS1_3_CLIENT_APPLICATION_TRAFFIC_SECRET,
    MBEDTLS_SSL_KEY_EXPORT_TLS1_3_SERVER_APPLICATION_TRAFFIC_SECRET,
#endif
} mbedtls_ssl_key_export_type;

typedef void mbedtls_ssl_export_keys_t(void *p_expkey,
                                       mbedtls_ssl_key_export_type type,
                                       const unsigned char *secret,
                                       size_t secret_len,
                                       const unsigned char client_random[32],
                                       const unsigned char server_random[32],
                                       mbedtls_tls_prf_types tls_prf_type);

#if defined(MBEDTLS_SSL_SRV_C)

typedef int (*mbedtls_ssl_hs_cb_t)(mbedtls_ssl_context *ssl);
#endif

typedef union {
    uintptr_t n;
    void *p;
} mbedtls_ssl_user_data_t;

struct mbedtls_ssl_config {

    mbedtls_ssl_protocol_version MBEDTLS_PRIVATE(max_tls_version);
    mbedtls_ssl_protocol_version MBEDTLS_PRIVATE(min_tls_version);

    uint8_t MBEDTLS_PRIVATE(endpoint);
    uint8_t MBEDTLS_PRIVATE(transport);
    uint8_t MBEDTLS_PRIVATE(authmode);

    uint8_t MBEDTLS_PRIVATE(allow_legacy_renegotiation);
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    uint8_t MBEDTLS_PRIVATE(mfl_code);
#endif
#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    uint8_t MBEDTLS_PRIVATE(encrypt_then_mac);
#endif
#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    uint8_t MBEDTLS_PRIVATE(extended_ms);
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    uint8_t MBEDTLS_PRIVATE(anti_replay);
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    uint8_t MBEDTLS_PRIVATE(disable_renegotiation);
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_CLI_C)

    uint8_t MBEDTLS_PRIVATE(session_tickets);
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)
    uint16_t MBEDTLS_PRIVATE(new_session_tickets_count);
#endif

#if defined(MBEDTLS_SSL_SRV_C)
    uint8_t MBEDTLS_PRIVATE(cert_req_ca_list);
    uint8_t MBEDTLS_PRIVATE(respect_cli_pref);
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    uint8_t MBEDTLS_PRIVATE(ignore_unexpected_cid);
#endif
#if defined(MBEDTLS_SSL_DTLS_SRTP)
    uint8_t MBEDTLS_PRIVATE(dtls_srtp_mki_support);
#endif

    const int *MBEDTLS_PRIVATE(ciphersuite_list);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

    int MBEDTLS_PRIVATE(tls13_kex_modes);
#endif

    void(*MBEDTLS_PRIVATE(f_dbg))(void *, int, const char *, int, const char *);
    void *MBEDTLS_PRIVATE(p_dbg);

    int(*MBEDTLS_PRIVATE(f_rng))(void *, unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_rng);

    mbedtls_ssl_cache_get_t *MBEDTLS_PRIVATE(f_get_cache);

    mbedtls_ssl_cache_set_t *MBEDTLS_PRIVATE(f_set_cache);
    void *MBEDTLS_PRIVATE(p_cache);

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)

    int(*MBEDTLS_PRIVATE(f_sni))(void *, mbedtls_ssl_context *, const unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_sni);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

    int(*MBEDTLS_PRIVATE(f_vrfy))(void *, mbedtls_x509_crt *, int, uint32_t *);
    void *MBEDTLS_PRIVATE(p_vrfy);
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
#if defined(MBEDTLS_SSL_SRV_C)

    int(*MBEDTLS_PRIVATE(f_psk))(void *, mbedtls_ssl_context *, const unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_psk);
#endif
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)

    int(*MBEDTLS_PRIVATE(f_cookie_write))(void *, unsigned char **, unsigned char *,
                                          const unsigned char *, size_t);

    int(*MBEDTLS_PRIVATE(f_cookie_check))(void *, const unsigned char *, size_t,
                                          const unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_cookie);
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_SRV_C)

    int(*MBEDTLS_PRIVATE(f_ticket_write))(void *, const mbedtls_ssl_session *,
                                          unsigned char *, const unsigned char *, size_t *,
                                          uint32_t *);

    int(*MBEDTLS_PRIVATE(f_ticket_parse))(void *, mbedtls_ssl_session *, unsigned char *, size_t);
    void *MBEDTLS_PRIVATE(p_ticket);
#endif
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    size_t MBEDTLS_PRIVATE(cid_len);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    const mbedtls_x509_crt_profile *MBEDTLS_PRIVATE(cert_profile);
    mbedtls_ssl_key_cert *MBEDTLS_PRIVATE(key_cert);
    mbedtls_x509_crt *MBEDTLS_PRIVATE(ca_chain);
    mbedtls_x509_crl *MBEDTLS_PRIVATE(ca_crl);
#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)
    mbedtls_x509_crt_ca_cb_t MBEDTLS_PRIVATE(f_ca_cb);
    void *MBEDTLS_PRIVATE(p_ca_cb);
#endif
#endif

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_ssl_async_sign_t *MBEDTLS_PRIVATE(f_async_sign_start);
    mbedtls_ssl_async_decrypt_t *MBEDTLS_PRIVATE(f_async_decrypt_start);
#endif
    mbedtls_ssl_async_resume_t *MBEDTLS_PRIVATE(f_async_resume);
    mbedtls_ssl_async_cancel_t *MBEDTLS_PRIVATE(f_async_cancel);
    void *MBEDTLS_PRIVATE(p_async_config_data);
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
    const int *MBEDTLS_PRIVATE(sig_hashes);
#endif
    const uint16_t *MBEDTLS_PRIVATE(sig_algs);
#endif

#if defined(MBEDTLS_ECP_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
    const mbedtls_ecp_group_id *MBEDTLS_PRIVATE(curve_list);
#endif

    const uint16_t *MBEDTLS_PRIVATE(group_list);

#if defined(MBEDTLS_DHM_C)
    mbedtls_mpi MBEDTLS_PRIVATE(dhm_P);
    mbedtls_mpi MBEDTLS_PRIVATE(dhm_G);
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
    unsigned char *MBEDTLS_PRIVATE(psk);
    size_t         MBEDTLS_PRIVATE(psk_len);

    unsigned char *MBEDTLS_PRIVATE(psk_identity);
    size_t         MBEDTLS_PRIVATE(psk_identity_len);
#endif

#if defined(MBEDTLS_SSL_EARLY_DATA)
    int MBEDTLS_PRIVATE(early_data_enabled);

#if defined(MBEDTLS_SSL_SRV_C)

    uint32_t MBEDTLS_PRIVATE(max_early_data_size);
#endif

#endif

#if defined(MBEDTLS_SSL_ALPN)
    const char **MBEDTLS_PRIVATE(alpn_list);
#endif

#if defined(MBEDTLS_SSL_DTLS_SRTP)

    const mbedtls_ssl_srtp_profile *MBEDTLS_PRIVATE(dtls_srtp_profile_list);

    size_t MBEDTLS_PRIVATE(dtls_srtp_profile_list_len);
#endif

    uint32_t MBEDTLS_PRIVATE(read_timeout);

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint32_t MBEDTLS_PRIVATE(hs_timeout_min);
    uint32_t MBEDTLS_PRIVATE(hs_timeout_max);
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
    int MBEDTLS_PRIVATE(renego_max_records);
    unsigned char MBEDTLS_PRIVATE(renego_period)[8];
#endif

    unsigned int MBEDTLS_PRIVATE(badmac_limit);

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_CLI_C)
    unsigned int MBEDTLS_PRIVATE(dhm_min_bitlen);
#endif

    mbedtls_ssl_user_data_t MBEDTLS_PRIVATE(user_data);

#if defined(MBEDTLS_SSL_SRV_C)
    mbedtls_ssl_hs_cb_t MBEDTLS_PRIVATE(f_cert_cb);
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)
    const mbedtls_x509_crt *MBEDTLS_PRIVATE(dn_hints);
#endif
};

struct mbedtls_ssl_context {
    const mbedtls_ssl_config *MBEDTLS_PRIVATE(conf);

    int MBEDTLS_PRIVATE(state);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    int MBEDTLS_PRIVATE(renego_status);
    int MBEDTLS_PRIVATE(renego_records_seen);
#endif

    mbedtls_ssl_protocol_version MBEDTLS_PRIVATE(tls_version);

#if defined(MBEDTLS_SSL_EARLY_DATA) && defined(MBEDTLS_SSL_CLI_C)

    int MBEDTLS_PRIVATE(early_data_state);
#endif

    unsigned MBEDTLS_PRIVATE(badmac_seen_or_in_hsfraglen);

#if defined(MBEDTLS_X509_CRT_PARSE_C)

    int(*MBEDTLS_PRIVATE(f_vrfy))(void *, mbedtls_x509_crt *, int, uint32_t *);
    void *MBEDTLS_PRIVATE(p_vrfy);
#endif

    mbedtls_ssl_send_t *MBEDTLS_PRIVATE(f_send);
    mbedtls_ssl_recv_t *MBEDTLS_PRIVATE(f_recv);
    mbedtls_ssl_recv_timeout_t *MBEDTLS_PRIVATE(f_recv_timeout);

    void *MBEDTLS_PRIVATE(p_bio);

    mbedtls_ssl_session *MBEDTLS_PRIVATE(session_in);
    mbedtls_ssl_session *MBEDTLS_PRIVATE(session_out);
    mbedtls_ssl_session *MBEDTLS_PRIVATE(session);
    mbedtls_ssl_session *MBEDTLS_PRIVATE(session_negotiate);

    mbedtls_ssl_handshake_params *MBEDTLS_PRIVATE(handshake);

    mbedtls_ssl_transform *MBEDTLS_PRIVATE(transform_in);
    mbedtls_ssl_transform *MBEDTLS_PRIVATE(transform_out);
    mbedtls_ssl_transform *MBEDTLS_PRIVATE(transform);
#if defined(MBEDTLS_SSL_PROTO_TLS1_2)
    mbedtls_ssl_transform *MBEDTLS_PRIVATE(transform_negotiate);
#endif

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

    mbedtls_ssl_transform *MBEDTLS_PRIVATE(transform_application);
#endif

    void *MBEDTLS_PRIVATE(p_timer);

    mbedtls_ssl_set_timer_t *MBEDTLS_PRIVATE(f_set_timer);
    mbedtls_ssl_get_timer_t *MBEDTLS_PRIVATE(f_get_timer);

    unsigned char *MBEDTLS_PRIVATE(in_buf);
    unsigned char *MBEDTLS_PRIVATE(in_ctr);
    unsigned char *MBEDTLS_PRIVATE(in_hdr);
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    unsigned char *MBEDTLS_PRIVATE(in_cid);
#endif
    unsigned char *MBEDTLS_PRIVATE(in_len);
    unsigned char *MBEDTLS_PRIVATE(in_iv);
    unsigned char *MBEDTLS_PRIVATE(in_msg);
    unsigned char *MBEDTLS_PRIVATE(in_offt);

    int MBEDTLS_PRIVATE(in_msgtype);
    size_t MBEDTLS_PRIVATE(in_msglen);
    size_t MBEDTLS_PRIVATE(in_left);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t MBEDTLS_PRIVATE(in_buf_len);
#endif
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint16_t MBEDTLS_PRIVATE(in_epoch);
    size_t MBEDTLS_PRIVATE(next_record_offset);
#endif
#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
    uint64_t MBEDTLS_PRIVATE(in_window_top);
    uint64_t MBEDTLS_PRIVATE(in_window);
#endif

    size_t MBEDTLS_PRIVATE(in_hslen);
    int MBEDTLS_PRIVATE(nb_zero);

    int MBEDTLS_PRIVATE(keep_current_message);

    unsigned char MBEDTLS_PRIVATE(send_alert);
    unsigned char MBEDTLS_PRIVATE(alert_type);
    int MBEDTLS_PRIVATE(alert_reason);

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint8_t MBEDTLS_PRIVATE(disable_datagram_packing);
#endif

#if defined(MBEDTLS_SSL_EARLY_DATA)
#if defined(MBEDTLS_SSL_SRV_C)

    uint8_t MBEDTLS_PRIVATE(discard_early_data_record);
#endif
    uint32_t MBEDTLS_PRIVATE(total_early_data_size);
#endif

    unsigned char *MBEDTLS_PRIVATE(out_buf);
    unsigned char *MBEDTLS_PRIVATE(out_ctr);
    unsigned char *MBEDTLS_PRIVATE(out_hdr);
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    unsigned char *MBEDTLS_PRIVATE(out_cid);
#endif
    unsigned char *MBEDTLS_PRIVATE(out_len);
    unsigned char *MBEDTLS_PRIVATE(out_iv);
    unsigned char *MBEDTLS_PRIVATE(out_msg);

    int MBEDTLS_PRIVATE(out_msgtype);
    size_t MBEDTLS_PRIVATE(out_msglen);
    size_t MBEDTLS_PRIVATE(out_left);
#if defined(MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH)
    size_t MBEDTLS_PRIVATE(out_buf_len);
#endif

    unsigned char MBEDTLS_PRIVATE(cur_out_ctr)[MBEDTLS_SSL_SEQUENCE_NUMBER_LEN];

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    uint16_t MBEDTLS_PRIVATE(mtu);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

    char *MBEDTLS_PRIVATE(hostname);
#endif

#if defined(MBEDTLS_SSL_ALPN)
    const char *MBEDTLS_PRIVATE(alpn_chosen);
#endif

#if defined(MBEDTLS_SSL_DTLS_SRTP)

    mbedtls_dtls_srtp_info MBEDTLS_PRIVATE(dtls_srtp_info);
#endif

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)
    unsigned char  *MBEDTLS_PRIVATE(cli_id);
    size_t          MBEDTLS_PRIVATE(cli_id_len);
#endif

    int MBEDTLS_PRIVATE(secure_renegotiation);
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    size_t MBEDTLS_PRIVATE(verify_data_len);
    char MBEDTLS_PRIVATE(own_verify_data)[MBEDTLS_SSL_VERIFY_DATA_MAX_LEN];
    char MBEDTLS_PRIVATE(peer_verify_data)[MBEDTLS_SSL_VERIFY_DATA_MAX_LEN];
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)

    unsigned char MBEDTLS_PRIVATE(own_cid)[MBEDTLS_SSL_CID_IN_LEN_MAX];
    uint8_t MBEDTLS_PRIVATE(own_cid_len);
    uint8_t MBEDTLS_PRIVATE(negotiate_cid);
#endif

    mbedtls_ssl_export_keys_t *MBEDTLS_PRIVATE(f_export_keys);
    void *MBEDTLS_PRIVATE(p_export_keys);

    mbedtls_ssl_user_data_t MBEDTLS_PRIVATE(user_data);
};

const char *mbedtls_ssl_get_ciphersuite_name(const int ciphersuite_id);

int mbedtls_ssl_get_ciphersuite_id(const char *ciphersuite_name);

void mbedtls_ssl_init(mbedtls_ssl_context *ssl);

int mbedtls_ssl_setup(mbedtls_ssl_context *ssl,
                      const mbedtls_ssl_config *conf);

int mbedtls_ssl_session_reset(mbedtls_ssl_context *ssl);

void mbedtls_ssl_conf_endpoint(mbedtls_ssl_config *conf, int endpoint);

static inline int mbedtls_ssl_conf_get_endpoint(const mbedtls_ssl_config *conf)
{
    return conf->MBEDTLS_PRIVATE(endpoint);
}

void mbedtls_ssl_conf_transport(mbedtls_ssl_config *conf, int transport);

void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode);

#if defined(MBEDTLS_SSL_EARLY_DATA)

void mbedtls_ssl_conf_early_data(mbedtls_ssl_config *conf,
                                 int early_data_enabled);

#if defined(MBEDTLS_SSL_SRV_C)

void mbedtls_ssl_conf_max_early_data_size(
    mbedtls_ssl_config *conf, uint32_t max_early_data_size);
#endif

#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

void mbedtls_ssl_conf_verify(mbedtls_ssl_config *conf,
                             int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                             void *p_vrfy);
#endif

void mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf,
                          mbedtls_f_rng_t *f_rng,
                          void *p_rng);

void mbedtls_ssl_conf_dbg(mbedtls_ssl_config *conf,
                          void (*f_dbg)(void *, int, const char *, int, const char *),
                          void  *p_dbg);

static inline const mbedtls_ssl_config *mbedtls_ssl_context_get_config(
    const mbedtls_ssl_context *ssl)
{
    return ssl->MBEDTLS_PRIVATE(conf);
}

void mbedtls_ssl_set_bio(mbedtls_ssl_context *ssl,
                         void *p_bio,
                         mbedtls_ssl_send_t *f_send,
                         mbedtls_ssl_recv_t *f_recv,
                         mbedtls_ssl_recv_timeout_t *f_recv_timeout);

#if defined(MBEDTLS_SSL_PROTO_DTLS)

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)

int mbedtls_ssl_set_cid(mbedtls_ssl_context *ssl,
                        int enable,
                        unsigned char const *own_cid,
                        size_t own_cid_len);

int mbedtls_ssl_get_own_cid(mbedtls_ssl_context *ssl,
                            int *enabled,
                            unsigned char own_cid[MBEDTLS_SSL_CID_IN_LEN_MAX],
                            size_t *own_cid_len);

int mbedtls_ssl_get_peer_cid(mbedtls_ssl_context *ssl,
                             int *enabled,
                             unsigned char peer_cid[MBEDTLS_SSL_CID_OUT_LEN_MAX],
                             size_t *peer_cid_len);

#endif

void mbedtls_ssl_set_mtu(mbedtls_ssl_context *ssl, uint16_t mtu);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

void mbedtls_ssl_set_verify(mbedtls_ssl_context *ssl,
                            int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy);
#endif

void mbedtls_ssl_conf_read_timeout(mbedtls_ssl_config *conf, uint32_t timeout);

int mbedtls_ssl_check_record(mbedtls_ssl_context const *ssl,
                             unsigned char *buf,
                             size_t buflen);

void mbedtls_ssl_set_timer_cb(mbedtls_ssl_context *ssl,
                              void *p_timer,
                              mbedtls_ssl_set_timer_t *f_set_timer,
                              mbedtls_ssl_get_timer_t *f_get_timer);

#if defined(MBEDTLS_SSL_SRV_C)

static inline void mbedtls_ssl_conf_cert_cb(mbedtls_ssl_config *conf,
                                            mbedtls_ssl_hs_cb_t f_cert_cb)
{
    conf->MBEDTLS_PRIVATE(f_cert_cb) = f_cert_cb;
}
#endif

typedef int mbedtls_ssl_ticket_write_t(void *p_ticket,
                                       const mbedtls_ssl_session *session,
                                       unsigned char *start,
                                       const unsigned char *end,
                                       size_t *tlen,
                                       uint32_t *lifetime);

typedef int mbedtls_ssl_ticket_parse_t(void *p_ticket,
                                       mbedtls_ssl_session *session,
                                       unsigned char *buf,
                                       size_t len);

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_SRV_C)

void mbedtls_ssl_conf_session_tickets_cb(mbedtls_ssl_config *conf,
                                         mbedtls_ssl_ticket_write_t *f_ticket_write,
                                         mbedtls_ssl_ticket_parse_t *f_ticket_parse,
                                         void *p_ticket);

#if defined(MBEDTLS_HAVE_TIME)

static inline int mbedtls_ssl_session_get_ticket_creation_time(
    mbedtls_ssl_session *session, mbedtls_ms_time_t *ticket_creation_time)
{
    if (session == NULL || ticket_creation_time == NULL ||
        session->MBEDTLS_PRIVATE(endpoint) != MBEDTLS_SSL_IS_SERVER) {
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }

    *ticket_creation_time = session->MBEDTLS_PRIVATE(ticket_creation_time);

    return 0;
}
#endif
#endif

static inline unsigned const char (*mbedtls_ssl_session_get_id(const mbedtls_ssl_session *
                                                               session))[32]
{
    return &session->MBEDTLS_PRIVATE(id);
}

static inline size_t mbedtls_ssl_session_get_id_len(const mbedtls_ssl_session *session)
{
    return session->MBEDTLS_PRIVATE(id_len);
}

static inline int mbedtls_ssl_session_get_ciphersuite_id(const mbedtls_ssl_session *session)
{
    return session->MBEDTLS_PRIVATE(ciphersuite);
}

void mbedtls_ssl_set_export_keys_cb(mbedtls_ssl_context *ssl,
                                    mbedtls_ssl_export_keys_t *f_export_keys,
                                    void *p_export_keys);

static inline void mbedtls_ssl_conf_set_user_data_p(
    mbedtls_ssl_config *conf,
    void *p)
{
    conf->MBEDTLS_PRIVATE(user_data).p = p;
}

static inline void mbedtls_ssl_conf_set_user_data_n(
    mbedtls_ssl_config *conf,
    uintptr_t n)
{
    conf->MBEDTLS_PRIVATE(user_data).n = n;
}

static inline void *mbedtls_ssl_conf_get_user_data_p(
    mbedtls_ssl_config *conf)
{
    return conf->MBEDTLS_PRIVATE(user_data).p;
}

static inline uintptr_t mbedtls_ssl_conf_get_user_data_n(
    mbedtls_ssl_config *conf)
{
    return conf->MBEDTLS_PRIVATE(user_data).n;
}

static inline void mbedtls_ssl_set_user_data_p(
    mbedtls_ssl_context *ssl,
    void *p)
{
    ssl->MBEDTLS_PRIVATE(user_data).p = p;
}

static inline void mbedtls_ssl_set_user_data_n(
    mbedtls_ssl_context *ssl,
    uintptr_t n)
{
    ssl->MBEDTLS_PRIVATE(user_data).n = n;
}

static inline void *mbedtls_ssl_get_user_data_p(
    mbedtls_ssl_context *ssl)
{
    return ssl->MBEDTLS_PRIVATE(user_data).p;
}

static inline uintptr_t mbedtls_ssl_get_user_data_n(
    mbedtls_ssl_context *ssl)
{
    return ssl->MBEDTLS_PRIVATE(user_data).n;
}

#if defined(MBEDTLS_SSL_ASYNC_PRIVATE)

void mbedtls_ssl_conf_async_private_cb(mbedtls_ssl_config *conf,
                                       mbedtls_ssl_async_sign_t *f_async_sign,
                                       mbedtls_ssl_async_decrypt_t *f_async_decrypt,
                                       mbedtls_ssl_async_resume_t *f_async_resume,
                                       mbedtls_ssl_async_cancel_t *f_async_cancel,
                                       void *config_data);

void *mbedtls_ssl_conf_get_async_config_data(const mbedtls_ssl_config *conf);

void *mbedtls_ssl_get_async_operation_data(const mbedtls_ssl_context *ssl);

void mbedtls_ssl_set_async_operation_data(mbedtls_ssl_context *ssl,
                                          void *ctx);
#endif

typedef int mbedtls_ssl_cookie_write_t(void *ctx,
                                       unsigned char **p, unsigned char *end,
                                       const unsigned char *info, size_t ilen);

typedef int mbedtls_ssl_cookie_check_t(void *ctx,
                                       const unsigned char *cookie, size_t clen,
                                       const unsigned char *info, size_t ilen);

#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY) && defined(MBEDTLS_SSL_SRV_C)

void mbedtls_ssl_conf_dtls_cookies(mbedtls_ssl_config *conf,
                                   mbedtls_ssl_cookie_write_t *f_cookie_write,
                                   mbedtls_ssl_cookie_check_t *f_cookie_check,
                                   void *p_cookie);

int mbedtls_ssl_set_client_transport_id(mbedtls_ssl_context *ssl,
                                        const unsigned char *info,
                                        size_t ilen);

#endif

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)

void mbedtls_ssl_conf_dtls_anti_replay(mbedtls_ssl_config *conf, char mode);
#endif

void mbedtls_ssl_conf_dtls_badmac_limit(mbedtls_ssl_config *conf, unsigned limit);

#if defined(MBEDTLS_SSL_PROTO_DTLS)

void mbedtls_ssl_set_datagram_packing(mbedtls_ssl_context *ssl,
                                      unsigned allow_packing);

void mbedtls_ssl_conf_handshake_timeout(mbedtls_ssl_config *conf, uint32_t min, uint32_t max);
#endif

#if defined(MBEDTLS_SSL_SRV_C)

void mbedtls_ssl_conf_session_cache(mbedtls_ssl_config *conf,
                                    void *p_cache,
                                    mbedtls_ssl_cache_get_t *f_get_cache,
                                    mbedtls_ssl_cache_set_t *f_set_cache);
#endif

#if defined(MBEDTLS_SSL_CLI_C)

int mbedtls_ssl_set_session(mbedtls_ssl_context *ssl, const mbedtls_ssl_session *session);
#endif

int mbedtls_ssl_session_load(mbedtls_ssl_session *session,
                             const unsigned char *buf,
                             size_t len);

int mbedtls_ssl_session_save(const mbedtls_ssl_session *session,
                             unsigned char *buf,
                             size_t buf_len,
                             size_t *olen);

void mbedtls_ssl_conf_ciphersuites(mbedtls_ssl_config *conf,
                                   const int *ciphersuites);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

void mbedtls_ssl_conf_tls13_key_exchange_modes(mbedtls_ssl_config *conf,
                                               const int kex_modes);
#endif

#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define MBEDTLS_SSL_UNEXPECTED_CID_IGNORE 0
#define MBEDTLS_SSL_UNEXPECTED_CID_FAIL   1

int mbedtls_ssl_conf_cid(mbedtls_ssl_config *conf, size_t len,
                         int ignore_other_cids);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

void mbedtls_ssl_conf_cert_profile(mbedtls_ssl_config *conf,
                                   const mbedtls_x509_crt_profile *profile);

void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config *conf,
                               mbedtls_x509_crt *ca_chain,
                               mbedtls_x509_crl *ca_crl);

#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)

static inline
void mbedtls_ssl_conf_dn_hints(mbedtls_ssl_config *conf,
                               const mbedtls_x509_crt *crt)
{
    conf->MBEDTLS_PRIVATE(dn_hints) = crt;
}
#endif

#if defined(MBEDTLS_X509_TRUSTED_CERTIFICATE_CALLBACK)

void mbedtls_ssl_conf_ca_cb(mbedtls_ssl_config *conf,
                            mbedtls_x509_crt_ca_cb_t f_ca_cb,
                            void *p_ca_cb);
#endif

int mbedtls_ssl_conf_own_cert(mbedtls_ssl_config *conf,
                              mbedtls_x509_crt *own_cert,
                              mbedtls_pk_context *pk_key);
#endif

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)

int mbedtls_ssl_conf_psk(mbedtls_ssl_config *conf,
                         const unsigned char *psk, size_t psk_len,
                         const unsigned char *psk_identity, size_t psk_identity_len);

int mbedtls_ssl_set_hs_psk(mbedtls_ssl_context *ssl,
                           const unsigned char *psk, size_t psk_len);

#if defined(MBEDTLS_SSL_SRV_C)

void mbedtls_ssl_conf_psk_cb(mbedtls_ssl_config *conf,
                             int (*f_psk)(void *, mbedtls_ssl_context *, const unsigned char *,
                                          size_t),
                             void *p_psk);
#endif
#endif

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_SRV_C)

int mbedtls_ssl_conf_dh_param_bin(mbedtls_ssl_config *conf,
                                  const unsigned char *dhm_P, size_t P_len,
                                  const unsigned char *dhm_G,  size_t G_len);

int mbedtls_ssl_conf_dh_param_ctx(mbedtls_ssl_config *conf, mbedtls_dhm_context *dhm_ctx);
#endif

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_SSL_CLI_C)

void mbedtls_ssl_conf_dhm_min_bitlen(mbedtls_ssl_config *conf,
                                     unsigned int bitlen);
#endif

#if defined(MBEDTLS_ECP_C)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)

void MBEDTLS_DEPRECATED mbedtls_ssl_conf_curves(mbedtls_ssl_config *conf,
                                                const mbedtls_ecp_group_id *curves);
#endif
#endif

void mbedtls_ssl_conf_groups(mbedtls_ssl_config *conf,
                             const uint16_t *groups);

#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_CERT_ENABLED)
#if !defined(MBEDTLS_DEPRECATED_REMOVED) && defined(MBEDTLS_SSL_PROTO_TLS1_2)

void MBEDTLS_DEPRECATED mbedtls_ssl_conf_sig_hashes(mbedtls_ssl_config *conf,
                                                    const int *hashes);
#endif

void mbedtls_ssl_conf_sig_algs(mbedtls_ssl_config *conf,
                               const uint16_t *sig_algs);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)

int mbedtls_ssl_set_hostname(mbedtls_ssl_context *ssl, const char *hostname);

static inline const char *mbedtls_ssl_get_hostname(mbedtls_ssl_context *ssl)
{
    return ssl->MBEDTLS_PRIVATE(hostname);
}
#endif

#if defined(MBEDTLS_SSL_SERVER_NAME_INDICATION)

const unsigned char *mbedtls_ssl_get_hs_sni(mbedtls_ssl_context *ssl,
                                            size_t *name_len);

int mbedtls_ssl_set_hs_own_cert(mbedtls_ssl_context *ssl,
                                mbedtls_x509_crt *own_cert,
                                mbedtls_pk_context *pk_key);

void mbedtls_ssl_set_hs_ca_chain(mbedtls_ssl_context *ssl,
                                 mbedtls_x509_crt *ca_chain,
                                 mbedtls_x509_crl *ca_crl);

#if defined(MBEDTLS_KEY_EXCHANGE_CERT_REQ_ALLOWED_ENABLED)

void mbedtls_ssl_set_hs_dn_hints(mbedtls_ssl_context *ssl,
                                 const mbedtls_x509_crt *crt);
#endif

void mbedtls_ssl_set_hs_authmode(mbedtls_ssl_context *ssl,
                                 int authmode);

void mbedtls_ssl_conf_sni(mbedtls_ssl_config *conf,
                          int (*f_sni)(void *, mbedtls_ssl_context *, const unsigned char *,
                                       size_t),
                          void *p_sni);
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED)

int mbedtls_ssl_set_hs_ecjpake_password(mbedtls_ssl_context *ssl,
                                        const unsigned char *pw,
                                        size_t pw_len);

int mbedtls_ssl_set_hs_ecjpake_password_opaque(mbedtls_ssl_context *ssl,
                                               mbedtls_svc_key_id_t pwd);
#endif

#if defined(MBEDTLS_SSL_ALPN)

int mbedtls_ssl_conf_alpn_protocols(mbedtls_ssl_config *conf, const char **protos);

const char *mbedtls_ssl_get_alpn_protocol(const mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_SSL_DTLS_SRTP)
#if defined(MBEDTLS_DEBUG_C)
static inline const char *mbedtls_ssl_get_srtp_profile_as_string(mbedtls_ssl_srtp_profile profile)
{
    switch (profile) {
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80:
            return "MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_80";
        case MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32:
            return "MBEDTLS_TLS_SRTP_AES128_CM_HMAC_SHA1_32";
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80:
            return "MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_80";
        case MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32:
            return "MBEDTLS_TLS_SRTP_NULL_HMAC_SHA1_32";
        default: break;
    }
    return "";
}
#endif

void mbedtls_ssl_conf_srtp_mki_value_supported(mbedtls_ssl_config *conf,
                                               int support_mki_value);

int mbedtls_ssl_conf_dtls_srtp_protection_profiles
    (mbedtls_ssl_config *conf,
    const mbedtls_ssl_srtp_profile *profiles);

int mbedtls_ssl_dtls_srtp_set_mki_value(mbedtls_ssl_context *ssl,
                                        unsigned char *mki_value,
                                        uint16_t mki_len);

void mbedtls_ssl_get_dtls_srtp_negotiation_result(const mbedtls_ssl_context *ssl,
                                                  mbedtls_dtls_srtp_info *dtls_srtp_info);
#endif

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

void MBEDTLS_DEPRECATED mbedtls_ssl_conf_max_version(mbedtls_ssl_config *conf, int major,
                                                     int minor);
#endif

static inline void mbedtls_ssl_conf_max_tls_version(mbedtls_ssl_config *conf,
                                                    mbedtls_ssl_protocol_version tls_version)
{
    conf->MBEDTLS_PRIVATE(max_tls_version) = tls_version;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)

void MBEDTLS_DEPRECATED mbedtls_ssl_conf_min_version(mbedtls_ssl_config *conf, int major,
                                                     int minor);
#endif

static inline void mbedtls_ssl_conf_min_tls_version(mbedtls_ssl_config *conf,
                                                    mbedtls_ssl_protocol_version tls_version)
{
    conf->MBEDTLS_PRIVATE(min_tls_version) = tls_version;
}

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)

void mbedtls_ssl_conf_encrypt_then_mac(mbedtls_ssl_config *conf, char etm);
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)

void mbedtls_ssl_conf_extended_master_secret(mbedtls_ssl_config *conf, char ems);
#endif

#if defined(MBEDTLS_SSL_SRV_C)

void mbedtls_ssl_conf_cert_req_ca_list(mbedtls_ssl_config *conf,
                                       char cert_req_ca_list);
#endif

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)

int mbedtls_ssl_conf_max_frag_len(mbedtls_ssl_config *conf, unsigned char mfl_code);
#endif

#if defined(MBEDTLS_SSL_SRV_C)

void mbedtls_ssl_conf_preference_order(mbedtls_ssl_config *conf, int order);
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && defined(MBEDTLS_SSL_CLI_C)

void mbedtls_ssl_conf_session_tickets(mbedtls_ssl_config *conf, int use_tickets);

#if defined(MBEDTLS_SSL_PROTO_TLS1_3)

void mbedtls_ssl_conf_tls13_enable_signal_new_session_tickets(
    mbedtls_ssl_config *conf, int signal_new_session_tickets);

#endif
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS) && \
    defined(MBEDTLS_SSL_SRV_C) && \
    defined(MBEDTLS_SSL_PROTO_TLS1_3)

void mbedtls_ssl_conf_new_session_tickets(mbedtls_ssl_config *conf,
                                          uint16_t num_tickets);
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)

void mbedtls_ssl_conf_renegotiation(mbedtls_ssl_config *conf, int renegotiation);
#endif

void mbedtls_ssl_conf_legacy_renegotiation(mbedtls_ssl_config *conf, int allow_legacy);

#if defined(MBEDTLS_SSL_RENEGOTIATION)

void mbedtls_ssl_conf_renegotiation_enforced(mbedtls_ssl_config *conf, int max_records);

void mbedtls_ssl_conf_renegotiation_period(mbedtls_ssl_config *conf,
                                           const unsigned char period[8]);
#endif

int mbedtls_ssl_check_pending(const mbedtls_ssl_context *ssl);

size_t mbedtls_ssl_get_bytes_avail(const mbedtls_ssl_context *ssl);

uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context *ssl);

int mbedtls_ssl_get_ciphersuite_id_from_ssl(const mbedtls_ssl_context *ssl);

const char *mbedtls_ssl_get_ciphersuite(const mbedtls_ssl_context *ssl);

static inline mbedtls_ssl_protocol_version mbedtls_ssl_get_version_number(
    const mbedtls_ssl_context *ssl)
{
    return ssl->MBEDTLS_PRIVATE(tls_version);
}

const char *mbedtls_ssl_get_version(const mbedtls_ssl_context *ssl);

int mbedtls_ssl_get_record_expansion(const mbedtls_ssl_context *ssl);

int mbedtls_ssl_get_max_out_record_payload(const mbedtls_ssl_context *ssl);

int mbedtls_ssl_get_max_in_record_payload(const mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_X509_CRT_PARSE_C)

const mbedtls_x509_crt *mbedtls_ssl_get_peer_cert(const mbedtls_ssl_context *ssl);
#endif

#if defined(MBEDTLS_SSL_CLI_C)

int mbedtls_ssl_get_session(const mbedtls_ssl_context *ssl,
                            mbedtls_ssl_session *session);
#endif

int mbedtls_ssl_handshake(mbedtls_ssl_context *ssl);

static inline int mbedtls_ssl_is_handshake_over(mbedtls_ssl_context *ssl)
{
    return ssl->MBEDTLS_PRIVATE(state) >= MBEDTLS_SSL_HANDSHAKE_OVER;
}

int mbedtls_ssl_handshake_step(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_RENEGOTIATION)

int mbedtls_ssl_renegotiate(mbedtls_ssl_context *ssl);
#endif

int mbedtls_ssl_read(mbedtls_ssl_context *ssl, unsigned char *buf, size_t len);

int mbedtls_ssl_write(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len);

int mbedtls_ssl_send_alert_message(mbedtls_ssl_context *ssl,
                                   unsigned char level,
                                   unsigned char message);

int mbedtls_ssl_close_notify(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_EARLY_DATA)

#if defined(MBEDTLS_SSL_SRV_C)

int mbedtls_ssl_read_early_data(mbedtls_ssl_context *ssl,
                                unsigned char *buf, size_t len);
#endif

#if defined(MBEDTLS_SSL_CLI_C)

int mbedtls_ssl_write_early_data(mbedtls_ssl_context *ssl,
                                 const unsigned char *buf, size_t len);

int mbedtls_ssl_get_early_data_status(mbedtls_ssl_context *ssl);
#endif

#endif

void mbedtls_ssl_free(mbedtls_ssl_context *ssl);

#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)

int mbedtls_ssl_context_save(mbedtls_ssl_context *ssl,
                             unsigned char *buf,
                             size_t buf_len,
                             size_t *olen);

int mbedtls_ssl_context_load(mbedtls_ssl_context *ssl,
                             const unsigned char *buf,
                             size_t len);
#endif

void mbedtls_ssl_config_init(mbedtls_ssl_config *conf);

int mbedtls_ssl_config_defaults(mbedtls_ssl_config *conf,
                                int endpoint, int transport, int preset);

void mbedtls_ssl_config_free(mbedtls_ssl_config *conf);

void mbedtls_ssl_session_init(mbedtls_ssl_session *session);

void mbedtls_ssl_session_free(mbedtls_ssl_session *session);

int  mbedtls_ssl_tls_prf(const mbedtls_tls_prf_types prf,
                         const unsigned char *secret, size_t slen,
                         const char *label,
                         const unsigned char *random, size_t rlen,
                         unsigned char *dstbuf, size_t dlen);

#if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)

#define MBEDTLS_SSL_EXPORT_MAX_KEY_LEN 8160

int mbedtls_ssl_export_keying_material(mbedtls_ssl_context *ssl,
                                       uint8_t *out, const size_t key_len,
                                       const char *label, const size_t label_len,
                                       const unsigned char *context, const size_t context_len,
                                       const int use_context);
#endif
#ifdef __cplusplus
}
#endif

#endif
