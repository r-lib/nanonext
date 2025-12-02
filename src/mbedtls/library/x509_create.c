/*
 *  X.509 base functions for creating certificates / CSRs
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#include "common.h"
#if defined(MBEDTLS_X509_CREATE_C)
#include "x509_internal.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include <string.h>
#include "mbedtls/platform.h"
#include "mbedtls/asn1.h"
typedef struct {
    const char *name;
    size_t name_len;
    const char *oid;
    int default_tag;
} x509_attr_descriptor_t;
#define ADD_STRLEN(s) s, sizeof(s) - 1
static const x509_attr_descriptor_t x509_attrs[] =
{
    { ADD_STRLEN("CN"),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("commonName"),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("C"),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("countryName"),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("O"),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationName"),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("L"),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("locality"),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("R"),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("OU"),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("organizationalUnitName"),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("ST"),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("stateOrProvinceName"),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("emailAddress"),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("serialNumber"),
      MBEDTLS_OID_AT_SERIAL_NUMBER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalAddress"),
      MBEDTLS_OID_AT_POSTAL_ADDRESS, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("postalCode"),
      MBEDTLS_OID_AT_POSTAL_CODE, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("dnQualifier"),
      MBEDTLS_OID_AT_DN_QUALIFIER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN("title"),
      MBEDTLS_OID_AT_TITLE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("surName"),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("SN"),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("givenName"),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("GN"),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("initials"),
      MBEDTLS_OID_AT_INITIALS, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("pseudonym"),
      MBEDTLS_OID_AT_PSEUDONYM, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("generationQualifier"),
      MBEDTLS_OID_AT_GENERATION_QUALIFIER, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN("domainComponent"),
      MBEDTLS_OID_DOMAIN_COMPONENT, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN("DC"),
      MBEDTLS_OID_DOMAIN_COMPONENT, MBEDTLS_ASN1_IA5_STRING },
    { NULL, 0, NULL, MBEDTLS_ASN1_NULL }
};
static const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len)
{
    const x509_attr_descriptor_t *cur;
    for (cur = x509_attrs; cur->name != NULL; cur++) {
        if (cur->name_len == name_len &&
            strncmp(cur->name, name, name_len) == 0) {
            break;
        }
    }
    if (cur->name == NULL) {
        return NULL;
    }
    return cur;
}
static int hex_to_int(char c)
{
    return ('0' <= c && c <= '9') ? (c - '0') :
           ('a' <= c && c <= 'f') ? (c - 'a' + 10) :
           ('A' <= c && c <= 'F') ? (c - 'A' + 10) : -1;
}
static int hexpair_to_int(const char *hexpair)
{
    int n1 = hex_to_int(*hexpair);
    int n2 = hex_to_int(*(hexpair + 1));
    if (n1 != -1 && n2 != -1) {
        return (n1 << 4) | n2;
    } else {
        return -1;
    }
}
static int parse_attribute_value_string(const char *s,
                                        int len,
                                        unsigned char *data,
                                        size_t *data_len)
{
    const char *c;
    const char *end = s + len;
    unsigned char *d = data;
    int n;
    for (c = s; c < end; c++) {
        if (*c == '\\') {
            c++;
            if (c + 1 < end && (n = hexpair_to_int(c)) != -1) {
                if (n == 0) {
                    return MBEDTLS_ERR_X509_INVALID_NAME;
                }
                *(d++) = n;
                c++;
            } else if (c < end && strchr(" ,=+<>#;\"\\", *c)) {
                *(d++) = *c;
            } else {
                return MBEDTLS_ERR_X509_INVALID_NAME;
            }
        } else {
            *(d++) = *c;
        }
        if (d - data == MBEDTLS_X509_MAX_DN_NAME_SIZE) {
            return MBEDTLS_ERR_X509_INVALID_NAME;
        }
    }
    *data_len = (size_t) (d - data);
    return 0;
}
static int parse_attribute_value_hex_der_encoded(const char *s,
                                                 size_t len,
                                                 unsigned char *data,
                                                 size_t data_size,
                                                 size_t *data_len,
                                                 int *tag)
{
    if (len % 2 != 0) {
        return MBEDTLS_ERR_X509_INVALID_NAME;
    }
    size_t const der_length = len / 2;
    if (der_length > MBEDTLS_X509_MAX_DN_NAME_SIZE + 4) {
        return MBEDTLS_ERR_X509_INVALID_NAME;
    }
    if (der_length < 1) {
        return MBEDTLS_ERR_X509_INVALID_NAME;
    }
    unsigned char *der = mbedtls_calloc(1, der_length);
    if (der == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    for (size_t i = 0; i < der_length; i++) {
        int c = hexpair_to_int(s + 2 * i);
        if (c < 0) {
            goto error;
        }
        der[i] = c;
    }
    *tag = der[0];
    {
        unsigned char *p = der + 1;
        if (mbedtls_asn1_get_len(&p, der + der_length, data_len) != 0) {
            goto error;
        }
        if (*data_len > MBEDTLS_X509_MAX_DN_NAME_SIZE) {
            goto error;
        }
        if (MBEDTLS_ASN1_IS_STRING_TAG(*tag)) {
            for (size_t i = 0; i < *data_len; i++) {
                if (p[i] == 0) {
                    goto error;
                }
            }
        }
        if (*data_len > data_size) {
            goto error;
        }
        memcpy(data, p, *data_len);
    }
    mbedtls_free(der);
    return 0;
error:
    mbedtls_free(der);
    return MBEDTLS_ERR_X509_INVALID_NAME;
}
int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name)
{
    int ret = MBEDTLS_ERR_X509_INVALID_NAME;
    int parse_ret = 0;
    const char *s = name, *c = s;
    const char *end = s + strlen(s);
    mbedtls_asn1_buf oid = { .p = NULL, .len = 0, .tag = MBEDTLS_ASN1_NULL };
    const x509_attr_descriptor_t *attr_descr = NULL;
    int in_attr_type = 1;
    int tag;
    int numericoid = 0;
    unsigned char data[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    size_t data_len = 0;
    mbedtls_asn1_free_named_data_list(head);
    while (c <= end) {
        if (in_attr_type && *c == '=') {
            if ((attr_descr = x509_attr_descr_from_name(s, (size_t) (c - s))) == NULL) {
                if ((mbedtls_oid_from_numeric_string(&oid, s, (size_t) (c - s))) != 0) {
                    return MBEDTLS_ERR_X509_INVALID_NAME;
                } else {
                    numericoid = 1;
                }
            } else {
                oid.len = strlen(attr_descr->oid);
                oid.p = mbedtls_calloc(1, oid.len);
                memcpy(oid.p, attr_descr->oid, oid.len);
                numericoid = 0;
            }
            s = c + 1;
            in_attr_type = 0;
        }
        if (!in_attr_type && ((*c == ',' && *(c-1) != '\\') || c == end)) {
            if (s == c) {
                mbedtls_free(oid.p);
                return MBEDTLS_ERR_X509_INVALID_NAME;
            } else if (*s == '#') {
                parse_ret = parse_attribute_value_hex_der_encoded(
                    s + 1, (size_t) (c - s) - 1,
                    data, sizeof(data), &data_len, &tag);
                if (parse_ret != 0) {
                    mbedtls_free(oid.p);
                    return parse_ret;
                }
            } else {
                if (numericoid) {
                    mbedtls_free(oid.p);
                    return MBEDTLS_ERR_X509_INVALID_NAME;
                } else {
                    if ((parse_ret =
                             parse_attribute_value_string(s, (int) (c - s), data,
                                                          &data_len)) != 0) {
                        mbedtls_free(oid.p);
                        return parse_ret;
                    }
                    tag = attr_descr->default_tag;
                }
            }
            mbedtls_asn1_named_data *cur =
                mbedtls_asn1_store_named_data(head, (char *) oid.p, oid.len,
                                              (unsigned char *) data,
                                              data_len);
            mbedtls_free(oid.p);
            oid.p = NULL;
            if (cur == NULL) {
                return MBEDTLS_ERR_X509_ALLOC_FAILED;
            }
            cur->val.tag = tag;
            while (c < end && *(c + 1) == ' ') {
                c++;
            }
            s = c + 1;
            in_attr_type = 1;
            ret = 0;
        }
        c++;
    }
    if (oid.p != NULL) {
        mbedtls_free(oid.p);
    }
    return ret;
}
int mbedtls_x509_set_extension(mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                               int critical, const unsigned char *val, size_t val_len)
{
    mbedtls_asn1_named_data *cur;
    if (val_len > (SIZE_MAX - 1)) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    if ((cur = mbedtls_asn1_store_named_data(head, oid, oid_len,
                                             NULL, val_len + 1)) == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    cur->val.p[0] = critical;
    memcpy(cur->val.p + 1, val, val_len);
    return 0;
}
static int x509_write_name(unsigned char **p,
                           unsigned char *start,
                           mbedtls_asn1_named_data *cur_name)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    const char *oid = (const char *) cur_name->oid.p;
    size_t oid_len = cur_name->oid.len;
    const unsigned char *name = cur_name->val.p;
    size_t name_len = cur_name->val.len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tagged_string(p, start,
                                                               cur_name->val.tag,
                                                               (const char *) name,
                                                               name_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_oid(p, start, oid,
                                                     oid_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SET));
    return (int) len;
}
int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_asn1_named_data *cur = first;
    while (cur != NULL) {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_name(p, start, cur));
        cur = cur->next;
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}
int mbedtls_x509_write_sig(unsigned char **p, unsigned char *start,
                           const char *oid, size_t oid_len,
                           unsigned char *sig, size_t size,
                           mbedtls_pk_type_t pk_alg)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int write_null_par;
    size_t len = 0;
    if (*p < start || (size_t) (*p - start) < size) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    len = size;
    (*p) -= len;
    memcpy(*p, sig, len);
    if (*p - start < 1) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    *--(*p) = 0;
    len += 1;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BIT_STRING));
    if (pk_alg == MBEDTLS_PK_ECDSA) {
        write_null_par = 0;
    } else {
        write_null_par = 1;
    }
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier_ext(p, start, oid, oid_len,
                                                                     0, write_null_par));
    return (int) len;
}
static int x509_write_extension(unsigned char **p, unsigned char *start,
                                mbedtls_asn1_named_data *ext)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, ext->val.p + 1,
                                                            ext->val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext->val.len - 1));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));
    if (ext->val.p[0] != 0) {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bool(p, start, 1));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, ext->oid.p,
                                                            ext->oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, ext->oid.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OID));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}
int mbedtls_x509_write_extensions(unsigned char **p, unsigned char *start,
                                  mbedtls_asn1_named_data *first)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_asn1_named_data *cur_ext = first;
    while (cur_ext != NULL) {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_extension(p, start, cur_ext));
        cur_ext = cur_ext->next;
    }
    return (int) len;
}
#endif
