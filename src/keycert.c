// Copyright (C) 2023-2024 Hibiki AI Limited <info@hibiki-ai.com>
//
// This file is part of nanonext.
//
// nanonext is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// nanonext is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// nanonext. If not, see <https://www.gnu.org/licenses/>.

// nanonext - Key Generation and Certificates ----------------------------------

#define NANONEXT_KEYCERT
#include "nanonext.h"

#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR >= 4 || MBEDTLS_VERSION_MAJOR >= 4
static int parse_serial_decimal_format(unsigned char *obuf, size_t obufmax,
                                       const char *ibuf, size_t *len) {

  unsigned long long dec;
  unsigned int remaining_bytes = sizeof(dec);
  unsigned char *p = obuf;
  unsigned char val;
  char *end_ptr = NULL;

  errno = 0;
  dec = strtoull(ibuf, &end_ptr, 10);

  if ((errno != 0) || (end_ptr == ibuf))
    return -1;

  *len = 0;

  while (remaining_bytes > 0) {
    if (obufmax < (*len + 1))
      return -1;

    val = (dec >> ((remaining_bytes - 1) * 8)) & 0xFF;

    if ((val != 0) || (*len != 0)) {
      *p = val;
      (*len)++;
      p++;
    }

    remaining_bytes--;
  }

  return 0;

}
#endif

SEXP rnng_write_cert(SEXP cn, SEXP valid, SEXP inter) {

  const char *common = NANO_STRING(cn);
  const char *not_after = NANO_STRING(valid); /* validity period not after */
  const int interactive = NANO_INTEGER(inter);
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_pk_context key;
  const char *pers = "r-nanonext-key";

  unsigned char key_buf[16000];
  memset(key_buf, 0, 16000);

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_pk_init(&key);

  const char *serialvalue = "1";          /* serial number string (decimal)     */
  const char *not_before = "20010101000000";  /* validity period not before   */
  const int is_ca = 1;                  /* is a CA certificate                */
  const int max_pathlen = 0;            /* maximum CA path length             */
  const int version = 2;                /* CRT version                        */
  const mbedtls_md_type_t md = MBEDTLS_MD_SHA256;   /* Hash used for signing  */

  size_t clen = strlen(common) + 20;
  char issuer_name[clen];          /* issuer name for certificate        */
  snprintf(issuer_name, clen, "CN=%s,O=Nanonext,C=JP", common);

  int xc, exit = 1;
  if (interactive) REprintf("Generating key + certificate [    ]");
  mbedtls_x509_crt issuer_crt;
  mbedtls_pk_context loaded_issuer_key;
  mbedtls_pk_context *issuer_key = &loaded_issuer_key;
  char buf[1024];
  mbedtls_x509_csr csr; // #if defined(MBEDTLS_X509_CSR_PARSE_C)
  mbedtls_x509write_cert crt;
  const char *persn = "certificate";

  mbedtls_x509write_crt_init(&crt);
  mbedtls_pk_init(&loaded_issuer_key);
  mbedtls_x509_csr_init(&csr); // #if defined(MBEDTLS_X509_CSR_PARSE_C)
  mbedtls_x509_crt_init(&issuer_crt);
  memset(buf, 0, sizeof(buf));
  unsigned char output_buf[4096];
  memset(output_buf, 0, 4096);

#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR >= 4 || MBEDTLS_VERSION_MAJOR >= 4
  unsigned char serial[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
  size_t serial_len;
  memset(serial, 0, sizeof(serial));
#else
  mbedtls_mpi serial;
  mbedtls_mpi_init(&serial);
#endif

  if (interactive) REprintf("\b\b\b\b\b.   ]");

  if ((xc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) ||
      (xc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t) MBEDTLS_PK_RSA))))
    goto exitlevel1;

  if (interactive) REprintf("\b\b\b\b\b..  ]");

  if ((xc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537)))
    goto exitlevel1;

  if (interactive) REprintf("\b\b\b\b\b... ]");

  if ((xc = mbedtls_pk_write_key_pem(&key, key_buf, 16000)))
    goto exitlevel1;

  size_t klen = strlen((char *) key_buf);

  if ((xc = mbedtls_ctr_drbg_reseed(&ctr_drbg, (const unsigned char *) persn, strlen(persn))) ||
#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR >= 4 || MBEDTLS_VERSION_MAJOR >= 4
      (xc = parse_serial_decimal_format(serial, sizeof(serial), serialvalue, &serial_len)) ||
#else
      (xc = mbedtls_mpi_read_string(&serial, 10, serialvalue)) ||
#endif
#if MBEDTLS_VERSION_MAJOR >= 3
      (xc = mbedtls_pk_parse_key(&loaded_issuer_key, key_buf, klen + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg)))
#else
      (xc = mbedtls_pk_parse_key(&loaded_issuer_key, key_buf, klen + 1, NULL, 0)))
#endif
    goto exitlevel1;

  mbedtls_x509write_crt_set_subject_key(&crt, issuer_key);
  mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

  if ((xc = mbedtls_x509write_crt_set_subject_name(&crt, issuer_name)) ||
      (xc = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name)))
    goto exitlevel1;

  mbedtls_x509write_crt_set_version(&crt, version);
  mbedtls_x509write_crt_set_md_alg(&crt, md);

#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR >= 4 || MBEDTLS_VERSION_MAJOR >= 4
  if ((xc = mbedtls_x509write_crt_set_serial_raw(&crt, serial, serial_len)) ||
#else
  if ((xc = mbedtls_x509write_crt_set_serial(&crt, &serial)) ||
#endif
      (xc = mbedtls_x509write_crt_set_validity(&crt, not_before, not_after)) ||
      (xc = mbedtls_x509write_crt_set_basic_constraints(&crt, is_ca, max_pathlen)) ||
      (xc = mbedtls_x509write_crt_set_subject_key_identifier(&crt)) ||
      (xc = mbedtls_x509write_crt_set_authority_key_identifier(&crt)) ||
      (xc = mbedtls_x509write_crt_pem(&crt, output_buf, 4096, mbedtls_ctr_drbg_random, &ctr_drbg)))
    goto exitlevel1;

  SEXP vec, kcstr, cstr;
  const char *names[] = {"server", "client", ""};
  PROTECT(vec = Rf_mkNamed(VECSXP, names));
  kcstr = Rf_allocVector(STRSXP, 2);
  SET_VECTOR_ELT(vec, 0, kcstr);
  SET_STRING_ELT(kcstr, 0, Rf_mkChar((char *) &output_buf));
  SET_STRING_ELT(kcstr, 1, Rf_mkChar((char *) key_buf));
  cstr = Rf_allocVector(STRSXP, 2);
  SET_VECTOR_ELT(vec, 1, cstr);
  SET_STRING_ELT(cstr, 0, Rf_mkChar((char *) &output_buf));
  SET_STRING_ELT(cstr, 1, R_BlankString);

  if (interactive) REprintf("\b\b\b\b\bdone]\n");
  exit = 0;

  exitlevel1:

  mbedtls_x509_csr_free(&csr); // #if defined(MBEDTLS_X509_CSR_PARSE_C)
  mbedtls_x509_crt_free(&issuer_crt);
  mbedtls_x509write_crt_free(&crt);
  mbedtls_pk_free(&loaded_issuer_key);
#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR < 4 || MBEDTLS_VERSION_MAJOR < 3
  mbedtls_mpi_free(&serial);
#endif
  mbedtls_pk_free(&key);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  if (exit) {
    mbedtls_strerror(xc, buf, sizeof(buf));
    Rf_error("%d | %s", xc, buf);
  }

  UNPROTECT(1);
  return vec;

}
