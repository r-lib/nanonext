// nanonext - C level - Mbed TLS Functions -------------------------------------

#define NANONEXT_TLS
#include "nanonext.h"

// internals -------------------------------------------------------------------

static SEXP nano_hash_char(unsigned char *buf, const size_t sz) {

  SEXP out;
  char cbuf[sz + sz + 1];
  char *cptr = cbuf;

  for (size_t i = 0; i < sz; i++)
    cptr += snprintf(cptr, 3, "%.2x", buf[i]);

  PROTECT(out = Rf_allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, Rf_mkCharLenCE(cbuf, (int) (sz + sz), CE_NATIVE));

  UNPROTECT(1);
  return out;

}

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

// Mbed TLS Random Data Generator ----------------------------------------------

SEXP rnng_random(SEXP n, SEXP convert) {

#ifdef MBEDTLS_PSA_CRYPTO_C
  psa_crypto_init();
#endif

  int sz, xc;
  switch (TYPEOF(n)) {
  case INTSXP:
  case LGLSXP:
    sz = NANO_INTEGER(n);
    if (sz > 0 && sz <= 1024) break;
  case REALSXP:
    sz = Rf_asInteger(n);
    if (sz > 0 && sz <= 1024) break;
  default:
    Rf_error("`n` must be an integer value between 1 and 1024");
  }

  SEXP out;
  unsigned char buf[sz];
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *pers = "r-nanonext-rng";

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  xc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
  if (xc == 0) {
    xc = mbedtls_ctr_drbg_random(&ctr_drbg, buf, sz);
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  if (xc)
    Rf_error("error generating random bytes");

  if (NANO_INTEGER(convert)) {
    out = nano_hash_char(buf, sz);
  } else {
    out = Rf_allocVector(RAWSXP, sz);
    if (sz)
      memcpy(NANO_DATAPTR(out), buf, sz);
  }

  return out;

}

// nanonext - Key Generation and Certificates ----------------------------------

SEXP rnng_write_cert(SEXP cn, SEXP valid) {

#ifdef MBEDTLS_PSA_CRYPTO_C
  psa_crypto_init();
#endif

  const char *common = CHAR(STRING_ELT(cn, 0));
  const char *not_after = CHAR(STRING_ELT(valid, 0)); /* validity period not after */
  mbedtls_entropy_context entropy = {0};
  mbedtls_ctr_drbg_context ctr_drbg = {0};
  mbedtls_pk_context key = {0};
  const char *pers = "r-nanonext-key";

  unsigned char key_buf[16000] = {0};

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

  int xc, error = 1;
  mbedtls_x509_crt issuer_crt = {0};
  mbedtls_pk_context loaded_issuer_key = {0};
  mbedtls_pk_context *issuer_key = &loaded_issuer_key;
  char buf[1024] = {0};
  mbedtls_x509_csr csr; // #if defined(MBEDTLS_X509_CSR_PARSE_C)
  mbedtls_x509write_cert crt;
  const char *persn = "certificate";

  mbedtls_x509write_crt_init(&crt);
  mbedtls_pk_init(&loaded_issuer_key);
  mbedtls_x509_csr_init(&csr); // #if defined(MBEDTLS_X509_CSR_PARSE_C)
  mbedtls_x509_crt_init(&issuer_crt);
  unsigned char output_buf[4096] = {0};

#if MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR >= 4 || MBEDTLS_VERSION_MAJOR >= 4
  unsigned char serial[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN] = {0};
  size_t serial_len;
#else
  mbedtls_mpi serial = {0};
  mbedtls_mpi_init(&serial);
#endif

  if ((xc = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen(pers))) ||
      (xc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t) MBEDTLS_PK_RSA))) ||
      (xc = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537)) ||
      (xc = mbedtls_pk_write_key_pem(&key, key_buf, 16000)))
    goto cleanup;

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
    goto cleanup;

  mbedtls_x509write_crt_set_subject_key(&crt, issuer_key);
  mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

  if ((xc = mbedtls_x509write_crt_set_subject_name(&crt, issuer_name)) ||
      (xc = mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name)))
    goto cleanup;

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
    goto cleanup;

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

  error = 0;

  cleanup:

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

  if (error) {
    mbedtls_strerror(xc, buf, sizeof(buf));
    Rf_error("%d | %s", xc, buf);
  }

  UNPROTECT(1);
  return vec;

}

// TLS Config ------------------------------------------------------------------

SEXP rnng_tls_config(SEXP client, SEXP server, SEXP pass, SEXP auth) {

  const nng_tls_auth_mode mod = NANO_INTEGER(auth) ? NNG_TLS_AUTH_MODE_REQUIRED : NNG_TLS_AUTH_MODE_OPTIONAL;
  R_xlen_t usefile;
  nng_tls_config *cfg = NULL;
  int xc;
  const char *crl, *file, *key, *pss;
  SEXP xp;

  if (client != R_NilValue) {
    file = CHAR(STRING_ELT(client, 0));
    usefile = XLENGTH(client);
    if ((xc = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) ||
        (xc = nng_tls_config_auth_mode(cfg, mod)))
      goto fail;

    if (usefile > 1) {
      crl = NANO_STR_N(client, 1);
      if ((xc = nng_tls_config_ca_chain(cfg, file, strncmp(crl, "", 1) ? crl : NULL)))
        goto fail;
    } else {
      file = R_ExpandFileName(file);
      if ((xc = nng_tls_config_ca_file(cfg, file)))
        goto fail;
    }

  } else if (server != R_NilValue) {
    file = CHAR(STRING_ELT(server, 0));
    usefile = XLENGTH(server);
    pss = pass != R_NilValue ? CHAR(STRING_ELT(pass, 0)) : NULL;
    if ((xc = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_SERVER)) ||
        (xc = nng_tls_config_auth_mode(cfg, mod)))
      goto fail;

    if (usefile > 1) {
      key = NANO_STR_N(server, 1);
      if ((xc = nng_tls_config_own_cert(cfg, file, key, pss)))
        goto fail;
    } else {
      file = R_ExpandFileName(file);
      if ((xc = nng_tls_config_cert_key_file(cfg, file, pss)))
        goto fail;
    }

  } else {
    if ((xc = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) ||
        (xc = nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE)))
      goto fail;
  }

  PROTECT(xp = R_MakeExternalPtr(cfg, nano_TlsSymbol, R_NilValue));
  R_RegisterCFinalizerEx(xp, tls_finalizer, TRUE);
  Rf_classgets(xp, Rf_mkString("tlsConfig"));
  if (client != R_NilValue) {
    Rf_setAttrib(xp, R_SpecSymbol, Rf_mkString("client"));
    Rf_setAttrib(xp, R_ModeSymbol, Rf_mkString(mod == NNG_TLS_AUTH_MODE_REQUIRED ? "required" : "optional"));
  } else if (server != R_NilValue) {
    Rf_setAttrib(xp, R_SpecSymbol, Rf_mkString("server"));
    Rf_setAttrib(xp, R_ModeSymbol, Rf_mkString(mod == NNG_TLS_AUTH_MODE_REQUIRED ? "required" : "optional"));
  } else {
    Rf_setAttrib(xp, R_SpecSymbol, Rf_mkString("client"));
    Rf_setAttrib(xp, R_ModeSymbol, Rf_mkString("none"));
  }

  UNPROTECT(1);
  return xp;

  fail:
  if (cfg != NULL)
    nng_tls_config_free(cfg);
  ERROR_OUT(xc);

}

// utils -----------------------------------------------------------------------

SEXP rnng_version(void) {

  char mbed_version_string[18];
  mbedtls_version_get_string_full(mbed_version_string);
  SEXP version;
  PROTECT(version = Rf_allocVector(STRSXP, 2));
  SET_STRING_ELT(version, 0, Rf_mkChar(nng_version()));
  SET_STRING_ELT(version, 1, Rf_mkChar(mbed_version_string));
  UNPROTECT(1);

  return version;

}
