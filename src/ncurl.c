// nanonext - C level - ncurl --------------------------------------------------

#define NANONEXT_HTTP
#include "nanonext.h"

// internals -------------------------------------------------------------------

static SEXP mk_error_haio(const int xc, SEXP env) {

  SEXP err = PROTECT(Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ResultSymbol, err, env);
  Rf_defineVar(nano_ProtocolSymbol, err, env);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(nano_AioSymbol, R_NilValue, env);
  UNPROTECT(1);
  return err;

}

static SEXP mk_error_ncurl(const int xc) {

  const char *names[] = {"status", "headers", "data", ""};
  SEXP out = PROTECT(Rf_mkNamed(VECSXP, names));
  SEXP err = PROTECT(Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  SET_VECTOR_ELT(out, 0, err);
  SET_VECTOR_ELT(out, 1, err);
  SET_VECTOR_ELT(out, 2, err);
  UNPROTECT(2);
  return out;

}

static SEXP mk_error_ncurlaio(const int xc) {

  SEXP env, err;
  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  NANO_CLASS2(env, "ncurlAio", "recvAio");
  PROTECT(err = Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ResultSymbol, err, env);
  Rf_defineVar(nano_StatusSymbol, err, env);
  Rf_defineVar(nano_ProtocolSymbol, err, env);
  Rf_defineVar(nano_HeadersSymbol, err, env);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(nano_DataSymbol, err, env);
  UNPROTECT(2);
  return env;

}

static nano_buf nano_char_buf(const SEXP data) {

  nano_buf buf = {0};
  switch (TYPEOF(data)) {
  case STRSXP: ;
    const char *s = NANO_STRING(data);
    NANO_INIT(&buf, (unsigned char *) s, strlen(s));
    break;
  case RAWSXP:
    NANO_INIT(&buf, NANO_DATAPTR(data), XLENGTH(data));
    break;
  }

  return buf;

}

// aio completion callbacks ----------------------------------------------------

static void haio_complete(void *arg) {

  nano_aio *haio = (nano_aio *) arg;
  const int res = nng_aio_result(haio->aio);
  haio->result = res - !res;

  if (haio->cb != NULL)
    later2(haio_invoke_cb, haio->cb);

}

static void session_complete(void *arg) {

  nano_aio *haio = (nano_aio *) arg;
  const int res = nng_aio_result(haio->aio);
  haio->result = res - !res;

}

// finalisers ------------------------------------------------------------------

static void haio_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nano_handle *handle = (nano_handle *) xp->next;
  nng_aio_free(xp->aio);
  if (handle->cfg != NULL)
    nng_tls_config_free(handle->cfg);
  nng_http_res_free(handle->res);
  nng_http_req_free(handle->req);
  nng_http_client_free(handle->cli);
  nng_url_free(handle->url);
  free(handle);
  free(xp);

}

static void session_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nano_aio *xp = (nano_aio *) NANO_PTR(xptr);
  nano_handle *handle = (nano_handle *) xp->next;
  if (xp->data != NULL)
    nng_http_conn_close((nng_http_conn *) xp->data);
  nng_aio_free(xp->aio);
  if (handle->cfg != NULL)
    nng_tls_config_free(handle->cfg);
  nng_http_res_free(handle->res);
  nng_http_req_free(handle->req);
  nng_http_client_free(handle->cli);
  nng_url_free(handle->url);
  free(handle);
  free(xp);

}

// ncurl - internal ------------------------------------------------------------

static inline SEXP create_aio_http(SEXP env, nano_aio *haio, int typ) {

  if (haio->result > 0)
    return mk_error_haio(haio->result, env);

  void *dat;
  size_t sz;
  SEXP out, vec, rvec, response;
  nano_handle *handle = (nano_handle *) haio->next;

  PROTECT(response = Rf_findVarInFrame(env, nano_ResponseSymbol));
  int chk_resp = response != R_NilValue && TYPEOF(response) == STRSXP;
  const uint16_t code = nng_http_res_get_status(handle->res), relo = code >= 300 && code < 400;
  Rf_defineVar(nano_ResultSymbol, Rf_ScalarInteger(code), env);

  if (relo) {
    if (chk_resp) {
      const R_xlen_t rlen = XLENGTH(response);
      PROTECT(response = Rf_xlengthgets(response, rlen + 1));
      SET_STRING_ELT(response, rlen, Rf_mkChar("Location"));
    } else {
      PROTECT(response = Rf_mkString("Location"));
      chk_resp = 1;
    }
  }

  if (chk_resp) {
    const R_xlen_t rlen = XLENGTH(response);
    PROTECT(rvec = Rf_allocVector(VECSXP, rlen));
    Rf_namesgets(rvec, response);
    for (R_xlen_t i = 0; i < rlen; i++) {
      const char *r = nng_http_res_get_header(handle->res, NANO_STR_N(response, i));
      SET_VECTOR_ELT(rvec, i, r == NULL ? R_NilValue : Rf_mkString(r));
    }
    UNPROTECT(1);
  } else {
    rvec = R_NilValue;
  }
  if (relo) UNPROTECT(1);
  UNPROTECT(1);
  Rf_defineVar(nano_ProtocolSymbol, rvec, env);

  nng_http_res_get_data(handle->res, &dat, &sz);

  if (haio->mode) {
    vec = nano_raw_char(dat, sz);
  } else {
    vec = Rf_allocVector(RAWSXP, sz);
    if (dat != NULL)
      memcpy(NANO_DATAPTR(vec), dat, sz);
  }
  Rf_defineVar(nano_ValueSymbol, vec, env);

  Rf_defineVar(nano_AioSymbol, R_NilValue, env);

  switch (typ) {
  case 0: out = Rf_findVarInFrame(env, nano_ResultSymbol); break;
  case 1: out = Rf_findVarInFrame(env, nano_ProtocolSymbol); break;
  default: out = Rf_findVarInFrame(env, nano_ValueSymbol); break;
  }
  return out;

}

static inline SEXP nano_aio_http_impl(SEXP env, const int typ) {

  SEXP exist;
  switch (typ) {
  case 0: exist = Rf_findVarInFrame(env, nano_ResultSymbol); break;
  case 1: exist = Rf_findVarInFrame(env, nano_ProtocolSymbol); break;
  default: exist = Rf_findVarInFrame(env, nano_ValueSymbol); break;
  }
  if (exist != R_UnboundValue)
    return exist;

  const SEXP aio = Rf_findVarInFrame(env, nano_AioSymbol);
  nano_aio *haio = (nano_aio *) NANO_PTR(aio);

  if (nng_aio_busy(haio->aio))
    return nano_unresolved;

  return create_aio_http(env, haio, typ);

}

SEXP nano_aio_http_status(SEXP env) {

  SEXP exist = Rf_findVarInFrame(env, nano_ResultSymbol);
  if (exist != R_UnboundValue)
    return exist;

  const SEXP aio = Rf_findVarInFrame(env, nano_AioSymbol);
  nano_aio *haio = (nano_aio *) NANO_PTR(aio);

  return create_aio_http(env, haio, 0);

}

// ncurl - minimalist http client ----------------------------------------------

SEXP rnng_ncurl(SEXP http, SEXP convert, SEXP follow, SEXP method, SEXP headers,
                SEXP data, SEXP response, SEXP timeout, SEXP tls) {

  const char *addr = CHAR(STRING_ELT(http, 0));
  const char *mthd = method != R_NilValue ? CHAR(STRING_ELT(method, 0)) : NULL;
  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");
  int chk_resp = response != R_NilValue && TYPEOF(response) == STRSXP;

  nng_url *url = NULL;
  nng_http_client *client = NULL;
  nng_http_req *req = NULL;
  nng_http_res *res = NULL;
  nng_aio *aio = NULL;
  nng_tls_config *cfg = NULL;
  uint16_t code, relo;
  int xc;

  if ((xc = nng_url_parse(&url, addr)))
    goto fail;

  relocall:

  if ((xc = nng_http_client_alloc(&client, url)) ||
      (xc = nng_http_req_alloc(&req, url)) ||
      (xc = nng_http_res_alloc(&res)) ||
      (xc = nng_aio_alloc(&aio, NULL, NULL)))
    goto fail;

  if (mthd != NULL && (xc = nng_http_req_set_method(req, mthd)))
    goto fail;

  if (headers != R_NilValue && TYPEOF(headers) == STRSXP) {
    const R_xlen_t hlen = XLENGTH(headers);
    SEXP hnames = Rf_getAttrib(headers, R_NamesSymbol);
    if (TYPEOF(hnames) == STRSXP && XLENGTH(hnames) == hlen) {
      for (R_xlen_t i = 0; i < hlen; i++) {
        if ((xc = nng_http_req_set_header(req, NANO_STR_N(hnames, i), NANO_STR_N(headers, i))))
          goto fail;
      }
    }
  }
  if (data != R_NilValue) {
    nano_buf enc = nano_char_buf(data);
    if (enc.cur && (xc = nng_http_req_set_data(req, enc.buf, enc.cur)))
      goto fail;
  }

  if (!strcmp(url->u_scheme, "https")) {

    if (tls == R_NilValue) {
      if ((xc = nng_tls_config_alloc(&cfg, NNG_TLS_MODE_CLIENT)) ||
          (xc = nng_tls_config_server_name(cfg, url->u_hostname)) ||
          (xc = nng_tls_config_auth_mode(cfg, NNG_TLS_AUTH_MODE_NONE)) ||
          (xc = nng_http_client_set_tls(client, cfg)))
        goto fail;

    } else {
      cfg = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(cfg);

      if ((xc = nng_tls_config_server_name(cfg, url->u_hostname)) ||
          (xc = nng_http_client_set_tls(client, cfg)))
        goto fail;
    }

  }

  nng_aio_set_timeout(aio, dur);
  nng_http_client_transact(client, req, res, aio);
  nng_aio_wait(aio);
  if ((xc = nng_aio_result(aio)))
    goto fail;

  if (cfg != NULL)
    nng_tls_config_free(cfg);
  nng_aio_free(aio);

  code = nng_http_res_get_status(res), relo = code >= 300 && code < 400;

  if (relo && NANO_INTEGER(follow)) {
    const char *location = nng_http_res_get_header(res, "Location");
    if (location == NULL) goto resume;
    nng_url *oldurl = url;
    xc = nng_url_parse(&url, location);
    if (xc) goto resume;
    nng_http_res_free(res);
    res = NULL;
    nng_http_req_free(req);
    req = NULL;
    nng_http_client_free(client);
    client = NULL;
    nng_url_free(oldurl);
    cfg = NULL;
    goto relocall;
  }

  resume: ;

  SEXP out, vec, rvec;
  void *dat;
  size_t sz;
  const char *names[] = {"status", "headers", "data", ""};

  PROTECT(out = Rf_mkNamed(VECSXP, names));

  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(code));

  if (relo) {
    if (chk_resp) {
      const R_xlen_t rlen = XLENGTH(response);
      PROTECT(response = Rf_xlengthgets(response, rlen + 1));
      SET_STRING_ELT(response, rlen, Rf_mkChar("Location"));
    } else {
      PROTECT(response = Rf_mkString("Location"));
      chk_resp = 1;
    }
  }

  if (chk_resp) {
    const R_xlen_t rlen = XLENGTH(response);
    rvec = Rf_allocVector(VECSXP, rlen);
    SET_VECTOR_ELT(out, 1, rvec);
    Rf_namesgets(rvec, response);
    for (R_xlen_t i = 0; i < rlen; i++) {
      const char *r = nng_http_res_get_header(res, NANO_STR_N(response, i));
      SET_VECTOR_ELT(rvec, i, r == NULL ? R_NilValue : Rf_mkString(r));
    }
  } else {
    rvec = R_NilValue;
    SET_VECTOR_ELT(out, 1, rvec);
  }
  if (relo) UNPROTECT(1);

  nng_http_res_get_data(res, &dat, &sz);

  if (NANO_INTEGER(convert)) {
    vec = nano_raw_char(dat, sz);
  } else {
    vec = Rf_allocVector(RAWSXP, sz);
    if (dat != NULL)
      memcpy(NANO_DATAPTR(vec), dat, sz);
  }
  SET_VECTOR_ELT(out, 2, vec);

  nng_http_res_free(res);
  nng_http_req_free(req);
  nng_http_client_free(client);
  nng_url_free(url);

  UNPROTECT(1);
  return out;

  fail:
  if (cfg != NULL)
    nng_tls_config_free(cfg);
  nng_aio_free(aio);
  if (res != NULL)
    nng_http_res_free(res);
  if (req != NULL)
    nng_http_req_free(req);
  if (client != NULL)
    nng_http_client_free(client);
  nng_url_free(url);
  return mk_error_ncurl(xc);

}

// ncurl aio -------------------------------------------------------------------

SEXP rnng_ncurl_aio(SEXP http, SEXP convert, SEXP method, SEXP headers, SEXP data,
                    SEXP response, SEXP timeout, SEXP tls, SEXP clo) {

  const char *httr = CHAR(STRING_ELT(http, 0));
  const char *mthd = method != R_NilValue ? CHAR(STRING_ELT(method, 0)) : NULL;
  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  SEXP aio, env, fun;
  int xc;
  nano_aio *haio = NULL;
  nano_handle *handle = NULL;
  haio = calloc(1, sizeof(nano_aio));
  NANO_ENSURE_ALLOC(haio);
  handle = calloc(1, sizeof(nano_handle));
  NANO_ENSURE_ALLOC(handle);

  haio->type = HTTP_AIO;
  haio->mode = (uint8_t) NANO_INTEGER(convert);
  haio->next = handle;

  if ((xc = nng_url_parse(&handle->url, httr)) ||
      (xc = nng_http_client_alloc(&handle->cli, handle->url)) ||
      (xc = nng_http_req_alloc(&handle->req, handle->url)) ||
      (xc = nng_http_res_alloc(&handle->res)) ||
      (xc = nng_aio_alloc(&haio->aio, haio_complete, haio)))
    goto fail;

  if (mthd != NULL && (xc = nng_http_req_set_method(handle->req, mthd)))
    goto fail;

  if (headers != R_NilValue && TYPEOF(headers) == STRSXP) {
    const R_xlen_t hlen = XLENGTH(headers);
    SEXP hnames = Rf_getAttrib(headers, R_NamesSymbol);
    if (TYPEOF(hnames) == STRSXP && XLENGTH(hnames) == hlen) {
      for (R_xlen_t i = 0; i < hlen; i++) {
        if ((xc = nng_http_req_set_header(handle->req, NANO_STR_N(hnames, i), NANO_STR_N(headers, i))))
          goto fail;
      }
    }
  }
  if (data != R_NilValue) {
    nano_buf enc = nano_char_buf(data);
    if (enc.cur && (xc = nng_http_req_copy_data(handle->req, enc.buf, enc.cur)))
      goto fail;
  }

  if (!strcmp(handle->url->u_scheme, "https")) {

    if (tls == R_NilValue) {
      if ((xc = nng_tls_config_alloc(&handle->cfg, NNG_TLS_MODE_CLIENT)) ||
          (xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_tls_config_auth_mode(handle->cfg, NNG_TLS_AUTH_MODE_NONE)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto fail;

    } else {
      handle->cfg = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(handle->cfg);

      if ((xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto fail;
    }

  }

  nng_aio_set_timeout(haio->aio, dur);
  nng_http_client_transact(handle->cli, handle->req, handle->res, haio->aio);

  PROTECT(aio = R_MakeExternalPtr(haio, nano_AioSymbol, R_NilValue));
  R_RegisterCFinalizerEx(aio, haio_finalizer, TRUE);

  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  NANO_CLASS2(env, "ncurlAio", "recvAio");
  Rf_defineVar(nano_AioSymbol, aio, env);
  Rf_defineVar(nano_ResponseSymbol, response, env);

  int i = 0;
  for (SEXP fnlist = nano_aioNFuncs; fnlist != R_NilValue; fnlist = CDR(fnlist)) {
    PROTECT(fun = R_mkClosure(R_NilValue, CAR(fnlist), clo));
    switch (++i) {
    case 1: R_MakeActiveBinding(nano_StatusSymbol, fun, env);
    case 2: R_MakeActiveBinding(nano_HeadersSymbol, fun, env);
    case 3: R_MakeActiveBinding(nano_DataSymbol, fun, env);
    }
    UNPROTECT(1);
  }

  UNPROTECT(2);
  return env;

  fail:
  if (handle->cfg != NULL)
    nng_tls_config_free(handle->cfg);
  nng_aio_free(haio->aio);
  if (handle->res != NULL)
    nng_http_res_free(handle->res);
  if (handle->req != NULL)
    nng_http_req_free(handle->req);
  if (handle->cli != NULL)
    nng_http_client_free(handle->cli);
  nng_url_free(handle->url);
  failmem:
  free(handle);
  free(haio);
  return mk_error_ncurlaio(xc);

}

SEXP rnng_aio_http_status(SEXP env) {
  return nano_aio_http_impl(env, 0);
}

SEXP rnng_aio_http_headers(SEXP env) {
  return nano_aio_http_impl(env, 1);
}

SEXP rnng_aio_http_data(SEXP env) {
  return nano_aio_http_impl(env, 2);
}

// ncurl session ---------------------------------------------------------------

SEXP rnng_ncurl_session(SEXP http, SEXP convert, SEXP method, SEXP headers, SEXP data,
                        SEXP response, SEXP timeout, SEXP tls) {

  const char *httr = CHAR(STRING_ELT(http, 0));
  const char *mthd = method != R_NilValue ? CHAR(STRING_ELT(method, 0)) : NULL;
  const nng_duration dur = timeout == R_NilValue ? NNG_DURATION_DEFAULT : (nng_duration) nano_integer(timeout);
  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  SEXP sess;
  int xc;
  nano_aio *haio = NULL;
  nano_handle *handle = NULL;
  haio = calloc(1, sizeof(nano_aio));
  NANO_ENSURE_ALLOC(haio);
  handle = calloc(1, sizeof(nano_handle));
  NANO_ENSURE_ALLOC(handle);

  haio->type = HTTP_AIO;
  haio->mode = (uint8_t) NANO_INTEGER(convert);
  haio->next = handle;

  if ((xc = nng_url_parse(&handle->url, httr)) ||
      (xc = nng_http_client_alloc(&handle->cli, handle->url)) ||
      (xc = nng_http_req_alloc(&handle->req, handle->url)) ||
      (xc = nng_http_res_alloc(&handle->res)) ||
      (xc = nng_aio_alloc(&haio->aio, session_complete, haio)))
    goto fail;

  if (mthd != NULL && (xc = nng_http_req_set_method(handle->req, mthd)))
    goto fail;

  if (headers != R_NilValue && TYPEOF(headers) == STRSXP) {
    const R_xlen_t hlen = XLENGTH(headers);
    SEXP hnames = Rf_getAttrib(headers, R_NamesSymbol);
    if (TYPEOF(hnames) == STRSXP && XLENGTH(hnames) == hlen) {
      for (R_xlen_t i = 0; i < hlen; i++) {
        if ((xc = nng_http_req_set_header(handle->req, NANO_STR_N(hnames, i), NANO_STR_N(headers, i))))
          goto fail;
      }
    }
  }
  if (data != R_NilValue) {
    nano_buf enc = nano_char_buf(data);
    if (enc.cur && (xc = nng_http_req_copy_data(handle->req, enc.buf, enc.cur)))
      goto fail;
  }

  if (!strcmp(handle->url->u_scheme, "https")) {

    if (tls == R_NilValue) {
      if ((xc = nng_tls_config_alloc(&handle->cfg, NNG_TLS_MODE_CLIENT)) ||
          (xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_tls_config_auth_mode(handle->cfg, NNG_TLS_AUTH_MODE_NONE)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto fail;

    } else {

      handle->cfg = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(handle->cfg);

      if ((xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname)) ||
          (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
        goto fail;
    }

  }

  nng_aio_set_timeout(haio->aio, dur);
  nng_http_client_connect(handle->cli, haio->aio);
  nng_aio_wait(haio->aio);
  if ((xc = haio->result) > 0)
    goto fail;

  nng_http_conn *conn = nng_aio_get_output(haio->aio, 0);
  haio->data = conn;

  PROTECT(sess = R_MakeExternalPtr(haio, nano_StatusSymbol, (response != R_NilValue && TYPEOF(response) == STRSXP) ? response : R_NilValue));
  R_RegisterCFinalizerEx(sess, session_finalizer, TRUE);
  Rf_classgets(sess, Rf_mkString("ncurlSession"));

  UNPROTECT(1);
  return sess;

  fail:
  if (handle->cfg != NULL)
    nng_tls_config_free(handle->cfg);
  nng_aio_free(haio->aio);
  if (handle->res != NULL)
    nng_http_res_free(handle->res);
  if (handle->req != NULL)
    nng_http_req_free(handle->req);
  if (handle->cli != NULL)
    nng_http_client_free(handle->cli);
  nng_url_free(handle->url);
  failmem:
  free(handle);
  free(haio);
  ERROR_RET(xc);

}

SEXP rnng_ncurl_transact(SEXP session) {

  if (NANO_PTR_CHECK(session, nano_StatusSymbol))
    Rf_error("`session` is not a valid or active ncurlSession");

  nano_aio *haio = (nano_aio *) NANO_PTR(session);

  if (haio->data == NULL)
    return mk_error_ncurl(7);

  nng_http_conn *conn = (nng_http_conn *) haio->data;
  nano_handle *handle = (nano_handle *) haio->next;
  nng_http_conn_transact(conn, handle->req, handle->res, haio->aio);
  nng_aio_wait(haio->aio);
  if (haio->result > 0)
    return mk_error_ncurl(haio->result);

  SEXP out, vec, rvec, response;
  void *dat;
  size_t sz;
  const char *names[] = {"status", "headers", "data", ""};

  PROTECT(out = Rf_mkNamed(VECSXP, names));

  const uint16_t code = nng_http_res_get_status(handle->res);
  SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(code));

  response = NANO_PROT(session);
  if (response != R_NilValue) {
    const R_xlen_t rlen = XLENGTH(response);
    rvec = Rf_allocVector(VECSXP, rlen);
    SET_VECTOR_ELT(out, 1, rvec);
    Rf_namesgets(rvec, response);
    for (R_xlen_t i = 0; i < rlen; i++) {
      const char *r = nng_http_res_get_header(handle->res, NANO_STR_N(response, i));
      SET_VECTOR_ELT(rvec, i, r == NULL ? R_NilValue : Rf_mkString(r));
    }
  } else {
    rvec = R_NilValue;
    SET_VECTOR_ELT(out, 1, rvec);
  }

  nng_http_res_get_data(handle->res, &dat, &sz);

  if (haio->mode) {
    vec = nano_raw_char(dat, sz);
  } else {
    vec = Rf_allocVector(RAWSXP, sz);
    if (dat != NULL)
      memcpy(NANO_DATAPTR(vec), dat, sz);
  }
  SET_VECTOR_ELT(out, 2, vec);

  UNPROTECT(1);
  return out;

}

SEXP rnng_ncurl_session_close(SEXP session) {

  if (NANO_PTR_CHECK(session, nano_StatusSymbol))
    Rf_error("`session` is not a valid or active ncurlSession");

  nano_aio *haio = (nano_aio *) NANO_PTR(session);

  if (haio->data == NULL)
    ERROR_RET(7);

  nng_http_conn_close((nng_http_conn *) haio->data);
  haio->data = NULL;
  Rf_setAttrib(session, nano_StateSymbol, R_MissingArg);

  return nano_success;

}
