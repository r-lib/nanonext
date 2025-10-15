// nanonext - C level - Utilities ----------------------------------------------

#include "nanonext.h"

// utils -----------------------------------------------------------------------

SEXP rnng_strerror(SEXP error) {

  const int xc = nano_integer(error);
  char nano_errbuf[NANONEXT_STR_SIZE];
  snprintf(nano_errbuf, NANONEXT_STR_SIZE, "%d | %s", xc, nng_strerror(xc));

  return Rf_mkString(nano_errbuf);

}

SEXP rnng_clock(void) {

  const double time = (double) nng_clock();
  return Rf_ScalarReal(time);

}

SEXP rnng_sleep(SEXP msec) {

  int time;
  switch (TYPEOF(msec)) {
  case INTSXP:
    time = NANO_INTEGER(msec);
    if (time > 0) nng_msleep((nng_duration) time);
    break;
  case REALSXP:
    time = Rf_asInteger(msec);
    if (time > 0) nng_msleep((nng_duration) time);
    break;
  }

  return R_NilValue;

}

SEXP rnng_url_parse(SEXP url) {

  nng_url *urlp;
  const int xc = nng_url_parse(&urlp, CHAR(STRING_ELT(url, 0)));
  if (xc)
    ERROR_OUT(xc);

  SEXP out;
  const char *names[] = {"scheme", "userinfo", "hostname", "port", "path",
                         "query", "fragment", ""};

  PROTECT(out = Rf_mkNamed(STRSXP, names));
  SET_STRING_ELT(out, 0, Rf_mkChar(nng_url_scheme(urlp) == NULL ? "" : nng_url_scheme(urlp)));
  SET_STRING_ELT(out, 1, Rf_mkChar(nng_url_userinfo(urlp) == NULL ? "" : nng_url_userinfo(urlp)));
  SET_STRING_ELT(out, 2, Rf_mkChar(nng_url_hostname(urlp) == NULL ? "" : nng_url_hostname(urlp)));
  char port[NANONEXT_STR_SIZE];
  snprintf(port, NANONEXT_STR_SIZE, "%d", (int) nng_url_port(urlp));
  SET_STRING_ELT(out, 3, Rf_mkChar(port));
  SET_STRING_ELT(out, 4, Rf_mkChar(nng_url_path(urlp) == NULL ? "" : nng_url_path(urlp)));
  SET_STRING_ELT(out, 5, Rf_mkChar(nng_url_query(urlp) == NULL ? "" : nng_url_query(urlp)));
  SET_STRING_ELT(out, 6, Rf_mkChar(nng_url_fragment(urlp) == NULL ? "" : nng_url_fragment(urlp)));
  nng_url_free(urlp);

  UNPROTECT(1);
  return out;

}

SEXP rnng_status_code(SEXP x) {

  const int status = nano_integer(x);
  char *code;
  switch (status) {
  case 100: code = "Continue"; break;
  case 101: code = "Switching Protocols"; break;
  case 102: code = "Processing"; break;
  case 103: code = "Early Hints"; break;
  case 200: code = "OK"; break;
  case 201: code = "Created"; break;
  case 202: code = "Accepted"; break;
  case 203: code = "Non-Authoritative Information"; break;
  case 204: code = "No Content"; break;
  case 205: code = "Reset Content"; break;
  case 206: code = "Partial Content"; break;
  case 207: code = "Multi-Status"; break;
  case 208: code = "Already Reported"; break;
  case 226: code = "IM Used"; break;
  case 300: code = "Multiple Choices"; break;
  case 301: code = "Moved Permanently"; break;
  case 302: code = "Found"; break;
  case 303: code = "See Other"; break;
  case 304: code = "Not Modified"; break;
  case 305: code = "Use Proxy"; break;
  case 306: code = "Switch Proxy"; break;
  case 307: code = "Temporary Redirect"; break;
  case 308: code = "Permanent Redirect"; break;
  case 400: code = "Bad Request"; break;
  case 401: code = "Unauthorized"; break;
  case 402: code = "Payment Required"; break;
  case 403: code = "Forbidden"; break;
  case 404: code = "Not Found"; break;
  case 405: code = "Method Not Allowed"; break;
  case 406: code = "Not Acceptable"; break;
  case 407: code = "Proxy Authentication Required"; break;
  case 408: code = "Request Timeout"; break;
  case 409: code = "Conflict"; break;
  case 410: code = "Gone"; break;
  case 411: code = "Length Required"; break;
  case 412: code = "Precondition Failed"; break;
  case 413: code = "Payload Too Large"; break;
  case 414: code = "URI Too Long"; break;
  case 415: code = "Unsupported Media Type"; break;
  case 416: code = "Range Not Satisfiable"; break;
  case 417: code = "Expectation Failed"; break;
  case 418: code = "I'm a teapot"; break;
  case 421: code = "Misdirected Request"; break;
  case 422: code = "Unprocessable Entity"; break;
  case 423: code = "Locked"; break;
  case 424: code = "Failed Dependency"; break;
  case 425: code = "Too Early"; break;
  case 426: code = "Upgrade Required"; break;
  case 428: code = "Precondition Required"; break;
  case 429: code = "Too Many Requests"; break;
  case 431: code = "Request Header Fields Too Large"; break;
  case 451: code = "Unavailable For Legal Reasons"; break;
  case 500: code = "Internal Server Error"; break;
  case 501: code = "Not Implemented"; break;
  case 502: code = "Bad Gateway"; break;
  case 503: code = "Service Unavailable"; break;
  case 504: code = "Gateway Timeout"; break;
  case 505: code = "HTTP Version Not Supported"; break;
  case 506: code = "Variant Also Negotiates"; break;
  case 507: code = "Insufficient Storage"; break;
  case 508: code = "Loop Detected"; break;
  case 510: code = "Not Extended"; break;
  case 511: code = "Network Authentication Required"; break;
  default: code = "Unknown HTTP Status"; break;
  }
  char out[strlen(code) + 7];
  snprintf(out, sizeof(out), "%d | %s", status, code);

  return Rf_mkString(out);

}

SEXP rnng_is_nul_byte(SEXP x) {

  return Rf_ScalarLogical(TYPEOF(x) == RAWSXP && XLENGTH(x) == 1 && RAW(x)[0] == 0);

}

SEXP rnng_is_error_value(SEXP x) {

  return Rf_ScalarLogical(Rf_inherits(x, "errorValue"));

}

// options ---------------------------------------------------------------------

SEXP rnng_set_opt(SEXP object, SEXP opt, SEXP value) {

  const char *op = CHAR(STRING_ELT(opt, 0));
  const int typ = TYPEOF(value);
  int xc, val;

  if (!NANO_PTR_CHECK(object, nano_SocketSymbol)) {

    nng_socket *sock = (nng_socket *) NANO_PTR(object);
    switch (typ) {
    case REALSXP:
    case INTSXP:
      val = nano_integer(value);
      xc = nng_socket_set_ms(*sock, op, (nng_duration) val);
      if (xc == 0) break;
      xc = nng_socket_set_size(*sock, op, (size_t) val);
      if (xc == 0) break;
      xc = nng_socket_set_int(*sock, op, val);
      break;
    case LGLSXP:
      xc = nng_socket_set_bool(*sock, op, (bool) NANO_INTEGER(value));
      break;
    case VECSXP:
      if (strncmp(op, "serial", 6) || TYPEOF(value) != VECSXP)
        Rf_error("type of `value` not supported");
      NANO_SET_PROT(object, Rf_xlength(value) ? value : R_NilValue);
      xc = 0;
      break;
    default:
      Rf_error("type of `value` not supported");
    }

  } else if (!NANO_PTR_CHECK(object, nano_ContextSymbol)) {

    nng_ctx *ctx = (nng_ctx *) NANO_PTR(object);
    switch (typ) {
    case REALSXP:
    case INTSXP:
      val = nano_integer(value);
      xc = nng_ctx_set_ms(*ctx, op, (nng_duration) val);
      if (xc == 0) break;
      xc = nng_ctx_set_size(*ctx, op, (size_t) val);
      if (xc == 0) break;
      xc = nng_ctx_set_int(*ctx, op, val);
      break;
    case LGLSXP:
      xc = nng_ctx_set_bool(*ctx, op, (bool) NANO_INTEGER(value));
      break;
    default:
      Rf_error("type of `value` not supported");
    }

  } else if (!NANO_PTR_CHECK(object, nano_StreamSymbol)) {

    nano_stream *nst = (nano_stream *) NANO_PTR(object);
    switch (typ) {
    case REALSXP:
    case INTSXP:
      val = nano_integer(value);
      xc = nst->mode == NANO_STREAM_DIALER ? nng_stream_dialer_set_ms(nst->endpoint.dial, op, (nng_duration) val) : nng_stream_listener_set_ms(nst->endpoint.list, op, (nng_duration) val);
      if (xc == 0) break;
      xc = nst->mode == NANO_STREAM_DIALER ? nng_stream_dialer_set_size(nst->endpoint.dial, op, (size_t) val) : nng_stream_listener_set_size(nst->endpoint.list, op, (size_t) val);
      if (xc == 0) break;
      xc = nst->mode == NANO_STREAM_DIALER ? nng_stream_dialer_set_int(nst->endpoint.dial, op, val) : nng_stream_listener_set_int(nst->endpoint.list, op, val);
      break;
    case LGLSXP:
      xc = nst->mode == NANO_STREAM_DIALER ? nng_stream_dialer_set_bool(nst->endpoint.dial, op, (bool) NANO_INTEGER(value)) : nng_stream_listener_set_bool(nst->endpoint.list, op, (bool) NANO_INTEGER(value));
      break;
    default:
      Rf_error("type of `value` not supported");
    }

  } else if (!NANO_PTR_CHECK(object, nano_ListenerSymbol)) {

    nng_listener *list = (nng_listener *) NANO_PTR(object);
    switch (typ) {
    case STRSXP:
      xc = nng_listener_set_string(*list, op, NANO_STRING(value));
      break;
    case REALSXP:
    case INTSXP:
      val = nano_integer(value);
      xc = nng_listener_set_ms(*list, op, (nng_duration) val);
      if (xc == 0) break;
      xc = nng_listener_set_size(*list, op, (size_t) val);
      if (xc == 0) break;
      xc = nng_listener_set_int(*list, op, val);
      break;
    case LGLSXP:
      xc = nng_listener_set_bool(*list, op, (bool) NANO_INTEGER(value));
      break;
    default:
      Rf_error("type of `value` not supported");
    }

  } else if (!NANO_PTR_CHECK(object, nano_DialerSymbol)) {

    nng_dialer *dial = (nng_dialer *) NANO_PTR(object);
    switch (typ) {
    case STRSXP:
      xc = nng_dialer_set_string(*dial, op, NANO_STRING(value));
      break;
    case REALSXP:
    case INTSXP:
      val = nano_integer(value);
      xc = nng_dialer_set_ms(*dial, op, (nng_duration) val);
      if (xc == 0) break;
      xc = nng_dialer_set_size(*dial, op, (size_t) val);
      if (xc == 0) break;
      xc = nng_dialer_set_int(*dial, op, val);
      break;
    case LGLSXP:
      xc = nng_dialer_set_bool(*dial, op, (bool) NANO_INTEGER(value));
      break;
    default:
      Rf_error("type of `value` not supported");
    }

  } else {
    Rf_error("`object` is not a valid Socket, Context, Stream, Listener or Dialer");
  }

  if (xc)
    ERROR_OUT(xc);

  return object;

}

SEXP rnng_subscribe(SEXP object, SEXP value, SEXP sub) {

  nano_buf buf;
  int xc;

  if (!NANO_PTR_CHECK(object, nano_SocketSymbol)) {

    nng_socket *sock = (nng_socket *) NANO_PTR(object);
    nano_encode(&buf, value);
    xc = NANO_INTEGER(sub) ?
         nng_sub0_socket_subscribe(*sock, buf.buf, buf.cur - (TYPEOF(value) == STRSXP)) :
         nng_sub0_socket_unsubscribe(*sock, buf.buf, buf.cur - (TYPEOF(value) == STRSXP));

  } else if (!NANO_PTR_CHECK(object, nano_ContextSymbol)) {

    nng_ctx *ctx = (nng_ctx *) NANO_PTR(object);
    nano_encode(&buf, value);
    xc = NANO_INTEGER(sub) ?
         nng_sub0_ctx_subscribe(*ctx, buf.buf, buf.cur - (TYPEOF(value) == STRSXP)) :
         nng_sub0_ctx_unsubscribe(*ctx, buf.buf, buf.cur - (TYPEOF(value) == STRSXP));

  } else {
    Rf_error("`object` is not a valid Socket or Context");
  }

  if (xc)
    ERROR_OUT(xc);

  return object;

}

SEXP rnng_get_opt(SEXP object, SEXP opt) {

  const char *op = CHAR(STRING_ELT(opt, 0));
  SEXP out;
  int xc, typ;
  nano_opt optval;

  if (!NANO_PTR_CHECK(object, nano_SocketSymbol)) {

    nng_socket *sock = (nng_socket *) NANO_PTR(object);
    for (;;) {
      xc = nng_socket_get_ms(*sock, op, &optval.d);
      if (xc == 0) { typ = 2; break; }
      xc = nng_socket_get_size(*sock, op, &optval.s);
      if (xc == 0) { typ = 3; break; }
      xc = nng_socket_get_int(*sock, op, &optval.i);
      if (xc == 0) { typ = 4; break; }
      xc = nng_socket_get_bool(*sock, op, &optval.b);
      typ = 5; break;
    }

  } else if (!NANO_PTR_CHECK(object, nano_ContextSymbol)) {

    nng_ctx *ctx = (nng_ctx *) NANO_PTR(object);
    for (;;) {
      xc = nng_ctx_get_ms(*ctx, op, &optval.d);
      if (xc == 0) { typ = 2; break; }
      xc = nng_ctx_get_size(*ctx, op, &optval.s);
      if (xc == 0) { typ = 3; break; }
      xc = nng_ctx_get_int(*ctx, op, &optval.i);
      if (xc == 0) { typ = 4; break; }
      xc = nng_ctx_get_bool(*ctx, op, &optval.b);
      typ = 5; break;
    }

  } else if (!NANO_PTR_CHECK(object, nano_StreamSymbol)) {

    // Switch to stream dialer and stream listener options

    nng_stream **st = (nng_stream **) NANO_PTR(object);
    for (;;) {
      xc = nng_stream_get_string(*st, op, &optval.str);
      if (xc == 0) { typ = 1; break; }
      xc = nng_stream_get_ms(*st, op, &optval.d);
      if (xc == 0) { typ = 2; break; }
      xc = nng_stream_get_size(*st, op, &optval.s);
      if (xc == 0) { typ = 3; break; }
      xc = nng_stream_get_int(*st, op, &optval.i);
      if (xc == 0) { typ = 4; break; }
      xc = nng_stream_get_bool(*st, op, &optval.b);
      typ = 5; break;
    }

  } else if (!NANO_PTR_CHECK(object, nano_ListenerSymbol)) {

    nng_listener *list = (nng_listener *) NANO_PTR(object);
    for (;;) {
      xc = nng_listener_get_string(*list, op, &optval.str);
      if (xc == 0) { typ = 1; break; }
      xc = nng_listener_get_ms(*list, op, &optval.d);
      if (xc == 0) { typ = 2; break; }
      xc = nng_listener_get_size(*list, op, &optval.s);
      if (xc == 0) { typ = 3; break; }
      xc = nng_listener_get_int(*list, op, &optval.i);
      if (xc == 0) { typ = 4; break; }
      xc = nng_listener_get_bool(*list, op, &optval.b);
      typ = 5; break;
    }

  } else if (!NANO_PTR_CHECK(object, nano_DialerSymbol)) {

    nng_dialer *dial = (nng_dialer *) NANO_PTR(object);
    for (;;) {
      xc = nng_dialer_get_string(*dial, op, &optval.str);
      if (xc == 0) { typ = 1; break; }
      xc = nng_dialer_get_ms(*dial, op, &optval.d);
      if (xc == 0) { typ = 2; break; }
      xc = nng_dialer_get_size(*dial, op, &optval.s);
      if (xc == 0) { typ = 3; break; }
      xc = nng_dialer_get_int(*dial, op, &optval.i);
      if (xc == 0) { typ = 4; break; }
      xc = nng_dialer_get_bool(*dial, op, &optval.b);
      typ = 5; break;
    }

  } else {
    Rf_error("`object` is not a valid Socket, Context, Stream, Listener, or Dialer");
  }

  if (xc)
    ERROR_OUT(xc);

  switch (typ) {
  case 1:
    out = Rf_mkString(optval.str);
    nng_strfree(optval.str);
    break;
  case 2:
    out = Rf_ScalarInteger((int) optval.d);
    break;
  case 3:
    out = Rf_ScalarInteger((int) optval.s);
    break;
  case 4:
    out = Rf_ScalarInteger(optval.i);
    break;
  case 5:
    out = Rf_ScalarLogical((int) optval.b);
    break;
  }

  return out;

}

// statistics ------------------------------------------------------------------

SEXP rnng_stats_get(SEXP object, SEXP stat) {

  const char *statname = CHAR(STRING_ELT(stat, 0));
  SEXP out;
  int xc;
  nng_stat *nst;
  const nng_stat *sst, *res;

  if (!NANO_PTR_CHECK(object, nano_SocketSymbol)) {
    if ((xc = nng_stats_get(&nst)))
      ERROR_OUT(xc);
    nng_socket *sock = (nng_socket *) NANO_PTR(object);
    sst = nng_stat_find_socket(nst, *sock);

  } else if (!NANO_PTR_CHECK(object, nano_ListenerSymbol)) {
    if ((xc = nng_stats_get(&nst)))
      ERROR_OUT(xc);
    nng_listener *list = (nng_listener *) NANO_PTR(object);
    sst = nng_stat_find_listener(nst, *list);

  } else if (!NANO_PTR_CHECK(object, nano_DialerSymbol)) {
    if ((xc = nng_stats_get(&nst)))
      ERROR_OUT(xc);
    nng_dialer *dial = (nng_dialer *) NANO_PTR(object);
    sst = nng_stat_find_dialer(nst, *dial);

  } else {
    Rf_error("`object` is not a valid Socket, Listener or Dialer");
  }

  res = nng_stat_find(sst, statname);
  if (res == NULL) {
    nng_stats_free(nst);
    return R_NilValue;
  }

  out = nng_stat_type(res) == NNG_STAT_STRING ? Rf_mkString(nng_stat_string(res)) : Rf_ScalarReal((double) nng_stat_value(res));

  nng_stats_free(nst);
  return out;

}

// serialization config --------------------------------------------------------

SEXP rnng_serial_config(SEXP klass, SEXP sfunc, SEXP ufunc) {

  SEXP out;
  PROTECT(out = Rf_allocVector(VECSXP, 3));

  if (TYPEOF(klass) != STRSXP)
    Rf_error("`class` must be a character vector");
  SET_VECTOR_ELT(out, 0, klass);

  R_xlen_t xlen = XLENGTH(klass);
  if (Rf_xlength(sfunc) != xlen || Rf_xlength(ufunc) != xlen)
    Rf_error("`class`, `sfunc` and `ufunc` must all be the same length");

  switch (TYPEOF(sfunc)) {
  case VECSXP:
    SET_VECTOR_ELT(out, 1, sfunc);
    break;
  case CLOSXP:
  case SPECIALSXP:
  case BUILTINSXP: ;
    SEXP slist = Rf_allocVector(VECSXP, 1);
    SET_VECTOR_ELT(out, 1, slist);
    SET_VECTOR_ELT(slist, 0, sfunc);
    break;
  default:
    Rf_error("`sfunc` must be a function or list of functions");
  }

  switch (TYPEOF(ufunc)) {
  case VECSXP:
    SET_VECTOR_ELT(out, 2, ufunc);
    break;
  case CLOSXP:
  case SPECIALSXP:
  case BUILTINSXP: ;
    SEXP ulist = Rf_allocVector(VECSXP, 1);
    SET_VECTOR_ELT(out, 2, ulist);
    SET_VECTOR_ELT(ulist, 0, ufunc);
    break;
  default:
    Rf_error("`ufunc` must be a function or list of functions");
  }

  UNPROTECT(1);
  return out;

}

// specials --------------------------------------------------------------------

SEXP rnng_advance_rng_state(void) {

  GetRNGstate();
  (void) exp_rand();
  PutRNGstate();
  return R_NilValue;

}

SEXP rnng_fini_priors(void) {

  nano_thread_shutdown();
  nano_list_do(SHUTDOWN, NULL);
  return R_NilValue;

}

SEXP rnng_fini(void) {

  nng_fini();
  return R_NilValue;

}

SEXP rnng_traverse_precious(void) {

  SEXP list = nano_precious;
  int x = 0;
  for (SEXP head = CDR(list); head != R_NilValue; head = CDR(head))
    if (TAG(head) == R_NilValue) ++x;

  return Rf_ScalarInteger(x);

}
