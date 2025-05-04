// nanonext - C level - Core Functions -----------------------------------------

#include "nanonext.h"

// internals -------------------------------------------------------------------

static int special_marker = 0;
static int special_header = 0;
static nano_serial_bundle nano_bundle;
static SEXP nano_eval_res;

static void nano_eval_safe (void *call) {
  nano_eval_res = Rf_eval((SEXP) call, R_GlobalEnv);
}

static void nano_write_bytes(R_outpstream_t stream, void *src, int len) {

  nano_buf *buf = (nano_buf *) stream->data;

  size_t req = buf->cur + (size_t) len;
  if (req > buf->len) {
    if (req > R_XLEN_T_MAX) {
      if (buf->len) free(buf->buf);
      Rf_error("serialization exceeds max length of raw vector");
    }
    do {
      buf->len += buf->len > NANONEXT_SERIAL_THR ? NANONEXT_SERIAL_THR : buf->len;
    } while (buf->len < req);
    buf->buf = realloc(buf->buf, buf->len);
  }

  memcpy(buf->buf + buf->cur, src, len);
  buf->cur += len;

}

static void nano_read_bytes(R_inpstream_t stream, void *dst, int len) {

  nano_buf *buf = (nano_buf *) stream->data;
  if (buf->cur + len > buf->len) Rf_error("unserialization error");
  memcpy(dst, buf->buf + buf->cur, len);
  buf->cur += len;

}

static int nano_read_char(R_inpstream_t stream) {

  nano_buf *buf = (nano_buf *) stream->data;
  if (buf->cur >= buf->len) Rf_error("unserialization error");
  return buf->buf[buf->cur++];

}

// Serialization Hooks - this section only subject to copyright notice: --------

/*
 * MIT License
 *
 * Copyright (c) 2025 sakura authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

static SEXP nano_serialize_hook(SEXP x, SEXP bundle_xptr) {

  R_outpstream_t stream = nano_bundle.outpstream;
  SEXP klass = nano_bundle.klass;
  SEXP hook_func = nano_bundle.hook_func;
  int len = (int) XLENGTH(klass), match = 0, i;
  void (*OutBytes)(R_outpstream_t, void *, int) = stream->OutBytes;

  for (i = 0; i < len; i++) {
    if (Rf_inherits(x, NANO_STR_N(klass, i))) {
      match = 1;
      break;
    }
  }

  if (!match)
    return R_NilValue;

  SEXP call;
  PROTECT(call = Rf_lcons(NANO_VECTOR(hook_func)[i], Rf_cons(x, R_NilValue)));
  if (!R_ToplevelExec(nano_eval_safe, call) || TYPEOF(nano_eval_res) != RAWSXP) {
    UNPROTECT(1);
    return R_NilValue;
  }
  UNPROTECT(1);

  uint64_t size = XLENGTH(nano_eval_res);
  char size_string[21];
  snprintf(size_string, sizeof(size_string), "%020" PRIu64, size);

  static int int_0 = 0;
  static int int_1 = 1;
  static int int_20 = 20;
  static int int_charsxp = CHARSXP;
  static int int_persistsxp = 247;

  OutBytes(stream, &int_persistsxp, sizeof(int)); // 4
  OutBytes(stream, &int_0, sizeof(int));          // 8
  OutBytes(stream, &int_1, sizeof(int));          // 12
  OutBytes(stream, &int_charsxp, sizeof(int));    // 16
  OutBytes(stream, &int_20, sizeof(int));         // 20
  OutBytes(stream, &size_string[0], 20);          // 40

  unsigned char *src = (unsigned char *) DATAPTR_RO(nano_eval_res);
  while (size > NANONEXT_CHUNK_SIZE) {
    OutBytes(stream, src, NANONEXT_CHUNK_SIZE);
    src += NANONEXT_CHUNK_SIZE;
    size -= NANONEXT_CHUNK_SIZE;
  }
  OutBytes(stream, src, (int) size);
  OutBytes(stream, &i, sizeof(int));              // 4

  return R_BlankScalarString;

}

static SEXP nano_unserialize_hook(SEXP x, SEXP bundle_xptr) {

  R_inpstream_t stream = nano_bundle.inpstream;
  SEXP hook_func = nano_bundle.hook_func;
  void (*InBytes)(R_inpstream_t, void *, int) = stream->InBytes;

  const char *size_string = NANO_STRING(x);
  uint64_t size = strtoul(size_string, NULL, 10);

  SEXP raw, call, out;
  PROTECT(raw = Rf_allocVector(RAWSXP, size));
  unsigned char *dest = (unsigned char *) DATAPTR_RO(raw);
  while (size > NANONEXT_CHUNK_SIZE) {
    InBytes(stream, dest, NANONEXT_CHUNK_SIZE);
    dest += NANONEXT_CHUNK_SIZE;
    size -= NANONEXT_CHUNK_SIZE;
  }
  InBytes(stream, dest, (int) size);

  int i;
  InBytes(stream, &i, 4);

  char buf[20];
  InBytes(stream, buf, 20);

  PROTECT(call = Rf_lcons(NANO_VECTOR(hook_func)[i], Rf_cons(raw, R_NilValue)));
  out = Rf_eval(call, R_GlobalEnv);

  UNPROTECT(2);
  return out;

}

// functions with forward definitions in nanonext.h ----------------------------

void dialer_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_dialer *xp = (nng_dialer *) NANO_PTR(xptr);
  nng_dialer_close(*xp);
  free(xp);

}

void listener_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_listener *xp = (nng_listener *) NANO_PTR(xptr);
  nng_listener_close(*xp);
  free(xp);

}

void socket_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_socket *xp = (nng_socket *) NANO_PTR(xptr);
  nng_close(*xp);
  free(xp);

}

void tls_finalizer(SEXP xptr) {

  if (NANO_PTR(xptr) == NULL) return;
  nng_tls_config *xp = (nng_tls_config *) NANO_PTR(xptr);
  nng_tls_config_free(xp);

}

#if R_VERSION < R_Version(4, 1, 0)

inline SEXP R_NewEnv(SEXP parent, int hash, int size) {
  (void) parent;
  (void) hash;
  (void) size;
  return Rf_allocSExp(ENVSXP);
}

#endif

#if R_VERSION < R_Version(4, 5, 0)

inline SEXP R_mkClosure(SEXP formals, SEXP body, SEXP env) {
  SEXP fun = Rf_allocSExp(CLOSXP);
  SET_FORMALS(fun, formals);
  SET_BODY(fun, body);
  SET_CLOENV(fun, env);
  return fun;
}

#endif

inline SEXP nano_PreserveObject(const SEXP x) {

  SEXP tail = CDR(nano_precious);
  SEXP node = Rf_cons(nano_precious, tail);
  SETCDR(nano_precious, node);
  if (tail != R_NilValue)
    SETCAR(tail, node);
  SET_TAG(node, x);

  return node;

}

inline void nano_ReleaseObject(SEXP node) {

  SET_TAG(node, R_NilValue);
  SEXP head = CAR(node);
  SEXP tail = CDR(node);
  SETCDR(head, tail);
  if (tail != R_NilValue)
    SETCAR(tail, head);

}

void later2(void (*fun)(void *), void *data) {
  eln2(fun, data, 0, 0);
}

void raio_invoke_cb(void *arg) {

  SEXP call, node = (SEXP) arg, x = TAG(node);
  PROTECT(call = Rf_lcons(nano_ResolveSymbol, Rf_cons(rnng_aio_get_msg(x), R_NilValue)));
  Rf_eval(call, NANO_ENCLOS(x));
  UNPROTECT(1);
  nano_ReleaseObject(node);

}

inline int nano_integer(const SEXP x) {
  return (TYPEOF(x) == INTSXP || TYPEOF(x) == LGLSXP) ? NANO_INTEGER(x) : Rf_asInteger(x);
}

SEXP mk_error(const int xc) {

  SEXP err = Rf_ScalarInteger(xc);
  Rf_classgets(err, nano_error);
  return err;

}

SEXP mk_error_data(const int xc) {

  SEXP env, err;
  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  Rf_classgets(env, xc < 0 ? nano_sendAio : nano_recvAio);
  PROTECT(err = Rf_ScalarInteger(abs(xc)));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(xc < 0 ? nano_ResultSymbol : nano_DataSymbol, err, env);
  UNPROTECT(2);
  return env;

}

SEXP nano_raw_char(const unsigned char *buf, const size_t sz) {

  SEXP out;
  int i;
  for (i = 0; i < sz; i++) if (!buf[i]) break;
  if (sz - i > 1) {
    Rf_warningcall_immediate(R_NilValue, "data could not be converted to a character string");
    out = Rf_allocVector(RAWSXP, sz);
    memcpy(NANO_DATAPTR(out), buf, sz);
    return out;
  }

  PROTECT(out = Rf_allocVector(STRSXP, 1));
  SET_STRING_ELT(out, 0, Rf_mkCharLenCE((const char *) buf, i, CE_NATIVE));

  UNPROTECT(1);
  return out;

}

void nano_serialize(nano_buf *buf, SEXP object, SEXP hook) {

  NANO_ALLOC(buf, NANONEXT_INIT_BUFSIZE);
  struct R_outpstream_st output_stream;

  if (special_header || special_marker) {
    buf->buf[0] = 0x7;
    buf->buf[3] = (uint8_t) special_marker;
    if (special_header)
      memcpy(buf->buf + 4, &special_header, sizeof(int));
    buf->cur += 8;
  }

  if (hook != R_NilValue) {
    nano_bundle.klass = NANO_VECTOR(hook)[0];
    nano_bundle.hook_func = NANO_VECTOR(hook)[1];
    nano_bundle.outpstream = &output_stream;
  }

  R_InitOutPStream(
    &output_stream,
    (R_pstream_data_t) buf,
    R_pstream_binary_format,
    NANONEXT_SERIAL_VER,
    NULL,
    nano_write_bytes,
    hook != R_NilValue ? nano_serialize_hook : NULL,
    R_NilValue
  );

  R_Serialize(object, &output_stream);

}

SEXP nano_unserialize(unsigned char *buf, size_t sz, SEXP hook) {

  int match = 0;
  size_t cur;

  if (sz > 12) {
    switch (buf[0]) {
    case 0x41:
    case 0x42:
    case 0x58:
      cur = 0;
      match = 1;
      break;
    case 0x7:
      cur = 8;
      match = 1;
      break;
    }
  }

  if (!match) {
    Rf_warningcall_immediate(R_NilValue, "received data could not be unserialized");
    return nano_decode(buf, sz, 8, R_NilValue);
  }

  nano_buf nbuf = {.buf = buf, .len = sz, .cur = cur};

  struct R_inpstream_st input_stream;

  if (hook != R_NilValue) {
    nano_bundle.hook_func = NANO_VECTOR(hook)[2];
    nano_bundle.inpstream = &input_stream;
  }

  R_InitInPStream(
    &input_stream,
    (R_pstream_data_t) &nbuf,
    R_pstream_any_format,
    nano_read_char,
    nano_read_bytes,
    hook != R_NilValue ? nano_unserialize_hook : NULL,
    R_NilValue
  );

  return R_Unserialize(&input_stream);

}

SEXP nano_decode(unsigned char *buf, const size_t sz, const uint8_t mod, SEXP hook) {

  SEXP data;
  size_t size;

  switch (mod) {
  case 2:
    size = sz / 2 + 1;
    PROTECT(data = Rf_allocVector(STRSXP, size));
    R_xlen_t i, m, nbytes = sz, np = 0;
    for (i = 0, m = 0; i < size; i++) {
      unsigned char *p;
      R_xlen_t j;
      SEXP res;

      for (j = np, p = buf + np; j < nbytes; p++, j++)
        if (*p == '\0') break;

      res = Rf_mkCharLenCE((const char *) (buf + np), (int) (j - np), CE_NATIVE);
      if (res == R_NilValue) break;
      SET_STRING_ELT(data, i, res);
      if (XLENGTH(res) > 0) m = i;
      np = j < nbytes ? j + 1 : nbytes;
    }
    if (i)
      data = Rf_xlengthgets(data, m + 1);
    UNPROTECT(1);
    return data;
  case 3:
    size = 2 * sizeof(double);
    if (sz % size) {
      Rf_warningcall_immediate(R_NilValue, "received data could not be converted to complex");
      data = Rf_allocVector(RAWSXP, sz);
    } else {
      data = Rf_allocVector(CPLXSXP, sz / size);
    }
    break;
  case 4:
    size = sizeof(double);
    if (sz % size) {
      Rf_warningcall_immediate(R_NilValue, "received data could not be converted to double");
      data = Rf_allocVector(RAWSXP, sz);
    } else {
      data = Rf_allocVector(REALSXP, sz / size);
    }
    break;
  case 5:
    size = sizeof(int);
    if (sz % size) {
      Rf_warningcall_immediate(R_NilValue, "received data could not be converted to integer");
      data = Rf_allocVector(RAWSXP, sz);
    } else {
      data = Rf_allocVector(INTSXP, sz / size);
    }
    break;
  case 6:
    size = sizeof(int);
    if (sz % size) {
      Rf_warningcall_immediate(R_NilValue, "received data could not be converted to logical");
      data = Rf_allocVector(RAWSXP, sz);
    } else {
      data = Rf_allocVector(LGLSXP, sz / size);
    }
    break;
  case 7:
    size = sizeof(double);
    if (sz % size) {
      Rf_warningcall_immediate(R_NilValue, "received data could not be converted to numeric");
      data = Rf_allocVector(RAWSXP, sz);
    } else {
      data = Rf_allocVector(REALSXP, sz / size);
    }
    break;
  case 8:
    data = Rf_allocVector(RAWSXP, sz);
    break;
  case 9:
    return nano_raw_char(buf, sz);
  default:
    return nano_unserialize(buf, sz, hook);
  }

  if (sz)
    memcpy(NANO_DATAPTR(data), buf, sz);

  return data;

}

void nano_encode(nano_buf *enc, const SEXP object) {

  switch (TYPEOF(object)) {
  case STRSXP: ;
    const char *s;
    R_xlen_t xlen = XLENGTH(object);
    if (xlen == 1) {
      s = NANO_STRING(object);
      NANO_INIT(enc, (unsigned char *) s, strlen(s) + 1);
      break;
    }
    R_xlen_t i;
    size_t slen, outlen = 0;
    for (i = 0; i < xlen; i++)
      outlen += strlen(NANO_STR_N(object, i)) + 1;
    NANO_ALLOC(enc, outlen);
    for (i = 0; i < xlen; i++) {
      s = NANO_STR_N(object, i);
      slen = strlen(s) + 1;
      memcpy(enc->buf + enc->cur, s, slen);
      enc->cur += slen;
    }
    break;
  case REALSXP:
    NANO_INIT(enc, (unsigned char *) DATAPTR_RO(object), XLENGTH(object) * sizeof(double));
    break;
  case INTSXP:
  case LGLSXP:
    NANO_INIT(enc, (unsigned char *) DATAPTR_RO(object), XLENGTH(object) * sizeof(int));
    break;
  case CPLXSXP:
    NANO_INIT(enc, (unsigned char *) DATAPTR_RO(object), XLENGTH(object) * 2 * sizeof(double));
    break;
  case RAWSXP:
    NANO_INIT(enc, (unsigned char *) DATAPTR_RO(object), XLENGTH(object));
    break;
  case NILSXP:
    NANO_INIT(enc, NULL, 0);
    break;
  default:
    Rf_error("'data' must be an atomic vector type or NULL to send in mode 'raw'");
  }

}

int nano_encodes(const SEXP mode) {

  if (TYPEOF(mode) != INTSXP) {
    const char *mod = CHAR(STRING_ELT(mode, 0));
    size_t slen = strlen(mod);
    switch (slen) {
    case 1:
    case 2:
    case 3:
      if (!memcmp(mod, "raw", slen)) return 2;
    case 4:
    case 5:
    case 6:
      if (!memcmp(mod, "serial", slen)) return 1;
    default:
      Rf_error("'mode' should be either serial or raw");
    }
  }

  return INTEGER(mode)[0];

}

int nano_matcharg(const SEXP mode) {

  if (TYPEOF(mode) != INTSXP) {
    const char *mod = CHAR(STRING_ELT(mode, 0));
    size_t slen = strlen(mod);
    switch (slen) {
    case 1:
      if (!memcmp(mod, "c", slen) || !memcmp(mod, "s", slen))
        Rf_error("'mode' should be one of serial, character, complex, double, integer, logical, numeric, raw, string");
    case 2:
    case 3:
      if (!memcmp(mod, "raw", slen)) return 8;
    case 4:
    case 5:
    case 6:
      if (!memcmp(mod, "double", slen)) return 4;
      if (!memcmp(mod, "serial", slen)) return 1;
      if (!memcmp(mod, "string", slen)) return 9;
    case 7:
      if (!memcmp(mod, "integer", slen)) return 5;
      if (!memcmp(mod, "numeric", slen)) return 7;
      if (!memcmp(mod, "logical", slen)) return 6;
      if (!memcmp(mod, "complex", slen)) return 3;
    case 8:
    case 9:
      if (!memcmp(mod, "character", slen)) return 2;
    default:
      Rf_error("'mode' should be one of serial, character, complex, double, integer, logical, numeric, raw, string");
    }
  }

  return INTEGER(mode)[0];

}

int nano_matchargs(const SEXP mode) {

  if (TYPEOF(mode) != INTSXP) {
    const char *mod = CHAR(STRING_ELT(mode, XLENGTH(mode) == 9));
    size_t slen = strlen(mod);
    switch (slen) {
    case 1:
      if (!memcmp(mod, "c", slen))
        Rf_error("'mode' should be one of character, complex, double, integer, logical, numeric, raw, string");
    case 2:
    case 3:
      if (!memcmp(mod, "raw", slen)) return 8;
    case 4:
    case 5:
    case 6:
      if (!memcmp(mod, "double", slen)) return 4;
      if (!memcmp(mod, "string", slen)) return 9;
    case 7:
      if (!memcmp(mod, "integer", slen)) return 5;
      if (!memcmp(mod, "numeric", slen)) return 7;
      if (!memcmp(mod, "logical", slen)) return 6;
      if (!memcmp(mod, "complex", slen)) return 3;
    case 8:
    case 9:
      if (!memcmp(mod, "character", slen)) return 2;
    default:
      Rf_error("'mode' should be one of character, complex, double, integer, logical, numeric, raw, string");
    }
  }

  return INTEGER(mode)[0];

}

SEXP rnng_eval_safe(SEXP arg) {

  return R_ToplevelExec(nano_eval_safe, arg) ? nano_eval_res : Rf_allocVector(RAWSXP, 1);

}

// specials --------------------------------------------------------------------

SEXP rnng_marker_set(SEXP x) {

  special_marker = NANO_INTEGER(x);
  return x;

}

SEXP rnng_marker_read(SEXP x) {

  int res = 0;
  if (TYPEOF(x) == RAWSXP && XLENGTH(x) > 12) {
    unsigned char *buf = (unsigned char *) DATAPTR_RO(x);
    res = buf[0] == 0x7 && buf[3] == 0x1;
  }
  return Rf_ScalarLogical(res);

}

SEXP rnng_header_set(SEXP x) {

  special_header = NANO_INTEGER(x);
  return x;

}

SEXP rnng_header_read(SEXP x) {

  int res = 0;
  if (TYPEOF(x) == RAWSXP && XLENGTH(x) > 12) {
    unsigned char *buf = (unsigned char *) DATAPTR_RO(x);
    if (buf[0] == 0x7)
      memcpy(&res, buf + 4, sizeof(int));
  }
  return Rf_ScalarInteger(res);

}
