// nanonext - C level - Core Functions -----------------------------------------

#include "nanonext.h"

// internals -------------------------------------------------------------------

static int special_marker = 0;
static nano_serial_bundle nano_bundle;
static SEXP nano_eval_res;

static SEXP nano_eval_prot (void *call) {
  return Rf_eval((SEXP) call, R_GlobalEnv);
}

static void nano_cleanup(void *data, Rboolean jump) {
  (void) data;
  if (jump)
    free(((nano_buf *) nano_bundle.outpstream->data)->buf);
}

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
    unsigned char *nbuf = realloc(buf->buf, buf->len);
    if (nbuf == NULL) {
      free(buf->buf);
      Rf_error("memory allocation failed");
    }
    buf->buf = nbuf;
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

static SEXP nano_serialize_hook(SEXP x, SEXP hook_func) {

  SEXP klass = nano_bundle.klass;
  int len = (int) XLENGTH(klass), match = 0, i;

  for (i = 0; i < len; i++) {
    if (Rf_inherits(x, NANO_STR_N(klass, i))) {
      match = 1;
      break;
    }
  }

  if (!match)
    return R_NilValue;

  R_outpstream_t stream = nano_bundle.outpstream;
  void (*OutBytes)(R_outpstream_t, void *, int) = stream->OutBytes;

  SEXP out, call;
  PROTECT(call = Rf_lcons(NANO_VECTOR(hook_func)[i], Rf_cons(x, R_NilValue)));
  out = R_UnwindProtect(nano_eval_prot, call, nano_cleanup, NULL, NULL);
  UNPROTECT(1);
  if (TYPEOF(out) != RAWSXP) {
    free(((nano_buf *) stream->data)->buf);
    Rf_error("Serialization function for `%s` did not return a raw vector", NANO_STR_N(klass, i));
  }

  uint64_t size = XLENGTH(out);
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

  unsigned char *src = (unsigned char *) DATAPTR_RO(out);
  while (size > NANONEXT_CHUNK_SIZE) {
    OutBytes(stream, src, NANONEXT_CHUNK_SIZE);
    src += NANONEXT_CHUNK_SIZE;
    size -= NANONEXT_CHUNK_SIZE;
  }
  OutBytes(stream, src, (int) size);
  OutBytes(stream, &i, sizeof(int));              // 4

  return R_BlankScalarString;

}

static SEXP nano_unserialize_hook(SEXP x, SEXP hook_func) {

  R_inpstream_t stream = nano_bundle.inpstream;
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

void nano_serialize(nano_buf *buf, SEXP object, SEXP hook, int header) {

  NANO_ALLOC(buf, NANONEXT_INIT_BUFSIZE);
  struct R_outpstream_st output_stream;

  if (header || special_marker) {
    buf->buf[0] = 0x7;
    buf->buf[3] = (uint8_t) special_marker;
    if (header)
      memcpy(buf->buf + 4, &header, sizeof(int));
    buf->cur += 8;
  }

  if (hook != R_NilValue) {
    nano_bundle.klass = NANO_VECTOR(hook)[0];
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
    hook != R_NilValue ? NANO_VECTOR(hook)[1] : R_NilValue
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
    nano_bundle.inpstream = &input_stream;
  }

  R_InitInPStream(
    &input_stream,
    (R_pstream_data_t) &nbuf,
    R_pstream_any_format,
    nano_read_char,
    nano_read_bytes,
    hook != R_NilValue ? nano_unserialize_hook : NULL,
    hook != R_NilValue ? NANO_VECTOR(hook)[2] : R_NilValue
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
    Rf_error("`data` must be an atomic vector type or NULL to send in mode 'raw'");
  }

}

int nano_encode_mode(const SEXP mode) {

  if (TYPEOF(mode) == INTSXP)
    return NANO_INTEGER(mode) == 2;

  const char *mod = CHAR(STRING_ELT(mode, 0));
  const size_t slen = strlen(mod);

  switch (slen) {
  case 3:
    if (!memcmp(mod, "raw", slen)) return 1;
    break;
  case 6:
    if (!memcmp(mod, "serial", slen)) return 0;
    break;
  }

  Rf_error("`mode` should be one of: serial, raw");

}

int nano_matcharg(const SEXP mode) {

  if (TYPEOF(mode) == INTSXP)
    return NANO_INTEGER(mode);

  const char *mod = CHAR(STRING_ELT(mode, 0));
  size_t slen = strlen(mod);
  int i;
  switch (slen) {
  case 3:
    if (!memcmp(mod, "raw", slen)) { i = 8; break; }
    goto fail;
  case 6:
    if (!memcmp(mod, "serial", slen)) { i = 1; break; }
    if (!memcmp(mod, "double", slen)) { i = 4; break; }
    if (!memcmp(mod, "string", slen)) { i = 9; break; }
    goto fail;
  case 7:
    if (!memcmp(mod, "integer", slen)) { i = 5; break; }
    if (!memcmp(mod, "numeric", slen)) { i = 7; break; }
    if (!memcmp(mod, "logical", slen)) { i = 6; break; }
    if (!memcmp(mod, "complex", slen)) { i = 3; break; }
    goto fail;
  case 9:
    if (!memcmp(mod, "character", slen)) { i = 2; break; }
    goto fail;
  default:
    goto fail;
  }

  return i;

  fail:
  Rf_error("`mode` should be one of: serial, character, complex, double, integer, logical, numeric, raw, string");

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

SEXP rnng_header_read(SEXP x) {

  int res = 0;
  if (TYPEOF(x) == RAWSXP && XLENGTH(x) > 12) {
    unsigned char *buf = (unsigned char *) DATAPTR_RO(x);
    if (buf[0] == 0x7)
      memcpy(&res, buf + 4, sizeof(int));
  }
  return Rf_ScalarInteger(res);

}
