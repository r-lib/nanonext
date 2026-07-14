// nanonext - C level - ncurl --------------------------------------------------

#define NANONEXT_HTTP
#include "nanonext.h"

#include <ctype.h>
#include <limits.h>

// internals -------------------------------------------------------------------

// Helper to build named list of all response headers
static SEXP build_all_headers(nng_http_res *res) {
  int count = 0;
  for (nano_http_header_s *h = nano_http_header_first(res); h != NULL;
       h = nano_http_header_next(res, h))
    count++;

  if (count == 0)
    return R_NilValue;

  SEXP rvec, rnames;
  PROTECT(rvec = Rf_allocVector(VECSXP, count));
  rnames = Rf_allocVector(STRSXP, count);
  Rf_namesgets(rvec, rnames);

  int i = 0;
  for (nano_http_header_s *h = nano_http_header_first(res); h != NULL;
       h = nano_http_header_next(res, h)) {
    SET_STRING_ELT(rnames, i, Rf_mkChar(h->name));
    SET_VECTOR_ELT(rvec, i, Rf_mkString(h->value));
    i++;
  }

  UNPROTECT(1);
  return rvec;
}

// Helper to set request headers from a named character vector or named list
static int nano_set_req_headers(nng_http_req *req, SEXP headers) {
  if (headers == R_NilValue)
    return 0;
  const R_xlen_t hlen = XLENGTH(headers);
  SEXP hnames = Rf_getAttrib(headers, R_NamesSymbol);
  if (TYPEOF(hnames) != STRSXP || XLENGTH(hnames) != hlen)
    return 0;
  const SEXP *hnames_p = STRING_PTR_RO(hnames);
  int xc = 0;
  switch (TYPEOF(headers)) {
  case STRSXP: {
    const SEXP *headers_p = STRING_PTR_RO(headers);
    for (R_xlen_t i = 0; i < hlen; i++)
      if ((xc = nng_http_req_set_header(req, CHAR(hnames_p[i]), CHAR(headers_p[i]))))
        break;
    break;
  }
  case VECSXP:
    for (R_xlen_t i = 0; i < hlen; i++) {
      SEXP h = VECTOR_ELT(headers, i);
      if (TYPEOF(h) == STRSXP && XLENGTH(h) &&
          (xc = nng_http_req_set_header(req, CHAR(hnames_p[i]), CHAR(STRING_ELT(h, 0)))))
        break;
    }
    break;
  }
  return xc;
}

static SEXP mk_error_haio(const int xc, SEXP env) {

  SEXP err;
  PROTECT(err = Rf_ScalarInteger(xc));
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
  SEXP out, err;
  PROTECT(out = Rf_mkNamed(VECSXP, names));
  PROTECT(err = Rf_ScalarInteger(xc));
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

static SEXP mk_error_ncurl_stream_aio(const int xc) {
  SEXP env, err;
  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  NANO_CLASS2(env, "ncurlStreamAio", "recvAio");
  PROTECT(err = Rf_ScalarInteger(xc));
  Rf_classgets(err, nano_error);
  Rf_defineVar(nano_ValueSymbol, err, env);
  Rf_defineVar(nano_DataSymbol, err, env);
  Rf_defineVar(nano_AioSymbol, R_NilValue, env);
  UNPROTECT(2);
  return env;
}

static nano_buf nano_char_buf(const SEXP data) {

  nano_buf buf = {0};
  switch (TYPEOF(data)) {
  case STRSXP: {
    const char *s = CHAR(STRING_ELT(data, 0));
    NANO_INIT(&buf, (unsigned char *) s, strlen(s));
    break;
  }
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

// ncurl stream internals ------------------------------------------------------

#define NANO_HTTP_CHUNK_LINE_MAX 1024

typedef enum nano_http_body_mode_e {
  NANO_HTTP_BODY_NONE,
  NANO_HTTP_BODY_LENGTH,
  NANO_HTTP_BODY_CHUNKED,
  NANO_HTTP_BODY_CLOSE
} nano_http_body_mode;

typedef enum nano_http_chunk_state_e {
  NANO_HTTP_CHUNK_SIZE,
  NANO_HTTP_CHUNK_SIZE_LF,
  NANO_HTTP_CHUNK_DATA,
  NANO_HTTP_CHUNK_DATA_CR,
  NANO_HTTP_CHUNK_DATA_LF,
  NANO_HTTP_CHUNK_TRAILER,
  NANO_HTTP_CHUNK_TRAILER_LF,
  NANO_HTTP_CHUNK_DONE
} nano_http_chunk_state;

typedef enum nano_http_stream_state_e {
  NANO_HTTP_STREAM_OPENING,
  NANO_HTTP_STREAM_OPEN,
  NANO_HTTP_STREAM_ERROR,
  NANO_HTTP_STREAM_CLOSED
} nano_http_stream_state;

typedef struct nano_http_stream_s {
  nng_url *url;
  nng_http_client *client;
  nng_http_req *request;
  nng_http_res *response;
  nng_tls_config *tls;
  nng_http_conn *connection;
  nng_mtx *mtx;
  size_t buffer_size;
  uint64_t remaining;
  uint64_t chunk_remaining;
  char chunk_line[NANO_HTTP_CHUNK_LINE_MAX];
  size_t chunk_line_length;
  nano_http_body_mode body_mode;
  nano_http_chunk_state chunk_state;
  nano_http_stream_state state;
  int reading;
  int complete;
  int error;
} nano_http_stream;

typedef struct nano_http_stream_recv_s {
  nano_aio aio;
  nano_cv *cv;
  unsigned char *input;
  unsigned char *output;
  size_t output_size;
  int complete;
} nano_http_stream_recv;

static int nano_ascii_case_equal(const char left, const char right) {
  return tolower((unsigned char) left) == tolower((unsigned char) right);
}

static int nano_http_header_has_token(const char *header, const char *token) {
  if (header == NULL)
    return 0;

  const size_t token_length = strlen(token);
  const char *cursor = header;
  while (*cursor != '\0') {
    while (*cursor == ' ' || *cursor == '\t' || *cursor == ',')
      cursor++;
    const char *start = cursor;
    while (*cursor != '\0' && *cursor != ',' && *cursor != ';')
      cursor++;
    const char *end = cursor;
    while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
      end--;
    if ((size_t) (end - start) == token_length) {
      size_t index = 0;
      while (index < token_length && nano_ascii_case_equal(start[index], token[index]))
        index++;
      if (index == token_length)
        return 1;
    }
    while (*cursor != '\0' && *cursor != ',')
      cursor++;
  }
  return 0;
}

static int nano_http_content_length(const char *header, uint64_t *value) {
  if (header == NULL)
    return 0;

  const unsigned char *cursor = (const unsigned char *) header;
  while (*cursor == ' ' || *cursor == '\t')
    cursor++;
  if (!isdigit(*cursor))
    return -1;

  uint64_t length = 0;
  do {
    const unsigned int digit = (unsigned int) (*cursor - '0');
    if (length > (UINT64_MAX - digit) / 10u)
      return -1;
    length = length * 10u + digit;
    cursor++;
  } while (isdigit(*cursor));

  while (*cursor == ' ' || *cursor == '\t')
    cursor++;
  if (*cursor != '\0')
    return -1;

  *value = length;
  return 1;
}

static int nano_http_chunk_size(nano_http_stream *stream, uint64_t *value) {
  size_t end = 0;
  while (end < stream->chunk_line_length && stream->chunk_line[end] != ';')
    end++;
  if (end == 0)
    return NNG_EPROTO;

  uint64_t size = 0;
  for (size_t index = 0; index < end; index++) {
    const unsigned char byte = (unsigned char) stream->chunk_line[index];
    unsigned int digit;
    if (byte >= '0' && byte <= '9') {
      digit = (unsigned int) (byte - '0');
    } else if (byte >= 'a' && byte <= 'f') {
      digit = (unsigned int) (byte - 'a') + 10u;
    } else if (byte >= 'A' && byte <= 'F') {
      digit = (unsigned int) (byte - 'A') + 10u;
    } else {
      return NNG_EPROTO;
    }
    if (size > (UINT64_MAX - digit) / 16u)
      return NNG_EPROTO;
    size = size * 16u + digit;
  }
  *value = size;
  return 0;
}

static int nano_http_stream_configure_body(nano_http_stream *stream) {
  const uint16_t status = nng_http_res_get_status(stream->response);
  const char *method = nng_http_req_get_method(stream->request);
  if (!strcmp(method, "HEAD") || (status >= 100 && status < 200) ||
      status == 204 || status == 304) {
    stream->body_mode = NANO_HTTP_BODY_NONE;
    stream->complete = 1;
    return 0;
  }

  const char *encoding = nng_http_res_get_header(stream->response, "Transfer-Encoding");
  if (nano_http_header_has_token(encoding, "chunked")) {
    stream->body_mode = NANO_HTTP_BODY_CHUNKED;
    stream->chunk_state = NANO_HTTP_CHUNK_SIZE;
    return 0;
  }
  if (encoding != NULL) {
    stream->body_mode = NANO_HTTP_BODY_CLOSE;
    return 0;
  }

  const char *content_length = nng_http_res_get_header(stream->response, "Content-Length");
  const int length_result = nano_http_content_length(content_length, &stream->remaining);
  if (length_result < 0)
    return NNG_EPROTO;
  if (length_result > 0) {
    stream->body_mode = NANO_HTTP_BODY_LENGTH;
    stream->complete = stream->remaining == 0;
    return 0;
  }

  stream->body_mode = NANO_HTTP_BODY_CLOSE;
  return 0;
}

static int nano_http_stream_parse_chunked(
  nano_http_stream *stream,
  const unsigned char *input,
  const size_t input_size,
  unsigned char *output,
  size_t *output_size
) {
  size_t input_index = 0;
  size_t output_index = 0;

  while (input_index < input_size && !stream->complete) {
    switch (stream->chunk_state) {
    case NANO_HTTP_CHUNK_SIZE: {
      const unsigned char byte = input[input_index++];
      if (byte == '\r') {
        stream->chunk_state = NANO_HTTP_CHUNK_SIZE_LF;
      } else if (byte == '\n' || stream->chunk_line_length == NANO_HTTP_CHUNK_LINE_MAX) {
        return NNG_EPROTO;
      } else {
        stream->chunk_line[stream->chunk_line_length++] = (char) byte;
      }
      break;
    }
    case NANO_HTTP_CHUNK_SIZE_LF: {
      if (input[input_index++] != '\n')
        return NNG_EPROTO;
      int result = nano_http_chunk_size(stream, &stream->chunk_remaining);
      if (result != 0)
        return result;
      stream->chunk_line_length = 0;
      stream->chunk_state = stream->chunk_remaining == 0
        ? NANO_HTTP_CHUNK_TRAILER
        : NANO_HTTP_CHUNK_DATA;
      break;
    }
    case NANO_HTTP_CHUNK_DATA: {
      const size_t available = input_size - input_index;
      const size_t take = stream->chunk_remaining < available
        ? (size_t) stream->chunk_remaining
        : available;
      memcpy(output + output_index, input + input_index, take);
      input_index += take;
      output_index += take;
      stream->chunk_remaining -= take;
      if (stream->chunk_remaining == 0)
        stream->chunk_state = NANO_HTTP_CHUNK_DATA_CR;
      break;
    }
    case NANO_HTTP_CHUNK_DATA_CR:
      if (input[input_index++] != '\r')
        return NNG_EPROTO;
      stream->chunk_state = NANO_HTTP_CHUNK_DATA_LF;
      break;
    case NANO_HTTP_CHUNK_DATA_LF:
      if (input[input_index++] != '\n')
        return NNG_EPROTO;
      stream->chunk_state = NANO_HTTP_CHUNK_SIZE;
      break;
    case NANO_HTTP_CHUNK_TRAILER: {
      const unsigned char byte = input[input_index++];
      if (byte == '\r') {
        stream->chunk_state = NANO_HTTP_CHUNK_TRAILER_LF;
      } else if (byte == '\n' || stream->chunk_line_length == NANO_HTTP_CHUNK_LINE_MAX) {
        return NNG_EPROTO;
      } else {
        stream->chunk_line_length++;
      }
      break;
    }
    case NANO_HTTP_CHUNK_TRAILER_LF:
      if (input[input_index++] != '\n')
        return NNG_EPROTO;
      if (stream->chunk_line_length == 0) {
        stream->chunk_state = NANO_HTTP_CHUNK_DONE;
        stream->complete = 1;
      } else {
        stream->chunk_line_length = 0;
        stream->chunk_state = NANO_HTTP_CHUNK_TRAILER;
      }
      break;
    case NANO_HTTP_CHUNK_DONE:
      stream->complete = 1;
      break;
    }
  }

  *output_size = output_index;
  return 0;
}

static void nano_http_stream_release(nano_http_stream *stream) {
  if (stream == NULL)
    return;
  if (stream->connection != NULL && stream->state != NANO_HTTP_STREAM_CLOSED)
    nng_http_conn_close(stream->connection);
  if (stream->tls != NULL)
    nng_tls_config_free(stream->tls);
  if (stream->response != NULL)
    nng_http_res_free(stream->response);
  if (stream->request != NULL)
    nng_http_req_free(stream->request);
  if (stream->client != NULL)
    nng_http_client_free(stream->client);
  if (stream->url != NULL)
    nng_url_free(stream->url);
  if (stream->mtx != NULL)
    nng_mtx_free(stream->mtx);
  free(stream);
}

static void nano_http_stream_finalizer(SEXP xptr) {
  if (NANO_PTR(xptr) == NULL)
    return;
  nano_http_stream_release((nano_http_stream *) NANO_PTR(xptr));
  R_ClearExternalPtr(xptr);
}

static void nano_http_stream_start_aio_finalizer(SEXP xptr) {
  if (NANO_PTR(xptr) == NULL)
    return;
  nano_aio *aio = (nano_aio *) NANO_PTR(xptr);
  nng_aio_free(aio->aio);
  free(aio);
  R_ClearExternalPtr(xptr);
}

static void nano_http_stream_recv_aio_finalizer(SEXP xptr) {
  if (NANO_PTR(xptr) == NULL)
    return;
  nano_http_stream_recv *receive = (nano_http_stream_recv *) NANO_PTR(xptr);
  nng_aio_free(receive->aio.aio);
  free(receive->input);
  free(receive->output);
  free(receive);
  R_ClearExternalPtr(xptr);
}

static void nano_http_stream_start_complete(void *arg) {
  nano_aio *aio = (nano_aio *) arg;
  nano_http_stream *stream = (nano_http_stream *) aio->next;
  const int result = nng_aio_result(aio->aio);
  if (result != 0) {
    aio->result = result;
    goto complete;
  }

  switch (aio->mode) {
  case 0:
    stream->connection = nng_aio_get_output(aio->aio, 0);
    aio->mode = 1;
    nng_http_conn_write_req(stream->connection, stream->request, aio->aio);
    aio->result = nng_aio_result(aio->aio);
    if (aio->result != 0)
      goto complete;
    return;
  case 1:
    aio->mode = 2;
    nng_http_conn_read_res(stream->connection, stream->response, aio->aio);
    aio->result = nng_aio_result(aio->aio);
    if (aio->result != 0)
      goto complete;
    return;
  default:
    nng_mtx_lock(stream->mtx);
    aio->result = nano_http_stream_configure_body(stream);
    if (aio->result == 0) {
      stream->state = NANO_HTTP_STREAM_OPEN;
      aio->result = -1;
    }
    nng_mtx_unlock(stream->mtx);
  }

complete:
  if (aio->result > 0) {
    nng_mtx_lock(stream->mtx);
    if (stream->state == NANO_HTTP_STREAM_OPENING) {
      stream->state = NANO_HTTP_STREAM_ERROR;
      stream->error = aio->result;
    }
    nng_mtx_unlock(stream->mtx);
  }
  if (aio->cb != NULL)
    later2(raio_invoke_cb, aio->cb);
}

static void nano_http_stream_signal(nano_cv *cv);

static void nano_http_stream_receive_complete(void *arg) {
  nano_http_stream_recv *receive = (nano_http_stream_recv *) arg;
  nano_aio *aio = &receive->aio;
  nano_http_stream *stream = (nano_http_stream *) aio->next;
  const int result = nng_aio_result(aio->aio);
  nng_mtx_lock(stream->mtx);

  if (result != 0) {
    if (result == NNG_ECLOSED && stream->body_mode == NANO_HTTP_BODY_CLOSE &&
        stream->state == NANO_HTTP_STREAM_OPEN) {
      stream->complete = 1;
      receive->complete = 1;
      aio->result = -1;
    } else {
      if (stream->state == NANO_HTTP_STREAM_OPEN) {
        stream->state = NANO_HTTP_STREAM_ERROR;
        stream->error = result;
      }
      aio->result = result;
    }
    goto complete;
  }

  const size_t input_size = nng_aio_count(aio->aio);
  int parse_result = 0;
  switch (stream->body_mode) {
  case NANO_HTTP_BODY_NONE:
    stream->complete = 1;
    break;
  case NANO_HTTP_BODY_LENGTH:
    if ((uint64_t) input_size > stream->remaining) {
      parse_result = NNG_EPROTO;
      break;
    }
    memcpy(receive->output, receive->input, input_size);
    receive->output_size = input_size;
    stream->remaining -= input_size;
    stream->complete = stream->remaining == 0;
    break;
  case NANO_HTTP_BODY_CHUNKED:
    parse_result = nano_http_stream_parse_chunked(
      stream,
      receive->input,
      input_size,
      receive->output,
      &receive->output_size
    );
    break;
  case NANO_HTTP_BODY_CLOSE:
    memcpy(receive->output, receive->input, input_size);
    receive->output_size = input_size;
    break;
  }

  if (parse_result != 0) {
    if (stream->state == NANO_HTTP_STREAM_OPEN) {
      stream->state = NANO_HTTP_STREAM_ERROR;
      stream->error = parse_result;
    }
    aio->result = parse_result;
    goto complete;
  }
  receive->complete = stream->complete;
  if (receive->output_size == 0 && !receive->complete) {
    if (stream->state != NANO_HTTP_STREAM_OPEN) {
      aio->result = NNG_ECLOSED;
      goto complete;
    }
    nng_iov iov = {
      .iov_buf = receive->input,
      .iov_len = stream->buffer_size
    };
    const int iov_result = nng_aio_set_iov(aio->aio, 1u, &iov);
    if (iov_result != 0) {
      stream->state = NANO_HTTP_STREAM_ERROR;
      stream->error = iov_result;
      aio->result = iov_result;
      goto complete;
    }
    nng_http_conn_read(stream->connection, aio->aio);
    const int read_result = nng_aio_result(aio->aio);
    if (read_result != 0) {
      if (stream->state == NANO_HTTP_STREAM_OPEN) {
        stream->state = NANO_HTTP_STREAM_ERROR;
        stream->error = read_result;
      }
      aio->result = read_result;
      goto complete;
    }
    nng_mtx_unlock(stream->mtx);
    return;
  }
  aio->result = -1;

complete:
  stream->reading = 0;
  nng_mtx_unlock(stream->mtx);
  nano_http_stream_signal(receive->cv);
  if (aio->cb != NULL)
    later2(raio_invoke_cb, aio->cb);
}

static void nano_http_stream_signal(nano_cv *cv) {
  if (cv == NULL)
    return;
  nng_mtx_lock(cv->mtx);
  cv->condition++;
  nng_cv_wake(cv->cv);
  nng_mtx_unlock(cv->mtx);
}

// ncurl - internal ------------------------------------------------------------

static inline SEXP create_aio_http(SEXP env, nano_aio *haio, int typ) {

  if (haio->result > 0)
    return mk_error_haio(haio->result, env);

  void *dat;
  size_t sz;
  SEXP out, vec, rvec, response;
  nano_handle *handle = (nano_handle *) haio->next;

  PROTECT(response = nano_findVarInFrame(env, nano_ResponseSymbol, NULL));
  const int all_resp = response != R_NilValue && TYPEOF(response) == LGLSXP && LOGICAL(response)[0] == 1;
  int chk_resp = response != R_NilValue && TYPEOF(response) == STRSXP;
  const uint16_t code = nng_http_res_get_status(handle->res), relo = code >= 300 && code < 400;
  Rf_defineVar(nano_ResultSymbol, Rf_ScalarInteger(code), env);

  if (all_resp) {
    rvec = build_all_headers(handle->res);
  } else {
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
      const SEXP *response_p = STRING_PTR_RO(response);
      for (R_xlen_t i = 0; i < rlen; i++) {
        const char *r = nng_http_res_get_header(handle->res, CHAR(response_p[i]));
        SET_VECTOR_ELT(rvec, i, r == NULL ? R_NilValue : Rf_mkString(r));
      }
      UNPROTECT(1);
    } else {
      rvec = R_NilValue;
    }
    if (relo) UNPROTECT(1);
  }
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
  case 0: out = nano_findVarInFrame(env, nano_ResultSymbol, NULL); break;
  case 1: out = nano_findVarInFrame(env, nano_ProtocolSymbol, NULL); break;
  default: out = nano_findVarInFrame(env, nano_ValueSymbol, NULL); break;
  }
  return out;

}

static inline SEXP nano_aio_http_impl(SEXP env, const int typ) {

  int found;
  SEXP exist;
  switch (typ) {
  case 0: exist = nano_findVarInFrame(env, nano_ResultSymbol, &found); break;
  case 1: exist = nano_findVarInFrame(env, nano_ProtocolSymbol, &found); break;
  default: exist = nano_findVarInFrame(env, nano_ValueSymbol, &found); break;
  }
  if (found)
    return exist;

  const SEXP aio = nano_findVarInFrame(env, nano_AioSymbol, NULL);
  nano_aio *haio = (nano_aio *) NANO_PTR(aio);

  if (nng_aio_busy(haio->aio))
    return nano_unresolved;

  return create_aio_http(env, haio, typ);

}

SEXP nano_aio_http_status(SEXP env) {

  int found;
  SEXP exist = nano_findVarInFrame(env, nano_ResultSymbol, &found);
  if (found)
    return exist;

  const SEXP aio = nano_findVarInFrame(env, nano_AioSymbol, NULL);
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
  const int all_resp = response != R_NilValue && TYPEOF(response) == LGLSXP && LOGICAL(response)[0] == 1;
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

  if ((xc = nano_set_req_headers(req, headers)))
    goto fail;
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

      // tolerate NNG_EBUSY when re-applying server name (SNI) on a reused config
      xc = nng_tls_config_server_name(cfg, url->u_hostname);
      if (xc == NNG_EBUSY) xc = 0;
      if (xc || (xc = nng_http_client_set_tls(client, cfg)))
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

  if (all_resp) {
    rvec = build_all_headers(res);
    SET_VECTOR_ELT(out, 1, rvec);
  } else {
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
      const SEXP *response_p = STRING_PTR_RO(response);
      for (R_xlen_t i = 0; i < rlen; i++) {
        const char *r = nng_http_res_get_header(res, CHAR(response_p[i]));
        SET_VECTOR_ELT(rvec, i, r == NULL ? R_NilValue : Rf_mkString(r));
      }
    } else {
      rvec = R_NilValue;
      SET_VECTOR_ELT(out, 1, rvec);
    }
    if (relo) UNPROTECT(1);
  }

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

  if ((xc = nano_set_req_headers(handle->req, headers)))
    goto fail;
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

      // tolerate NNG_EBUSY when re-applying server name (SNI) on a reused config
      xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname);
      if (xc == NNG_EBUSY) xc = 0;
      if (xc || (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
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
    case 1: R_MakeActiveBinding(nano_StatusSymbol, fun, env); break;
    case 2: R_MakeActiveBinding(nano_HeadersSymbol, fun, env); break;
    case 3: R_MakeActiveBinding(nano_DataSymbol, fun, env); break;
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

// ncurl stream ---------------------------------------------------------------

static SEXP nano_http_stream_chunk_value(
  const unsigned char *data,
  const size_t size,
  const int complete
) {
  const char *names[] = {"data", "complete", ""};
  SEXP out, bytes;
  PROTECT(out = Rf_mkNamed(VECSXP, names));
  PROTECT(bytes = Rf_allocVector(RAWSXP, size));
  if (size > 0)
    memcpy(NANO_DATAPTR(bytes), data, size);
  SET_VECTOR_ELT(out, 0, bytes);
  SET_VECTOR_ELT(out, 1, Rf_ScalarLogical(complete));
  UNPROTECT(2);
  return out;
}

static void nano_http_stream_set_r_state(SEXP stream_xptr, const nano_http_stream *stream) {
  const char *state;
  switch (stream->state) {
  case NANO_HTTP_STREAM_OPENING:
    state = "opening";
    break;
  case NANO_HTTP_STREAM_ERROR:
    state = "error";
    break;
  case NANO_HTTP_STREAM_CLOSED:
    state = "closed";
    break;
  default:
    state = stream->complete ? "complete" : "open";
  }
  Rf_setAttrib(stream_xptr, nano_StateSymbol, Rf_mkString(state));
}

SEXP nano_aio_http_stream_value(SEXP env) {
  int found;
  SEXP exist = nano_findVarInFrame(env, nano_ValueSymbol, &found);
  if (found)
    return exist;

  const SEXP aio_xptr = nano_findVarInFrame(env, nano_AioSymbol, NULL);
  nano_aio *aio = (nano_aio *) NANO_PTR(aio_xptr);
  if (nng_aio_busy(aio->aio))
    return nano_unresolved;
  if (aio->result > 0) {
    SEXP stream_xptr = NANO_PROT(aio_xptr);
    if (!NANO_PTR_CHECK(stream_xptr, nano_HttpStreamSymbol))
      nano_http_stream_set_r_state(stream_xptr, (nano_http_stream *) NANO_PTR(stream_xptr));
    return mk_error_haio(aio->result, env);
  }

  SEXP out;
  if (aio->type == HTTP_STREAM_START_AIO) {
    nano_http_stream *stream = (nano_http_stream *) aio->next;
    const char *names[] = {"status", "headers", "stream", ""};
    PROTECT(out = Rf_mkNamed(VECSXP, names));
    SET_VECTOR_ELT(out, 0, Rf_ScalarInteger(nng_http_res_get_status(stream->response)));
    SET_VECTOR_ELT(out, 1, build_all_headers(stream->response));
    SET_VECTOR_ELT(out, 2, NANO_PROT(aio_xptr));
    nano_http_stream_set_r_state(NANO_PROT(aio_xptr), stream);
  } else {
    nano_http_stream_recv *receive = (nano_http_stream_recv *) aio;
    nano_http_stream_set_r_state(
      NANO_PROT(aio_xptr),
      (nano_http_stream *) receive->aio.next
    );
    PROTECT(out = nano_http_stream_chunk_value(
      receive->output,
      receive->output_size,
      receive->complete
    ));
  }

  Rf_defineVar(nano_ValueSymbol, out, env);
  Rf_defineVar(nano_AioSymbol, R_NilValue, env);
  UNPROTECT(1);
  return out;
}

SEXP rnng_ncurl_stream_aio(
  SEXP http,
  SEXP method,
  SEXP headers,
  SEXP data,
  SEXP timeout,
  SEXP tls,
  SEXP buffer,
  SEXP clo
) {
  const char *address = CHAR(STRING_ELT(http, 0));
  const char *request_method = method != R_NilValue ? CHAR(STRING_ELT(method, 0)) : NULL;
  const nng_duration duration = timeout == R_NilValue
    ? NNG_DURATION_DEFAULT
    : (nng_duration) nano_integer(timeout);
  const int buffer_size = nano_integer(buffer);
  if (buffer_size <= 0)
    Rf_error("`buffer` must be a positive integer");
  if (tls != R_NilValue && NANO_PTR_CHECK(tls, nano_TlsSymbol))
    Rf_error("`tls` is not a valid TLS Configuration");

  int result;
  SEXP stream_xptr, aio_xptr, env, fun;
  nano_http_stream *stream = calloc(1, sizeof(nano_http_stream));
  nano_aio *aio = calloc(1, sizeof(nano_aio));
  if (stream == NULL || aio == NULL) {
    result = NNG_ENOMEM;
    goto fail;
  }
  stream->buffer_size = (size_t) buffer_size;
  aio->type = HTTP_STREAM_START_AIO;
  aio->next = stream;

  if ((result = nng_mtx_alloc(&stream->mtx)) ||
      (result = nng_url_parse(&stream->url, address)) ||
      (result = nng_http_client_alloc(&stream->client, stream->url)) ||
      (result = nng_http_req_alloc(&stream->request, stream->url)) ||
      (result = nng_http_res_alloc(&stream->response)) ||
      (result = nng_aio_alloc(&aio->aio, nano_http_stream_start_complete, aio)))
    goto fail;

  if (request_method != NULL && (result = nng_http_req_set_method(stream->request, request_method)))
    goto fail;

  if ((result = nano_set_req_headers(stream->request, headers)))
    goto fail;
  if ((result = nng_http_req_set_header(stream->request, "Connection", "close")))
    goto fail;

  if (data != R_NilValue) {
    nano_buf encoded = nano_char_buf(data);
    if (encoded.cur && (result = nng_http_req_copy_data(
      stream->request,
      encoded.buf,
      encoded.cur
    )))
      goto fail;
  }

  if (!strcmp(stream->url->u_scheme, "https")) {
    if (tls == R_NilValue) {
      if ((result = nng_tls_config_alloc(&stream->tls, NNG_TLS_MODE_CLIENT)) ||
          (result = nng_tls_config_server_name(stream->tls, stream->url->u_hostname)) ||
          (result = nng_tls_config_auth_mode(stream->tls, NNG_TLS_AUTH_MODE_NONE)) ||
          (result = nng_http_client_set_tls(stream->client, stream->tls)))
        goto fail;
    } else {
      stream->tls = (nng_tls_config *) NANO_PTR(tls);
      nng_tls_config_hold(stream->tls);
      result = nng_tls_config_server_name(stream->tls, stream->url->u_hostname);
      if (result == NNG_EBUSY) result = 0;
      if (result || (result = nng_http_client_set_tls(stream->client, stream->tls)))
        goto fail;
    }
  }

  nng_aio_set_timeout(aio->aio, duration);
  nng_http_client_connect(stream->client, aio->aio);

  PROTECT(stream_xptr = R_MakeExternalPtr(stream, nano_HttpStreamSymbol, R_NilValue));
  R_RegisterCFinalizerEx(stream_xptr, nano_http_stream_finalizer, TRUE);
  Rf_classgets(stream_xptr, Rf_mkString("ncurlStream"));
  Rf_setAttrib(stream_xptr, nano_StateSymbol, Rf_mkString("opening"));
  Rf_setAttrib(stream_xptr, nano_UrlSymbol, http);

  PROTECT(aio_xptr = R_MakeExternalPtr(aio, nano_AioSymbol, stream_xptr));
  R_RegisterCFinalizerEx(aio_xptr, nano_http_stream_start_aio_finalizer, TRUE);

  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  SEXP classes;
  PROTECT(classes = Rf_allocVector(STRSXP, 2));
  SET_STRING_ELT(classes, 0, Rf_mkChar("ncurlStreamAio"));
  SET_STRING_ELT(classes, 1, Rf_mkChar("recvAio"));
  Rf_classgets(env, classes);
  Rf_defineVar(nano_AioSymbol, aio_xptr, env);

  PROTECT(fun = R_mkClosure(R_NilValue, nano_aioFuncMsg, clo));
  R_MakeActiveBinding(nano_DataSymbol, fun, env);

  UNPROTECT(5);
  return env;

fail:
  if (aio != NULL) {
    if (aio->aio != NULL)
      nng_aio_free(aio->aio);
    free(aio);
  }
  nano_http_stream_release(stream);
  return mk_error_ncurl_stream_aio(result);
}

SEXP rnng_ncurl_stream_recv(SEXP stream_xptr, SEXP timeout, SEXP cvar, SEXP clo) {
  if (NANO_PTR_CHECK(stream_xptr, nano_HttpStreamSymbol))
    Rf_error("`stream` is not a valid ncurlStream");

  const int signal = cvar != R_NilValue && !NANO_PTR_CHECK(cvar, nano_CvSymbol);
  if (cvar != R_NilValue && !signal)
    Rf_error("`cv` is not a valid Condition Variable");
  nano_cv *cv = signal ? (nano_cv *) NANO_PTR(cvar) : NULL;

  nano_http_stream *stream = (nano_http_stream *) NANO_PTR(stream_xptr);
  nng_mtx_lock(stream->mtx);
  if (stream->state == NANO_HTTP_STREAM_OPENING) {
    nng_mtx_unlock(stream->mtx);
    Rf_error("`stream` response headers are not ready");
  }
  if (stream->state == NANO_HTTP_STREAM_CLOSED) {
    nng_mtx_unlock(stream->mtx);
    nano_http_stream_signal(cv);
    return mk_error_data(NNG_ECLOSED);
  }
  if (stream->state == NANO_HTTP_STREAM_ERROR) {
    const int error = stream->error;
    nng_mtx_unlock(stream->mtx);
    nano_http_stream_signal(cv);
    return mk_error_data(error);
  }
  if (stream->reading) {
    nng_mtx_unlock(stream->mtx);
    Rf_error("`stream` already has an active receive");
  }

  if (stream->complete) {
    SEXP env, out;
    nng_mtx_unlock(stream->mtx);
    nano_http_stream_signal(cv);
    PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
    Rf_classgets(env, nano_recvAio);
    PROTECT(out = nano_http_stream_chunk_value(NULL, 0, 1));
    Rf_defineVar(nano_DataSymbol, out, env);
    Rf_defineVar(nano_ValueSymbol, out, env);
    Rf_defineVar(nano_AioSymbol, nano_success, env);
    UNPROTECT(2);
    return env;
  }
  nng_mtx_unlock(stream->mtx);

  const nng_duration duration = timeout == R_NilValue
    ? NNG_DURATION_DEFAULT
    : (nng_duration) nano_integer(timeout);
  int result;
  SEXP aio_xptr, env, fun;
  nano_http_stream_recv *receive = calloc(1, sizeof(nano_http_stream_recv));
  if (receive == NULL) {
    nano_http_stream_signal(cv);
    return mk_error_data(NNG_ENOMEM);
  }
  receive->aio.type = HTTP_STREAM_RECV_AIO;
  receive->aio.next = stream;
  receive->cv = cv;
  receive->input = malloc(stream->buffer_size);
  receive->output = malloc(stream->buffer_size);
  if (receive->input == NULL || receive->output == NULL) {
    result = NNG_ENOMEM;
    goto fail;
  }

  nng_iov iov = {
    .iov_buf = receive->input,
    .iov_len = stream->buffer_size
  };
  if ((result = nng_aio_alloc(
    &receive->aio.aio,
    nano_http_stream_receive_complete,
    receive
  )) || (result = nng_aio_set_iov(receive->aio.aio, 1u, &iov)))
    goto fail;

  nng_aio_set_timeout(receive->aio.aio, duration);
  nng_mtx_lock(stream->mtx);
  stream->reading = 1;
  nng_http_conn_read(stream->connection, receive->aio.aio);
  nng_mtx_unlock(stream->mtx);

  PROTECT(aio_xptr = R_MakeExternalPtr(&receive->aio, nano_AioSymbol, stream_xptr));
  R_RegisterCFinalizerEx(aio_xptr, nano_http_stream_recv_aio_finalizer, TRUE);
  PROTECT(env = R_NewEnv(R_NilValue, 0, 0));
  Rf_classgets(env, nano_recvAio);
  Rf_defineVar(nano_AioSymbol, aio_xptr, env);
  PROTECT(fun = R_mkClosure(R_NilValue, nano_aioFuncMsg, clo));
  R_MakeActiveBinding(nano_DataSymbol, fun, env);
  UNPROTECT(3);
  return env;

fail:
  if (receive->aio.aio != NULL)
    nng_aio_free(receive->aio.aio);
  free(receive->input);
  free(receive->output);
  free(receive);
  nano_http_stream_signal(cv);
  return mk_error_data(result);
}

SEXP rnng_ncurl_stream_close(SEXP stream_xptr) {
  if (NANO_PTR_CHECK(stream_xptr, nano_HttpStreamSymbol))
    Rf_error("`stream` is not a valid or active ncurlStream");

  nano_http_stream *stream = (nano_http_stream *) NANO_PTR(stream_xptr);
  nng_mtx_lock(stream->mtx);
  if (stream->state == NANO_HTTP_STREAM_CLOSED) {
    nng_mtx_unlock(stream->mtx);
    return mk_error(NNG_ECLOSED);
  }
  stream->state = NANO_HTTP_STREAM_CLOSED;
  nng_http_conn *connection = stream->connection;
  stream->connection = NULL;
  nng_mtx_unlock(stream->mtx);
  if (connection != NULL)
    nng_http_conn_close(connection);
  Rf_setAttrib(stream_xptr, nano_StateSymbol, Rf_mkString("closed"));
  return nano_success;
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

  if ((xc = nano_set_req_headers(handle->req, headers)))
    goto fail;
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

      // tolerate NNG_EBUSY when re-applying server name (SNI) on a reused config
      xc = nng_tls_config_server_name(handle->cfg, handle->url->u_hostname);
      if (xc == NNG_EBUSY) xc = 0;
      if (xc || (xc = nng_http_client_set_tls(handle->cli, handle->cfg)))
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

  int store_resp = response != R_NilValue &&
    (TYPEOF(response) == STRSXP || (TYPEOF(response) == LGLSXP && LOGICAL(response)[0] == 1));
  PROTECT(sess = R_MakeExternalPtr(haio, nano_StatusSymbol, store_resp ? response : R_NilValue));
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
  if (response != R_NilValue && TYPEOF(response) == LGLSXP && LOGICAL(response)[0] == 1) {
    rvec = build_all_headers(handle->res);
    SET_VECTOR_ELT(out, 1, rvec);
  } else if (response != R_NilValue && TYPEOF(response) == STRSXP) {
    const R_xlen_t rlen = XLENGTH(response);
    rvec = Rf_allocVector(VECSXP, rlen);
    SET_VECTOR_ELT(out, 1, rvec);
    Rf_namesgets(rvec, response);
    const SEXP *response_p = STRING_PTR_RO(response);
    for (R_xlen_t i = 0; i < rlen; i++) {
      const char *r = nng_http_res_get_header(handle->res, CHAR(response_p[i]));
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
  Rf_setAttrib(session, nano_StateSymbol, Rf_mkString("closed"));

  return nano_success;

}
