# nanonext - ncurl - async http client -----------------------------------------

#' ncurl
#'
#' nano cURL - a minimalist http(s) client.
#'
#' @param url the URL address.
#' @param convert \[default TRUE\] logical value whether to attempt conversion
#'   of the received raw bytes to a character vector. Set to `FALSE` if
#'   downloading non-text data.
#' @param follow \[default FALSE\] logical value whether to automatically follow
#'   redirects (not applicable for async requests). If `FALSE`, the redirect
#'   address is returned as response header 'Location'.
#' @param method (optional) the HTTP method as a character string. Defaults to
#'   'GET' if not specified, and could also be 'POST', 'PUT' etc.
#' @param headers (optional) a named character vector or named list specifying
#'   the HTTP request headers, for example: \cr
#'   `c(Authorization = "Bearer APIKEY", "Content-Type" = "text/plain")` or \cr
#'   `list(Authorization = "Bearer APIKEY", "Content-Type" = "text/plain")` \cr
#'   An unnamed vector or list will be ignored.
#' @param data (optional) request data to be submitted. Must be a character
#'   string or raw vector, and other objects are ignored. If a character vector,
#'   only the first element is taken. When supplying binary data, the
#'   appropriate 'Content-Type' header should be set to specify the binary
#'   format.
#' @param response (optional) `TRUE` to return all response headers, or a
#'   character vector specifying the response headers to return e.g.
#'   `c("date", "server")`. These are case-insensitive and will return NULL if
#'   not present. A non-character vector will be ignored (other than `TRUE`).
#' @param timeout (optional) integer value in milliseconds after which the
#'   transaction times out if not yet complete.
#' @param tls (optional) applicable to secure HTTPS sites only, a client TLS
#'   Configuration object created by [tls_config()]. If missing or NULL,
#'   certificates are not validated.
#'
#' @return Named list of 3 elements:
#'
#' - `$status` - integer HTTP repsonse status code (200 - OK). Use
#'   [status_code()] for a translation of the meaning.
#' - `$headers` - named list of response headers (all headers if
#'   `response = TRUE`, or those specified in `response`, or NULL otherwise).
#'   If the status code is within the 300 range, i.e. a redirect, the response
#'   header 'Location' is automatically appended to return the redirect address.
#' - `$data` - the response body, as a character string if `convert = TRUE` (may
#'   be further parsed as html, json, xml etc. as required), or a raw byte
#'   vector if FALSE (use [writeBin()] to save as a file).
#'
#' @section Public Internet HTTPS:
#'
#' When making HTTPS requests over the public internet, you should supply a TLS
#' configuration to validate server certificates. See [tls_config()] for
#' details.
#'
#' @seealso [ncurl_aio()] for asynchronous http requests; [ncurl_session()] for
#'   persistent connections.
#'
#' @examples
#' ncurl(
#'   "https://postman-echo.com/get",
#'   convert = FALSE,
#'   response = c("date", "content-type"),
#'   timeout = 1200L
#' )
#' ncurl(
#'   "https://postman-echo.com/get",
#'   response = TRUE,
#'   timeout = 1200L
#' )
#' ncurl(
#'   "https://postman-echo.com/put",
#'   method = "PUT",
#'   headers = c(Authorization = "Bearer APIKEY"),
#'   data = "hello world",
#'   timeout = 1500L
#' )
#' ncurl(
#'   "https://postman-echo.com/post",
#'   method = "POST",
#'   headers = c(`Content-Type` = "application/json"),
#'   data = '{"key":"value"}',
#'   timeout = 1500L
#' )
#'
#' @export
#'
ncurl <- function(
  url,
  convert = TRUE,
  follow = FALSE,
  method = NULL,
  headers = NULL,
  data = NULL,
  response = NULL,
  timeout = NULL,
  tls = NULL
)
  .Call(rnng_ncurl, url, convert, follow, method, headers, data, response, timeout, tls)

#' ncurl Async
#'
#' nano cURL - a minimalist http(s) client - async edition.
#'
#' @inheritParams ncurl
#'
#' @return An 'ncurlAio' (object of class 'ncurlAio' and 'recvAio') (invisibly).
#'   The following elements may be accessed:
#'
#' - `$status` - integer HTTP repsonse status code (200 - OK). Use
#'   [status_code()] for a translation of the meaning.
#' - `$headers` - named list of response headers (all headers if
#'   `response = TRUE`, or those specified in `response`, or NULL otherwise).
#'   If the status code is within the 300 range, i.e. a redirect, the response
#'   header 'Location' is automatically appended to return the redirect address.
#' - `$data` - the response body, as a character string if `convert = TRUE` (may
#'   be further parsed as html, json, xml etc. as required), or a raw byte
#'   vector if FALSE (use [writeBin()] to save as a file).
#'
#' @inheritSection ncurl Public Internet HTTPS
#'
#' @section Promises:
#'
#' 'ncurlAio' may be used anywhere that accepts a 'promise' from the
#' \CRANpkg{promises} package through the included `as.promise` method.
#'
#' The promises created are completely event-driven and non-polling.
#'
#' If a status code of 200 (OK) is returned then the promise is resolved with
#' the reponse body, otherwise it is rejected with a translation of the status
#' code or 'errorValue' as the case may be.
#'
#' @seealso [ncurl()] for synchronous http requests; [ncurl_session()] for
#'   persistent connections.
#'
#' @examples
#' nc <- ncurl_aio(
#'   "https://postman-echo.com/get",
#'   response = c("date", "server"),
#'   timeout = 2000L
#' )
#' call_aio(nc)
#' nc$status
#' nc$headers
#' nc$data
#'
#' @examplesIf interactive() && requireNamespace("promises", quietly = TRUE)
#' library(promises)
#' p <- as.promise(nc)
#' print(p)
#'
#' p2 <- ncurl_aio("https://postman-echo.com/get") %>%
#'   then(function(x) cat(x$data))
#' is.promise(p2)
#'
#' @export
#'
ncurl_aio <- function(
  url,
  convert = TRUE,
  method = NULL,
  headers = NULL,
  data = NULL,
  response = NULL,
  timeout = NULL,
  tls = NULL
)
  data <- .Call(rnng_ncurl_aio, url, convert, method, headers, data, response, timeout, tls, environment())

#' ncurl Session
#'
#' nano cURL - a minimalist http(s) client. A session encapsulates a connection,
#' along with all related parameters, and may be used to return data multiple
#' times by repeatedly calling `transact()`, which transacts once over the
#' connection.
#'
#' @inheritParams ncurl
#' @param timeout (optional) integer value in milliseconds after which the
#'   connection and subsequent transact attempts time out.
#'
#' @return For `ncurl_session`: an 'ncurlSession' object if successful, or else
#'   an 'errorValue'.
#'
#' @inheritSection ncurl Public Internet HTTPS
#'
#' @seealso [ncurl()] for synchronous http requests; [ncurl_aio()] for
#'   asynchronous http requests.
#'
#' @examples
#' s <- ncurl_session(
#'   "https://postman-echo.com/get",
#'   response = "date",
#'   timeout = 2000L
#' )
#' s
#' if (is_ncurl_session(s)) transact(s)
#' if (is_ncurl_session(s)) close(s)
#'
#' @export
#'
ncurl_session <- function(
  url,
  convert = TRUE,
  method = NULL,
  headers = NULL,
  data = NULL,
  response = NULL,
  timeout = NULL,
  tls = NULL
)
  .Call(rnng_ncurl_session, url, convert, method, headers, data, response, timeout, tls)

#' @param session an 'ncurlSession' object.
#'
#' @return For `transact`: a named list of 3 elements:
#'
#' - `$status` - integer HTTP repsonse status code (200 - OK). Use
#'   [status_code()] for a translation of the meaning.
#' - `$headers` - named list of response headers (all headers if
#'   `response = TRUE` was specified for the session, those specified in
#'   `response`, or NULL otherwise).
#' - `$data` - the response body as a character string (if `convert = TRUE` was
#'   specified for the session), which may be further parsed as html, json, xml
#'   etc. as required, or else a raw byte vector, which may be saved as a file
#'   using [writeBin()].
#'
#' @rdname ncurl_session
#' @export
#'
transact <- function(session) .Call(rnng_ncurl_transact, session)

#' @rdname close
#' @method close ncurlSession
#' @export
#'
close.ncurlSession <- function(con, ...) invisible(.Call(rnng_ncurl_session_close, con))

#' Make ncurlAio Promise
#'
#' Creates a 'promise' from an 'ncurlAio' object.
#'
#' This function is an S3 method for the generic `as.promise` for class
#' 'ncurlAio'.
#'
#' Requires the \pkg{promises} package.
#'
#' Allows an 'ncurlAio' to be used with functions such as `promises::then()`,
#' which schedules a function to run upon resolution of the Aio.
#'
#' The promise is resolved with a list of 'status', 'headers' and 'data' or
#' rejected with the error translation if an NNG error is returned e.g. for an
#' invalid address.
#'
#' @param x an object of class 'ncurlAio'.
#'
#' @return A 'promise' object.
#'
#' @exportS3Method promises::as.promise
#'
as.promise.ncurlAio <- function(x) {
  promise <- .subset2(x, "promise")

  if (is.null(promise)) {
    promise <- promises::promise(
      function(resolve, reject) {
        if (unresolved(x)) {
          .keep(x, environment())
        } else {
          resolve(
            list(
              status = .subset2(x, "result"),
              headers = .subset2(x, "protocol"),
              data = .subset2(x, "value")
            )
          )
        }
      }
    )$then(onFulfilled = check_for_nng_error)
    `[[<-`(x, "promise", promise)
  }

  promise
}

#' ncurl Stream Async
#'
#' Opens an HTTP(S) request asynchronously and resolves when the response head
#' is available without consuming the response body. Body bytes are read with
#' [ncurl_stream_recv()] as they arrive. Chunked transfer coding is decoded by
#' the client, so each receive returns entity-body bytes only.
#'
#' @inheritParams ncurl
#' @param buffer positive integer maximum number of transport bytes read by one
#'   receive operation.
#' @param timeout (optional) integer value in milliseconds. For
#'   `ncurl_stream_aio()`, this bounds opening the request through receipt of the
#'   response head. For `ncurl_stream_recv()`, it bounds that receive.
#'
#' @return `ncurl_stream_aio()` returns an 'ncurlStreamAio' (also a 'recvAio').
#'   Its value is a named list containing `status`, `headers`, and `stream`,
#'   where `stream` is an 'ncurlStream'. `ncurl_stream_recv()` returns a
#'   'recvAio' whose value is a named list containing raw `data` and logical
#'   `complete`.
#'
#' @section Lifecycle:
#'
#' Only one receive may be active for a stream. A receive resolves when body
#' data is available, the response body is complete, an error occurs, or its
#' timeout elapses. A receive error, including a timeout, is terminal for the
#' stream. Close the stream after completion or error to release the HTTP
#' connection. Closing a stream cancels an active receive.
#'
#' @section Signalling:
#'
#' Supplying `cv` signals the condition variable when the receive resolves,
#' using the same signalling contract as [recv_aio()].
#'
#' @inheritSection ncurl Public Internet HTTPS
#' @seealso [ncurl_aio()] for asynchronous transactions that collect the full
#'   response body.
#'
#' @examplesIf interactive()
#' opening <- ncurl_stream_aio(
#'   "https://postman-echo.com/server-events/3",
#'   timeout = 2000L
#' )
#' head <- opening[]
#' if (!is_error_value(head)) {
#'   chunk <- ncurl_stream_recv(head$stream, timeout = 2000L)[]
#'   close(head$stream)
#' }
#'
#' @export
#'
ncurl_stream_aio <- function(
  url,
  method = NULL,
  headers = NULL,
  data = NULL,
  timeout = NULL,
  tls = NULL,
  buffer = 65536L
)
  data <- .Call(
    rnng_ncurl_stream_aio,
    url,
    method,
    headers,
    data,
    timeout,
    tls,
    buffer,
    environment()
  )

#' @param stream an active 'ncurlStream'.
#' @param cv (optional) a 'conditionVariable' to signal when the receive is
#'   complete.
#'
#' @rdname ncurl_stream_aio
#' @export
#'
ncurl_stream_recv <- function(stream, timeout = NULL, cv = NULL)
  data <- .Call(rnng_ncurl_stream_recv, stream, timeout, cv, environment())

#' @rdname close
#' @method close ncurlStream
#' @export
#'
close.ncurlStream <- function(con, ...) invisible(.Call(rnng_ncurl_stream_close, con))

#' @exportS3Method promises::is.promising
#'
is.promising.ncurlAio <- function(x) TRUE

check_for_nng_error <- function(value, .visible) {
  value[["status"]] >= 100 || stop(nng_error(value[["status"]]))
  value
}
