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
#' @param headers (optional) a named character vector specifying the HTTP
#'   request headers, for example: \cr
#'   `c(Authorization = "Bearer APIKEY", "Content-Type" = "text/plain")` \cr
#'   A non-character or non-named vector will be ignored.
#' @param data (optional) character string request data to be submitted. If a
#'   vector, only the first element is taken, and non-character objects are
#'   ignored.
#' @param response (optional) a character vector specifying the response headers
#'   to return e.g. `c("date", "server")`. These are case-insensitive and
#'   will return NULL if not present. A non-character vector will be ignored.
#' @param timeout (optional) integer value in milliseconds after which the
#'   transaction times out if not yet complete.
#' @param tls (optional) applicable to secure HTTPS sites only, a client TLS
#'   Configuration object created by [tls_config()]. If missing or NULL,
#'   certificates are not validated.
#'
#' @return Named list of 3 elements:
#'  \itemize{
#'     \item `$status` - integer HTTP repsonse status code (200 - OK).
#'     Use [status_code()] for a translation of the meaning.
#'     \item `$headers` - named list of response headers supplied in `response`,
#'     or NULL otherwise. If the status code is within the 300 range, i.e. a
#'     redirect, the response header 'Location' is automatically appended to
#'     return the redirect address.
#'     \item `$data` - the response body, as a character string if
#'     `convert = TRUE` (may be further parsed as html, json, xml etc. as
#'     required), or a raw byte vector if FALSE (use [writeBin()] to save as a
#'     file).
#'  }
#'
#' @seealso [ncurl_aio()] for asynchronous http requests; [ncurl_session()] for
#'   persistent connections.
#'
#' @examples
#' ncurl("https://postman-echo.com/get",
#'        convert = FALSE,
#'        response = c("date", "content-type"),
#'        timeout = 1200L)
#' ncurl("https://postman-echo.com/put",
#'       method = "PUT",
#'       headers = c(Authorization = "Bearer APIKEY"),
#'       data = "hello world",
#'       timeout = 1500L)
#' ncurl("https://postman-echo.com/post",
#'       method = "POST",
#'       headers = c(`Content-Type` = "application/json"),
#'       data = '{"key":"value"}',
#'       timeout = 1500L)
#'
#' @export
#'
ncurl <- function(url,
                  convert = TRUE,
                  follow = FALSE,
                  method = NULL,
                  headers = NULL,
                  data = NULL,
                  response = NULL,
                  timeout = NULL,
                  tls = NULL)
  .Call(rnng_ncurl, url, convert, follow, method, headers, data, response, timeout, tls)

#' ncurl Async
#'
#' nano cURL - a minimalist http(s) client - async edition.
#'
#' @inheritParams ncurl
#'
#' @return An 'ncurlAio' (object of class 'ncurlAio' and 'recvAio') (invisibly).
#'   The following elements may be accessed:
#'   \itemize{
#'     \item `$status` - integer HTTP repsonse status code (200 - OK).
#'     Use [status_code()] for a translation of the meaning.
#'     \item `$headers` - named list of response headers supplied in `response`,
#'     or NULL otherwise. If the status code is within the 300 range, i.e. a
#'     redirect, the response header 'Location' is automatically appended to
#'     return the redirect address.
#'     \item `$data` - the response body, as a character string if
#'     `convert = TRUE` (may be further parsed as html, json, xml etc. as
#'     required), or a raw byte vector if FALSE (use [writeBin()] to save as a
#'     file).
#'   }
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
#' nc <- ncurl_aio("https://postman-echo.com/get",
#'                 response = c("date", "server"),
#'                 timeout = 2000L)
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
#' p2 <- ncurl_aio("https://postman-echo.com/get") %...>% cat
#' is.promise(p2)
#'
#' @export
#'
ncurl_aio <- function(url,
                      convert = TRUE,
                      method = NULL,
                      headers = NULL,
                      data = NULL,
                      response = NULL,
                      timeout = NULL,
                      tls = NULL)
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
#' @seealso [ncurl()] for synchronous http requests; [ncurl_aio()] for
#'   asynchronous http requests.
#'
#' @examples
#' s <- ncurl_session("https://postman-echo.com/get",
#'                    response = "date",
#'                    timeout = 2000L)
#' s
#' if (is_ncurl_session(s)) transact(s)
#' if (is_ncurl_session(s)) close(s)
#'
#' @export
#'
ncurl_session <- function(url,
                          convert = TRUE,
                          method = NULL,
                          headers = NULL,
                          data = NULL,
                          response = NULL,
                          timeout = NULL,
                          tls = NULL)
    .Call(rnng_ncurl_session, url, convert, method, headers, data, response, timeout, tls)

#' @param session an 'ncurlSession' object.
#'
#' @return For `transact`: a named list of 3 elements:
#'   \itemize{
#'     \item `$status` - integer HTTP repsonse status code (200 - OK).
#'     Use [status_code()] for a translation of the meaning.
#'     \item `$headers` - named list of response headers (if specified in the
#'     session), or NULL otherwise. If the status code is within the 300 range,
#'     i.e. a redirect, the response header 'Location' is automatically appended
#'     to return the redirect address.
#'     \item `$data` - the response body as a character string (if
#'     `convert = TRUE` was specified for the session), which may be further
#'     parsed as html, json, xml etc. as required, or else a raw byte vector,
#'     which may be saved as a file using [writeBin()].
#'   }
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
#' Allows an 'ncurlAio' to be used with the promise pipe `%...>%`, which
#' schedules a function to run upon resolution of the Aio.
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

    promise <- if (unresolved(x)) {
      promises::promise(
        function(resolve, reject) .keep(x, environment())
      )$then(
        onFulfilled = function(value, .visible) {
          value == 200L || stop(if (value < 100) nng_error(value) else status_code(value))
          .subset2(x, "value")
        }
      )
    } else {
      value <- .subset2(x, "result")
      promises::promise(
        function(resolve, reject)
          resolve({
            value == 200L || stop(if (value < 100) nng_error(value) else status_code(value))
            .subset2(x, "value")
          })
      )
    }

    `[[<-`(x, "promise", promise)

  }

  promise

}

#' @exportS3Method promises::is.promising
#'
is.promising.ncurlAio <- function(x) TRUE
