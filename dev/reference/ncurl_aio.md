# ncurl Async

nano cURL - a minimalist http(s) client - async edition.

## Usage

``` r
ncurl_aio(
  url,
  convert = TRUE,
  method = NULL,
  headers = NULL,
  data = NULL,
  response = NULL,
  timeout = NULL,
  tls = NULL
)
```

## Arguments

- url:

  the URL address.

- convert:

  \[default TRUE\] logical value whether to attempt conversion of the
  received raw bytes to a character vector. Set to `FALSE` if
  downloading non-text data.

- method:

  (optional) the HTTP method as a character string. Defaults to 'GET' if
  not specified, and could also be 'POST', 'PUT' etc.

- headers:

  (optional) a named character vector specifying the HTTP request
  headers, for example:  
  `c(Authorization = "Bearer APIKEY", "Content-Type" = "text/plain")`  
  A non-character or non-named vector will be ignored.

- data:

  (optional) request data to be submitted. Must be a character string or
  raw vector, and other objects are ignored. If a character vector, only
  the first element is taken. When supplying binary data, the
  appropriate 'Content-Type' header should be set to specify the binary
  format.

- response:

  (optional) a character vector specifying the response headers to
  return e.g. `c("date", "server")`. These are case-insensitive and will
  return NULL if not present. A non-character vector will be ignored.

- timeout:

  (optional) integer value in milliseconds after which the transaction
  times out if not yet complete.

- tls:

  (optional) applicable to secure HTTPS sites only, a client TLS
  Configuration object created by
  [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md).
  If missing or NULL, certificates are not validated.

## Value

An 'ncurlAio' (object of class 'ncurlAio' and 'recvAio') (invisibly).
The following elements may be accessed:

- `$status` - integer HTTP repsonse status code (200 - OK). Use
  [`status_code()`](https://nanonext.r-lib.org/dev/reference/status_code.md)
  for a translation of the meaning.

- `$headers` - named list of response headers supplied in `response`, or
  NULL otherwise. If the status code is within the 300 range, i.e. a
  redirect, the response header 'Location' is automatically appended to
  return the redirect address.

- `$data` - the response body, as a character string if `convert = TRUE`
  (may be further parsed as html, json, xml etc. as required), or a raw
  byte vector if FALSE (use
  [`writeBin()`](https://rdrr.io/r/base/readBin.html) to save as a
  file).

## Promises

'ncurlAio' may be used anywhere that accepts a 'promise' from the
[promises](https://CRAN.R-project.org/package=promises) package through
the included `as.promise` method.

The promises created are completely event-driven and non-polling.

If a status code of 200 (OK) is returned then the promise is resolved
with the reponse body, otherwise it is rejected with a translation of
the status code or 'errorValue' as the case may be.

## See also

[`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) for
synchronous http requests;
[`ncurl_session()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
for persistent connections.

## Examples

``` r
nc <- ncurl_aio(
  "https://postman-echo.com/get",
  response = c("date", "server"),
  timeout = 2000L
)
call_aio(nc)
nc$status
#> [1] 200
nc$headers
#> $date
#> [1] "Tue, 02 Dec 2025 14:53:15 GMT"
#> 
#> $server
#> [1] "cloudflare"
#> 
nc$data
#> [1] "{\"args\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\"},\"url\":\"https://postman-echo.com/get\"}"

if (FALSE) { # interactive() && requireNamespace("promises", quietly = TRUE)
library(promises)
p <- as.promise(nc)
print(p)

p2 <- ncurl_aio("https://postman-echo.com/get") %>%
  then(function(x) cat(x$data))
is.promise(p2)
}
```
