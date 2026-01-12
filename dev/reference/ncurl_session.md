# ncurl Session

nano cURL - a minimalist http(s) client. A session encapsulates a
connection, along with all related parameters, and may be used to return
data multiple times by repeatedly calling `transact()`, which transacts
once over the connection.

## Usage

``` r
ncurl_session(
  url,
  convert = TRUE,
  method = NULL,
  headers = NULL,
  data = NULL,
  response = NULL,
  timeout = NULL,
  tls = NULL
)

transact(session)
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

  (optional) integer value in milliseconds after which the connection
  and subsequent transact attempts time out.

- tls:

  (optional) applicable to secure HTTPS sites only, a client TLS
  Configuration object created by
  [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md).
  If missing or NULL, certificates are not validated.

- session:

  an 'ncurlSession' object.

## Value

For `ncurl_session`: an 'ncurlSession' object if successful, or else an
'errorValue'.

For `transact`: a named list of 3 elements:

- `$status` - integer HTTP repsonse status code (200 - OK). Use
  [`status_code()`](https://nanonext.r-lib.org/dev/reference/status_code.md)
  for a translation of the meaning.

- `$headers` - named list of response headers (if specified in the
  session), or NULL otherwise. If the status code is within the 300
  range, i.e. a redirect, the response header 'Location' is
  automatically appended to return the redirect address.

- `$data` - the response body as a character string (if `convert = TRUE`
  was specified for the session), which may be further parsed as html,
  json, xml etc. as required, or else a raw byte vector, which may be
  saved as a file using
  [`writeBin()`](https://rdrr.io/r/base/readBin.html).

## See also

[`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) for
synchronous http requests;
[`ncurl_aio()`](https://nanonext.r-lib.org/dev/reference/ncurl_aio.md)
for asynchronous http requests.

## Examples

``` r
s <- ncurl_session(
  "https://postman-echo.com/get",
  response = "date",
  timeout = 2000L
)
s
#> < ncurlSession > - transact() to return data
if (is_ncurl_session(s)) transact(s)
#> $status
#> [1] 200
#> 
#> $headers
#> $headers$date
#> [1] "Mon, 12 Jan 2026 14:23:03 GMT"
#> 
#> 
#> $data
#> [1] "{\"args\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\"},\"url\":\"https://postman-echo.com/get\"}"
#> 
if (is_ncurl_session(s)) close(s)
```
