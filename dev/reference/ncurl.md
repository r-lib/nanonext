# ncurl

nano cURL - a minimalist http(s) client.

## Usage

``` r
ncurl(
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
```

## Arguments

- url:

  the URL address.

- convert:

  \[default TRUE\] logical value whether to attempt conversion of the
  received raw bytes to a character vector. Set to `FALSE` if
  downloading non-text data.

- follow:

  \[default FALSE\] logical value whether to automatically follow
  redirects (not applicable for async requests). If `FALSE`, the
  redirect address is returned as response header 'Location'.

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

Named list of 3 elements:

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

## See also

[`ncurl_aio()`](https://nanonext.r-lib.org/dev/reference/ncurl_aio.md)
for asynchronous http requests;
[`ncurl_session()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
for persistent connections.

## Examples

``` r
ncurl(
  "https://postman-echo.com/get",
  convert = FALSE,
  response = c("date", "content-type"),
  timeout = 1200L
)
#> $status
#> [1] 200
#> 
#> $headers
#> $headers$date
#> [1] "Tue, 02 Dec 2025 14:53:14 GMT"
#> 
#> $headers$`content-type`
#> [1] "application/json; charset=utf-8"
#> 
#> 
#> $data
#>   [1] 7b 22 61 72 67 73 22 3a 7b 7d 2c 22 68 65 61 64 65 72 73 22 3a 7b
#>  [23] 22 68 6f 73 74 22 3a 22 70 6f 73 74 6d 61 6e 2d 65 63 68 6f 2e 63
#>  [45] 6f 6d 22 2c 22 61 63 63 65 70 74 2d 65 6e 63 6f 64 69 6e 67 22 3a
#>  [67] 22 67 7a 69 70 2c 20 62 72 22 2c 22 78 2d 66 6f 72 77 61 72 64 65
#>  [89] 64 2d 70 72 6f 74 6f 22 3a 22 68 74 74 70 73 22 7d 2c 22 75 72 6c
#> [111] 22 3a 22 68 74 74 70 73 3a 2f 2f 70 6f 73 74 6d 61 6e 2d 65 63 68
#> [133] 6f 2e 63 6f 6d 2f 67 65 74 22 7d
#> 
ncurl(
  "https://postman-echo.com/put",
  method = "PUT",
  headers = c(Authorization = "Bearer APIKEY"),
  data = "hello world",
  timeout = 1500L
)
#> $status
#> [1] 200
#> 
#> $headers
#> NULL
#> 
#> $data
#> [1] "{\"args\":{},\"data\":\"hello world\",\"files\":{},\"form\":{},\"headers\":{\"host\":\"postman-echo.com\",\"authorization\":\"Bearer APIKEY\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\",\"content-length\":\"11\",\"content-type\":\"application/json\"},\"json\":null,\"url\":\"https://postman-echo.com/put\"}"
#> 
ncurl(
  "https://postman-echo.com/post",
  method = "POST",
  headers = c(`Content-Type` = "application/json"),
  data = '{"key":"value"}',
  timeout = 1500L
)
#> $status
#> [1] 200
#> 
#> $headers
#> NULL
#> 
#> $data
#> [1] "{\"args\":{},\"data\":{\"key\":\"value\"},\"files\":{},\"form\":{},\"headers\":{\"host\":\"postman-echo.com\",\"content-type\":\"application/json\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\",\"content-length\":\"15\"},\"json\":{\"key\":\"value\"},\"url\":\"https://postman-echo.com/post\"}"
#> 
```
