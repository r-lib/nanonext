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
  return NULL if not present. Specify `TRUE` to return all response
  headers. A non-character vector will be ignored (other than `TRUE`).

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

- `$headers` - named list of response headers (all headers if
  `response = TRUE`, or those specified in `response`, or NULL
  otherwise). If the status code is within the 300 range, i.e. a
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
#> [1] "Fri, 06 Feb 2026 00:22:34 GMT"
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
  "https://postman-echo.com/get",
  response = TRUE,
  timeout = 1200L
)
#> $status
#> [1] 200
#> 
#> $headers
#> $headers$Date
#> [1] "Fri, 06 Feb 2026 00:22:34 GMT"
#> 
#> $headers$`Content-Type`
#> [1] "application/json; charset=utf-8"
#> 
#> $headers$`Content-Length`
#> [1] "143"
#> 
#> $headers$Connection
#> [1] "close"
#> 
#> $headers$`CF-RAY`
#> [1] "9c967e70cff8081c-IAD"
#> 
#> $headers$etag
#> [1] "W/\"8f-7zN8nSad8A9WlFJjKQZB04z5nHE\""
#> 
#> $headers$vary
#> [1] "Accept-Encoding"
#> 
#> $headers$`Set-Cookie`
#> [1] "sails.sid=s%3AFj24ltE_HqXAN9WAnCPIszbtf8t_wtkn.aYRVBP47uwm%2BFFji4dUtVNSMo4qWYmxXv%2FnHFquTcN4; Path=/; HttpOnly, __cf_bm=z.vzarViQg.EjGw9QkCmxKDWQsT9Slexbrfn8XLlZ3s-1770337354-1.0.1.1-Rf6QmKcjhGepaOgFcKSa_jhaLTc0B2cwkgaF._fUPAF3vezmEa.WB1tFMdPw9KYoRt2EUKfKn2CTF55OU8kS5P6NN6RvmEicezCU7UMsryY; path=/; expires=Fri, 06-Feb-26 00:52:34 GMT; domain=.postman-echo.com; HttpOnly; Secure, _cfuvid=HXsCSujGz6GqIawC_YedFLLCOWxPIGxKdeWm0NrJUcU-1770337354389-0.0.1.1-604800000; path=/; domain=.postman-echo.com; HttpOnly; Secure; SameSite=None"
#> 
#> $headers$`x-envoy-upstream-service-time`
#> [1] "5"
#> 
#> $headers$`cf-cache-status`
#> [1] "DYNAMIC"
#> 
#> $headers$Server
#> [1] "cloudflare"
#> 
#> 
#> $data
#> [1] "{\"args\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\"},\"url\":\"https://postman-echo.com/get\"}"
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
