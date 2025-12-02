# Translate HTTP Status Codes

Provides an explanation for HTTP response status codes (in the range 100
to 599). If the status code is not defined as per RFC 9110,
`"Unknown HTTP Status"` is returned - this may be a custom code used by
the server.

## Usage

``` r
status_code(x)
```

## Arguments

- x:

  numeric HTTP status code to translate.

## Value

A character vector comprising the status code and explanation separated
by `'|'`.

## Examples

``` r
status_code(200)
#> [1] "200 | OK"
status_code(404)
#> [1] "404 | Not Found"
```
