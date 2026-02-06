# Create Inline Static Content Handler

Creates an HTTP handler that serves in-memory static content. Useful for
small files like robots.txt or inline JSON/HTML.

## Usage

``` r
handler_inline(path, data, content_type = NULL, prefix = FALSE)
```

## Arguments

- path:

  URI path to match (e.g., "/robots.txt").

- data:

  Content to serve. Character data is converted to raw bytes.

- content_type:

  MIME type (e.g., "text/plain", "application/json"). Defaults to
  "application/octet-stream" if NULL.

- prefix:

  \[default FALSE\] Logical, if TRUE matches path as a prefix.

## Value

A handler object for use with
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md).

## Examples

``` r
h1 <- handler_inline("/robots.txt", "User-agent: *\nDisallow:",
                     content_type = "text/plain")
h2 <- handler_inline("/health", '{"status":"ok"}',
                     content_type = "application/json")
```
