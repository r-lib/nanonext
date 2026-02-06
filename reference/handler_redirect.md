# Create HTTP Redirect Handler

Creates an HTTP handler that returns a redirect response.

## Usage

``` r
handler_redirect(path, location, status = 302L, prefix = FALSE)
```

## Arguments

- path:

  URI path to match (e.g., "/old-page").

- location:

  URL to redirect to. Can be relative (e.g., "/new-page") or absolute
  (e.g., "https://example.com/page").

- status:

  HTTP redirect status code. Must be one of:

  - 301 - Moved Permanently

  - 302 - Found (default)

  - 303 - See Other

  - 307 - Temporary Redirect

  - 308 - Permanent Redirect

- prefix:

  \[default FALSE\] Logical, if TRUE matches path as a prefix.

## Value

A handler object for use with
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md).

## Examples

``` r
# Permanent redirect
h1 <- handler_redirect("/old", "/new", status = 301L)

# Redirect bare path to trailing slash
h2 <- handler_redirect("/app", "/app/")
```
