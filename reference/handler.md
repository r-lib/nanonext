# Create HTTP Handler

Creates an HTTP route handler for use with
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md).

## Usage

``` r
handler(path, callback, method = "GET", prefix = FALSE)
```

## Arguments

- path:

  URI path to match (e.g., "/api/data", "/users").

- callback:

  Function to handle requests. Receives a list with:

  - `method` - HTTP method (character)

  - `uri` - Request URI (character)

  - `headers` - Named character vector of headers

  - `body` - Request body (raw vector)

  Should return a list with:

  - `status` - HTTP status code (integer, default 200)

  - `headers` - Response headers as a named character vector, e.g.
    `c("Content-Type" = "application/json")` (optional)

  - `body` - Response body (character or raw)

- method:

  \[default "GET"\] HTTP method to match (e.g., "GET", "POST", "PUT",
  "DELETE"). Use `"*"` to match any method.

- prefix:

  \[default FALSE\] Logical, if TRUE matches path as a prefix (e.g.,
  "/api" will match "/api/users", "/api/items", etc.).

## Value

A handler object for use with
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md).

## Details

If the callback throws an error, a 500 Internal Server Error response is
returned to the client.

## See also

[`handler_ws()`](https://nanonext.r-lib.org/reference/handler_ws.md) for
WebSocket handlers. Static handlers:
[`handler_file()`](https://nanonext.r-lib.org/reference/handler_file.md),
[`handler_directory()`](https://nanonext.r-lib.org/reference/handler_directory.md),
[`handler_inline()`](https://nanonext.r-lib.org/reference/handler_inline.md),
[`handler_redirect()`](https://nanonext.r-lib.org/reference/handler_redirect.md).

## Examples

``` r
# Simple GET handler
h1 <- handler("/hello", function(req) {
  list(status = 200L, body = "Hello!")
})

# POST handler that echoes the request body
h2 <- handler("/echo", function(req) {
  list(status = 200L, body = req$body)
}, method = "POST")

# Catch-all handler for a path prefix
h3 <- handler("/static", function(req) {
  # Serve static files under /static/*
}, method = "*", prefix = TRUE)
```
