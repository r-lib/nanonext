# Create HTTP/WebSocket Server

Creates a server that can handle HTTP requests and WebSocket
connections.

## Usage

``` r
http_server(url, handlers = list(), tls = NULL)
```

## Arguments

- url:

  URL to listen on (e.g., "http://127.0.0.1:8080").

- handlers:

  A handler or list of handlers created with
  [`handler()`](https://nanonext.r-lib.org/dev/reference/handler.md),
  [`handler_ws()`](https://nanonext.r-lib.org/dev/reference/handler_ws.md),
  etc.

- tls:

  TLS configuration for HTTPS/WSS, created via
  [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md).

## Value

A nanoServer object with methods:

- `$start()` - Start accepting connections

- `$close()` - Stop and release all resources

- `$url` - The server URL

## Details

This function leverages NNG's shared HTTP server architecture. When both
HTTP handlers and WebSocket handlers are provided, they share the same
underlying server and port. WebSocket handlers automatically handle the
HTTP upgrade handshake and all WebSocket framing (RFC 6455).

WebSocket callbacks are executed on R's main thread via the 'later'
package. To process callbacks, you must run the event loop (e.g., using
[`later::run_now()`](https://later.r-lib.org/reference/run_now.html) in
a loop).

## Examples

``` r
if (FALSE) { # interactive() && requireNamespace("later", quietly = TRUE)
# Simple HTTP server
server <- http_server(
  url = "http://127.0.0.1:8080",
  handlers = list(
    handler("/", function(req) {
      list(status = 200L, body = "Hello, World!")
    }),
    handler("/api/data", function(req) {
      list(
        status = 200L,
        headers = c("Content-Type" = "application/json"),
        body = '{"value": 42}'
      )
    })
  )
)
server$start()
# Run event loop: repeat later::run_now(Inf)
server$close()

# HTTP + WebSocket server
server <- http_server(
  url = "http://127.0.0.1:8080",
  handlers = list(
    handler("/", function(req) {
      list(status = 200L, body = "<html>...</html>")
    }),
    handler_ws("/ws", function(ws, data) {
      ws$send(data)  # Echo
    }, textframes = TRUE)
  )
)

# Multiple WebSocket endpoints
server <- http_server(
  url = "http://127.0.0.1:8080",
  handlers = list(
    handler_ws("/echo", function(ws, data) ws$send(data)),
    handler_ws("/upper", function(ws, data) ws$send(toupper(data)), textframes = TRUE)
  )
)

# HTTPS server with self-signed certificate
cert <- write_cert(cn = "127.0.0.1")
cfg <- tls_config(server = cert$server)
server <- http_server(
  url = "https://127.0.0.1:8443",
  handlers = list(
    handler("/", function(req) list(status = 200L, body = "Secure!"))
  ),
  tls = cfg
)
server$start()

# Send async request and run event loop
aio <- ncurl_aio(
  "https://127.0.0.1:8443/",
  tls = tls_config(client = cert$client),
  timeout = 2000
)
while (unresolved(aio)) later::run_now(0.1)

aio$status
aio$data

server$close()
}
```
