# Create HTTP Streaming Handler

Creates an HTTP streaming handler using chunked transfer encoding.
Supports any streaming HTTP protocol including Server-Sent Events (SSE),
newline- delimited JSON (NDJSON), and custom streaming formats.

## Usage

``` r
handler_stream(path, on_request, on_close = NULL, method = "*", prefix = FALSE)
```

## Arguments

- path:

  URI path to match (e.g., "/stream").

- on_request:

  Function called when a request arrives. Signature:
  `function(conn, req)` where `conn` is the connection object and `req`
  is a list with `method`, `uri`, `headers`, `body`.

- on_close:

  \[default NULL\] Function called when the connection closes.
  Signature: `function(conn)`

- method:

  \[default "\*"\] HTTP method to match (e.g., "GET", "POST"). Use `"*"`
  to match any method.

- prefix:

  \[default FALSE\] Logical, if TRUE matches path as a prefix.

## Value

A handler object for use with
[`http_server()`](https://nanonext.r-lib.org/dev/reference/http_server.md).

## Details

HTTP streaming uses chunked transfer encoding (RFC 9112). The first
`$send()` triggers writing of HTTP headers with
`Transfer-Encoding: chunked`. Headers cannot be modified after the first
send.

Set an appropriate `Content-Type` header for your streaming format:

- NDJSON: `application/x-ndjson`

- JSON stream: `application/stream+json`

- SSE: `text/event-stream` (see
  [`format_sse()`](https://nanonext.r-lib.org/dev/reference/format_sse.md))

- Plain text: `text/plain`

**SSE Reconnection:** When an SSE client reconnects after a disconnect,
it sends a `Last-Event-ID` header containing the last event ID it
received. Access this via `req$headers["Last-Event-ID"]` in `on_request`
to resume the event stream from the correct position.

To broadcast to multiple clients, store connection objects in a list and
iterate over them (e.g., `lapply(conns, function(c) c$send(data))`).

## Connection Object

The `conn` object passed to callbacks has these methods:

- `conn$send(data)`: Send data chunk to client.

- `conn$close()`: Close the connection (sends terminal chunk).

- `conn$set_status(code)`: Set HTTP status code (before first send).

- `conn$set_header(name, value)`: Set response header (before first
  send).

- `conn$id`: Unique connection identifier.

## See also

[`format_sse()`](https://nanonext.r-lib.org/dev/reference/format_sse.md)
for formatting Server-Sent Events.

## Examples

``` r
# NDJSON streaming endpoint
h <- handler_stream("/stream", function(conn, req) {
  conn$set_header("Content-Type", "application/x-ndjson")
  conn$send('{"status":"connected"}\n')
})

# SSE endpoint with reconnection support
h <- handler_stream("/events", function(conn, req) {
  conn$set_header("Content-Type", "text/event-stream")
  conn$set_header("Cache-Control", "no-cache")
  last_id <- req$headers["Last-Event-ID"]
  # Resume from last_id if client is reconnecting
  conn$send(format_sse(data = "connected", id = "1"))
})

# Long-lived streaming with broadcast triggered by POST
conns <- list()
handlers <- list(
  handler_stream("/stream",
    on_request = function(conn, req) {
      conn$set_header("Content-Type", "application/x-ndjson")
      conns[[as.character(conn$id)]] <<- conn
      conn$send('{"status":"connected"}\n')
    },
    on_close = function(conn) {
      conns[[as.character(conn$id)]] <<- NULL
    }
  ),
  # POST endpoint triggers broadcast to all streaming clients
  handler("/broadcast", function(req) {
    msg <- paste0('{"msg":"', rawToChar(req$body), '"}\n')
    lapply(conns, function(c) c$send(msg))
    list(status = 200L, body = "sent")
  }, method = "POST")
)
```
