# Create WebSocket Handler

Creates a WebSocket handler for use with
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md).

## Usage

``` r
handler_ws(
  path,
  on_message,
  on_open = NULL,
  on_close = NULL,
  textframes = FALSE
)
```

## Arguments

- path:

  URI path for WebSocket connections (e.g., "/ws").

- on_message:

  Function called when a message is received. Signature:
  `function(ws, data)` where `ws` is the connection object and `data` is
  the message. Use `ws$send()` to send responses; the return value is
  ignored.

- on_open:

  \[default NULL\] Function called when a connection opens. Signature:
  `function(ws)`

- on_close:

  \[default NULL\] Function called when a connection closes. Signature:
  `function(ws)`

- textframes:

  \[default FALSE\] Logical, use text frames instead of binary. When
  TRUE: incoming `data` is character, outgoing data should be character.
  When FALSE: incoming `data` is raw vector, outgoing data should be raw
  vector.

## Value

A handler object for use with
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md).

## Connection Object

The `ws` object passed to callbacks has the following fields and
methods:

- `ws$send(data)`: Send a message to the client. `data` can be a raw
  vector or character string. Returns 0 on success, or an error code on
  failure (e.g., if the connection is closed).

- `ws$close()`: Close the connection.

- `ws$id`: Unique integer identifier for this connection. No two
  connections on the same server will share an ID, even across different
  handlers, making IDs safe to use as keys in a shared data structure.

## Examples

``` r
# Simple echo server
h <- handler_ws("/ws", function(ws, data) ws$send(data))

# With connection tracking
clients <- list()
h <- handler_ws(
  "/chat",
  on_message = function(ws, data) {
    # Broadcast to all
    for (client in clients) client$send(data)
  },
  on_open = function(ws) {
    clients[[as.character(ws$id)]] <<- ws
  },
  on_close = function(ws) {
    clients[[as.character(ws$id)]] <<- NULL
  },
  textframes = TRUE
)
```
