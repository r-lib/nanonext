# nanonext - HTTP/WebSocket Server Interface ------------------------------------

#' Create HTTP/WebSocket Server
#'
#' Creates a server that can handle HTTP requests and WebSocket connections.
#'
#' @param url URL to listen on (e.g., "http://127.0.0.1:8080").
#' @param handlers A handler or list of handlers created with [handler()], [handler_ws()], etc.
#' @param tls TLS configuration for HTTPS/WSS, created via [tls_config()].
#'
#' @return A nanoServer object with methods:
#'
#'   - `$start()` - Start accepting connections
#'   - `$close()` - Stop and release all resources
#'   - `$url` - The server URL
#'
#' @details
#' This function leverages NNG's shared HTTP server architecture. When both
#' HTTP handlers and WebSocket handlers are provided, they share the same
#' underlying server and port. WebSocket handlers automatically handle
#' the HTTP upgrade handshake and all WebSocket framing (RFC 6455).
#'
#' WebSocket callbacks are executed on R's main thread via the 'later' package.
#' To process callbacks, you must run the event loop (e.g., using
#' `later::run_now()` in a loop).
#'
#' @examplesIf interactive() && requireNamespace("later", quietly = TRUE)
#' # Simple HTTP server
#' server <- http_server(
#'   url = "http://127.0.0.1:8080",
#'   handlers = list(
#'     handler("/", function(req) {
#'       list(status = 200L, body = "Hello, World!")
#'     }),
#'     handler("/api/data", function(req) {
#'       list(
#'         status = 200L,
#'         headers = c("Content-Type" = "application/json"),
#'         body = '{"value": 42}'
#'       )
#'     })
#'   )
#' )
#' server$start()
#' # Run event loop: repeat later::run_now(Inf)
#' server$close()
#'
#' # HTTP + WebSocket server
#' server <- http_server(
#'   url = "http://127.0.0.1:8080",
#'   handlers = list(
#'     handler("/", function(req) {
#'       list(status = 200L, body = "<html>...</html>")
#'     }),
#'     handler_ws("/ws", function(ws, data) {
#'       ws$send(data)  # Echo
#'     }, textframes = TRUE)
#'   )
#' )
#'
#' # Multiple WebSocket endpoints
#' server <- http_server(
#'   url = "http://127.0.0.1:8080",
#'   handlers = list(
#'     handler_ws("/echo", function(ws, data) ws$send(data)),
#'     handler_ws("/upper", function(ws, data) ws$send(toupper(data)), textframes = TRUE)
#'   )
#' )
#'
#' # HTTPS server with self-signed certificate
#' cert <- write_cert(cn = "127.0.0.1")
#' cfg <- tls_config(server = cert$server)
#' server <- http_server(
#'   url = "https://127.0.0.1:8443",
#'   handlers = list(
#'     handler("/", function(req) list(status = 200L, body = "Secure!"))
#'   ),
#'   tls = cfg
#' )
#' server$start()
#'
#' # Send async request and run event loop
#' aio <- ncurl_aio(
#'   "https://127.0.0.1:8443/",
#'   tls = tls_config(client = cert$client),
#'   timeout = 2000
#' )
#' while (unresolved(aio)) later::run_now(0.1)
#'
#' aio$status
#' aio$data
#'
#' server$close()
#'
#' @export
#'
http_server <- function(url, handlers = list(), tls = NULL) {
  if (is.integer(handlers$type))
    handlers <- list(handlers)
  srv <- .Call(rnng_http_server_create, url, handlers, tls)
  attr(srv, "start") <- function() {
    invisible(.Call(rnng_http_server_start, srv))
  }
  attr(srv, "close") <- function() {
    res <- .Call(rnng_http_server_close, srv)
    if (res == 0L) attr(srv, "state") <- "closed"
    invisible(res)
  }
  srv
}

#' Create HTTP Handler
#'
#' Creates an HTTP route handler for use with [http_server()].
#'
#' @param path URI path to match (e.g., "/api/data", "/users").
#' @param callback Function to handle requests. Receives a list with:
#'
#'   - `method` - HTTP method (character)
#'   - `uri` - Request URI (character)
#'   - `headers` - Named character vector of headers
#'   - `body` - Request body (raw vector)
#'
#'   Should return a list with:
#'
#'   - `status` - HTTP status code (integer, default 200)
#'   - `headers` - Response headers as a named character vector, e.g.
#'     `c("Content-Type" = "application/json")` (optional)
#'   - `body` - Response body (character or raw)
#' @param method \[default "GET"\] HTTP method to match (e.g., "GET", "POST",
#'   "PUT", "DELETE"). Use `"*"` to match any method.
#' @param prefix \[default FALSE\] Logical, if TRUE matches path as a prefix
#'   (e.g., "/api" will match "/api/users", "/api/items", etc.).
#'
#' @return A handler object for use with [http_server()].
#'
#' @details If the callback throws an error, a 500 Internal Server Error
#'   response is returned to the client.
#'
#' @seealso [handler_ws()] for WebSocket handlers. Static handlers:
#'   [handler_file()], [handler_directory()], [handler_inline()],
#'   [handler_redirect()].
#'
#' @examples
#' # Simple GET handler
#' h1 <- handler("/hello", function(req) {
#'   list(status = 200L, body = "Hello!")
#' })
#'
#' # POST handler that echoes the request body
#' h2 <- handler("/echo", function(req) {
#'   list(status = 200L, body = req$body)
#' }, method = "POST")
#'
#' # Catch-all handler for a path prefix
#' h3 <- handler("/static", function(req) {
#'   # Serve static files under /static/*
#' }, method = "*", prefix = TRUE)
#'
#' @export
#'
handler <- function(path, callback, method = "GET", prefix = FALSE) {
  list(type = 1L, path = path, callback = callback, method = method, prefix = prefix)
}

#' Create WebSocket Handler
#'
#' Creates a WebSocket handler for use with [http_server()].
#'
#' @param path URI path for WebSocket connections (e.g., "/ws").
#' @param on_message Function called when a message is received.
#'   Signature: `function(ws, data)` where `ws` is the connection
#'   object and `data` is the message. Use `ws$send()` to send
#'   responses; the return value is ignored.
#' @param on_open \[default NULL\] Function called when a connection opens.
#'   Signature: `function(ws)`
#' @param on_close \[default NULL\] Function called when a connection closes.
#'   Signature: `function(ws)`
#' @param textframes \[default FALSE\] Logical, use text frames instead of binary.
#'   When TRUE: incoming `data` is character, outgoing data should be character.
#'   When FALSE: incoming `data` is raw vector, outgoing data should be raw vector.
#'
#' @return A handler object for use with [http_server()].
#'
#' @section Connection Object:
#' The `ws` object passed to callbacks has the following fields and methods:
#'
#' - `ws$send(data)`: Send a message to the client. `data` can be
#'   a raw vector or character string. Returns 0 on success, or an error code
#'   on failure (e.g., if the connection is closed).
#' - `ws$close()`: Close the connection.
#' - `ws$id`: Unique integer identifier for this connection. No two
#'   connections on the same server will share an ID, even across different
#'   handlers, making IDs safe to use as keys in a shared data structure.
#'
#' @examples
#' # Simple echo server
#' h <- handler_ws("/ws", function(ws, data) ws$send(data))
#'
#' # With connection tracking
#' clients <- list()
#' h <- handler_ws(
#'   "/chat",
#'   on_message = function(ws, data) {
#'     # Broadcast to all
#'     for (client in clients) client$send(data)
#'   },
#'   on_open = function(ws) {
#'     clients[[as.character(ws$id)]] <<- ws
#'   },
#'   on_close = function(ws) {
#'     clients[[as.character(ws$id)]] <<- NULL
#'   },
#'   textframes = TRUE
#' )
#'
#' @export
#'
handler_ws <- function(path, on_message, on_open = NULL, on_close = NULL,
                       textframes = FALSE) {
  list(type = 2L, path = path, on_message = on_message, on_open = on_open,
       on_close = on_close, textframes = textframes)
}

#' Create Static File Handler
#'
#' Creates an HTTP handler that serves a single file. NNG handles MIME type
#' detection automatically.
#'
#' @param path URI path to match (e.g., "/favicon.ico").
#' @param file Path to the file to serve.
#' @param prefix \[default FALSE\] Logical, if TRUE matches path as a prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @examplesIf interactive()
#' h <- handler_file("/favicon.ico", "~/favicon.ico")
#'
#' @export
#'
handler_file <- function(path, file, prefix = FALSE) {
  if (!file.exists(file))
    warning("file does not exist: ", file)
  list(type = 3L, path = path, file = normalizePath(file, mustWork = FALSE),
       prefix = prefix)
}

#' Create Static Directory Handler
#'
#' Creates an HTTP handler that serves files from a directory tree. NNG handles
#' MIME type detection automatically.
#'
#' @param path URI path prefix (e.g., "/static"). Requests to "/static/foo.js"
#'   will serve "directory/foo.js".
#' @param directory Path to the directory to serve.
#'
#' @return A handler object for use with [http_server()].
#'
#' @details
#' Directory handlers automatically match all paths under the prefix (prefix
#' matching is implicit). The URI path is mapped to the filesystem:
#'
#' - Request to "/static/css/style.css" serves "directory/css/style.css"
#' - Request to "/static/" serves "directory/index.html" if it exists
#'
#' Note: The trailing slash behavior depends on how clients make requests.
#' A request to "/static" (no trailing slash) will not automatically redirect
#' to "/static/". Consider using [handler_redirect()] if you need this behavior.
#'
#' @examplesIf interactive()
#' h <- handler_directory("/static", "www/assets")
#'
#' @export
#'
handler_directory <- function(path, directory) {
  if (!dir.exists(directory))
    warning("directory does not exist: ", directory)
  list(type = 4L, path = path,
       directory = normalizePath(directory, mustWork = FALSE))
}

#' Create Inline Static Content Handler
#'
#' Creates an HTTP handler that serves in-memory static content. Useful for
#' small files like robots.txt or inline JSON/HTML.
#'
#' @param path URI path to match (e.g., "/robots.txt").
#' @param data Content to serve. Character data is converted to raw bytes.
#' @param content_type MIME type (e.g., "text/plain", "application/json").
#'   Defaults to "application/octet-stream" if NULL.
#' @param prefix \[default FALSE\] Logical, if TRUE matches path as a prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @examples
#' h1 <- handler_inline("/robots.txt", "User-agent: *\nDisallow:",
#'                      content_type = "text/plain")
#' h2 <- handler_inline("/health", '{"status":"ok"}',
#'                      content_type = "application/json")
#'
#' @export
#'
handler_inline <- function(path, data, content_type = NULL, prefix = FALSE) {
  list(type = 5L, path = path, data = data, content_type = content_type,
       prefix = prefix)
}

#' Create HTTP Redirect Handler
#'
#' Creates an HTTP handler that returns a redirect response.
#'
#' @param path URI path to match (e.g., "/old-page").
#' @param location URL to redirect to. Can be relative (e.g., "/new-page") or
#'   absolute (e.g., "https://example.com/page").
#' @param status HTTP redirect status code. Must be one of:
#'
#'   - 301 - Moved Permanently
#'   - 302 - Found (default)
#'   - 303 - See Other
#'   - 307 - Temporary Redirect
#'   - 308 - Permanent Redirect
#' @param prefix \[default FALSE\] Logical, if TRUE matches path as a prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @examples
#' # Permanent redirect
#' h1 <- handler_redirect("/old", "/new", status = 301L)
#'
#' # Redirect bare path to trailing slash
#' h2 <- handler_redirect("/app", "/app/")
#'
#' @export
#'
handler_redirect <- function(path, location, status = 302L, prefix = FALSE) {
  status <- as.integer(status)
  if (!status %in% c(301L, 302L, 303L, 307L, 308L))
    stop("redirect status must be 301, 302, 303, 307, or 308")
  list(type = 6L, path = path, location = location, status = status, prefix = prefix)
}

#' @rdname close
#' @method close nanoServer
#' @export
#'
close.nanoServer <- function(con, ...) invisible(.Call(rnng_http_server_close, con))

#' @export
#'
print.nanoServer <- function(x, ...) {
  cat("< nanoServer >\n")
  cat(" - url:", attr(x, "url"), "\n")
  cat(" - state:", attr(x, "state"), "\n")
  invisible(x)
}

#' @export
#'
print.nanoWsConn <- function(x, ...) {
  cat("< nanoWsConn >\n")
  cat(" - id:", attr(x, "id"), "\n")
  invisible(x)
}

#' @export
#'
`$.nanoWsConn` <- function(x, name) {
  switch(name,
         send = function(data) .Call(rnng_ws_send, x, data),
         close = function() .Call(rnng_ws_close, x),
         id = attr(x, "id"),
         attr(x, name, exact = TRUE))
}

#' Create HTTP Streaming Handler
#'
#' Creates an HTTP streaming handler using chunked transfer encoding. Supports
#' any streaming HTTP protocol including Server-Sent Events (SSE), newline-
#' delimited JSON (NDJSON), and custom streaming formats.
#'
#' @param path URI path to match (e.g., "/stream").
#' @param on_request Function called when a request arrives. Signature:
#'   `function(conn, req)` where `conn` is the connection object and `req`
#'   is a list with `method`, `uri`, `headers`, `body`.
#' @param on_close \[default NULL\] Function called when the connection closes.
#'   Signature: `function(conn)`
#' @param method \[default "*"\] HTTP method to match (e.g., "GET", "POST").
#'   Use `"*"` to match any method.
#' @param prefix \[default FALSE\] Logical, if TRUE matches path as a prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @section Connection Object:
#' The `conn` object passed to callbacks has these methods:
#'
#' - `conn$send(data)`: Send data chunk to client.
#' - `conn$close()`: Close the connection (sends terminal chunk).
#' - `conn$set_status(code)`: Set HTTP status code (before first send).
#' - `conn$set_header(name, value)`: Set response header (before first send).
#' - `conn$id`: Unique connection identifier.
#'
#' @details
#' HTTP streaming uses chunked transfer encoding (RFC 9112). The first
#' `$send()` triggers writing of HTTP headers with `Transfer-Encoding: chunked`.
#' Headers cannot be modified after the first send.
#'
#' Set an appropriate `Content-Type` header for your streaming format:
#' - NDJSON: `application/x-ndjson`
#' - JSON stream: `application/stream+json`
#' - SSE: `text/event-stream` (see [format_sse()])
#' - Plain text: `text/plain`
#'
#' **SSE Reconnection:** When an SSE client reconnects after a disconnect, it
#' sends a `Last-Event-ID` header containing the last event ID it received.
#' Access this via `req$headers["Last-Event-ID"]` in `on_request` to resume
#' the event stream from the correct position.
#'
#' To broadcast to multiple clients, store connection objects in a list and
#' iterate over them (e.g., `lapply(conns, function(c) c$send(data))`).
#'
#' @seealso [format_sse()] for formatting Server-Sent Events.
#'
#' @examples
#' # NDJSON streaming endpoint
#' h <- handler_stream("/stream", function(conn, req) {
#'   conn$set_header("Content-Type", "application/x-ndjson")
#'   conn$send('{"status":"connected"}\n')
#' })
#'
#' # SSE endpoint with reconnection support
#' h <- handler_stream("/events", function(conn, req) {
#'   conn$set_header("Content-Type", "text/event-stream")
#'   conn$set_header("Cache-Control", "no-cache")
#'   last_id <- req$headers["Last-Event-ID"]
#'   # Resume from last_id if client is reconnecting
#'   conn$send(format_sse(data = "connected", id = "1"))
#' })
#'
#' # Long-lived streaming with broadcast triggered by POST
#' conns <- list()
#' handlers <- list(
#'   handler_stream("/stream",
#'     on_request = function(conn, req) {
#'       conn$set_header("Content-Type", "application/x-ndjson")
#'       conns[[as.character(conn$id)]] <<- conn
#'       conn$send('{"status":"connected"}\n')
#'     },
#'     on_close = function(conn) {
#'       conns[[as.character(conn$id)]] <<- NULL
#'     }
#'   ),
#'   # POST endpoint triggers broadcast to all streaming clients
#'   handler("/broadcast", function(req) {
#'     msg <- paste0('{"msg":"', rawToChar(req$body), '"}\n')
#'     lapply(conns, function(c) c$send(msg))
#'     list(status = 200L, body = "sent")
#'   }, method = "POST")
#' )
#'
#' @export
#'
handler_stream <- function(path, on_request, on_close = NULL,
                           method = "*", prefix = FALSE) {
  list(type = 7L, path = path, on_request = on_request, on_close = on_close,
       method = method, prefix = prefix)
}

#' Format Server-Sent Event
#'
#' Helper function to format messages according to the Server-Sent Events (SSE)
#' specification. Use with [handler_stream()] to create SSE endpoints.
#'
#' @param data The data payload. Will be prefixed with "data: " on each line.
#' @param event \[default NULL\] Optional event type (e.g., "message", "error").
#' @param id \[default NULL\] Optional event ID for client reconnection.
#' @param retry \[default NULL\] Optional retry interval in milliseconds.
#'
#' @return A character string formatted as an SSE message, ready to pass to
#'   `conn$send()`.
#'
#' @details
#' Server-Sent Events is a W3C standard for server-to-client streaming over
#' HTTP, supported natively by browsers via the `EventSource` API. SSE is
#' commonly used for real-time updates, notifications, and LLM token streaming.
#'
#' SSE messages have this format:
#'
#' ```
#' event: <event-type>
#' id: <event-id>
#' retry: <milliseconds>
#' data: <data-line-1>
#' data: <data-line-2>
#'
#' ```
#'
#' Each message ends with two newlines. Multi-line data is split and each
#' line prefixed with "data: ".
#'
#' When using SSE with [handler_stream()], set the appropriate headers:
#' - `Content-Type: text/event-stream`
#' - `Cache-Control: no-cache`
#' - `X-Accel-Buffering: no` (prevents proxy buffering)
#'
#' @seealso [handler_stream()] for creating streaming HTTP endpoints.
#'
#' @examples
#' format_sse(data = "Hello")
#' #> "data: Hello\n\n"
#'
#' format_sse(data = "Hello", event = "greeting")
#' #> "event: greeting\ndata: Hello\n\n"
#'
#' format_sse(data = "Line 1\nLine 2")
#' #> "data: Line 1\ndata: Line 2\n\n"
#'
#' # Typical SSE endpoint setup
#' h <- handler_stream("/events", function(conn, req) {
#'   conn$set_header("Content-Type", "text/event-stream")
#'   conn$set_header("Cache-Control", "no-cache")
#'   conn$set_header("X-Accel-Buffering", "no")
#'   conn$send(format_sse(data = "connected", id = "1"))
#' })
#'
#' @export
#'
format_sse <- function(data, event = NULL, id = NULL, retry = NULL) {
  parts <- character()
  if (!is.null(event)) parts <- c(parts, paste0("event: ", event))
  if (!is.null(id)) parts <- c(parts, paste0("id: ", id))
  if (!is.null(retry)) parts <- c(parts, paste0("retry: ", as.integer(retry)))
  lines <- strsplit(as.character(data), "\n", fixed = TRUE)[[1L]]
  parts <- c(parts, paste0("data: ", lines))
  paste0(paste(parts, collapse = "\n"), "\n\n")
}

#' @export
#'
print.nanoStreamConn <- function(x, ...) {
  cat("< nanoStreamConn >\n")
  cat(" - id:", attr(x, "id"), "\n")
  invisible(x)
}

#' @export
#'
`$.nanoStreamConn` <- function(x, name) {
  switch(name,
         send = function(data) .Call(rnng_stream_conn_send, x, data),
         close = function() .Call(rnng_conn_close, x),
         set_status = function(code) .Call(rnng_stream_conn_set_status, x, as.integer(code)),
         set_header = function(name, value) .Call(rnng_stream_conn_set_header, x, name, value),
         id = attr(x, "id"),
         attr(x, name, exact = TRUE))
}

