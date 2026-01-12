# nanonext - HTTP/WebSocket Server Interface ------------------------------------

#' Create HTTP/WebSocket Server
#'
#' Creates a server that can handle HTTP requests and WebSocket connections.
#'
#' @param url URL to listen on (e.g., "http://127.0.0.1:8080").
#' @param handlers List of handlers created with [handler()], [handler_ws()], etc.
#' @param tls TLS configuration for HTTPS/WSS, created via [tls_config()].
#'
#' @return A nanoServer object with methods:
#'
#'   - `$start()` - Start accepting connections
#'   - `$stop()` - Stop accepting new connections
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
  srv <- .Call(rnng_http_server_create, url, handlers, tls)
  # Add method attributes for $start(), $stop(), $close() access
  attr(srv, "start") <- function() {
    res <- .Call(rnng_http_server_start, srv)
    if (res == 0L) attr(srv, "state") <- "started"
    invisible(res)
  }
  attr(srv, "stop") <- function() {
    res <- .Call(rnng_http_server_stop, srv)
    if (res == 0L) attr(srv, "state") <- "stopped"
    invisible(res)
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
#'   - `headers` - Named character vector of response headers (optional)
#'   - `body` - Response body (character or raw)
#' @param method HTTP method to match (e.g., "GET", "POST", "PUT", "DELETE").
#'   Use NULL to match any method.
#' @param tree \[default FALSE\] Logical, if TRUE matches path as prefix.
#'
#' @return A handler object for use with [http_server()].
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
#' }, method = NULL, tree = TRUE)
#'
#' @export
#'
handler <- function(path, callback, method = "GET", tree = FALSE) {
  list(path = path, callback = callback, method = method, tree = tree)
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
#' - `ws$id`: Unique integer identifier for this connection. IDs are
#'   unique server-wide across all WebSocket handlers, making them safe to use
#'   as keys in a shared data structure.
#'
#' @examples
#' # Simple echo server
#' h <- handler_ws("/ws", function(ws, data) ws$send(data))
#'
#' # With connection tracking
#' clients <- new.env()
#' h <- handler_ws(
#'   "/chat",
#'   on_message = function(ws, data) {
#'     # Broadcast to all
#'     for (id in ls(clients)) {
#'       clients[[id]]$send(data)
#'     }
#'   },
#'   on_open = function(ws) {
#'     clients[[as.character(ws$id)]] <<- ws
#'   },
#'   on_close = function(ws) {
#'     rm(list = as.character(ws$id), envir = clients)
#'   },
#'   textframes = TRUE
#' )
#'
#' @export
#'
handler_ws <- function(path, on_message, on_open = NULL, on_close = NULL,
                       textframes = FALSE) {
  list(
    type = "ws",
    path = path,
    on_message = on_message,
    on_open = on_open,
    on_close = on_close,
    textframes = textframes
  )
}

#' Create Static File Handler
#'
#' Creates an HTTP handler that serves a single file. NNG handles MIME type
#' detection automatically.
#'
#' @param path URI path to match (e.g., "/favicon.ico").
#' @param file Path to the file to serve.
#' @param tree \[default FALSE\] Logical, if TRUE matches path as prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @examplesIf interactive()
#' h <- handler_file("/favicon.ico", "~/favicon.ico")
#'
#' @export
#'
handler_file <- function(path, file, tree = FALSE) {
  if (!file.exists(file))
    warning("file does not exist: ", file)
  list(type = "file", path = path, file = normalizePath(file, mustWork = FALSE),
       tree = tree)
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
#' Directory handlers automatically match all paths under the prefix (tree
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
  list(type = "directory", path = path,
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
#' @param tree \[default FALSE\] Logical, if TRUE matches path as prefix.
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
handler_inline <- function(path, data, content_type = NULL, tree = FALSE) {
  if (is.character(data)) data <- charToRaw(data)
  list(type = "inline", path = path, data = data, content_type = content_type,
       tree = tree)
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
#' @param tree \[default FALSE\] Logical, if TRUE matches path as prefix.
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
handler_redirect <- function(path, location, status = 302L, tree = FALSE) {
  status <- as.integer(status)
  if (!status %in% c(301L, 302L, 303L, 307L, 308L))
    stop("redirect status must be 301, 302, 303, 307, or 308")
  list(type = "redirect", path = path, location = location, status = status,
       tree = tree)
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
