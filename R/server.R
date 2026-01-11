# nanonext - HTTP/WebSocket Server Interface ------------------------------------

#' Create HTTP/WebSocket Server
#'
#' Creates an HTTP server that can handle both HTTP requests and WebSocket
#' connections on the same port. Supports HTTP, HTTPS, WS, and WSS.
#'
#' @param url URL to listen on. Use "http://" or "https://" scheme.
#'   Examples: "http://0.0.0.0:8080", "https://127.0.0.1:8443"
#' @param handlers List of HTTP handlers created with [handler()].
#' @param ws_path Path for WebSocket connections (default "/"). Only used
#'   if WebSocket callbacks are provided.
#' @param on_open Function called when a WebSocket client connects.
#'   Receives the connection object as its argument.
#' @param on_message Function called when a WebSocket message is received.
#'   Receives the connection object and message data.
#' @param on_close Function called when a WebSocket client disconnects.
#'   Receives the connection object.
#' @param tls TLS configuration for HTTPS/WSS, created via [tls_config()].
#' @param textframes \[default FALSE\] Logical, use WebSocket text frames.
#'
#' @return A nanoServer object with methods:
#'   \itemize{
#'     \item \code{$start()} - Start accepting connections
#'     \item \code{$stop()} - Stop accepting new connections
#'     \item \code{$close()} - Stop and release all resources
#'     \item \code{$url} - The server URL
#'   }
#'
#' @details
#' This function leverages NNG's shared HTTP server architecture. When both
#' HTTP handlers and WebSocket callbacks are provided, they share the same
#' underlying server and port. The WebSocket listener automatically handles
#' the HTTP upgrade handshake and all WebSocket framing (RFC 6455).
#'
#' WebSocket callbacks are executed on R's main thread via the 'later' package.
#' To process callbacks, you must run the event loop (e.g., using
#' \code{later::run_now()} in a loop).
#'
#' @examples
#' \dontrun{
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
#'
#' # HTTP + WebSocket server
#' server <- http_server(
#'   url = "http://127.0.0.1:8080",
#'   handlers = list(
#'     handler("/", function(req) {
#'       list(status = 200L, body = "<html>...</html>")
#'     })
#'   ),
#'   ws_path = "/ws",
#'   on_open = function(ws) {
#'     cat("WebSocket connected:", ws$id, "\n")
#'   },
#'   on_message = function(ws, data) {
#'     cat("Received:", data, "\n")
#'     ws$send(data)
#'   },
#'   on_close = function(ws) {
#'     cat("WebSocket disconnected:", ws$id, "\n")
#'   },
#'   textframes = TRUE
#' )
#' server$start()
#'
#' # Run event loop
#' repeat later::run_now(Inf)
#'
#' server$close()
#' }
#'
#' @export
#'
http_server <- function(url,
                        handlers = list(),
                        ws_path = "/",
                        on_open = NULL,
                        on_message = NULL,
                        on_close = NULL,
                        tls = NULL,
                        textframes = FALSE) {
  srv <- .Call(rnng_http_server_create, url, handlers, ws_path,
               on_open, on_message, on_close, tls, textframes)
  # Add method attributes for $start(), $stop(), $close() access
  attr(srv, "start") <- function() {
    res <- .Call(rnng_http_server_start, srv)
    if (res == 0L) attr(srv, "state") <<- "started"
    invisible(res)
  }
  attr(srv, "stop") <- function() {
    res <- .Call(rnng_http_server_stop, srv)
    if (res == 0L) attr(srv, "state") <<- "stopped"
    invisible(res)
  }
  attr(srv, "close") <- function() invisible(.Call(rnng_http_server_close, srv))
  srv
}

#' Create HTTP Handler
#'
#' Creates an HTTP route handler for use with [http_server()].
#'
#' @param path URI path to match (e.g., "/api/data", "/users").
#' @param callback Function to handle requests. Receives a list with:
#'   \itemize{
#'     \item \code{method} - HTTP method (character)
#'     \item \code{uri} - Request URI (character)
#'     \item \code{headers} - Named character vector of headers
#'     \item \code{body} - Request body (raw vector)
#'   }
#'   Should return a list with:
#'   \itemize{
#'     \item \code{status} - HTTP status code (integer, default 200)
#'     \item \code{headers} - Named character vector of response headers (optional)
#'     \item \code{body} - Response body (character or raw)
#'   }
#' @param method HTTP method to match (e.g., "GET", "POST", "PUT", "DELETE").
#'   Use NULL to match any method.
#' @param tree \[default FALSE\] Logical, if TRUE matches path as prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @examples
#' \dontrun{
#' # Simple GET handler
#' h1 <- handler("/hello", function(req) {
#'   list(status = 200L, body = "Hello!")
#' })
#'
#' # POST handler with JSON
#' h2 <- handler("/api/submit", function(req) {
#'   data <- jsonlite::fromJSON(rawToChar(req$body))
#'   result <- process(data)
#'   list(
#'     status = 200L,
#'     headers = c("Content-Type" = "application/json"),
#'     body = jsonlite::toJSON(result)
#'   )
#' }, method = "POST")
#'
#' # Catch-all handler for a path prefix
#' h3 <- handler("/static", function(req) {
#'   # Serve static files under /static/*
#' }, method = NULL, tree = TRUE)
#' }
#'
#' @export
#'
handler <- function(path, callback, method = "GET", tree = FALSE) {
  list(path = path, callback = callback, method = method, tree = tree)
}

#' Create Static File Handler
#'
#' Creates an HTTP handler that serves a single file. NNG handles MIME type
#' detection, ETag caching, and range requests automatically.
#'
#' @param path URI path to match (e.g., "/favicon.ico").
#' @param file Path to the file to serve. Must exist.
#' @param tree \[default FALSE\] Logical, if TRUE matches path as prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @examples
#' \dontrun{
#' h <- handler_file("/favicon.ico", "www/favicon.ico")
#' }
#'
#' @export
#'
handler_file <- function(path, file, tree = FALSE) {
  list(type = "file", path = path, file = normalizePath(file, mustWork = TRUE),
       tree = tree)
}

#' Create Static Directory Handler
#'
#' Creates an HTTP handler that serves files from a directory tree. NNG handles
#' MIME type detection, ETag caching, and range requests automatically.
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
#' \itemize{
#'   \item Request to "/static/css/style.css" serves "directory/css/style.css"
#'   \item Request to "/static/" serves "directory/index.html" if it exists
#' }
#'
#' Note: The trailing slash behavior depends on how clients make requests.
#' A request to "/static" (no trailing slash) will not automatically redirect
#' to "/static/". Consider using [handler_redirect()] if you need this behavior.
#'
#' NNG prevents directory traversal attacks (e.g., "../" in paths).
#'
#' @examples
#' \dontrun{
#' h <- handler_directory("/static", "www/assets")
#' }
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
#' \dontrun{
#' h1 <- handler_inline("/robots.txt", "User-agent: *\nDisallow:",
#'                      content_type = "text/plain")
#' h2 <- handler_inline("/health", '{"status":"ok"}',
#'                      content_type = "application/json")
#' }
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
#'   \itemize{
#'     \item 301 - Moved Permanently
#'     \item 302 - Found (default)
#'     \item 303 - See Other
#'     \item 307 - Temporary Redirect
#'     \item 308 - Permanent Redirect
#'   }
#' @param tree \[default FALSE\] Logical, if TRUE matches path as prefix.
#'
#' @return A handler object for use with [http_server()].
#'
#' @examples
#' \dontrun{
#' # Permanent redirect
#' h1 <- handler_redirect("/old", "/new", status = 301L)
#'
#' # Redirect bare path to trailing slash
#' h2 <- handler_redirect("/app", "/app/")
#' }
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
  cat(" - status:", attr(x, "state"), "\n")
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
