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
#' @param onWSOpen Function called when a WebSocket client connects.
#'   Receives the connection object as its argument.
#' @param onWSMessage Function called when a WebSocket message is received.
#'   Receives the connection object and message data.
#' @param onWSClose Function called when a WebSocket client disconnects.
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
#'   onWSOpen = function(ws) {
#'     cat("WebSocket connected:", ws$id, "\n")
#'   },
#'   onWSMessage = function(ws, data) {
#'     cat("Received:", data, "\n")
#'     ws$send(data)
#'   },
#'   onWSClose = function(ws) {
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
                        onWSOpen = NULL,
                        onWSMessage = NULL,
                        onWSClose = NULL,
                        tls = NULL,
                        textframes = FALSE) {
  srv <- .Call(rnng_http_server_create, url, handlers, ws_path,
               onWSOpen, onWSMessage, onWSClose, tls, textframes)
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
