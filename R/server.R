# nanonext - server - HTTP REST Server -----------------------------------------

#' Simple Async HTTP Echo Server
#'
#' Creates a simple HTTP echo server that runs entirely asynchronously and
#'     echoes back all request information including method, headers, URI, and data.
#'
#' @param url full http address including hostname and port at which to host
#'     the echo server. Default is "http://127.0.0.1:5556/echo".
#'
#' @return An external pointer to the server thread. The server runs asynchronously
#'     in the background. The thread will be automatically destroyed when the
#'     returned object is garbage collected.
#'
#' @details This server echoes back the complete HTTP request information as JSON,
#'     including:
#'     \itemize{
#'         \item HTTP method (GET, POST, etc.)
#'         \item All request headers
#'         \item Request URI/path
#'         \item Request body data
#'         \item Server timestamp
#'     }
#'
#'     The server accepts requests using any HTTP method and responds with
#'     status 200 OK and Content-Type application/json.
#'
#' @examples
#' if (interactive()) {
#'
#' # Start echo server (returns immediately, server runs in background)
#' server_thread <- echo_server("http://127.0.0.1:5556/echo")
#'
#' # Test with GET request
#' ncurl("http://127.0.0.1:5556/echo?param=value")
#'
#' # Test with POST request including headers and data
#' ncurl("http://127.0.0.1:5556/echo",
#'       method = "POST", 
#'       headers = c("Content-Type" = "application/json", "X-Custom" = "test"),
#'       data = '{"message": "hello world"}')
#'
#' # Server will automatically stop when server_thread is garbage collected
#' # or you can explicitly remove it:
#' rm(server_thread)
#' gc()
#'
#' }
#'
#' @export
#'
echo_server <- function(url = "http://127.0.0.1:5556/echo")
  .Call(rnng_echo_server, url)
