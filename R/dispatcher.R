# nanonext - Dispatcher --------------------------------------------------------

#' Dispatcher
#'
#' Run the dispatcher event loop for mirai task distribution.
#'
#' @param sock REP socket for host communication.
#' @param psock POLY socket for daemon communication.
#' @param monitor Monitor object for pipe events (its CV is used for signaling).
#' @param reset Pre-serialized connection reset error (raw vector).
#' @param serial Serialization configuration (list or NULL).
#' @param envir Environment containing RNG stream state.
#' @param next_stream Function to get next RNG stream, called as next_stream(envir).
#'
#' @return Integer status code (0 = normal exit).
#'
#' @keywords internal
#' @export
#'
.dispatcher <- function(sock, psock, monitor, reset, serial, envir, next_stream) {
  .Call(rnng_dispatcher_run, sock, psock, monitor, reset, serial, envir, next_stream)
}

#' Start In-Process Dispatcher
#'
#' @param url URL to listen at for daemon connections.
#' @param disp_url inproc:// URL for host REQ socket.
#' @param tls TLS configuration or NULL.
#' @param serial Serialization configuration (list or NULL).
#' @param stream RNG stream integer vector (.Random.seed).
#' @param limit Maximum in-flight tasks (NULL for unlimited).
#' @param cvar Shared condition variable for limit signaling.
#'
#' @return External pointer to dispatcher handle.
#'
#' @keywords internal
#' @export
#'
.dispatcher_start <- function(url, disp_url, tls, serial, stream, limit, cvar) {
  .Call(rnng_dispatcher_start, url, disp_url, tls, serial, stream, limit, cvar)
}

#' Stop In-Process Dispatcher
#'
#' @param disp External pointer to dispatcher handle.
#'
#' @return Invisible NULL.
#'
#' @keywords internal
#' @export
#'
.dispatcher_stop <- function(disp) invisible(.Call(rnng_dispatcher_stop, disp))

#' Wait for N Daemon Connections
#'
#' @param disp External pointer to dispatcher handle.
#' @param n Number of connections to wait for.
#'
#' @return Invisible NULL.
#'
#' @keywords internal
#' @export
#'
.dispatcher_wait <- function(disp, n) invisible(.Call(rnng_dispatcher_wait, disp, n))

#' Limit Gate
#'
#' Block until inflight count is below limit, then increment.
#'
#' @param disp External pointer to dispatcher handle.
#'
#' @return Invisible NULL.
#'
#' @keywords internal
#' @export
#'
.limit_gate <- function(disp) invisible(.Call(rnng_limit_gate, disp))
