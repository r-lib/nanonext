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
.dispatcher <- function(sock, psock, monitor, reset, serial, envir, next_stream)
    .Call(rnng_dispatcher_run, sock, psock, monitor, reset, serial, envir, next_stream)
