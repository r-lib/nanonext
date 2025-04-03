# nanonext - Byte Stream Interface ---------------------------------------------

#' Open Stream
#'
#' Open a Stream by either dialing (establishing an outgoing connection) or
#' listening (accepting an incoming connection) at an address. This is a
#' low-level interface intended for communicating with non-NNG endpoints.
#'
#' A Stream is used for raw byte stream connections. Byte streams are reliable
#' in that data will not be delivered out of order, or with portions missing.
#'
#' Can be used to dial a (secure) websocket address starting 'ws://' or
#' 'wss://'. It is often the case that `textframes` needs to be set to `TRUE`.
#'
#' Specify only one of `dial` or `listen`. If both are specified, `listen` will
#' be ignored.
#'
#' Closing a stream renders it invalid and attempting to perform additional
#' operations on it will error.
#'
#' @param dial a URL to dial, specifying the transport and address as a
#'   character string e.g. 'ipc:///tmp/anyvalue' or 'tcp://127.0.0.1:5555' (not
#'   all transports are supported).
#' @param listen a URL to listen at, specifying the transport and address as a
#'   character string e.g. 'ipc:///tmp/anyvalue' or 'tcp://127.0.0.1:5555' (not
#'   all transports are supported).
#' @param textframes \[default FALSE\] applicable to the websocket transport
#'   only, enables sending and receiving of TEXT frames (ignored otherwise).
#' @param tls (optional) applicable to secure websockets only, a client or
#'   server TLS configuration object created by [tls_config()]. If missing or
#'   NULL, certificates are not validated.
#'
#' @return A Stream (object of class 'nanoStream' and 'nano').
#'
#' @examples
#' # Will succeed only if there is an open connection at the address:
#' s <- tryCatch(stream(dial = "tcp://127.0.0.1:5555"), error = identity)
#' s
#' @examplesIf interactive()
#' # Run in interactive sessions only as connection is not always available:
#' s <- tryCatch(
#'   stream(dial = "wss://echo.websocket.events/", textframes = TRUE),
#'   error = identity
#' )
#' s
#' if (is_nano(s)) recv(s)
#' if (is_nano(s)) send(s, "hello")
#' if (is_nano(s)) recv(s)
#' if (is_nano(s)) close(s)
#'
#' @export
#'
stream <- function(dial = NULL, listen = NULL, textframes = FALSE, tls = NULL)
  .Call(rnng_stream_open, dial, listen, textframes, tls)

#' @rdname close
#' @method close nanoStream
#' @export
#'
close.nanoStream <- function(con, ...) invisible(.Call(rnng_stream_close, con))
