# nanonext - Listeners / Dialers -----------------------------------------------

#' Dial an Address from a Socket
#'
#' Creates a new Dialer and binds it to a Socket.
#'
#' To view all Dialers bound to a socket use `$dialer` on the socket, which
#' returns a list of Dialer objects. To access any individual Dialer (e.g. to
#' set options on it), index into the list e.g. `$dialer[[1]]` to return the
#' first Dialer.
#'
#' A Dialer is an external pointer to a dialer object, which creates a single
#' outgoing connection at a time. If the connection is broken, or fails, the
#' dialer object will automatically attempt to reconnect, and will keep doing so
#' until the dialer or socket is destroyed.
#'
#' @param socket a Socket.
#' @param url \[default 'inproc://nanonext'\] a URL to dial, specifying the
#'   transport and address as a character string e.g. 'inproc://anyvalue' or
#'   'tcp://127.0.0.1:5555' (see [transports]).
#' @param tls \[default NULL\] for secure tls+tcp:// or wss:// connections only,
#'   provide a TLS configuration object created by [tls_config()].
#' @param autostart \[default TRUE\] whether to start the dialer (by default
#'   asynchronously). Set to NA to start synchronously - this is less resilient
#'   if a connection is not immediately possible, but avoids subtle errors from
#'   attempting to use the socket before an asynchronous dial has completed. Set
#'   to FALSE if setting configuration options on the dialer as it is not
#'   generally possible to change these once started.
#' @param fail \[default 'warn'\] failure mode - a character value or integer
#'   equivalent, whether to warn (1L), error (2L), or for none (3L) just return
#'   an 'errorValue' without any corresponding warning.
#' @param ... not used (and will be removed).
#'
#' @return Invisibly, an integer exit code (zero on success). A new Dialer
#'   (object of class 'nanoDialer' and 'nano') is created and bound to the
#'   Socket if successful.
#'
#' @section Further details:
#'
#' Dialers and Listeners are always associated with a single socket. A given
#' socket may have multiple Listeners and/or multiple Dialers.
#'
#' The client/server relationship described by dialer/listener is completely
#' orthogonal to any similar relationship in the protocols. For example, a rep
#' socket may use a dialer to connect to a listener on an req socket. This
#' orthogonality can lead to innovative solutions to otherwise challenging
#' communications problems.
#'
#' Any configuration options on the dialer/listener should be set by [opt<-()]
#' before starting the dialer/listener with [start()].
#'
#' Dialers/Listeners may be destroyed by [close()]. They are also closed when
#' their associated socket is closed.
#'
#' @examples
#' socket <- socket("rep")
#' dial(socket, url = "inproc://nanodial", autostart = FALSE)
#' socket$dialer
#' start(socket$dialer[[1]])
#' socket$dialer
#' close(socket$dialer[[1]])
#' close(socket)
#'
#' nano <- nano("bus")
#' nano$dial(url = "inproc://nanodial", autostart = FALSE)
#' nano$dialer
#' nano$dialer_start()
#' nano$dialer
#' close(nano$dialer[[1]])
#' nano$close()
#'
#' @export
#'
dial <- function(socket, url = "inproc://nanonext", tls = NULL, autostart = TRUE, fail = c("warn", "error", "none"), ...) {
  ...length() && { fail <- 2L }
  invisible(.Call(rnng_dial, socket, url, tls, autostart, fail))
}

#' Listen to an Address from a Socket
#'
#' Creates a new Listener and binds it to a Socket.
#'
#' To view all Listeners bound to a socket use `$listener` on the socket,
#' which returns a list of Listener objects. To access any individual Listener
#' (e.g. to set options on it), index into the list e.g. `$listener[[1]]`
#' to return the first Listener.
#'
#' A listener is an external pointer to a listener object, which accepts
#' incoming connections. A given listener object may have many connections at
#' the same time, much like an HTTP server can have many connections to multiple
#' clients simultaneously.
#'
#' @inheritParams dial
#' @param autostart \[default TRUE\] whether to start the listener. Set to FALSE
#'   if setting configuration options on the listener as it is not generally
#'   possible to change these once started.
#'
#' @return Invisibly, an integer exit code (zero on success). A new Listener
#'   (object of class 'nanoListener' and 'nano') is created and bound to the
#'   Socket if successful.
#'
#' @inheritSection dial Further details
#'
#' @examples
#' socket <- socket("req")
#' listen(socket, url = "inproc://nanolisten", autostart = FALSE)
#' socket$listener
#' start(socket$listener[[1]])
#' socket$listener
#' close(socket$listener[[1]])
#' close(socket)
#'
#' nano <- nano("bus")
#' nano$listen(url = "inproc://nanolisten", autostart = FALSE)
#' nano$listener
#' nano$listener_start()
#' nano$listener
#' close(nano$listener[[1]])
#' nano$close()
#'
#' @export
#'
listen <- function(socket, url = "inproc://nanonext", tls = NULL, autostart = TRUE, fail = c("warn", "error", "none"), ...) {
  ...length() && { fail <- 2L }
  invisible(.Call(rnng_listen, socket, url, tls, autostart, fail))
}

#' Start Listener/Dialer
#'
#' Start a Listener/Dialer.
#'
#' @param x a Listener or Dialer.
#' @param async \[default TRUE\] (applicable to Dialers only) logical flag
#'   whether the connection attempt, including any name resolution, is to be
#'   made asynchronously. This behaviour is more resilient, but also generally
#'   makes diagnosing failures somewhat more difficult. If FALSE, failure, such
#'   as if the connection is refused, will be returned immediately, and no
#'   further action will be taken.
#' @param ... not used.
#'
#' @return Invisibly, an integer exit code (zero on success).
#'
#' @name start
#' @rdname start
#'
NULL

#' @rdname start
#' @exportS3Method stats::start
#'
start.nanoListener <- function(x, ...)
  invisible(.Call(rnng_listener_start, x))

#' @rdname start
#' @exportS3Method stats::start
#'
start.nanoDialer <- function(x, async = TRUE, ...)
  invisible(.Call(rnng_dialer_start, x, async))

#' @rdname close
#' @method close nanoDialer
#' @export
#'
close.nanoDialer <- function(con, ...)
  invisible(.Call(rnng_dialer_close, con))

#' @rdname close
#' @method close nanoListener
#' @export
#'
close.nanoListener <- function(con, ...)
  invisible(.Call(rnng_listener_close, con))
