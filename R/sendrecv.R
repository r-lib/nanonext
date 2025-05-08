# nanonext - Core Functions - send/recv ----------------------------------------

#' Send
#'
#' Send data over a connection (Socket, Context or Stream).
#'
#' @param con a Socket, Context or Stream.
#' @param data an object (a vector, if `mode = "raw"`).
#' @param mode \[default 'serial'\] character value or integer equivalent -
#'   either `"serial"` (1L) to send serialised R objects, or `"raw"` (2L) to
#'   send atomic vectors of any type as a raw byte vector. For Streams, `"raw"`
#'   is the only option and this argument is ignored.
#' @param block \[default NULL\] which applies the connection default (see
#'   section 'Blocking' below). Specify logical `TRUE` to block until successful
#'   or `FALSE` to return immediately even if unsuccessful (e.g. if no
#'   connection is available), or else an integer value specifying the maximum
#'   time to block in milliseconds, after which the operation will time out.
#' @param pipe \[default 0L\] only applicable to Sockets using the 'poly'
#'   protocol, an integer pipe ID if directing the send via a specific pipe.
#'
#' @return An integer exit code (zero on success).
#'
#' @section Blocking:
#'
#' For Sockets and Contexts: the default behaviour is non-blocking with
#' `block = FALSE`. This will return immediately with an error if the message
#' could not be queued for sending. Certain protocol / transport combinations
#' may limit the number of messages that can be queued if they have yet to be
#' received.
#'
#' For Streams: the default behaviour is blocking with `block = TRUE`. This will
#' wait until the send has completed. Set a timeout to ensure that the function
#' returns under all scenarios. As the underlying implementation uses an
#' asynchronous send with a wait, it is recommended to set a small positive
#' value for `block` rather than `FALSE`.
#'
#' @section Send Modes:
#'
#' The default mode `"serial"` sends serialised R objects to ensure perfect
#' reproducibility within R. When receiving, the corresponding mode `"serial"`
#' should be used. Custom serialization and unserialization functions for
#' reference objects may be enabled by the function [serial_config()].
#'
#' Mode `"raw"` sends atomic vectors of any type as a raw byte vector, and must
#' be used when interfacing with external applications or raw system sockets,
#' where R serialization is not in use. When receiving, the mode corresponding
#' to the vector sent should be used.
#'
#' @seealso [send_aio()] for asynchronous send.
#'
#' @examples
#' pub <- socket("pub", dial = "inproc://nanonext")
#'
#' send(pub, data.frame(a = 1, b = 2))
#' send(pub, c(10.1, 20.2, 30.3), mode = "raw", block = 100)
#'
#' close(pub)
#'
#' req <- socket("req", listen = "inproc://nanonext")
#' rep <- socket("rep", dial = "inproc://nanonext")
#'
#' ctx <- context(req)
#' send(ctx, data.frame(a = 1, b = 2), block = 100)
#'
#' msg <- recv_aio(rep, timeout = 100)
#' send(ctx, c(1.1, 2.2, 3.3), mode = "raw", block = 100)
#'
#' close(req)
#' close(rep)
#'
#' @export
#'
send <- function(con, data, mode = c("serial", "raw"), block = NULL, pipe = 0L)
  .Call(rnng_send, con, data, mode, block, pipe)

#' Receive
#'
#' Receive data over a connection (Socket, Context or Stream).
#'
#' @inheritParams send
#' @param mode \[default 'serial'\] character value or integer equivalent - one
#'   of `"serial"` (1L), `"character"` (2L), `"complex"` (3L), `"double"` (4L),
#'   `"integer"` (5L), `"logical"` (6L), `"numeric"` (7L), `"raw"` (8L), or
#'   `"string"` (9L). The default `"serial"` means a serialised R object; for
#'   the other modes, received bytes are converted into the respective mode.
#'   `"string"` is a faster option for length one character vectors. For
#'   Streams, `"serial"` will default to `"character"`.
#' @param n \[default 65536L\] applicable to Streams only, the maximum number of
#'   bytes to receive. Can be an over-estimate, but note that a buffer of this
#'   size is reserved.
#'
#' @return The received data in the `mode` specified.
#'
#' @section Errors:
#'
#' In case of an error, an integer 'errorValue' is returned (to be
#' distiguishable from an integer message value). This can be verified using
#' [is_error_value()].
#'
#' If an error occurred in unserialization or conversion of the message data to
#' the specified mode, a raw vector will be returned instead to allow recovery
#' (accompanied by a warning).
#'
#' @section Blocking:
#'
#' For Sockets and Contexts: the default behaviour is non-blocking with
#' `block = FALSE`. This will return immediately with an error if no messages
#' are available.
#'
#' For Streams: the default behaviour is blocking with `block = TRUE`. This will
#' wait until a message is received. Set a timeout to ensure that the function
#' returns under all scenarios. As the underlying implementation uses an
#' asynchronous receive with a wait, it is recommended to set a small positive
#' value for `block` rather than `FALSE`.
#'
#' @seealso [recv_aio()] for asynchronous receive.
#'
#' @examples
#' s1 <- socket("pair", listen = "inproc://nanonext")
#' s2 <- socket("pair", dial = "inproc://nanonext")
#'
#' send(s1, data.frame(a = 1, b = 2))
#' res <- recv(s2)
#' res
#' send(s1, data.frame(a = 1, b = 2))
#' recv(s2)
#'
#' send(s1, c(1.1, 2.2, 3.3), mode = "raw")
#' res <- recv(s2, mode = "double", block = 100)
#' res
#' send(s1, "example message", mode = "raw")
#' recv(s2, mode = "character")
#'
#' close(s1)
#' close(s2)
#'
#' req <- socket("req", listen = "inproc://nanonext")
#' rep <- socket("rep", dial = "inproc://nanonext")
#'
#' ctxq <- context(req)
#' ctxp <- context(rep)
#' send(ctxq, data.frame(a = 1, b = 2), block = 100)
#' recv(ctxp, block = 100)
#'
#' send(ctxq, c(1.1, 2.2, 3.3), mode = "raw", block = 100)
#' recv(ctxp, mode = "double", block = 100)
#'
#' close(req)
#' close(rep)
#'
#' @export
#'
recv <- function(
  con,
  mode = c("serial", "character", "complex", "double", "integer", "logical", "numeric", "raw", "string"),
  block = NULL,
  n = 65536L
)
  .Call(rnng_recv, con, mode, block, n)
