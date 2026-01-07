# nanonext - Core - Aio Functions ----------------------------------------------

# send_aio/recv_aio ------------------------------------------------------------

#' Send Async
#'
#' Send data asynchronously over a connection (Socket, Context, Stream or Pipe).
#'
#' Async send is always non-blocking and returns a 'sendAio' immediately.
#'
#' For a 'sendAio', the send result is available at `$result`. An 'unresolved'
#' logical NA is returned if the async operation is yet to complete. The
#' resolved value will be zero on success, or else an integer error code.
#'
#' To wait for and check the result of the send operation, use [call_aio()] on
#' the returned 'sendAio' object.
#'
#' Alternatively, to stop the async operation, use [stop_aio()].
#'
#' @inheritParams send
#' @param con a Socket, Context or Stream.
#' @param timeout \[default NULL\] integer value in milliseconds or NULL, which
#'   applies a socket-specific default, usually the same as no timeout.
#'
#' @return A 'sendAio' (object of class 'sendAio') (invisibly).
#'
#' @inheritSection send Send Modes
#'
#' @seealso [send()] for synchronous send.
#'
#' @examples
#' pub <- socket("pub", dial = "inproc://nanonext")
#'
#' res <- send_aio(pub, data.frame(a = 1, b = 2), timeout = 100)
#' res
#' res$result
#'
#' res <- send_aio(pub, "example message", mode = "raw", timeout = 100)
#' call_aio(res)$result
#'
#' close(pub)
#'
#' @export
#'
send_aio <- function(con, data, mode = c("serial", "raw"), timeout = NULL, pipe = 0L)
  data <- .Call(rnng_send_aio, con, data, mode, timeout, pipe, environment())

#' Receive Async
#'
#' Receive data asynchronously over a connection (Socket, Context or Stream).
#'
#' Async receive is always non-blocking and returns a 'recvAio' immediately.
#'
#' For a 'recvAio', the received message is available at `$data`. An
#' 'unresolved' logical NA is returned if the async operation is yet to
#' complete.
#'
#' To wait for the async operation to complete and retrieve the received
#' message, use [call_aio()] on the returned 'recvAio' object.
#'
#' Alternatively, to stop the async operation, use [stop_aio()].
#'
#' In case of an error, an integer 'errorValue' is returned (to be
#' distiguishable from an integer message value). This can be checked using
#' [is_error_value()].
#'
#' If an error occurred in unserialization or conversion of the message data to
#' the specified mode, a raw vector will be returned instead to allow recovery
#' (accompanied by a warning).
#'
#' @inheritParams recv
#' @inheritParams send_aio
#' @param cv (optional) a 'conditionVariable' to signal when the async receive
#'   is complete.
#'
#' @return A 'recvAio' (object of class 'recvAio') (invisibly).
#'
#' @section Signalling:
#'
#' By supplying a 'conditionVariable', when the receive is complete, the
#' 'conditionVariable' is signalled by incrementing its value by 1. This
#' happens asynchronously and independently of the R execution thread.
#'
#' @seealso [recv()] for synchronous receive.
#'
#' @examples
#' s1 <- socket("pair", listen = "inproc://nanonext")
#' s2 <- socket("pair", dial = "inproc://nanonext")
#'
#' res <- send_aio(s1, data.frame(a = 1, b = 2), timeout = 100)
#' msg <- recv_aio(s2, timeout = 100)
#' msg
#' msg$data
#'
#' res <- send_aio(s1, c(1.1, 2.2, 3.3), mode = "raw", timeout = 100)
#' msg <- recv_aio(s2, mode = "double", timeout = 100)
#' msg
#' msg$data
#'
#' res <- send_aio(s1, "example message", mode = "raw", timeout = 100)
#' msg <- recv_aio(s2, mode = "character", timeout = 100)
#' call_aio(msg)
#' msg$data
#'
#' close(s1)
#' close(s2)
#'
#' # Signalling a condition variable
#'
#' s1 <- socket("pair", listen = "inproc://cv-example")
#' cv <- cv()
#' msg <- recv_aio(s1, timeout = 100, cv = cv)
#' until(cv, 10L)
#' msg$data
#' close(s1)
#'
#' # in another process in parallel
#' s2 <- socket("pair", dial = "inproc://cv-example")
#' res <- send_aio(s2, c(1.1, 2.2, 3.3), mode = "raw", timeout = 100)
#' close(s2)
#'
#' @export
#'
recv_aio <- function(
  con,
  mode = c("serial", "character", "complex", "double", "integer", "logical", "numeric", "raw", "string"),
  timeout = NULL,
  cv = NULL,
  n = 65536L
)
  data <- .Call(rnng_recv_aio, con, mode, timeout, cv, n, environment())

# Core aio functions -----------------------------------------------------------

#' Call the Value of an Asynchronous Aio Operation
#'
#' `call_aio` retrieves the value of an asynchronous Aio operation, waiting
#' for the operation to complete if still in progress. For a list of Aios, waits
#' for all asynchronous operations to complete before returning.
#'
#' For a 'recvAio', the received value may be retrieved at `$data`.
#'
#' For a 'sendAio', the send result may be retrieved at `$result`.
#' This will be zero on success, or else an integer error code.
#'
#' To access the values directly, use for example on a 'recvAio' `x`:
#' `call_aio(x)$data`.
#'
#' For a 'recvAio', if an error occurred in unserialization or conversion of the
#' message data to the specified mode, a raw vector will be returned instead to
#' allow recovery (accompanied by a warning).
#'
#' Note: this function operates silently and does not error even if `x` is not
#' an active Aio or list of Aios, always returning invisibly the passed object.
#'
#' @param x an Aio or list of Aios (objects of class 'sendAio', 'recvAio' or
#'   'ncurlAio').
#'
#' @return The passed object (invisibly).
#'
#' @section Alternatively:
#'
#' Aio values may be accessed directly at `$result` for a 'sendAio', and `$data`
#' for a 'recvAio'. If the Aio operation is yet to complete, an 'unresolved'
#' logical NA will be returned. Once complete, the resolved value will be
#' returned instead.
#'
#' [unresolved()] may also be used, which returns `TRUE` only if an Aio or Aio
#' value has yet to resolve and `FALSE` otherwise. This is suitable for use in
#' control flow statements such as `while` or `if`.
#'
#' @examples
#' s1 <- socket("pair", listen = "inproc://nanonext")
#' s2 <- socket("pair", dial = "inproc://nanonext")
#'
#' res <- send_aio(s1, data.frame(a = 1, b = 2), timeout = 100)
#' res
#' call_aio(res)
#' res$result
#'
#' msg <- recv_aio(s2, timeout = 100)
#' msg
#' call_aio_(msg)$data
#'
#' close(s1)
#' close(s2)
#'
#' @export
#'
call_aio <- function(x) invisible(.Call(rnng_aio_call, x))

#' Call the Value of an Asynchronous Aio Operation
#'
#' `call_aio_` is a variant that allows user interrupts, suitable for
#' interactive use.
#'
#' @rdname call_aio
#' @export
#'
call_aio_ <- function(x) invisible(.Call(rnng_wait_thread_create, x))

#' Collect Data of an Aio or List of Aios
#'
#' `collect_aio` collects the data of an Aio or list of Aios, waiting for
#' resolution if still in progress.
#'
#' This function will wait for the asynchronous operation(s) to complete if
#' still in progress (blocking).
#'
#' Using `x[]` on an Aio `x` is equivalent to the user-interruptible
#' `collect_aio_(x)`.
#'
#' @inheritParams call_aio
#'
#' @return Depending on the type of `x` supplied, an object or list of objects
#'   (the same length as `x`, preserving names).
#'
#' @examples
#' s1 <- socket("pair", listen = "inproc://nanonext")
#' s2 <- socket("pair", dial = "inproc://nanonext")
#'
#' res <- send_aio(s1, data.frame(a = 1, b = 2), timeout = 100)
#' collect_aio(res)
#'
#' msg <- recv_aio(s2, timeout = 100)
#' collect_aio_(msg)
#'
#' msg[]
#'
#' close(s1)
#' close(s2)
#'
#' @export
#'
collect_aio <- function(x) .Call(rnng_aio_collect, x)

#' Collect Data of an Aio or List of Aios
#'
#' `collect_aio_` is a variant that allows user interrupts, suitable for
#' interactive use.
#'
#' @rdname collect_aio
#' @export
#'
collect_aio_ <- function(x) .Call(rnng_aio_collect_safe, x)

#' Race Aio
#'
#' Returns the index of the first resolved Aio in a list, waiting if necessary.
#'
#' @param x A list of Aio objects.
#' @param cv A condition variable. This must be the same cv supplied to
#'   [recv_aio()] or [request()] when creating the Aio objects in `x`.
#'
#' @return Integer index of the first resolved Aio, or 0L if none are resolved,
#'   the list is empty, or the cv was terminated.
#'
#' @keywords internal
#' @export
#'
race_aio <- function(x, cv) .Call(rnng_race_aio, x, cv)

#' Stop Asynchronous Aio Operation
#'
#' Stop an asynchronous Aio operation, or a list of Aio operations.
#'
#' Stops the asynchronous I/O operation associated with Aio `x` by aborting, and
#' then waits for it to complete or to be completely aborted, and for the
#' callback associated with the Aio to have completed executing. If successful,
#' the Aio will resolve to an 'errorValue' 20 (Operation canceled).
#'
#' Note this function operates silently and does not error even if `x` is not an
#' active Aio, always returning invisible NULL.
#'
#' @inheritParams call_aio
#'
#' @return Invisible NULL.
#'
#' @export
#'
stop_aio <- function(x) invisible(.Call(rnng_aio_stop, x))

#' Stop Request Operation
#'
#' Stop an asynchronous Aio operation, or a list of Aio operations, created by
#' [request()]. This is an augmented version of [stop_aio()] that additionally
#' requests cancellation by sending an integer zero followed by the context ID
#' over the context, and waiting for the response.
#'
#' @param x an Aio or list of Aios (objects of class 'recvAio' returned by
#'   [request()]).
#'
#' @return Invisibly, a logical vector.
#'
#' @keywords internal
#' @export
#'
stop_request <- function(x) invisible(.Call(rnng_request_stop, x))

#' Query if an Aio is Unresolved
#'
#' Query whether an Aio, Aio value or list of Aios remains unresolved. Unlike
#' [call_aio()], this function does not wait for completion.
#'
#' Suitable for use in control flow statements such as `while` or `if`.
#'
#' Note: querying resolution may cause a previously unresolved Aio to resolve.
#'
#' @param x an Aio or list of Aios (objects of class 'sendAio', 'recvAio' or
#'   'ncurlAio'), or Aio value stored at `$result` or `$data` etc.
#'
#' @return Logical `TRUE` if `x` is an unresolved Aio or Aio value or the list
#'   of Aios contains at least one unresolved Aio, or `FALSE` otherwise.
#'
#' @examples
#' s1 <- socket("pair", listen = "inproc://nanonext")
#' aio <- send_aio(s1, "test", timeout = 100)
#'
#' while (unresolved(aio)) {
#'   # do stuff before checking resolution again
#'   cat("unresolved\n")
#'   msleep(100)
#' }
#'
#' unresolved(aio)
#'
#' close(s1)
#'
#' @export
#'
unresolved <- function(x) .Call(rnng_unresolved, x)

#' Get the Pipe ID of a recvAio
#'
#' Caution: must only be used on an already-resolved 'recvAio'. This function
#' does not perform validation of these pre-conditions.
#'
#' @param x a resolved 'recvAio'.
#'
#' @return Integer pipe ID.
#'
#' @export
#'
pipe_id <- function(x) .subset2(x, "aio")

#' Technical Utility: Query if an Aio is Unresolved
#'
#' Query whether an Aio or list of Aios remains unresolved. This is an
#' experimental technical utility version of [unresolved()] not intended for
#' ordinary use. Provides a method of querying the busy status of an Aio without
#' altering its state in any way i.e. not attempting to retrieve the result or
#' message.
#'
#' `.unresolved()` is not intended to be used for 'recvAio' returned by a
#' signalling function, in which case [unresolved()] must be used in all cases.
#'
#' @inheritParams call_aio
#'
#' @return Logical `TRUE` if `x` is an unresolved Aio or else `FALSE`, or if `x`
#'   is a list, the integer number of unresolved Aios in the list.
#'
#' @keywords internal
#' @export
#'
.unresolved <- function(x) .Call(rnng_unresolved2, x)

#' Make recvAio Promise
#'
#' Creates a 'promise' from an 'recvAio' object.
#'
#' This function is an S3 method for the generic `as.promise` for class
#' 'recvAio'.
#'
#' Requires the \pkg{promises} package.
#'
#' Allows a 'recvAio' to be used with the promise pipe `%...>%`, which schedules
#' a function to run upon resolution of the Aio.
#'
#' @param x an object of class 'recvAio'.
#'
#' @return A 'promise' object.
#'
#' @exportS3Method promises::as.promise
#'
as.promise.recvAio <- function(x) {
  promise <- .subset2(x, "promise")

  if (is.null(promise)) {
    promise <- promises::promise(
      function(resolve, reject) {
      if (unresolved(x)) .keep(x, environment()) else resolve(.subset2(x, "value"))
      }
    )$then(
      onFulfilled = handle_fulfilled
    )
    `[[<-`(x, "promise", promise)
  }

  promise
}

handle_fulfilled <- function(value, .visible) {
  is_error_value(value) && stop(nng_error(value))
  value
}

#' @exportS3Method promises::is.promising
#'
is.promising.recvAio <- function(x) TRUE

#' Keep Promise
#'
#' Internal package function.
#'
#' If successful, both `x` and `ctx` are preserved and accessible from the
#' promise callback.
#'
#' @param x a 'recvAio' or 'ncurlAio' object.
#' @param ctx the return value of `environment()`.
#'
#' @return NULL.
#'
#' @keywords internal
#' @export
#'
.keep <- function(x, ctx) .Call(rnng_set_promise_context, x, ctx)
