# nanonext - Synchronisation Primitives ----------------------------------------

#' Condition Variables
#'
#' `cv` creates a new condition variable (protected by a mutex internal to the
#' object).
#'
#' Pass the 'conditionVariable' to the asynchronous receive functions
#' [recv_aio()] or [request()]. Alternatively, to be notified of a pipe event,
#' pass it to [pipe_notify()].
#'
#' Completion of the receive or pipe event, which happens asynchronously and
#' independently of the main R thread, will signal the condition variable by
#' incrementing it by 1.
#'
#' This will cause the R execution thread waiting on the condition variable
#' using `wait()` or `until()` to wake and continue.
#'
#' For argument `msec`, non-integer values will be coerced to integer.
#' Non-numeric input will be ignored and return immediately.
#'
#' @return For **cv**: a 'conditionVariable' object.
#'
#'  For **wait**: (invisibly) logical TRUE, or else FALSE if a flag has been
#'  set.
#'
#'  For **until**: (invisibly) logical TRUE if signalled, or else FALSE if the
#'  timeout was reached.
#'
#'  For **cv_value**: integer value of the condition variable.
#'
#'  For **cv_reset** and **cv_signal**: zero (invisibly).
#'
#' @section Condition:
#'
#' The condition internal to this 'conditionVariable' maintains a state (value).
#' Each signal increments the value by 1. Each time `wait()` or `until()`
#' returns (apart from due to timeout), the value is decremented by 1.
#'
#' The internal condition may be inspected at any time using `cv_value()` and
#' reset using `cv_reset()`. This affords a high degree of flexibility in
#' designing complex concurrent applications.
#'
#' @section Flag:
#'
#' The condition variable also contains a flag that certain signalling functions
#' such as [pipe_notify()] can set. When this flag has been set, all subsequent
#' `wait()` calls will return logical FALSE instead of TRUE.
#'
#' Note that the flag is not automatically reset, but may be reset manually
#' using `cv_reset()`.
#'
#' @examples
#' cv <- cv()
#'
#' @export
#'
cv <- function() .Call(rnng_cv_alloc)

#' Condition Variables - Wait
#'
#' `wait` waits on a condition being signalled by completion of an
#' asynchronous receive or pipe event. \cr `wait_` is a variant that allows
#' user interrupts, suitable for interactive use.
#'
#' @param cv a 'conditionVariable' object.
#'
#' @examples
#' \dontrun{
#' wait(cv) # would block until the cv is signalled
#' wait_(cv) # would block until the cv is signalled or interrupted
#' }
#'
#' @rdname cv
#' @export
#'
wait <- function(cv) invisible(.Call(rnng_cv_wait, cv))

#' @rdname cv
#' @export
#'
wait_ <- function(cv) invisible(.Call(rnng_cv_wait_safe, cv))

#' Condition Variables - Until
#'
#' `until` waits until a future time on a condition being signalled by
#' completion of an asynchronous receive or pipe event. \cr `until_` is a
#' variant that allows user interrupts, suitable for interactive use.
#'
#' @param msec maximum time in milliseconds to wait for the condition variable
#'   to be signalled.
#'
#' @examples
#' until(cv, 10L)
#' until_(cv, 10L)
#'
#' @rdname cv
#' @export
#'
until <- function(cv, msec) invisible(.Call(rnng_cv_until, cv, msec))

#' @rdname cv
#' @export
#'
until_ <- function(cv, msec) invisible(.Call(rnng_cv_until_safe, cv, msec))

#' Condition Variables - Value
#'
#' `cv_value` inspects the internal value of a condition variable.
#'
#' @examples
#' cv_value(cv)
#'
#' @rdname cv
#' @export
#'
cv_value <- function(cv) .Call(rnng_cv_value, cv)

#' Condition Variables - Reset
#'
#' `cv_reset` resets the internal value and flag of a condition variable.
#'
#' @examples
#' cv_reset(cv)
#'
#' @rdname cv
#' @export
#'
cv_reset <- function(cv) invisible(.Call(rnng_cv_reset, cv))

#' Condition Variables - Signal
#'
#' `cv_signal` signals a condition variable.
#'
#' @examples
#' cv_value(cv)
#' cv_signal(cv)
#' cv_value(cv)
#'
#' @rdname cv
#' @export
#'
cv_signal <- function(cv) invisible(.Call(rnng_cv_signal, cv))

#' Pipe Notify
#'
#' Signals a 'conditionVariable' whenever pipes (individual connections) are
#' added or removed at a socket.
#'
#' For add: this event occurs after the pipe is fully added to the socket. Prior
#' to this time, it is not possible to communicate over the pipe with the
#' socket.
#'
#' For remove: this event occurs after the pipe has been removed from the
#' socket. The underlying transport may be closed at this point, and it is not
#' possible to communicate using this pipe.
#'
#' @param socket a Socket.
#' @param cv a 'conditionVariable' to signal, or NULL to cancel a previously set
#'   signal.
#' @param add \[default FALSE\] logical value whether to signal (or cancel
#'   signal) when a pipe is added.
#' @param remove \[default FALSE\] logical value whether to signal (or cancel
#'   signal) when a pipe is removed.
#' @param flag \[default FALSE\] logical value whether to also set a flag in the
#'   'conditionVariable'. This can help distinguish between different types of
#'   signal, and causes any subsequent [wait()] to return FALSE instead of TRUE.
#'   If a signal from the \pkg{tools} package, e.g. `tools::SIGINT`, or an
#'   equivalent integer value is supplied, this sets a flag and additionally
#'   raises this signal upon the flag being set.
#'
#' @return Invisibly, zero on success (will otherwise error).
#'
#' @examples
#' s <- socket(listen = "inproc://nanopipe")
#' cv <- cv()
#'
#' pipe_notify(s, cv, add = TRUE, remove = TRUE, flag = TRUE)
#' cv_value(cv)
#'
#' s1 <- socket(dial = "inproc://nanopipe")
#' cv_value(cv)
#' reap(s1)
#' cv_value(cv)
#'
#' pipe_notify(s, NULL, add = TRUE, remove = TRUE)
#' s1 <- socket(dial = "inproc://nanopipe")
#' cv_value(cv)
#' reap(s1)
#'
#' (wait(cv))
#'
#' close(s)
#'
#' @export
#'
pipe_notify <- function(socket, cv, add = FALSE, remove = FALSE, flag = FALSE)
  invisible(.Call(rnng_pipe_notify, socket, cv, add, remove, flag))

#' Signal Forwarder
#'
#' Forwards signals from one 'conditionVariable' to another.
#'
#' The condition value of `cv` is initially reset to zero when this operator
#' returns. Only one forwarder can be active on a `cv` at any given time, and
#' assigning a new forwarding target cancels any currently existing forwarding.
#'
#' Changes in the condition value of `cv` are forwarded to `cv2`, but only on
#' each occassion `cv` is signalled. This means that waiting on `cv` will cause
#' a temporary divergence between the actual condition value of `cv` and that
#' recorded at `cv2`, until the next time `cv` is signalled.
#'
#' @param cv a 'conditionVariable' object, from which to forward the signal.
#' @param cv2 a 'conditionVariable' object, to which the signal is forwarded.
#'
#' @return Invisibly, `cv2`.
#'
#' @examples
#' cva <- cv(); cvb <- cv(); cv1 <- cv(); cv2 <- cv()
#'
#' cva %~>% cv1 %~>% cv2
#' cvb %~>% cv2
#'
#' cv_signal(cva)
#' cv_signal(cvb)
#' cv_value(cv1)
#' cv_value(cv2)
#'
#' @export
#'
`%~>%` <- function(cv, cv2) invisible(.Call(rnng_signal_thread_create, cv, cv2))
