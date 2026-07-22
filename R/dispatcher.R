# nanonext - Dispatcher --------------------------------------------------------

#' Start In-Process Dispatcher
#'
#' @param url URL to listen at for daemon connections.
#' @param disp_url inproc:// URL for host REQ socket.
#' @param tls TLS configuration or NULL.
#' @param serial Serialization configuration (list or NULL).
#' @param stream RNG stream integer vector (.Random.seed).
#' @param capacity Memory budget in MB (metric, 1 MB = 1,000,000 bytes) for
#'   queued task payloads. `NULL`, 0, non-finite, or negative values are
#'   treated as unlimited.
#' @param cvar Unused; accepted for compatibility and ignored.
#'
#' @return External pointer to dispatcher handle.
#'
#' @keywords internal
#' @export
#'
.dispatcher_start <- function(url, disp_url, tls, serial, stream, capacity, cvar = NULL) {
  .Call(rnng_dispatcher_start, url, disp_url, tls, serial, stream, capacity)
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

#' Dispatcher Info
#'
#' Read dispatcher statistics directly under lock.
#'
#' @param disp External pointer to dispatcher handle.
#'
#' @return Integer vector of length 5: connections, cumulative, awaiting,
#'   executing, completed.
#'
#' @keywords internal
#' @export
#'
.dispatcher_info <- function(disp) .Call(rnng_dispatcher_info, disp)

#' Dispatcher Capacity
#'
#' Read current and peak queued task payload usage at dispatcher, plus the
#' configured capacity, in MB (metric, 1 MB = 1,000,000 bytes).
#'
#' @param disp External pointer to dispatcher handle.
#'
#' @return Named numeric vector of length 3: **used** (current) and **peak**
#'   (high-watermark) usage, and **capacity** (the `capacity` set on
#'   [.dispatcher_start()], `NA_real_` if unset/unbounded), all in MB.
#'   `NA_real_` in each slot if `disp` is invalid.
#'
#' @keywords internal
#' @export
#'
.dispatcher_capacity <- function(disp) .Call(rnng_dispatcher_capacity, disp)

#' Dispatcher Gate
#'
#' Block while queued bytes at dispatcher exceed the memory budget set on
#' `.dispatcher_start()`.
#'
#' @param disp External pointer to dispatcher handle.
#'
#' @return Logical TRUE.
#'
#' @keywords internal
#' @export
#'
.dispatcher_gate <- function(disp) .Call(rnng_dispatcher_gate, disp)

#' Dispatcher Try Gate
#'
#' Snapshot read of dispatcher capacity. Returns immediately, never blocks.
#' The non-blocking counterpart to [.dispatcher_gate()].
#'
#' @param disp External pointer to dispatcher handle.
#'
#' @return Logical `TRUE` if submission would not block (queued bytes below
#'   the memory budget set on `.dispatcher_start()`, or unbounded), `FALSE`
#'   if at or over the budget. `NULL` if `disp` is invalid.
#'
#' @keywords internal
#' @export
#'
.dispatcher_try_gate <- function(disp) .Call(rnng_dispatcher_try_gate, disp)
