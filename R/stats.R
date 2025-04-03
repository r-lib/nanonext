# nanonext - Stats -------------------------------------------------------------

#' Get Statistic for a Socket, Listener or Dialer
#'
#' Obtain value of a statistic for a Socket, Listener or Dialer. This function
#' exposes the stats interface of NNG.
#'
#' Note: the values of individual statistics are guaranteed to be atomic, but
#' due to the way statistics are collected there may be discrepancies between
#' them at times. For example, statistics counting bytes and messages received
#' may not reflect the same number of messages, depending on when the snapshot
#' is taken. This potential inconsistency arises as a result of optimisations to
#' minimise the impact of statistics on actual operations.
#'
#' @param object a Socket, Listener or Dialer.
#' @param name character name of statistic to return.
#'
#' @return The value of the statistic (character or double depending on the type
#'   of statistic requested) if available, or else NULL.
#'
#' @section Stats:
#'
#' The following stats may be requested for a Socket:
#' \itemize{
#'   \item 'id' - numeric id of the socket.
#'   \item 'name' - character socket name.
#'   \item 'protocol' - character protocol type e.g. 'bus'.
#'   \item 'pipes' - numeric number of pipes (active connections).
#'   \item 'dialers' - numeric number of listeners attached to the socket.
#'   \item 'listeners' - numeric number of dialers attached to the socket.
#' }
#'
#' The following stats may be requested for a Listener / Dialer:
#' \itemize{
#'   \item 'id' - numeric id of the listener / dialer.
#'   \item 'socket' - numeric id of the socket of the listener / dialer.
#'   \item 'url' - character URL address.
#'   \item 'pipes' - numeric number of pipes (active connections).
#' }
#'
#' The following additional stats may be requested for a Listener:
#' \itemize{
#'   \item 'accept' - numeric total number of connection attempts, whether
#'   successful or not.
#'   \item 'reject' - numeric total number of rejected connection attempts e.g.
#'   due to incompatible protocols.
#' }
#'
#' The following additional stats may be requested for a Dialer:
#' \itemize{
#'   \item 'connect' - numeric total number of connection attempts, whether
#'   successful or not.
#'   \item 'reject' - numeric total number of rejected connection attempts e.g.
#'   due to incompatible protocols.
#'   \item 'refused' - numeric total number of refused connections e.g. when
#'   starting synchronously with no listener on the other side.
#' }
#'
#' @examples
#' s <- socket("bus", listen = "inproc://stats")
#' stat(s, "pipes")
#'
#' s1 <- socket("bus", dial = "inproc://stats")
#' stat(s, "pipes")
#'
#' close(s1)
#' stat(s, "pipes")
#'
#' close(s)
#'
#' @export
#'
stat <- function(object, name) .Call(rnng_stats_get, object, name)
