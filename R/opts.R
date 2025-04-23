# nanonext - Options Configuration and Helper Functions ------------------------

#' Get and Set Options for a Socket, Context, Stream, Listener or Dialer
#'
#' Get and set the value of options for a Socket, Context, Stream, Listener or
#' Dialer.
#'
#' Note: once a dialer or listener has started, it is not generally possible to
#' change its configuration. Hence create the dialer or listener with
#' `autostart = FALSE` if configuration needs to be set.
#'
#' To get or set options on a Listener or Dialer attached to a Socket or nano
#' object, pass in the objects directly via for example `$listener[[1]]` for the
#' first Listener.
#'
#' Some options are only meaningful or supported in certain contexts; for
#' example there is no single meaningful address for a socket, since sockets can
#' have multiple dialers and endpoints associated with them.
#'
#' For an authoritative guide please refer to the online documentation for the
#' NNG library at <https://nng.nanomsg.org/man/>.
#'
#' @param object a Socket, Context, Stream, Listener or Dialer.
#' @param name name of option, e.g. 'recv-buffer', as a character string. See
#'   below options details.
#' @param value value of option. Supply character type for 'string' options,
#'   integer or double for 'int', 'duration', 'size' and 'uint64', and logical
#'   for 'bool'.
#'
#' @return The value of the option (logical for type 'bool', integer for 'int',
#'   'duration' and 'size', character for 'string', and double for 'uint64').
#'
#' @section Serialization:
#'
#' Apart from the NNG options documented below, there is the following special
#' option:
#'
#' \itemize{
#'   \item 'serial' (type list)
#'
#'   For Sockets only. This accepts a configuration created by
#'   [serial_config()]. Setting a new configuration replaces any already set. To
#'   remove entirely, supply an empty list. Note: this option is write-only and
#'   can be set but not retrieved.
#' }
#'
#' @section Global Options:
#'
#' \itemize{
#'   \item 'reconnect-time-min' (type 'ms')
#'
#'   This is the minimum amount of time (milliseconds) to wait before attempting
#'   to establish a connection after a previous attempt has failed. This can be
#'   set on a socket, but it can also be overridden on an individual dialer. The
#'   option is irrelevant for listeners.
#'
#'   \item 'reconnect-time-max' (type 'ms')
#'
#'   This is the maximum amount of time (milliseconds) to wait before attempting
#'   to establish a connection after a previous attempt has failed. If this is
#'   non-zero, then the time between successive connection attempts will start
#'   at the value of 'reconnect-time-min', and grow exponentially, until it
#'   reaches this value. If this value is zero, then no exponential back-off
#'   between connection attempts is done, and each attempt will wait the time
#'   specified by 'reconnect-time-min'. This can be set on a socket, but it can
#'   also be overridden on an individual dialer. The option is irrelevant for
#'   listeners.
#'
#'   \item 'recv-size-max' (type 'size')
#'
#'   This is the maximum message size that the will be accepted from a remote
#'   peer. If a peer attempts to send a message larger than this, then the
#'   message will be discarded. If the value of this is zero, then no limit on
#'   message sizes is enforced. This option exists to prevent certain kinds of
#'   denial-of-service attacks, where a malicious agent can claim to want to
#'   send an extraordinarily large message, without sending any data. This
#'   option can be set for the socket, but may be overridden for on a per-dialer
#'   or per-listener basis. NOTE: Applications on hostile networks should set
#'   this to a non-zero value to prevent denial-of-service attacks. NOTE: Some
#'   transports may have further message size restrictions.
#'
#'   \item 'recv-buffer' (type 'int')
#'
#'   This is the depth of the socket’s receive buffer as a number of messages.
#'   Messages received by a transport may be buffered until the application has
#'   accepted them for delivery. This value must be an integer between 0 and
#'   8192, inclusive. NOTE: Not all protocols support buffering received
#'   messages. For example req can only deal with a single reply at a time.
#'
#'   \item 'recv-timeout' (type 'ms')
#'
#'   This is the socket receive timeout in milliseconds. When no message is
#'   available for receiving at the socket for this period of time, receive
#'   operations will fail with a return value of 5L ('timed out').
#'
#'   \item 'send-buffer' (type 'int')
#'
#'   This is the depth of the socket send buffer as a number of messages.
#'   Messages sent by an application may be buffered by the socket until a
#'   transport is ready to accept them for delivery. This value must be an
#'   integer between 0 and 8192, inclusive. NOTE: Not all protocols support
#'   buffering sent messages; generally multicast protocols like pub will simply
#'   discard messages when they cannot be delivered immediately.
#'
#'   \item 'send-timeout' (type 'ms')
#'
#'   This is the socket send timeout in milliseconds. When a message cannot be
#'   queued for delivery by the socket for this period of time (such as if send
#'   buffers are full), the operation will fail with a return value of 5L
#'   ('timed out').
#'
#'   \item 'recv-fd' (type 'int')
#'
#'   This is the socket receive file descriptor. For supported protocols, this
#'   will become readable when a message is available for receiving on the
#'   socket. Attempts should not be made to read or write to the returned file
#'   descriptor, but it is suitable for use with poll(), select(), or WSAPoll()
#'   on Windows, and similar functions.
#'
#'   \item 'send-fd' (type 'int')
#'
#'   This is the socket send file descriptor. Attempts should not be made to
#'   read or write to the returned file descriptor, but it is suitable for use
#'   with poll(), select(), or WSAPoll() on Windows, and similar functions.
#'
#'   \item 'socket-name' (type 'string')
#'
#'   This is the socket name. By default this is a string corresponding to the
#'   value of the socket. The string must fit within 64-bytes, including the
#'   terminating NUL byte. The value is intended for application use, and is not
#'   used for anything in the library itself.
#'
#'   \item 'url' (type 'string')
#'
#'   This read-only option is used on a listener or dialer to obtain the URL
#'   with which it was configured.
#'
#' }
#'
#' @section Protocol-specific Options:
#'
#' \itemize{
#'   \item 'req:resend-time' (type 'ms')
#'
#'   (Request protocol) When a new request is started, a timer of this duration
#'   is also started. If no reply is received before this timer expires, then
#'   the request will be resent. (Requests are also automatically resent if the
#'   peer to whom the original request was sent disconnects, or if a peer
#'   becomes available while the requester is waiting for an available peer.)
#'
#'   \item 'sub:subscribe' (type 'string')
#'
#'   (Subscribe protocol) This option registers a topic that the subscriber is
#'   interested in. Each incoming message is checked against the list of
#'   subscribed topics. If the body begins with the entire set of bytes in the
#'   topic, then the message is accepted. If no topic matches, then the message
#'   is discarded. To receive all messages, set the topic to NULL.
#'
#'   \item 'sub:unsubscribe' (type 'string')
#'
#'   (Subscribe protocol) This option removes a topic from the subscription
#'   list. Note that if the topic was not previously subscribed to with
#'   'sub:subscribe' then an 'entry not found' error will result.
#'
#'   \item 'sub:prefnew' (type 'bool')
#'
#'   (Subscribe protocol) This option specifies the behavior of the subscriber
#'   when the queue is full. When TRUE (the default), the subscriber will make
#'   room in the queue by removing the oldest message. When FALSE, the
#'   subscriber will reject messages if the message queue does not have room.
#'
#'   \item 'surveyor:survey-time' (type 'ms')
#'
#'   (Surveyor protocol) Duration of surveys. When a new survey is started, a
#'   timer of this duration is also started. Any responses arriving after this
#'   time will be discarded. Attempts to receive after the timer expires with no
#'   other surveys started will result in an 'incorrect state' error. Attempts
#'   to receive when this timer expires will result in a 'timed out' error.
#'
#' }
#'
#' @section Transport-specific Options:
#'
#' \itemize{
#'   \item 'ipc:permissions' (type 'int')
#'
#'   (IPC transport) This option may be applied to a listener to configure the
#'   permissions that are used on the UNIX domain socket created by that
#'   listener. This property is only supported on POSIX systems. The value is of
#'   type int, representing the normal permission bits on a file, such as 0600
#'   (typically meaning read-write to the owner, and no permissions for anyone
#'   else.) The default is system-specific, most often 0644.
#'
#'   \item 'tcp-nodelay' (type 'bool')
#'
#'   (TCP transport) This option is used to disable (or enable) the use of
#'   Nagle's algorithm for TCP connections. When TRUE (the default), messages
#'   are sent immediately by the underlying TCP stream without waiting to gather
#'   more data. When FALSE, Nagle’s algorithm is enabled, and the TCP stream may
#'   wait briefly in an attempt to coalesce messages. Nagle’s algorithm is
#'   useful on low-bandwidth connections to reduce overhead, but it comes at a
#'   cost to latency. When used on a dialer or a listener, the value affects how
#'   newly created connections will be configured.
#'
#'   \item 'tcp-keepalive' (type 'bool')
#'
#'   (TCP transport) This option is used to enable the sending of keep-alive
#'   messages on the underlying TCP stream. This option is FALSE by default.
#'   When enabled, if no messages are seen for a period of time, then a zero
#'   length TCP message is sent with the ACK flag set in an attempt to tickle
#'   some traffic from the peer. If none is still seen (after some
#'   platform-specific number of retries and timeouts), then the remote peer is
#'   presumed dead, and the connection is closed. When used on a dialer or a
#'   listener, the value affects how newly created connections will be
#'   configured. This option has two purposes. First, it can be used to detect
#'   dead peers on an otherwise quiescent network. Second, it can be used to
#'   keep connection table entries in NAT and other middleware from expiring due
#'   to lack of activity.
#'
#'   \item 'tcp-bound-port' (type 'int')
#'
#'   (TCP transport) Local TCP port number. This is used on a listener, and is
#'   intended to be used after starting the listener in combination with a
#'   wildcard (0) local port. This determines the actual ephemeral port that was
#'   selected and bound. The value is provided as an integer, but only the low
#'   order 16 bits will be set, and is in native byte order for convenience.
#'
#'   \item 'ws:request-headers' (type 'string')
#'
#'   (WebSocket transport) Concatenation of multiple lines terminated by CRLF
#'   sequences, that can be used to add further headers to the HTTP request sent
#'   when connecting. This option can be set on dialers, and must be done before
#'   the transport is started.
#'
#'   \item 'ws:response-headers' (type 'string')
#'
#'   (WebSocket transport) Concatenation of multiple lines terminated by CRLF
#'   sequences, that can be used to add further headers to the HTTP response
#'   sent when connecting. This option can be set on listeners, and must be done
#'   before the transport is started.
#'
#'   \item 'ws:request-uri' (type 'string')
#'
#'   (WebSocket transport) For obtaining the URI sent by the client. This can be
#'   useful when a handler supports an entire directory tree.
#'
#' }
#'
#' @examples
#' s <- socket("pair")
#' opt(s, "send-buffer")
#' close(s)
#'
#' s <- socket("req")
#' ctx <- context(s)
#' opt(ctx, "send-timeout")
#' close(ctx)
#' close(s)
#'
#' s <- socket("pair", dial = "inproc://nanonext", autostart = FALSE)
#' opt(s$dialer[[1]], "reconnect-time-min")
#' close(s)
#'
#' s <- socket("pair", listen = "inproc://nanonext", autostart = FALSE)
#' opt(s$listener[[1]], "recv-size-max")
#' close(s)
#'
#' @export
#'
opt <- function(object, name) .Call(rnng_get_opt, object, name)

#' @examples
#' s <- socket("pair")
#' opt(s, "recv-timeout") <- 2000
#' close(s)
#'
#' s <- socket("req")
#' ctx <- context(s)
#' opt(ctx, "send-timeout") <- 2000
#' close(ctx)
#' close(s)
#'
#' s <- socket("pair", dial = "inproc://nanonext", autostart = FALSE)
#' opt(s$dialer[[1]], "reconnect-time-min") <- 2000
#' start(s$dialer[[1]])
#' close(s)
#'
#' s <- socket("pair", listen = "inproc://nanonext", autostart = FALSE)
#' opt(s$listener[[1]], "recv-size-max") <- 1024
#' start(s$listener[[1]])
#' close(s)
#'
#' @rdname opt
#' @export
#'
`opt<-` <- function(object, name, value) .Call(rnng_set_opt, object, name, value)

#' Subscribe / Unsubscribe Topic
#'
#' For a socket or context using the sub protocol in a publisher/subscriber
#' pattern. Set a topic to subscribe to, or remove a topic from the subscription
#' list.
#'
#' To use pub/sub the publisher must:
#' \itemize{
#'   \item specify `mode = 'raw'` when sending.
#'   \item ensure the sent vector starts with the topic.
#' }
#' The subscriber should then receive specifying the correct mode.
#'
#' @param con a Socket or Context using the 'sub' protocol.
#' @param topic \[default NULL\] an atomic type or `NULL`. The default `NULL`
#'   subscribes to all topics / unsubscribes from all topics (if all topics were
#'   previously subscribed).
#'
#' @return Invisibly, the passed Socket or Context.
#'
#' @examples
#' pub <- socket("pub", listen = "inproc://nanonext")
#' sub <- socket("sub", dial = "inproc://nanonext")
#'
#' subscribe(sub, "examples")
#'
#' send(pub, c("examples", "this is an example"), mode = "raw")
#' recv(sub, "character")
#' send(pub, "examples will also be received", mode = "raw")
#' recv(sub, "character")
#' send(pub, c("other", "this other topic will not be received"), mode = "raw")
#' recv(sub, "character")
#' unsubscribe(sub, "examples")
#' send(pub, c("examples", "this example is no longer received"), mode = "raw")
#' recv(sub, "character")
#'
#' subscribe(sub, 2)
#' send(pub, c(2, 10, 10, 20), mode = "raw")
#' recv(sub, "double")
#' unsubscribe(sub, 2)
#' send(pub, c(2, 10, 10, 20), mode = "raw")
#' recv(sub, "double")
#'
#' close(pub)
#' close(sub)
#'
#' @export
#'
subscribe <- function(con, topic = NULL)
  invisible(.Call(rnng_subscribe, con, topic, TRUE))

#' @rdname subscribe
#' @export
#'
unsubscribe <- function(con, topic = NULL)
  invisible(.Call(rnng_subscribe, con, topic, FALSE))

#' Set Survey Time
#'
#' For a socket or context using the surveyor protocol in a surveyor/respondent
#' pattern. Set the survey timeout in milliseconds (remains valid for all
#' subsequent surveys). Messages received by the surveyor after the timer has
#' ended are discarded.
#'
#' After using this function, to start a new survey, the surveyor must:
#' \itemize{
#'   \item send a message.
#'   \item switch to receiving responses.
#' }
#'
#' To respond to a survey, the respondent must:
#' \itemize{
#'   \item receive the survey message.
#'   \item send a reply using [send_aio()] before the survey has timed out (a
#'   reply can only be sent after receiving a survey).
#' }
#'
#' @param con a Socket or Context using the 'surveyor' protocol.
#' @param value \[default 1000L\] integer survey timeout in milliseconds.
#'
#' @return Invisibly, the passed Socket or Context.
#'
#' @examples
#' sur <- socket("surveyor", listen = "inproc://nanonext")
#' res <- socket("respondent", dial = "inproc://nanonext")
#'
#' survey_time(sur, 1000)
#'
#' send(sur, "reply to this survey")
#' aio <- recv_aio(sur)
#'
#' recv(res)
#' s <- send_aio(res, "replied")
#'
#' call_aio(aio)$data
#'
#' close(sur)
#' close(res)
#'
#' @export
#'
`survey_time` <- function(con, value = 1000L)
  invisible(.Call(rnng_set_opt, con, "surveyor:survey-time", value))
