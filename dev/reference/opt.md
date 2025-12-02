# Get and Set Options for a Socket, Context, Stream, Listener or Dialer

Get and set the value of options for a Socket, Context, Stream, Listener
or Dialer.

## Usage

``` r
opt(object, name)

opt(object, name) <- value
```

## Arguments

- object:

  a Socket, Context, Stream, Listener or Dialer.

- name:

  name of option, e.g. 'recv-buffer', as a character string. See below
  options details.

- value:

  value of option. Supply character type for 'string' options, integer
  or double for 'int', 'duration', 'size' and 'uint64', and logical for
  'bool'.

## Value

The value of the option (logical for type 'bool', integer for 'int',
'duration' and 'size', character for 'string', and double for 'uint64').

## Details

Note: once a dialer or listener has started, it is not generally
possible to change its configuration. Hence create the dialer or
listener with `autostart = FALSE` if configuration needs to be set.

To get or set options on a Listener or Dialer attached to a Socket or
nano object, pass in the objects directly via for example
`$listener[[1]]` for the first Listener.

Some options are only meaningful or supported in certain contexts; for
example there is no single meaningful address for a socket, since
sockets can have multiple dialers and endpoints associated with them.

For an authoritative guide please refer to the online documentation for
the NNG library at <https://nng.nanomsg.org/man/>.

## Serialization

Apart from the NNG options documented below, there is the following
special option:

- 'serial' (type list)

  For Sockets only. This accepts a configuration created by
  [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md).
  Setting a new configuration replaces any already set. To remove
  entirely, supply an empty list. Note: this option is write-only and
  can be set but not retrieved.

## Global Options

- 'reconnect-time-min' (type 'ms')

  This is the minimum amount of time (milliseconds) to wait before
  attempting to establish a connection after a previous attempt has
  failed. This can be set on a socket, but it can also be overridden on
  an individual dialer. The option is irrelevant for listeners.

- 'reconnect-time-max' (type 'ms')

  This is the maximum amount of time (milliseconds) to wait before
  attempting to establish a connection after a previous attempt has
  failed. If this is non-zero, then the time between successive
  connection attempts will start at the value of 'reconnect-time-min',
  and grow exponentially, until it reaches this value. If this value is
  zero, then no exponential back-off between connection attempts is
  done, and each attempt will wait the time specified by
  'reconnect-time-min'. This can be set on a socket, but it can also be
  overridden on an individual dialer. The option is irrelevant for
  listeners.

- 'recv-size-max' (type 'size')

  This is the maximum message size that the will be accepted from a
  remote peer. If a peer attempts to send a message larger than this,
  then the message will be discarded. If the value of this is zero, then
  no limit on message sizes is enforced. This option exists to prevent
  certain kinds of denial-of-service attacks, where a malicious agent
  can claim to want to send an extraordinarily large message, without
  sending any data. This option can be set for the socket, but may be
  overridden for on a per-dialer or per-listener basis. NOTE:
  Applications on hostile networks should set this to a non-zero value
  to prevent denial-of-service attacks. NOTE: Some transports may have
  further message size restrictions.

- 'recv-buffer' (type 'int')

  This is the depth of the socket’s receive buffer as a number of
  messages. Messages received by a transport may be buffered until the
  application has accepted them for delivery. This value must be an
  integer between 0 and 8192, inclusive. NOTE: Not all protocols support
  buffering received messages. For example req can only deal with a
  single reply at a time.

- 'recv-timeout' (type 'ms')

  This is the socket receive timeout in milliseconds. When no message is
  available for receiving at the socket for this period of time, receive
  operations will fail with a return value of 5L ('timed out').

- 'send-buffer' (type 'int')

  This is the depth of the socket send buffer as a number of messages.
  Messages sent by an application may be buffered by the socket until a
  transport is ready to accept them for delivery. This value must be an
  integer between 0 and 8192, inclusive. NOTE: Not all protocols support
  buffering sent messages; generally multicast protocols like pub will
  simply discard messages when they cannot be delivered immediately.

- 'send-timeout' (type 'ms')

  This is the socket send timeout in milliseconds. When a message cannot
  be queued for delivery by the socket for this period of time (such as
  if send buffers are full), the operation will fail with a return value
  of 5L ('timed out').

- 'recv-fd' (type 'int')

  This is the socket receive file descriptor. For supported protocols,
  this will become readable when a message is available for receiving on
  the socket. Attempts should not be made to read or write to the
  returned file descriptor, but it is suitable for use with poll(),
  select(), or WSAPoll() on Windows, and similar functions.

- 'send-fd' (type 'int')

  This is the socket send file descriptor. Attempts should not be made
  to read or write to the returned file descriptor, but it is suitable
  for use with poll(), select(), or WSAPoll() on Windows, and similar
  functions.

- 'socket-name' (type 'string')

  This is the socket name. By default this is a string corresponding to
  the value of the socket. The string must fit within 64-bytes,
  including the terminating NUL byte. The value is intended for
  application use, and is not used for anything in the library itself.

- 'url' (type 'string')

  This read-only option is used on a listener or dialer to obtain the
  URL with which it was configured.

## Protocol-specific Options

- 'req:resend-time' (type 'ms')

  (Request protocol) When a new request is started, a timer of this
  duration is also started. If no reply is received before this timer
  expires, then the request will be resent. (Requests are also
  automatically resent if the peer to whom the original request was sent
  disconnects, or if a peer becomes available while the requester is
  waiting for an available peer.)

- 'sub:subscribe' (type 'string')

  (Subscribe protocol) This option registers a topic that the subscriber
  is interested in. Each incoming message is checked against the list of
  subscribed topics. If the body begins with the entire set of bytes in
  the topic, then the message is accepted. If no topic matches, then the
  message is discarded. To receive all messages, set the topic to NULL.

- 'sub:unsubscribe' (type 'string')

  (Subscribe protocol) This option removes a topic from the subscription
  list. Note that if the topic was not previously subscribed to with
  'sub:subscribe' then an 'entry not found' error will result.

- 'sub:prefnew' (type 'bool')

  (Subscribe protocol) This option specifies the behavior of the
  subscriber when the queue is full. When TRUE (the default), the
  subscriber will make room in the queue by removing the oldest message.
  When FALSE, the subscriber will reject messages if the message queue
  does not have room.

- 'surveyor:survey-time' (type 'ms')

  (Surveyor protocol) Duration of surveys. When a new survey is started,
  a timer of this duration is also started. Any responses arriving after
  this time will be discarded. Attempts to receive after the timer
  expires with no other surveys started will result in an 'incorrect
  state' error. Attempts to receive when this timer expires will result
  in a 'timed out' error.

## Transport-specific Options

- 'ipc:permissions' (type 'int')

  (IPC transport) This option may be applied to a listener to configure
  the permissions that are used on the UNIX domain socket created by
  that listener. This property is only supported on POSIX systems. The
  value is of type int, representing the normal permission bits on a
  file, such as 0600 (typically meaning read-write to the owner, and no
  permissions for anyone else.) The default is system-specific, most
  often 0644.

- 'tcp-nodelay' (type 'bool')

  (TCP transport) This option is used to disable (or enable) the use of
  Nagle's algorithm for TCP connections. When TRUE (the default),
  messages are sent immediately by the underlying TCP stream without
  waiting to gather more data. When FALSE, Nagle’s algorithm is enabled,
  and the TCP stream may wait briefly in an attempt to coalesce
  messages. Nagle’s algorithm is useful on low-bandwidth connections to
  reduce overhead, but it comes at a cost to latency. When used on a
  dialer or a listener, the value affects how newly created connections
  will be configured.

- 'tcp-keepalive' (type 'bool')

  (TCP transport) This option is used to enable the sending of
  keep-alive messages on the underlying TCP stream. This option is FALSE
  by default. When enabled, if no messages are seen for a period of
  time, then a zero length TCP message is sent with the ACK flag set in
  an attempt to tickle some traffic from the peer. If none is still seen
  (after some platform-specific number of retries and timeouts), then
  the remote peer is presumed dead, and the connection is closed. When
  used on a dialer or a listener, the value affects how newly created
  connections will be configured. This option has two purposes. First,
  it can be used to detect dead peers on an otherwise quiescent network.
  Second, it can be used to keep connection table entries in NAT and
  other middleware from expiring due to lack of activity.

- 'tcp-bound-port' (type 'int')

  (TCP transport) Local TCP port number. This is used on a listener, and
  is intended to be used after starting the listener in combination with
  a wildcard (0) local port. This determines the actual ephemeral port
  that was selected and bound. The value is provided as an integer, but
  only the low order 16 bits will be set, and is in native byte order
  for convenience.

- 'ws:request-headers' (type 'string')

  (WebSocket transport) Concatenation of multiple lines terminated by
  CRLF sequences, that can be used to add further headers to the HTTP
  request sent when connecting. This option can be set on dialers, and
  must be done before the transport is started.

- 'ws:response-headers' (type 'string')

  (WebSocket transport) Concatenation of multiple lines terminated by
  CRLF sequences, that can be used to add further headers to the HTTP
  response sent when connecting. This option can be set on listeners,
  and must be done before the transport is started.

- 'ws:request-uri' (type 'string')

  (WebSocket transport) For obtaining the URI sent by the client. This
  can be useful when a handler supports an entire directory tree.

## Examples

``` r
s <- socket("pair")
opt(s, "send-buffer")
#> [1] 0
close(s)

s <- socket("req")
ctx <- context(s)
opt(ctx, "send-timeout")
#> [1] -1
close(ctx)
close(s)

s <- socket("pair", dial = "inproc://nanonext", autostart = FALSE)
opt(s$dialer[[1]], "reconnect-time-min")
#> [1] 1000
close(s)

s <- socket("pair", listen = "inproc://nanonext", autostart = FALSE)
opt(s$listener[[1]], "recv-size-max")
#> [1] 0
close(s)

s <- socket("pair")
opt(s, "recv-timeout") <- 2000
close(s)

s <- socket("req")
ctx <- context(s)
opt(ctx, "send-timeout") <- 2000
close(ctx)
close(s)

s <- socket("pair", dial = "inproc://nanonext", autostart = FALSE)
opt(s$dialer[[1]], "reconnect-time-min") <- 2000
start(s$dialer[[1]])
close(s)

s <- socket("pair", listen = "inproc://nanonext", autostart = FALSE)
opt(s$listener[[1]], "recv-size-max") <- 1024
start(s$listener[[1]])
close(s)
```
