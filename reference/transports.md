# Transports (Documentation)

Transports supported by nanonext.

For an authoritative guide please refer to the online documentation for
the NNG library at <https://nng.nanomsg.org/man/>.

## Inproc

The inproc transport provides communication support between sockets
within the same process. This may be used as an alternative to slower
transports when data must be moved within the same process. This
transport tries hard to avoid copying data, and thus is very
light-weight.

**\[URI, inproc://\]** This transport uses URIs using the scheme
inproc://, followed by an arbitrary string of text, terminated by a NUL
byte. inproc://nanonext is a valid example URL.

- Multiple URIs can be used within the same application, and they will
  not interfere with one another.

- Two applications may also use the same URI without interfering with
  each other, and they will be unable to communicate with each other
  using that URI.

## IPC

The IPC transport provides communication support between sockets within
different processes on the same host. For POSIX platforms, this is
implemented using UNIX domain sockets. For Windows, this is implemented
using Windows Named Pipes. Other platforms may have different
implementation strategies.

*Traditional Names*

**\[URI, ipc://\]** This transport uses URIs using the scheme ipc://,
followed by a path name in the file system where the socket or named
pipe should be created.

- On POSIX platforms, the path is taken literally, and is relative to
  the current directory, unless it begins with /, in which case it is
  relative to the root directory. For example, ipc://nanonext refers to
  the name nanonext in the current directory, whereas
  ipc:///tmp/nanonext refers to nanonext located in /tmp.

- On Windows, all names are prefixed by \\\\ pipe\\ and do not reside in
  the normal file system - the required prefix is added automatically by
  NNG, so a URL of the form ipc://nanonext is fine.

*UNIX Aliases*

**\[URI, unix://\]** The unix:// scheme is an alias for ipc:// and can
be used inter-changeably, but only on POSIX systems. The purpose of this
scheme is to support a future transport making use of AF_UNIX on Windows
systems, at which time it will be necessary to discriminate between the
Named Pipes and the AF_UNIX based transports.

*Abstract Names*

**\[URI, abstract://\]** On Linux, this transport also can support
abstract sockets. Abstract sockets use a URI-encoded name after the
scheme, which allows arbitrary values to be conveyed in the path,
including embedded NUL bytes. abstract://nanonext is a valid example
URL.

- Abstract sockets do not have any representation in the file system,
  and are automatically freed by the system when no longer in use.
  Abstract sockets ignore socket permissions, but it is still possible
  to determine the credentials of the peer.

## TCP/IP

The TCP transport provides communication support between sockets across
a TCP/IP network. Both IPv4 and IPv6 are supported when supported by the
underlying platform.

**\[URI, tcp://\]** This transport uses URIs using the scheme tcp://,
followed by an IP address or hostname, followed by a colon and finally a
TCP port number. For example, to contact port 80 on the localhost either
of the following URIs could be used: tcp://127.0.0.1:80 or
tcp://localhost:80.

- A URI may be restricted to IPv6 using the scheme tcp6://, and may be
  restricted to IPv4 using the scheme tcp4://

- Note: Specifying tcp6:// may not prevent IPv4 hosts from being used
  with IPv4-in-IPv6 addresses, particularly when using a wildcard
  hostname with listeners. The details of this varies across operating
  systems.

- Note: both tcp6:// and tcp4:// are specific to NNG, and might not be
  understood by other implementations.

- It is recommended to use either numeric IP addresses, or names that
  are specific to either IPv4 or IPv6 to prevent confusion and
  surprises.

- When specifying IPv6 addresses, the address must be enclosed in square
  brackets (\[\]) to avoid confusion with the final colon separating the
  port. For example, the same port 80 on the IPv6 loopback address (::1)
  would be specified as tcp://\[::1\]:80.

- The special value of 0 (INADDR_ANY) can be used for a listener to
  indicate that it should listen on all interfaces on the host. A
  shorthand for this form is to either omit the address, or specify the
  asterisk (*) character. For example, the following three URIs are all
  equivalent, and could be used to listen to port 9999 on the host: (1)
  tcp://0.0.0.0:9999 (2) tcp://*:9999 (3) tcp://:9999

## TLS

The TLS transport provides communication support between peers across a
TCP/IP network using TLS v1.2 on top of TCP. Both IPv4 and IPv6 are
supported when supported by the underlying platform.

**\[URI, tls+tcp://\]** This transport uses URIs using the scheme
tls+tcp://, followed by an IP address or hostname, followed by a colon
and finally a TCP port number. For example, to contact port 4433 on the
localhost either of the following URIs could be used:
tls+tcp://127.0.0.1:4433 or tls+tcp://localhost:4433.

- A URI may be restricted to IPv6 using the scheme tls+tcp6://, or IPv4
  using the scheme tls+tcp4://.

## WebSocket

The ws and wss transport provides communication support between peers
across a TCP/IP network using WebSockets. Both IPv4 and IPv6 are
supported when supported by the underlying platform.

**\[URI, ws://\]** This transport uses URIs using the scheme ws://,
followed by an IP address or hostname, optionally followed by a colon
and a TCP port number, optionally followed by a path. (If no port number
is specified then port 80 is assumed. If no path is specified then a
path of / is assumed.) For example, the URI ws://localhost/app/pubsub
would use port 80 on localhost, with the path /app/pubsub.

**\[URI, wss://\]** Secure WebSockets use the scheme wss://, and the
default TCP port number of 443. Otherwise the format is the same as for
regular WebSockets.

- A URI may be restricted to IPv6 using the scheme ws6:// or wss6://, or
  IPv4 using the scheme ws4:// or wss4://.

- When specifying IPv6 addresses, the address must be enclosed in square
  brackets (\[\]) to avoid confusion with the final colon separating the
  port. For example, the same path and port on the IPv6 loopback address
  (::1) would be specified as ws://\[::1\]/app/pubsub.

- Note: The value specified as the host, if any, will also be used in
  the Host: HTTP header during HTTP negotiation.

- To listen to all ports on the system, the host name may be elided from
  the URL on the listener. This will wind up listening to all interfaces
  on the system, with possible caveats for IPv4 and IPv6 depending on
  what the underlying system supports. (On most modern systems it will
  map to the special IPv6 address ::, and both IPv4 and IPv6 connections
  will be permitted, with IPv4 addresses mapped to IPv6 addresses.)

- This transport makes use of shared HTTP server instances, permitting
  multiple sockets or listeners to be configured with the same hostname
  and port. When creating a new listener, it is registered with an
  existing HTTP server instance if one can be found. Note that the
  matching algorithm is somewhat simple, using only a string based
  hostname or IP address and port to match. Therefore it is recommended
  to use only IP addresses or the empty string as the hostname in
  listener URLs.

- All sharing of server instances is only typically possible within the
  same process.

- The server may also be used by other things (for example to serve
  static content), in the same process.
