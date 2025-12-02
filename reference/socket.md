# Open Socket

Open a Socket implementing `protocol`, and optionally dial (establish an
outgoing connection) or listen (accept an incoming connection) at an
address.

## Usage

``` r
socket(
  protocol = c("bus", "pair", "poly", "push", "pull", "pub", "sub", "req", "rep",
    "surveyor", "respondent"),
  dial = NULL,
  listen = NULL,
  tls = NULL,
  autostart = TRUE,
  raw = FALSE
)
```

## Arguments

- protocol:

  \[default 'bus'\] choose protocol - `"bus"`, `"pair"`, `"poly"`,
  `"push"`, `"pull"`, `"pub"`, `"sub"`, `"req"`, `"rep"`, `"surveyor"`,
  or `"respondent"` - see
  [protocols](https://nanonext.r-lib.org/reference/protocols.md).

- dial:

  (optional) a URL to dial, specifying the transport and address as a
  character string e.g. 'inproc://anyvalue' or 'tcp://127.0.0.1:5555'
  (see
  [transports](https://nanonext.r-lib.org/reference/transports.md)).

- listen:

  (optional) a URL to listen at, specifying the transport and address as
  a character string e.g. 'inproc://anyvalue' or 'tcp://127.0.0.1:5555'
  (see
  [transports](https://nanonext.r-lib.org/reference/transports.md)).

- tls:

  \[default NULL\] for secure tls+tcp:// or wss:// connections only,
  provide a TLS configuration object created by
  [`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md).

- autostart:

  \[default TRUE\] whether to start the dialer/listener. Set to FALSE if
  setting configuration options on the dialer/listener as it is not
  generally possible to change these once started. For dialers only: set
  to NA to start synchronously - this is less resilient if a connection
  is not immediately possible, but avoids subtle errors from attempting
  to use the socket before an asynchronous dial has completed.

- raw:

  \[default FALSE\] whether to open raw mode sockets. Note: not for
  general use - do not enable unless you have a specific need (refer to
  NNG documentation).

## Value

A Socket (object of class 'nanoSocket' and 'nano').

## Details

NNG presents a socket view of networking. The sockets are constructed
using protocol-specific functions, as a given socket implements
precisely one protocol.

Each socket may be used to send and receive messages (if the protocol
supports it, and implements the appropriate protocol semantics). For
example, sub sockets automatically filter incoming messages to discard
those for topics that have not been subscribed.

This function (optionally) binds a single Dialer and/or Listener to a
Socket. More complex network topologies may be created by binding
further Dialers / Listeners to the Socket as required using
[`dial()`](https://nanonext.r-lib.org/reference/dial.md) and
[`listen()`](https://nanonext.r-lib.org/reference/listen.md).

New contexts may also be created using
[`context()`](https://nanonext.r-lib.org/reference/context.md) if the
protocol supports it.

## Protocols

The following Scalability Protocols (communication patterns) are
implemented:

- Bus (mesh networks) - protocol: 'bus'

- Pair (two-way radio) - protocol: 'pair'

- Poly (one-to-one of many) - protocol: 'poly'

- Pipeline (one-way pipe) - protocol: 'push', 'pull'

- Publisher/Subscriber (topics & broadcast) - protocol: 'pub', 'sub'

- Request/Reply (RPC) - protocol: 'req', 'rep'

- Survey (voting & service discovery) - protocol: 'surveyor',
  'respondent'

Please see
[protocols](https://nanonext.r-lib.org/reference/protocols.md) for
further documentation.

## Transports

The following communications transports may be used:

- Inproc (in-process) - url: 'inproc://'

- IPC (inter-process communications) - url: 'ipc://' (or 'abstract://'
  on Linux)

- TCP and TLS over TCP - url: 'tcp://' and 'tls+tcp://'

- WebSocket and TLS over WebSocket - url: 'ws://' and 'wss://'

Please see
[transports](https://nanonext.r-lib.org/reference/transports.md) for
further documentation.

## Examples

``` r
s <- socket(protocol = "req", listen = "inproc://nanosocket")
s
#> < nanoSocket >
#>  - id: 45
#>  - state: opened
#>  - protocol: req
#>  - listener:
#>     inproc://nanosocket
s1 <- socket(protocol = "rep", dial = "inproc://nanosocket")
s1
#> < nanoSocket >
#>  - id: 46
#>  - state: opened
#>  - protocol: rep
#>  - dialer:
#>     inproc://nanosocket

send(s, "hello world!")
#> [1] 0
recv(s1)
#> [1] "hello world!"

close(s1)
close(s)
```
