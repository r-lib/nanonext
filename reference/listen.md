# Listen to an Address from a Socket

Creates a new Listener and binds it to a Socket.

## Usage

``` r
listen(
  socket,
  url = "inproc://nanonext",
  tls = NULL,
  autostart = TRUE,
  fail = c("warn", "error", "none")
)
```

## Arguments

- socket:

  a Socket.

- url:

  \[default 'inproc://nanonext'\] a URL to dial, specifying the
  transport and address as a character string e.g. 'inproc://anyvalue'
  or 'tcp://127.0.0.1:5555' (see
  [transports](https://nanonext.r-lib.org/reference/transports.md)).

- tls:

  \[default NULL\] for secure tls+tcp:// or wss:// connections only,
  provide a TLS configuration object created by
  [`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md).

- autostart:

  \[default TRUE\] whether to start the listener. Set to FALSE if
  setting configuration options on the listener as it is not generally
  possible to change these once started.

- fail:

  \[default 'warn'\] failure mode - a character value or integer
  equivalent, whether to warn (1L), error (2L), or for none (3L) just
  return an 'errorValue' without any corresponding warning.

## Value

Invisibly, an integer exit code (zero on success). A new Listener
(object of class 'nanoListener' and 'nano') is created and bound to the
Socket if successful.

## Details

To view all Listeners bound to a socket use `$listener` on the socket,
which returns a list of Listener objects. To access any individual
Listener (e.g. to set options on it), index into the list e.g.
`$listener[[1]]` to return the first Listener.

A listener is an external pointer to a listener object, which accepts
incoming connections. A given listener object may have many connections
at the same time, much like an HTTP server can have many connections to
multiple clients simultaneously.

## Further details

Dialers and Listeners are always associated with a single socket. A
given socket may have multiple Listeners and/or multiple Dialers.

The client/server relationship described by dialer/listener is
completely orthogonal to any similar relationship in the protocols. For
example, a rep socket may use a dialer to connect to a listener on an
req socket. This orthogonality can lead to innovative solutions to
otherwise challenging communications problems.

Any configuration options on the dialer/listener should be set by
[`opt<-()`](https://nanonext.r-lib.org/reference/opt.md) before starting
the dialer/listener with
[`start()`](https://nanonext.r-lib.org/reference/start.md).

Dialers/Listeners may be destroyed by
[`close()`](https://nanonext.r-lib.org/reference/close.md). They are
also closed when their associated socket is closed.

## Examples

``` r
socket <- socket("req")
listen(socket, url = "inproc://nanolisten", autostart = FALSE)
socket$listener
#> [[1]]
#> < nanoListener >
#>  - id: 5
#>  - socket: 12
#>  - state: not started
#>  - url: inproc://nanolisten
#> 
start(socket$listener[[1]])
socket$listener
#> [[1]]
#> < nanoListener >
#>  - id: 5
#>  - socket: 12
#>  - state: started
#>  - url: inproc://nanolisten
#> 
close(socket$listener[[1]])
close(socket)

nano <- nano("bus")
nano$listen(url = "inproc://nanolisten", autostart = FALSE)
nano$listener
#> [[1]]
#> < nanoListener >
#>  - id: 6
#>  - socket: 13
#>  - state: not started
#>  - url: inproc://nanolisten
#> 
nano$listener_start()
nano$listener
#> [[1]]
#> < nanoListener >
#>  - id: 6
#>  - socket: 13
#>  - state: started
#>  - url: inproc://nanolisten
#> 
close(nano$listener[[1]])
nano$close()
```
