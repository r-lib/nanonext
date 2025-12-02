# Dial an Address from a Socket

Creates a new Dialer and binds it to a Socket.

## Usage

``` r
dial(
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
  [transports](https://nanonext.r-lib.org/dev/reference/transports.md)).

- tls:

  \[default NULL\] for secure tls+tcp:// or wss:// connections only,
  provide a TLS configuration object created by
  [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md).

- autostart:

  \[default TRUE\] whether to start the dialer (by default
  asynchronously). Set to NA to start synchronously - this is less
  resilient if a connection is not immediately possible, but avoids
  subtle errors from attempting to use the socket before an asynchronous
  dial has completed. Set to FALSE if setting configuration options on
  the dialer as it is not generally possible to change these once
  started.

- fail:

  \[default 'warn'\] failure mode - a character value or integer
  equivalent, whether to warn (1L), error (2L), or for none (3L) just
  return an 'errorValue' without any corresponding warning.

## Value

Invisibly, an integer exit code (zero on success). A new Dialer (object
of class 'nanoDialer' and 'nano') is created and bound to the Socket if
successful.

## Details

To view all Dialers bound to a socket use `$dialer` on the socket, which
returns a list of Dialer objects. To access any individual Dialer (e.g.
to set options on it), index into the list e.g. `$dialer[[1]]` to return
the first Dialer.

A Dialer is an external pointer to a dialer object, which creates a
single outgoing connection at a time. If the connection is broken, or
fails, the dialer object will automatically attempt to reconnect, and
will keep doing so until the dialer or socket is destroyed.

## Further details

Dialers and Listeners are always associated with a single socket. A
given socket may have multiple Listeners and/or multiple Dialers.

The client/server relationship described by dialer/listener is
completely orthogonal to any similar relationship in the protocols. For
example, a rep socket may use a dialer to connect to a listener on an
req socket. This orthogonality can lead to innovative solutions to
otherwise challenging communications problems.

Any configuration options on the dialer/listener should be set by
[`opt<-()`](https://nanonext.r-lib.org/dev/reference/opt.md) before
starting the dialer/listener with
[`start()`](https://nanonext.r-lib.org/dev/reference/start.md).

Dialers/Listeners may be destroyed by
[`close()`](https://nanonext.r-lib.org/dev/reference/close.md). They are
also closed when their associated socket is closed.

## Examples

``` r
socket <- socket("rep")
dial(socket, url = "inproc://nanodial", autostart = FALSE)
socket$dialer
#> [[1]]
#> < nanoDialer >
#>  - id: 3
#>  - socket: 7
#>  - state: not started
#>  - url: inproc://nanodial
#> 
start(socket$dialer[[1]])
socket$dialer
#> [[1]]
#> < nanoDialer >
#>  - id: 3
#>  - socket: 7
#>  - state: started
#>  - url: inproc://nanodial
#> 
close(socket$dialer[[1]])
close(socket)

nano <- nano("bus")
nano$dial(url = "inproc://nanodial", autostart = FALSE)
nano$dialer
#> [[1]]
#> < nanoDialer >
#>  - id: 4
#>  - socket: 8
#>  - state: not started
#>  - url: inproc://nanodial
#> 
nano$dialer_start()
nano$dialer
#> [[1]]
#> < nanoDialer >
#>  - id: 4
#>  - socket: 8
#>  - state: started
#>  - url: inproc://nanodial
#> 
close(nano$dialer[[1]])
nano$close()
```
