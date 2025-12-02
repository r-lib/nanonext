# Create Nano Object

Create a nano object, encapsulating a Socket, Dialers/Listeners and
associated methods.

## Usage

``` r
nano(
  protocol = c("bus", "pair", "poly", "push", "pull", "pub", "sub", "req", "rep",
    "surveyor", "respondent"),
  dial = NULL,
  listen = NULL,
  tls = NULL,
  autostart = TRUE
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

## Value

A nano object of class 'nanoObject'.

## Details

This function encapsulates a Socket, Dialer and/or Listener, and its
associated methods.

The Socket may be accessed by `$socket`, and the Dialer or Listener by
`$dialer[[1]]` or `$listener[[1]]` respectively.

The object's methods may be accessed by `$` e.g. `$send()` or `$recv()`.
These methods mirror their functional equivalents, with the same
arguments and defaults, apart from that the first argument of the
functional equivalent is mapped to the object's encapsulated socket (or
context, if active) and does not need to be supplied.

More complex network topologies may be created by binding further
dialers or listeners using the object's `$dial()` and `$listen()`
methods. The new dialer/listener will be attached to the object e.g. if
the object already has a dialer, then at `$dialer[[2]]` etc.

Note that `$dialer_opt()` and `$listener_opt()` methods will be
available once dialers/listeners are attached to the object. These
methods get or apply settings for all dialers or listeners equally. To
get or apply settings for individual dialers/listeners, access them
directly via `$dialer[[2]]` or `$listener[[2]]` etc.

The methods `$opt()`, and also `$dialer_opt()` or `$listener_opt()` as
may be applicable, will get the requested option if a single argument
`name` is provided, and will set the value for the option if both
arguments `name` and `value` are provided.

For Dialers or Listeners not automatically started, the
`$dialer_start()` or `$listener_start()` methods will be available.
These act on the most recently created Dialer or Listener respectively.

For applicable protocols, new contexts may be created by using the
`$context_open()` method. This will attach a new context at `$context`
as well as a `$context_close()` method. While a context is active, all
object methods use the context rather than the socket. A new context may
be created by calling `$context_open()`, which will replace any existing
context. It is only necessary to use `$context_close()` to close the
existing context and revert to using the socket.

## Examples

``` r
nano <- nano("bus", listen = "inproc://nanonext")
nano
#> < nano object >
#>  - socket id: 16
#>  - state: opened
#>  - protocol: bus
#>  - listener:
#>     inproc://nanonext
nano$socket
#> < nanoSocket >
#>  - id: 16
#>  - state: opened
#>  - protocol: bus
#>  - listener:
#>     inproc://nanonext
nano$listener[[1]]
#> < nanoListener >
#>  - id: 8
#>  - socket: 16
#>  - state: started
#>  - url: inproc://nanonext

nano$opt("send-timeout", 1500)
nano$opt("send-timeout")
#> [1] 1500

nano$listen(url = "inproc://nanonextgen")
nano$listener
#> [[1]]
#> < nanoListener >
#>  - id: 8
#>  - socket: 16
#>  - state: started
#>  - url: inproc://nanonext
#> 
#> [[2]]
#> < nanoListener >
#>  - id: 9
#>  - socket: 16
#>  - state: started
#>  - url: inproc://nanonextgen
#> 

nano1 <- nano("bus", dial = "inproc://nanonext")
nano$send("example test", mode = "raw")
#> [1] 0
nano1$recv("character")
#> [1] "example test"

nano$close()
nano1$close()
```
