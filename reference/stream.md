# Open Stream

Open a Stream by either dialing (establishing an outgoing connection) or
listening (accepting an incoming connection) at an address. This is a
low-level interface intended for communicating with non-NNG endpoints.

## Usage

``` r
stream(dial = NULL, listen = NULL, textframes = FALSE, tls = NULL)
```

## Arguments

- dial:

  a URL to dial, specifying the transport and address as a character
  string e.g. 'ipc:///tmp/anyvalue' or 'tcp://127.0.0.1:5555' (not all
  transports are supported).

- listen:

  a URL to listen at, specifying the transport and address as a
  character string e.g. 'ipc:///tmp/anyvalue' or 'tcp://127.0.0.1:5555'
  (not all transports are supported).

- textframes:

  \[default FALSE\] applicable to the websocket transport only, enables
  sending and receiving of TEXT frames (ignored otherwise).

- tls:

  (optional) applicable to secure websockets only, a client or server
  TLS configuration object created by
  [`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md).
  If missing or NULL, certificates are not validated.

## Value

A Stream (object of class 'nanoStream' and 'nano').

## Details

A Stream is used for raw byte stream connections. Byte streams are
reliable in that data will not be delivered out of order, or with
portions missing.

Can be used to dial a (secure) websocket address starting 'ws://' or
'wss://'. It is often the case that `textframes` needs to be set to
`TRUE`.

Specify only one of `dial` or `listen`. If both are specified, `listen`
will be ignored.

Closing a stream renders it invalid and attempting to perform additional
operations on it will error.

## Examples

``` r
# Will succeed only if there is an open connection at the address:
s <- tryCatch(stream(dial = "tcp://127.0.0.1:5555"), error = identity)
s
#> <simpleError in stream(dial = "tcp://127.0.0.1:5555"): 6 | Connection refused>
if (FALSE) { # interactive()
# Run in interactive sessions only as connection is not always available:
s <- tryCatch(
  stream(dial = "wss://echo.websocket.events/", textframes = TRUE),
  error = identity
)
s
if (is_nano(s)) recv(s)
if (is_nano(s)) send(s, "hello")
if (is_nano(s)) recv(s)
if (is_nano(s)) close(s)
}
```
