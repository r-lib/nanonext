# Send

Send data over a connection (Socket, Context or Stream).

## Usage

``` r
send(con, data, mode = c("serial", "raw"), block = NULL, pipe = 0L)
```

## Arguments

- con:

  a Socket, Context or Stream.

- data:

  an object (a vector, if `mode = "raw"`).

- mode:

  \[default 'serial'\] character value or integer equivalent - either
  `"serial"` (1L) to send serialised R objects, or `"raw"` (2L) to send
  atomic vectors of any type as a raw byte vector. For Streams, `"raw"`
  is the only option and this argument is ignored.

- block:

  \[default NULL\] which applies the connection default (see section
  'Blocking' below). Specify logical `TRUE` to block until successful or
  `FALSE` to return immediately even if unsuccessful (e.g. if no
  connection is available), or else an integer value specifying the
  maximum time to block in milliseconds, after which the operation will
  time out.

- pipe:

  \[default 0L\] only applicable to Sockets using the 'poly' protocol,
  an integer pipe ID if directing the send via a specific pipe.

## Value

An integer exit code (zero on success).

## Blocking

For Sockets and Contexts: the default behaviour is non-blocking with
`block = FALSE`. This will return immediately with an error if the
message could not be queued for sending. Certain protocol / transport
combinations may limit the number of messages that can be queued if they
have yet to be received.

For Streams: the default behaviour is blocking with `block = TRUE`. This
will wait until the send has completed. Set a timeout to ensure that the
function returns under all scenarios. As the underlying implementation
uses an asynchronous send with a wait, it is recommended to set a small
positive value for `block` rather than `FALSE`.

## Send Modes

The default mode `"serial"` sends serialised R objects to ensure perfect
reproducibility within R. When receiving, the corresponding mode
`"serial"` should be used. Custom serialization and unserialization
functions for reference objects may be enabled by the function
[`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md).

Mode `"raw"` sends atomic vectors of any type as a raw byte vector, and
must be used when interfacing with external applications or raw system
sockets, where R serialization is not in use. When receiving, the mode
corresponding to the vector sent should be used.

## See also

[`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md) for
asynchronous send.

## Examples

``` r
pub <- socket("pub", dial = "inproc://nanonext")

send(pub, data.frame(a = 1, b = 2))
#> [1] 0
send(pub, c(10.1, 20.2, 30.3), mode = "raw", block = 100)
#> [1] 0

close(pub)

req <- socket("req", listen = "inproc://nanonext")
rep <- socket("rep", dial = "inproc://nanonext")

ctx <- context(req)
send(ctx, data.frame(a = 1, b = 2), block = 100)
#> [1] 0

msg <- recv_aio(rep, timeout = 100)
send(ctx, c(1.1, 2.2, 3.3), mode = "raw", block = 100)
#> [1] 0

close(req)
close(rep)
```
