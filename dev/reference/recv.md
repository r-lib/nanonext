# Receive

Receive data over a connection (Socket, Context or Stream).

## Usage

``` r
recv(
  con,
  mode = c("serial", "character", "complex", "double", "integer", "logical", "numeric",
    "raw", "string"),
  block = NULL,
  n = 65536L
)
```

## Arguments

- con:

  a Socket, Context or Stream.

- mode:

  \[default 'serial'\] character value or integer equivalent - one of
  `"serial"` (1L), `"character"` (2L), `"complex"` (3L), `"double"`
  (4L), `"integer"` (5L), `"logical"` (6L), `"numeric"` (7L), `"raw"`
  (8L), or `"string"` (9L). The default `"serial"` means a serialised R
  object; for the other modes, received bytes are converted into the
  respective mode. `"string"` is a faster option for length one
  character vectors. For Streams, `"serial"` will default to
  `"character"`.

- block:

  \[default NULL\] which applies the connection default (see section
  'Blocking' below). Specify logical `TRUE` to block until successful or
  `FALSE` to return immediately even if unsuccessful (e.g. if no
  connection is available), or else an integer value specifying the
  maximum time to block in milliseconds, after which the operation will
  time out.

- n:

  \[default 65536L\] applicable to Streams only, the maximum number of
  bytes to receive. Can be an over-estimate, but note that a buffer of
  this size is reserved.

## Value

The received data in the `mode` specified.

## Errors

In case of an error, an integer 'errorValue' is returned (to be
distiguishable from an integer message value). This can be verified
using
[`is_error_value()`](https://nanonext.r-lib.org/dev/reference/is_error_value.md).

If an error occurred in unserialization or conversion of the message
data to the specified mode, a raw vector will be returned instead to
allow recovery (accompanied by a warning).

## Blocking

For Sockets and Contexts: the default behaviour is non-blocking with
`block = FALSE`. This will return immediately with an error if no
messages are available.

For Streams: the default behaviour is blocking with `block = TRUE`. This
will wait until a message is received. Set a timeout to ensure that the
function returns under all scenarios. As the underlying implementation
uses an asynchronous receive with a wait, it is recommended to set a
small positive value for `block` rather than `FALSE`.

## See also

[`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md) for
asynchronous receive.

## Examples

``` r
s1 <- socket("pair", listen = "inproc://nanonext")
s2 <- socket("pair", dial = "inproc://nanonext")

send(s1, data.frame(a = 1, b = 2))
#> [1] 0
res <- recv(s2)
res
#>   a b
#> 1 1 2
send(s1, data.frame(a = 1, b = 2))
#> [1] 0
recv(s2)
#>   a b
#> 1 1 2

send(s1, c(1.1, 2.2, 3.3), mode = "raw")
#> [1] 0
res <- recv(s2, mode = "double", block = 100)
res
#> [1] 1.1 2.2 3.3
send(s1, "example message", mode = "raw")
#> [1] 0
recv(s2, mode = "character")
#> [1] "example message"

close(s1)
close(s2)

req <- socket("req", listen = "inproc://nanonext")
rep <- socket("rep", dial = "inproc://nanonext")

ctxq <- context(req)
ctxp <- context(rep)
send(ctxq, data.frame(a = 1, b = 2), block = 100)
#> [1] 0
recv(ctxp, block = 100)
#>   a b
#> 1 1 2

send(ctxq, c(1.1, 2.2, 3.3), mode = "raw", block = 100)
#> [1] 0
recv(ctxp, mode = "double", block = 100)
#> [1] 1.1 2.2 3.3

close(req)
close(rep)
```
