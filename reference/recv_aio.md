# Receive Async

Receive data asynchronously over a connection (Socket, Context or
Stream).

## Usage

``` r
recv_aio(
  con,
  mode = c("serial", "character", "complex", "double", "integer", "logical", "numeric",
    "raw", "string"),
  timeout = NULL,
  cv = NULL,
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

- timeout:

  \[default NULL\] integer value in milliseconds or NULL, which applies
  a socket-specific default, usually the same as no timeout.

- cv:

  (optional) a 'conditionVariable' to signal when the async receive is
  complete.

- n:

  \[default 65536L\] applicable to Streams only, the maximum number of
  bytes to receive. Can be an over-estimate, but note that a buffer of
  this size is reserved.

## Value

A 'recvAio' (object of class 'recvAio') (invisibly).

## Details

Async receive is always non-blocking and returns a 'recvAio'
immediately.

For a 'recvAio', the received message is available at `$data`. An
'unresolved' logical NA is returned if the async operation is yet to
complete.

To wait for the async operation to complete and retrieve the received
message, use
[`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md) on the
returned 'recvAio' object.

Alternatively, to stop the async operation, use
[`stop_aio()`](https://nanonext.r-lib.org/reference/stop_aio.md).

In case of an error, an integer 'errorValue' is returned (to be
distiguishable from an integer message value). This can be checked using
[`is_error_value()`](https://nanonext.r-lib.org/reference/is_error_value.md).

If an error occurred in unserialization or conversion of the message
data to the specified mode, a raw vector will be returned instead to
allow recovery (accompanied by a warning).

## Signalling

By supplying a 'conditionVariable', when the receive is complete, the
'conditionVariable' is signalled by incrementing its value by 1. This
happens asynchronously and independently of the R execution thread.

## See also

[`recv()`](https://nanonext.r-lib.org/reference/recv.md) for synchronous
receive.

## Examples

``` r
s1 <- socket("pair", listen = "inproc://nanonext")
s2 <- socket("pair", dial = "inproc://nanonext")

res <- send_aio(s1, data.frame(a = 1, b = 2), timeout = 100)
msg <- recv_aio(s2, timeout = 100)
msg
#> < recvAio | $data >
msg$data
#>   a b
#> 1 1 2

res <- send_aio(s1, c(1.1, 2.2, 3.3), mode = "raw", timeout = 100)
msg <- recv_aio(s2, mode = "double", timeout = 100)
msg
#> < recvAio | $data >
msg$data
#> [1] 1.1 2.2 3.3

res <- send_aio(s1, "example message", mode = "raw", timeout = 100)
msg <- recv_aio(s2, mode = "character", timeout = 100)
call_aio(msg)
msg$data
#> [1] "example message"

close(s1)
close(s2)

# Signalling a condition variable

s1 <- socket("pair", listen = "inproc://cv-example")
cv <- cv()
msg <- recv_aio(s1, timeout = 100, cv = cv)
until(cv, 10L)
msg$data
#> 'unresolved' logi NA
close(s1)

# in another process in parallel
s2 <- socket("pair", dial = "inproc://cv-example")
res <- send_aio(s2, c(1.1, 2.2, 3.3), mode = "raw", timeout = 100)
close(s2)
```
