# Send Async

Send data asynchronously over a connection (Socket, Context, Stream or
Pipe).

## Usage

``` r
send_aio(con, data, mode = c("serial", "raw"), timeout = NULL, pipe = 0L)
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

- timeout:

  \[default NULL\] integer value in milliseconds or NULL, which applies
  a socket-specific default, usually the same as no timeout.

- pipe:

  \[default 0L\] only applicable to Sockets using the 'poly' protocol,
  an integer pipe ID if directing the send via a specific pipe.

## Value

A 'sendAio' (object of class 'sendAio') (invisibly).

## Details

Async send is always non-blocking and returns a 'sendAio' immediately.

For a 'sendAio', the send result is available at `$result`. An
'unresolved' logical NA is returned if the async operation is yet to
complete. The resolved value will be zero on success, or else an integer
error code.

To wait for and check the result of the send operation, use
[`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md) on the
returned 'sendAio' object.

Alternatively, to stop the async operation, use
[`stop_aio()`](https://nanonext.r-lib.org/reference/stop_aio.md).

## Send Modes

The default mode `"serial"` sends serialised R objects to ensure perfect
reproducibility within R. When receiving, the corresponding mode
`"serial"` should be used. Custom serialization and unserialization
functions for reference objects may be enabled by the function
[`serial_config()`](https://nanonext.r-lib.org/reference/serial_config.md).

Mode `"raw"` sends atomic vectors of any type as a raw byte vector, and
must be used when interfacing with external applications or raw system
sockets, where R serialization is not in use. When receiving, the mode
corresponding to the vector sent should be used.

## See also

[`send()`](https://nanonext.r-lib.org/reference/send.md) for synchronous
send.

## Examples

``` r
pub <- socket("pub", dial = "inproc://nanonext")

res <- send_aio(pub, data.frame(a = 1, b = 2), timeout = 100)
res
#> < sendAio | $result >
res$result
#> [1] 0

res <- send_aio(pub, "example message", mode = "raw", timeout = 100)
call_aio(res)$result
#> [1] 0

close(pub)
```
