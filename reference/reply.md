# Reply over Context (RPC Server for Req/Rep Protocol)

Implements an executor/server for the rep node of the req/rep protocol.
Awaits data, applies an arbitrary specified function, and returns the
result to the caller/client.

## Usage

``` r
reply(
  context,
  execute,
  recv_mode = c("serial", "character", "complex", "double", "integer", "logical",
    "numeric", "raw", "string"),
  send_mode = c("serial", "raw"),
  timeout = NULL,
  ...
)
```

## Arguments

- context:

  a Context.

- execute:

  a function which takes the received (converted) data as its first
  argument. Can be an anonymous function of the form
  `function(x) do(x)`. Additional arguments can also be passed in
  through `...`.

- recv_mode:

  \[default 'serial'\] character value or integer equivalent - one of
  `"serial"` (1L), `"character"` (2L), `"complex"` (3L), `"double"`
  (4L), `"integer"` (5L), `"logical"` (6L), `"numeric"` (7L), `"raw"`
  (8L), or `"string"` (9L). The default `"serial"` means a serialised R
  object; for the other modes, received bytes are converted into the
  respective mode. `"string"` is a faster option for length one
  character vectors.

- send_mode:

  \[default 'serial'\] character value or integer equivalent - either
  `"serial"` (1L) to send serialised R objects, or `"raw"` (2L) to send
  atomic vectors of any type as a raw byte vector.

- timeout:

  \[default NULL\] integer value in milliseconds or NULL, which applies
  a socket-specific default, usually the same as no timeout. Note that
  this applies to receiving the request. The total elapsed time would
  also include performing 'execute' on the received data. The timeout
  then also applies to sending the result (in the event that the
  requestor has become unavailable since sending the request).

- ...:

  additional arguments passed to the function specified by 'execute'.

## Value

Integer exit code (zero on success).

## Details

Receive will block while awaiting a message to arrive and is usually the
desired behaviour. Set a timeout to allow the function to return if no
data is forthcoming.

In the event of an error in either processing the messages or in
evaluation of the function with respect to the data, a nul byte `00` (or
serialized nul byte) will be sent in reply to the client to signal an
error. This is to be distinguishable from a possible return value.
[`is_nul_byte()`](https://nanonext.r-lib.org/reference/is_error_value.md)
can be used to test for a nul byte.

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

## Examples

``` r
req <- socket("req", listen = "inproc://req-example")
rep <- socket("rep", dial = "inproc://req-example")

ctxq <- context(req)
ctxp <- context(rep)

send(ctxq, 2022, block = 100)
#> [1] 0
reply(ctxp, execute = function(x) x + 1, send_mode = "raw", timeout = 100)
#> [1] 0
recv(ctxq, mode = "double", block = 100)
#> [1] 2023

send(ctxq, 100, mode = "raw", block = 100)
#> [1] 0
reply(ctxp, recv_mode = "double", execute = log, base = 10, timeout = 100)
#> [1] 0
recv(ctxq, block = 100)
#> [1] 2

close(req)
close(rep)
```
