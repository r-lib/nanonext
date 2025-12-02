# Request over Context (RPC Client for Req/Rep Protocol)

Implements a caller/client for the req node of the req/rep protocol.
Sends data to the rep node (executor/server) and returns an Aio, which
can be called for the value when required.

## Usage

``` r
request(
  context,
  data,
  send_mode = c("serial", "raw"),
  recv_mode = c("serial", "character", "complex", "double", "integer", "logical",
    "numeric", "raw", "string"),
  timeout = NULL,
  cv = NULL,
  id = NULL
)
```

## Arguments

- context:

  a Context.

- data:

  an object (if `send_mode = "raw"`, a vector).

- send_mode:

  \[default 'serial'\] character value or integer equivalent - either
  `"serial"` (1L) to send serialised R objects, or `"raw"` (2L) to send
  atomic vectors of any type as a raw byte vector.

- recv_mode:

  \[default 'serial'\] character value or integer equivalent - one of
  `"serial"` (1L), `"character"` (2L), `"complex"` (3L), `"double"`
  (4L), `"integer"` (5L), `"logical"` (6L), `"numeric"` (7L), `"raw"`
  (8L), or `"string"` (9L). The default `"serial"` means a serialised R
  object; for the other modes, received bytes are converted into the
  respective mode. `"string"` is a faster option for length one
  character vectors.

- timeout:

  \[default NULL\] integer value in milliseconds or NULL, which applies
  a socket-specific default, usually the same as no timeout.

- cv:

  (optional) a 'conditionVariable' to signal when the async receive is
  complete, or NULL.

- id:

  (optional) set to `TRUE` (or any non-NULL value) to send a message via
  the context upon timeout (asynchronously) consisting of an integer
  zero, followed by the integer `context` ID.

## Value

A 'recvAio' (object of class 'mirai' and 'recvAio') (invisibly).

## Details

Sending the request and receiving the result are both performed async,
hence the function will return immediately with a 'recvAio' object.
Access the return value at `$data`.

This is designed so that the process on the server can run concurrently
without blocking the client.

Optionally use
[`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md) on
the 'recvAio' to call (and wait for) the result.

If an error occured in the server process, a nul byte `00` will be
received. This allows an error to be easily distinguished from a NULL
return value.
[`is_nul_byte()`](https://nanonext.r-lib.org/dev/reference/is_error_value.md)
can be used to test for a nul byte.

It is recommended to use a new context for each request to ensure
consistent state tracking. The integer context ID is appended as the
attribute `id` to the returned 'recvAio'.

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

## Signalling

By supplying a 'conditionVariable', when the receive is complete, the
'conditionVariable' is signalled by incrementing its value by 1. This
happens asynchronously and independently of the R execution thread.

## Examples

``` r
if (FALSE) { # \dontrun{

# works if req and rep are running in parallel in different processes

req <- socket("req", listen = "tcp://127.0.0.1:6546")
rep <- socket("rep", dial = "tcp://127.0.0.1:6546")

reply(.context(rep), execute = function(x) x + 1, timeout = 50)
aio <- request(.context(req), data = 2022)
aio$data

close(req)
close(rep)

# Signalling a condition variable

req <- socket("req", listen = "tcp://127.0.0.1:6546")
ctxq <- context(req)
cv <- cv()
aio <- request(ctxq, data = 2022, cv = cv)
until(cv, 10L)
close(req)

# The following should be run in another process
rep <- socket("rep", dial = "tcp://127.0.0.1:6546")
ctxp <- context(rep)
reply(ctxp, execute = function(x) x + 1)
close(rep)

} # }
```
