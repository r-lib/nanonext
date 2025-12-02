# Open Context

Open a new Context to be used with a Socket. The purpose of a Context is
to permit applications to share a single socket, with its underlying
dialers and listeners, while still benefiting from separate state
tracking.

## Usage

``` r
context(socket)
```

## Arguments

- socket:

  a Socket.

## Value

A Context (object of class 'nanoContext' and 'nano').

## Details

Contexts allow the independent and concurrent use of stateful operations
using the same socket. For example, two different contexts created on a
rep socket can each receive requests, and send replies to them, without
any regard to or interference with each other.

Only the following protocols support creation of contexts: req, rep, sub
(in a pub/sub pattern), surveyor, respondent.

To send and receive over a context use
[`send()`](https://nanonext.r-lib.org/reference/send.md) and
[`recv()`](https://nanonext.r-lib.org/reference/recv.md) or their async
counterparts
[`send_aio()`](https://nanonext.r-lib.org/reference/send_aio.md) and
[`recv_aio()`](https://nanonext.r-lib.org/reference/recv_aio.md).

For nano objects, use the `$context_open()` method, which will attach a
new context at `$context`. See
[`nano()`](https://nanonext.r-lib.org/reference/nano.md).

## See also

[`request()`](https://nanonext.r-lib.org/reference/request.md) and
[`reply()`](https://nanonext.r-lib.org/reference/reply.md) for use with
contexts.

## Examples

``` r
s <- socket("req", listen = "inproc://nanonext")
ctx <- context(s)
ctx
#> < nanoContext >
#>  - id: 1
#>  - socket: 5
#>  - state: opened
#>  - protocol: req
close(ctx)
close(s)

n <- nano("req", listen = "inproc://nanonext")
n$context_open()
n$context
#> < nanoContext >
#>  - id: 2
#>  - socket: 6
#>  - state: opened
#>  - protocol: req
n$context_open()
n$context
#> < nanoContext >
#>  - id: 3
#>  - socket: 6
#>  - state: opened
#>  - protocol: req
n$context_close()
#> [1] 0
n$close()
```
