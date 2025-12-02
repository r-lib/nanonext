# Call the Value of an Asynchronous Aio Operation

`call_aio` retrieves the value of an asynchronous Aio operation, waiting
for the operation to complete if still in progress. For a list of Aios,
waits for all asynchronous operations to complete before returning.

`call_aio_` is a variant that allows user interrupts, suitable for
interactive use.

## Usage

``` r
call_aio(x)

call_aio_(x)
```

## Arguments

- x:

  an Aio or list of Aios (objects of class 'sendAio', 'recvAio' or
  'ncurlAio').

## Value

The passed object (invisibly).

## Details

For a 'recvAio', the received value may be retrieved at `$data`.

For a 'sendAio', the send result may be retrieved at `$result`. This
will be zero on success, or else an integer error code.

To access the values directly, use for example on a 'recvAio' `x`:
`call_aio(x)$data`.

For a 'recvAio', if an error occurred in unserialization or conversion
of the message data to the specified mode, a raw vector will be returned
instead to allow recovery (accompanied by a warning).

Note: this function operates silently and does not error even if `x` is
not an active Aio or list of Aios, always returning invisibly the passed
object.

## Alternatively

Aio values may be accessed directly at `$result` for a 'sendAio', and
`$data` for a 'recvAio'. If the Aio operation is yet to complete, an
'unresolved' logical NA will be returned. Once complete, the resolved
value will be returned instead.

[`unresolved()`](https://nanonext.r-lib.org/dev/reference/unresolved.md)
may also be used, which returns `TRUE` only if an Aio or Aio value has
yet to resolve and `FALSE` otherwise. This is suitable for use in
control flow statements such as `while` or `if`.

## Examples

``` r
s1 <- socket("pair", listen = "inproc://nanonext")
s2 <- socket("pair", dial = "inproc://nanonext")

res <- send_aio(s1, data.frame(a = 1, b = 2), timeout = 100)
res
#> < sendAio | $result >
call_aio(res)
res$result
#> [1] 0

msg <- recv_aio(s2, timeout = 100)
msg
#> < recvAio | $data >
call_aio_(msg)$data
#>   a b
#> 1 1 2

close(s1)
close(s2)
```
