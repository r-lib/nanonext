# Query if an Aio is Unresolved

Query whether an Aio, Aio value or list of Aios remains unresolved.
Unlike [`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md),
this function does not wait for completion.

## Usage

``` r
unresolved(x)
```

## Arguments

- x:

  an Aio or list of Aios (objects of class 'sendAio', 'recvAio' or
  'ncurlAio'), or Aio value stored at `$result` or `$data` etc.

## Value

Logical `TRUE` if `x` is an unresolved Aio or Aio value or the list of
Aios contains at least one unresolved Aio, or `FALSE` otherwise.

## Details

Suitable for use in control flow statements such as `while` or `if`.

Note: querying resolution may cause a previously unresolved Aio to
resolve.

## Examples

``` r
s1 <- socket("pair", listen = "inproc://nanonext")
aio <- send_aio(s1, "test", timeout = 100)

while (unresolved(aio)) {
  # do stuff before checking resolution again
  cat("unresolved\n")
  msleep(100)
}
#> unresolved
#> unresolved

unresolved(aio)
#> [1] FALSE

close(s1)
```
