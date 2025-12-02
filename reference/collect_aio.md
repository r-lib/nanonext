# Collect Data of an Aio or List of Aios

`collect_aio` collects the data of an Aio or list of Aios, waiting for
resolution if still in progress.

`collect_aio_` is a variant that allows user interrupts, suitable for
interactive use.

## Usage

``` r
collect_aio(x)

collect_aio_(x)
```

## Arguments

- x:

  an Aio or list of Aios (objects of class 'sendAio', 'recvAio' or
  'ncurlAio').

## Value

Depending on the type of `x` supplied, an object or list of objects (the
same length as `x`, preserving names).

## Details

This function will wait for the asynchronous operation(s) to complete if
still in progress (blocking).

Using `x[]` on an Aio `x` is equivalent to the user-interruptible
`collect_aio_(x)`.

## Examples

``` r
s1 <- socket("pair", listen = "inproc://nanonext")
s2 <- socket("pair", dial = "inproc://nanonext")

res <- send_aio(s1, data.frame(a = 1, b = 2), timeout = 100)
collect_aio(res)
#> [1] 0

msg <- recv_aio(s2, timeout = 100)
collect_aio_(msg)
#>   a b
#> 1 1 2

msg[]
#>   a b
#> 1 1 2

close(s1)
close(s2)
```
