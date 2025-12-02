# Keep Promise

Internal package function.

## Usage

``` r
.keep(x, ctx)
```

## Arguments

- x:

  a 'recvAio' or 'ncurlAio' object.

- ctx:

  the return value of
  [`environment()`](https://rdrr.io/r/base/environment.html).

## Value

NULL.

## Details

If successful, both `x` and `ctx` are preserved and accessible from the
promise callback.
