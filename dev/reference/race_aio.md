# Race Aio

Returns the index of the first resolved Aio in a list, waiting if
necessary.

## Usage

``` r
race_aio(x, cv)
```

## Arguments

- x:

  A list of Aio objects.

- cv:

  A condition variable. This must be the same cv supplied to
  [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
  or [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  when creating the Aio objects in `x`.

## Value

Integer index of the first resolved Aio, or 0L if none are resolved, the
list is empty, or the cv was terminated.
