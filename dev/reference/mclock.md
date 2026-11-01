# Clock Utility

Provides the number of elapsed milliseconds since an arbitrary reference
time in the past. The reference time will be the same for a given
session, but may differ between sessions.

## Usage

``` r
mclock()
```

## Value

A double.

## Details

A convenience function for building concurrent applications. The
resolution of the clock depends on the underlying system timing
facilities and may not be particularly fine-grained. This utility should
however be faster than using
[`Sys.time()`](https://rdrr.io/r/base/Sys.time.html).

## Examples

``` r
time <- mclock(); msleep(100); mclock() - time
#> [1] 100
```
