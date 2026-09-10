# Sleep Utility

Sleep function. May block for longer than requested, with the actual
wait time determined by the capabilities of the underlying system.

## Usage

``` r
msleep(time)
```

## Arguments

- time:

  integer number of milliseconds to block the caller.

## Value

Invisible NULL.

## Details

Non-integer values for `time` are coerced to integer. Negative, logical
and other non-numeric values are ignored, causing the function to return
immediately.

Note that unlike [`Sys.sleep()`](https://rdrr.io/r/base/Sys.sleep.html),
this function is not user-interruptible by sending SIGINT e.g. with
ctrl + c.

## Examples

``` r
time <- mclock(); msleep(100); mclock() - time
#> [1] 101
```
