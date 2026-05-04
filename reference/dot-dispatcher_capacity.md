# Dispatcher Capacity

Read current and peak queued task payload usage at dispatcher, plus the
configured capacity, in MB (metric, 1 MB = 1,000,000 bytes).

## Usage

``` r
.dispatcher_capacity(disp)
```

## Arguments

- disp:

  External pointer to dispatcher handle.

## Value

Named numeric vector of length 3: **used** (current) and **peak**
(high-watermark) usage, and **capacity** (the `capacity` set on
[`.dispatcher_start()`](https://nanonext.r-lib.org/reference/dot-dispatcher_start.md),
`NA_real_` if unset/unbounded), all in MB. `NA_real_` in each slot if
`disp` is invalid.
