# Dispatcher Gate

Block while queued bytes at dispatcher exceed the memory budget set on
[`.dispatcher_start()`](https://nanonext.r-lib.org/reference/dot-dispatcher_start.md).

## Usage

``` r
.dispatcher_gate(disp)
```

## Arguments

- disp:

  External pointer to dispatcher handle.

## Value

Logical TRUE.
