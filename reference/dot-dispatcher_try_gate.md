# Dispatcher Try Gate

Snapshot read of dispatcher capacity. Returns immediately, never blocks.
The non-blocking counterpart to
[`.dispatcher_gate()`](https://nanonext.r-lib.org/reference/dot-dispatcher_gate.md).

## Usage

``` r
.dispatcher_try_gate(disp)
```

## Arguments

- disp:

  External pointer to dispatcher handle.

## Value

Logical `TRUE` if submission would not block (queued bytes below the
memory budget set on
[`.dispatcher_start()`](https://nanonext.r-lib.org/reference/dot-dispatcher_start.md),
or unbounded), `FALSE` if at or over the budget. `NULL` if `disp` is
invalid.
