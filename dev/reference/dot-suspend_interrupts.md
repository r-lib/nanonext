# Suspend Interrupts

Internal package function.

## Usage

``` r
.suspend_interrupts(suspend = TRUE)
```

## Arguments

- suspend:

  (logical) if `TRUE`, suspends interrupts; if `FALSE`, clears any
  pending interrupt and then un-suspends interrupts.

## Value

NULL.

## Details

Whilst interrupts are suspended, a pending interrupt is held and never
raised, as `R_CheckUserInterrupt()` becomes a no-op. Un-suspending first
clears any pending interrupt (still whilst suspended) so a stale
interrupt cannot fire subsequently.
