# Internal Package Function

Only present for cleaning up after running examples and tests. Do not
attempt to run the examples.

## Usage

``` r
zzz()
```

## Examples

``` r
if (Sys.info()[["sysname"]] == "Linux") {
  rm(list = ls())
  invisible(gc())
  .Call(nanonext:::rnng_fini_priors)
  Sys.sleep(1L)
  .Call(nanonext:::rnng_fini)
}
#> NULL
```
