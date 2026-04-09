# Dispatcher Info

Read dispatcher statistics directly under lock.

## Usage

``` r
.dispatcher_info(disp)
```

## Arguments

- disp:

  External pointer to dispatcher handle.

## Value

Integer vector of length 5: connections, cumulative, awaiting,
executing, completed.
