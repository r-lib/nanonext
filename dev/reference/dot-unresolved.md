# Technical Utility: Query if an Aio is Unresolved

Query whether an Aio or list of Aios remains unresolved. This is an
experimental technical utility version of
[`unresolved()`](https://nanonext.r-lib.org/dev/reference/unresolved.md)
not intended for ordinary use. Provides a method of querying the busy
status of an Aio without altering its state in any way i.e. not
attempting to retrieve the result or message.

## Usage

``` r
.unresolved(x)
```

## Arguments

- x:

  an Aio or list of Aios (objects of class 'sendAio', 'recvAio' or
  'ncurlAio').

## Value

Logical `TRUE` if `x` is an unresolved Aio or else `FALSE`, or if `x` is
a list, the integer number of unresolved Aios in the list.

## Details

`.unresolved()` is not intended to be used for 'recvAio' returned by a
signalling function, in which case
[`unresolved()`](https://nanonext.r-lib.org/dev/reference/unresolved.md)
must be used in all cases.
