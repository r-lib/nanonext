# Technical Utility: Open Context

Open a new Context to be used with a Socket. This function is a
performance variant of
[`context()`](https://nanonext.r-lib.org/dev/reference/context.md),
designed to wrap a socket in a function argument when calling
[`request()`](https://nanonext.r-lib.org/dev/reference/request.md) or
[`reply()`](https://nanonext.r-lib.org/dev/reference/reply.md).

## Usage

``` r
.context(socket)
```

## Arguments

- socket:

  a Socket.

## Value

An external pointer.

## Details

External pointers created by this function are unclassed, hence methods
for contexts such as
[`close()`](https://nanonext.r-lib.org/dev/reference/close.md) will not
work (use [`reap()`](https://nanonext.r-lib.org/dev/reference/reap.md)
instead). Otherwise they function identically to a Context when passed
to all messaging functions.
