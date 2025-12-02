# Reap

An alternative to `close` for Sockets, Contexts, Listeners, and Dialers
avoiding S3 method dispatch.

## Usage

``` r
reap(con)
```

## Arguments

- con:

  a Socket, Context, Listener or Dialer.

## Value

An integer exit code (zero on success).

## Details

May be used on unclassed external pointers e.g. those created by
[`.context()`](https://nanonext.r-lib.org/reference/dot-context.md).
Returns silently and does not warn or error, nor does it update the
state of object attributes.

## See also

[`close()`](https://nanonext.r-lib.org/reference/close.md)

## Examples

``` r
s <- socket("req")
listen(s)
dial(s)
ctx <- .context(s)

reap(ctx)
#> [1] 0
reap(s[["dialer"]][[1]])
#> [1] 0
reap(s[["listener"]][[1]])
#> [1] 0
reap(s)
#> [1] 0
reap(s)
#> 'errorValue' int 7 | Object closed
```
