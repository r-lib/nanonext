# Stop Request Operation

Stop an asynchronous Aio operation, or a list of Aio operations, created
by [`request()`](https://nanonext.r-lib.org/dev/reference/request.md).
This is an augmented version of
[`stop_aio()`](https://nanonext.r-lib.org/dev/reference/stop_aio.md)
that additionally requests cancellation by sending an integer zero
followed by the context ID over the context, and waiting for the
response.

## Usage

``` r
stop_request(x)
```

## Arguments

- x:

  an Aio or list of Aios (objects of class 'recvAio' returned by
  [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)).

## Value

Invisibly, a logical vector.
