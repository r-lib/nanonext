# Stop Asynchronous Aio Operation

Stop an asynchronous Aio operation, or a list of Aio operations.

## Usage

``` r
stop_aio(x)
```

## Arguments

- x:

  an Aio or list of Aios (objects of class 'sendAio', 'recvAio' or
  'ncurlAio').

## Value

Invisible NULL.

## Details

Stops the asynchronous I/O operation associated with Aio `x` by
aborting, and then waits for it to complete or to be completely aborted,
and for the callback associated with the Aio to have completed
executing. If successful, the Aio will resolve to an 'errorValue' 20
(Operation canceled).

Note this function operates silently and does not error even if `x` is
not an active Aio, always returning invisible NULL.
