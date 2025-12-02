# Make recvAio Promise

Creates a 'promise' from an 'recvAio' object.

## Usage

``` r
# S3 method for class 'recvAio'
as.promise(x)
```

## Arguments

- x:

  an object of class 'recvAio'.

## Value

A 'promise' object.

## Details

This function is an S3 method for the generic `as.promise` for class
'recvAio'.

Requires the promises package.

Allows a 'recvAio' to be used with the promise pipe `%...>%`, which
schedules a function to run upon resolution of the Aio.
