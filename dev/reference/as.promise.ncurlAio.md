# Make ncurlAio Promise

Creates a 'promise' from an 'ncurlAio' object.

## Usage

``` r
# S3 method for class 'ncurlAio'
as.promise(x)
```

## Arguments

- x:

  an object of class 'ncurlAio'.

## Value

A 'promise' object.

## Details

This function is an S3 method for the generic `as.promise` for class
'ncurlAio'.

Requires the promises package.

Allows an 'ncurlAio' to be used with functions such as
[`promises::then()`](https://rstudio.github.io/promises/reference/then.html),
which schedules a function to run upon resolution of the Aio.

The promise is resolved with a list of 'status', 'headers' and 'data' or
rejected with the error translation if an NNG error is returned e.g. for
an invalid address.
