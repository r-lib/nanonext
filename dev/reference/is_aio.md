# Validators

Validator functions for object types created by nanonext.

## Usage

``` r
is_aio(x)

is_nano(x)

is_ncurl_session(x)
```

## Arguments

- x:

  an object.

## Value

Logical value TRUE or FALSE.

## Details

Is the object an Aio (inheriting from class 'sendAio' or 'recvAio').

Is the object an object inheriting from class 'nano' i.e. a nanoSocket,
nanoContext, nanoStream, nanoListener, nanoDialer, nanoMonitor or nano
Object.

Is the object an ncurlSession (object of class 'ncurlSession').

Is the object a Condition Variable (object of class
'conditionVariable').

## Examples

``` r
nc <- call_aio(ncurl_aio("https://postman-echo.com/get", timeout = 1000L))
is_aio(nc)
#> [1] TRUE

s <- socket()
is_nano(s)
#> [1] TRUE
n <- nano()
is_nano(n)
#> [1] TRUE
close(s)
n$close()

s <- ncurl_session("https://postman-echo.com/get", timeout = 1000L)
is_ncurl_session(s)
#> [1] TRUE
if (is_ncurl_session(s)) close(s)
```
