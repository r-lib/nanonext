# Start Listener/Dialer

Start a Listener/Dialer.

## Usage

``` r
# S3 method for class 'nanoListener'
start(x, ...)

# S3 method for class 'nanoDialer'
start(x, async = TRUE, ...)
```

## Arguments

- x:

  a Listener or Dialer.

- ...:

  not used.

- async:

  \[default TRUE\] (applicable to Dialers only) logical flag whether the
  connection attempt, including any name resolution, is to be made
  asynchronously. This behaviour is more resilient, but also generally
  makes diagnosing failures somewhat more difficult. If FALSE, failure,
  such as if the connection is refused, will be returned immediately,
  and no further action will be taken.

## Value

Invisibly, an integer exit code (zero on success).
