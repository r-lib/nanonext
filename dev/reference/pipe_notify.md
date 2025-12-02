# Pipe Notify

Signals a 'conditionVariable' whenever pipes (individual connections)
are added or removed at a socket.

## Usage

``` r
pipe_notify(socket, cv, add = FALSE, remove = FALSE, flag = FALSE)
```

## Arguments

- socket:

  a Socket.

- cv:

  a 'conditionVariable' to signal, or NULL to cancel a previously set
  signal.

- add:

  \[default FALSE\] logical value whether to signal (or cancel signal)
  when a pipe is added.

- remove:

  \[default FALSE\] logical value whether to signal (or cancel signal)
  when a pipe is removed.

- flag:

  \[default FALSE\] logical value whether to also set a flag in the
  'conditionVariable'. This can help distinguish between different types
  of signal, and causes any subsequent
  [`wait()`](https://nanonext.r-lib.org/dev/reference/cv.md) to return
  FALSE instead of TRUE. If a signal from the tools package, e.g.
  [`tools::SIGINT`](https://rdrr.io/r/tools/pskill.html), or an
  equivalent integer value is supplied, this sets a flag and
  additionally raises this signal upon the flag being set. For
  [`tools::SIGTERM`](https://rdrr.io/r/tools/pskill.html), the signal is
  raised with a 200ms grace period to allow a process to exit normally.

## Value

Invisibly, zero on success (will otherwise error).

## Details

For add: this event occurs after the pipe is fully added to the socket.
Prior to this time, it is not possible to communicate over the pipe with
the socket.

For remove: this event occurs after the pipe has been removed from the
socket. The underlying transport may be closed at this point, and it is
not possible to communicate using this pipe.

## Examples

``` r
s <- socket(listen = "inproc://nanopipe")
cv <- cv()

pipe_notify(s, cv, add = TRUE, remove = TRUE, flag = TRUE)
cv_value(cv)
#> [1] 0

s1 <- socket(dial = "inproc://nanopipe")
cv_value(cv)
#> [1] 1
reap(s1)
#> [1] 0
cv_value(cv)
#> [1] 2

pipe_notify(s, NULL, add = TRUE, remove = TRUE)
s1 <- socket(dial = "inproc://nanopipe")
cv_value(cv)
#> [1] 2
reap(s1)
#> [1] 0

(wait(cv))
#> [1] FALSE

close(s)
```
