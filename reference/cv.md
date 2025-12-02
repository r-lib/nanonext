# Condition Variables

`cv` creates a new condition variable (protected by a mutex internal to
the object).

`wait` waits on a condition being signalled by completion of an
asynchronous receive or pipe event.  
`wait_` is a variant that allows user interrupts, suitable for
interactive use.

`until` waits until a future time on a condition being signalled by
completion of an asynchronous receive or pipe event.  
`until_` is a variant that allows user interrupts, suitable for
interactive use.

`cv_value` inspects the internal value of a condition variable.

`cv_reset` resets the internal value and flag of a condition variable.

`cv_signal` signals a condition variable.

## Usage

``` r
cv()

wait(cv)

wait_(cv)

until(cv, msec)

until_(cv, msec)

cv_value(cv)

cv_reset(cv)

cv_signal(cv)
```

## Arguments

- cv:

  a 'conditionVariable' object.

- msec:

  maximum time in milliseconds to wait for the condition variable to be
  signalled.

## Value

For **cv**: a 'conditionVariable' object.

For **wait**: (invisibly) logical TRUE, or else FALSE if a flag has been
set.

For **until**: (invisibly) logical TRUE if signalled, or else FALSE if
the timeout was reached.

For **cv_value**: integer value of the condition variable.

For **cv_reset** and **cv_signal**: zero (invisibly).

## Details

Pass the 'conditionVariable' to the asynchronous receive functions
[`recv_aio()`](https://nanonext.r-lib.org/reference/recv_aio.md) or
[`request()`](https://nanonext.r-lib.org/reference/request.md).
Alternatively, to be notified of a pipe event, pass it to
[`pipe_notify()`](https://nanonext.r-lib.org/reference/pipe_notify.md).

Completion of the receive or pipe event, which happens asynchronously
and independently of the main R thread, will signal the condition
variable by incrementing it by 1.

This will cause the R execution thread waiting on the condition variable
using `wait()` or `until()` to wake and continue.

For argument `msec`, non-integer values will be coerced to integer.
Non-numeric input will be ignored and return immediately.

## Condition

The condition internal to this 'conditionVariable' maintains a state
(value). Each signal increments the value by 1. Each time `wait()` or
`until()` returns (apart from due to timeout), the value is decremented
by 1.

The internal condition may be inspected at any time using `cv_value()`
and reset using `cv_reset()`. This affords a high degree of flexibility
in designing complex concurrent applications.

## Flag

The condition variable also contains a flag that certain signalling
functions such as
[`pipe_notify()`](https://nanonext.r-lib.org/reference/pipe_notify.md)
can set. When this flag has been set, all subsequent `wait()` calls will
return logical FALSE instead of TRUE.

Note that the flag is not automatically reset, but may be reset manually
using `cv_reset()`.

## Examples

``` r
cv <- cv()

if (FALSE) { # \dontrun{
wait(cv) # would block until the cv is signalled
wait_(cv) # would block until the cv is signalled or interrupted
} # }

until(cv, 10L)
until_(cv, 10L)

cv_value(cv)
#> [1] 0

cv_reset(cv)

cv_value(cv)
#> [1] 0
cv_signal(cv)
cv_value(cv)
#> [1] 1
```
