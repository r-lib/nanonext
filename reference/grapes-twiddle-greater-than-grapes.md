# Signal Forwarder

Forwards signals from one 'conditionVariable' to another.

## Usage

``` r
cv %~>% cv2
```

## Arguments

- cv:

  a 'conditionVariable' object, from which to forward the signal.

- cv2:

  a 'conditionVariable' object, to which the signal is forwarded.

## Value

Invisibly, `cv2`.

## Details

The condition value of `cv` is initially reset to zero when this
operator returns. Only one forwarder can be active on a `cv` at any
given time, and assigning a new forwarding target cancels any currently
existing forwarding.

Changes in the condition value of `cv` are forwarded to `cv2`, but only
on each occassion `cv` is signalled. This means that waiting on `cv`
will cause a temporary divergence between the actual condition value of
`cv` and that recorded at `cv2`, until the next time `cv` is signalled.

## Examples

``` r
cva <- cv(); cvb <- cv(); cv1 <- cv(); cv2 <- cv()

cva %~>% cv1 %~>% cv2
cvb %~>% cv2

cv_signal(cva)
cv_signal(cvb)
cv_value(cv1)
#> [1] 1
cv_value(cv2)
#> [1] 2
```
