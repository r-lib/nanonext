# Monitor a Socket for Pipe Changes

This function monitors pipe additions and removals from a socket.

## Usage

``` r
monitor(sock, cv)

read_monitor(x)
```

## Arguments

- sock:

  a Socket.

- cv:

  a 'conditionVariable'.

- x:

  a Monitor.

## Value

For `monitor`: a Monitor (object of class 'nanoMonitor').  
For `read_monitor`: an integer vector of pipe IDs (positive if added,
negative if removed), or else NULL if there were no changes since the
previous read.

## Examples

``` r
cv <- cv()
s <- socket("poly")
s1 <- socket("poly")

m <- monitor(s, cv)
m
#> < nanoMonitor >
#>  - socket: 14

listen(s)
dial(s1)

cv_value(cv)
#> [1] 1
read_monitor(m)
#> [1] 1606144753

close(s)
close(s1)

read_monitor(m)
#> [1] -1606144753
```
