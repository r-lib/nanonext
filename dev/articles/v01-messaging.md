# nanonext - Messaging and Async I/O

### 1. Cross-language Exchange

`nanonext` provides a fast, reliable data interface between different
programming languages where NNG has an implementation, including C, C++,
Java, Python, Go, and Rust.

This messaging interface is lightweight, robust, and has limited points
of failure. It enables:

- Communication between processes in the same or different languages
- Distributed computing across networks or on the same machine
- Real-time data pipelines where computation times exceed data frequency
- Modular software design following Unix philosophy

This example demonstrates numerical data exchange between R and Python
(NumPy).

Create socket in Python using the NNG binding ‘pynng’:

``` python
import numpy as np
import pynng
socket = pynng.Pair0(listen="ipc:///tmp/nanonext.socket")
```

Create nano object in R using `nanonext`, then send a vector of
‘doubles’, specifying mode as ‘raw’:

``` r
library(nanonext)
n <- nano("pair", dial = "ipc:///tmp/nanonext.socket")
n$send(c(1.1, 2.2, 3.3, 4.4, 5.5), mode = "raw")
#> [1] 0
```

Receive in Python as a NumPy array of ‘floats’, and send back to R:

``` python
raw = socket.recv()
array = np.frombuffer(raw)
print(array)
#> [1.1 2.2 3.3 4.4 5.5]

msg = array.tobytes()
socket.send(msg)

socket.close()
```

Receive in R, specifying the receive mode as ‘double’:

``` r
n$recv(mode = "double")
#> [1] 1.1 2.2 3.3 4.4 5.5

n$close()
```

### 2. Async and Concurrency

`nanonext` implements true async send and receive, leveraging NNG as a
massively-scalable concurrency framework.

``` r
s1 <- socket("pair", listen = "inproc://nano")
s2 <- socket("pair", dial = "inproc://nano")
```

[`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md) and
[`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
return immediately with an ‘Aio’ object that performs operations
asynchronously. Aio objects return an unresolved value while the
operation is ongoing, then automatically resolve once complete.

``` r
# async receive requested, but no messages waiting yet
msg <- recv_aio(s2)
msg
#> < recvAio | $data >
msg$data
#> 'unresolved' logi NA
```

For ‘sendAio’ objects, the result is stored at `$result`. For ‘recvAio’
objects, the message is stored at `$data`.

``` r
res <- send_aio(s1, data.frame(a = 1, b = 2))
res
#> < sendAio | $result >
res$result
#> [1] 0
```

> 0 indicates successful send - the message has been accepted by the
> socket for sending but may still be buffered within the system.

``` r
# once a message is sent, the recvAio resolves automatically
msg$data
#>   a b
#> 1 1 2
```

Use
[`unresolved()`](https://nanonext.r-lib.org/dev/reference/unresolved.md)
in control flow to perform actions before or after Aio resolution
without blocking.

``` r
msg <- recv_aio(s2)

# unresolved() checks resolution status
while (unresolved(msg)) {
  # perform other tasks while waiting
  send_aio(s1, "resolved")
  cat("unresolved")
}
#> unresolved

# access resolved value
msg$data
#> [1] "resolved"
```

Explicitly wait for completion with
[`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md)
(blocking).

``` r
# wait for completion and return resolved Aio
call_aio(msg)

# access resolved value (waiting if required):
call_aio(msg)$data
#> [1] "resolved"

# or directly:
collect_aio(msg)
#> [1] "resolved"

# or user-interruptible:
msg[]
#> [1] "resolved"

close(s1)
close(s2)
```

### 3. Synchronisation Primitives

`nanonext` implements cross-platform synchronisation primitives from the
NNG library, enabling synchronisation between NNG events and the main R
execution thread.

Condition variables can signal events such as asynchronous receive
completions and pipe events (connections established or dropped). Each
condition variable has a value (counter) and flag (boolean). Signals
increment the value; successful
[`wait()`](https://nanonext.r-lib.org/dev/reference/cv.md) or
[`until()`](https://nanonext.r-lib.org/dev/reference/cv.md) calls
decrement it. A non-zero value allows waiting threads to continue.

This approach is more efficient than polling - consuming no resources
while waiting and synchronising with zero latency.

**Example 1: Wait for connection**

``` r
sock <- socket("pair", listen = "inproc://nanopipe")

cv <- cv()
cv_value(cv)
#> [1] 0

pipe_notify(sock, cv = cv, add = TRUE, remove = TRUE)

# wait(cv) would block until connection established

# for illustration:
sock2 <- socket("pair", dial = "inproc://nanopipe")

cv_value(cv) # incremented when pipe created
#> [1] 1

wait(cv) # does not block as cv value is non-zero

cv_value(cv) # decremented by wait()
#> [1] 0

close(sock2)

cv_value(cv) # incremented when pipe destroyed
#> [1] 1

close(sock)
```

**Example 2: Wait for message or disconnection**

``` r
sock <- socket("pair", listen = "inproc://nanosignal")
sock2 <- socket("pair", dial = "inproc://nanosignal")

cv <- cv()
cv_value(cv)
#> [1] 0

pipe_notify(sock, cv = cv, add = FALSE, remove = TRUE, flag = TRUE)

send(sock2, "this message will wake waiting thread")
#> [1] 0

r <- recv_aio(sock, cv = cv)

# wakes when async receive completes
wait(cv) || stop("peer disconnected")
#> [1] TRUE

r$data
#> [1] "this message will wake waiting thread"

close(sock)
close(sock2)
```

When `flag = TRUE` is set for pipe notifications,
[`wait()`](https://nanonext.r-lib.org/dev/reference/cv.md) returns FALSE
for pipe events (rather than TRUE for message events). This
distinguishes between disconnections and successful receives, something
not possible using
[`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md)
alone.

This mechanism enables waiting simultaneously on multiple events while
distinguishing between them.
[`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
can signal up to two condition variables per event for additional
flexibility in concurrent applications.
