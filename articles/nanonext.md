# nanonext - NNG Lightweight Messaging Library

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

The following example demonstrates numerical data exchange between R and
Python (NumPy).

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

[`send_aio()`](https://nanonext.r-lib.org/reference/send_aio.md) and
[`recv_aio()`](https://nanonext.r-lib.org/reference/recv_aio.md) return
immediately with an ‘Aio’ object that performs operations
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

*Note: 0 indicates successful send - the message has been accepted by
the socket for sending but may still be buffered within the system.*

``` r
# once a message is sent, the recvAio resolves automatically
msg$data
#>   a b
#> 1 1 2
```

Use [`unresolved()`](https://nanonext.r-lib.org/reference/unresolved.md)
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
[`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md)
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
[`wait()`](https://nanonext.r-lib.org/reference/cv.md) or
[`until()`](https://nanonext.r-lib.org/reference/cv.md) calls decrement
it. A non-zero value allows waiting threads to continue.

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
[`wait()`](https://nanonext.r-lib.org/reference/cv.md) returns FALSE for
pipe events (rather than TRUE for message events). This distinguishes
between disconnections and successful receives, something not possible
using [`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md)
alone.

This mechanism enables waiting simultaneously on multiple events while
distinguishing between them.
[`pipe_notify()`](https://nanonext.r-lib.org/reference/pipe_notify.md)
can signal up to two condition variables per event for additional
flexibility in concurrent applications.

### 4. TLS Secure Connections

Secure connections use NNG and Mbed TLS libraries. Enable them by:

1.  Specifying a secure `tls+tcp://` or `wss://` URL
2.  Passing a TLS configuration object to the ‘tls’ argument of
    [`listen()`](https://nanonext.r-lib.org/reference/listen.md) or
    [`dial()`](https://nanonext.r-lib.org/reference/dial.md)

Create TLS configurations with
[`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md): -
Client configuration: requires PEM-encoded CA certificate to verify
server identity - Server configuration: requires certificate and private
key

Certificates may be supplied as files or character vectors. Valid X.509
certificates from Certificate Authorities are supported.

The convenience function
[`write_cert()`](https://nanonext.r-lib.org/reference/write_cert.md)
generates a 4096-bit RSA key pair and self-signed X.509 certificate. The
‘cn’ argument must match exactly the hostname/IP address of the URL
(e.g., use ‘127.0.0.1’ throughout, or ‘localhost’ throughout, not
mixed).

``` r
cert <- write_cert(cn = "127.0.0.1")
str(cert)
#> List of 2
#>  $ server: chr [1:2] "-----BEGIN CERTIFICATE-----\nMIIFOTCCAyGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQDDAkxMjcu\nMC4wLjExETAPBgNV"| __truncated__ "-----BEGIN RSA PRIVATE KEY-----\nMIIJKAIBAAKCAgEAwupvOgQzC3RQVt95gOTaOsDQ72tAbDzhHHLk9JfABqqWNpyl\nL7Fw3Foh7Nb9"| __truncated__
#>  $ client: chr [1:2] "-----BEGIN CERTIFICATE-----\nMIIFOTCCAyGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQDDAkxMjcu\nMC4wLjExETAPBgNV"| __truncated__ ""

ser <- tls_config(server = cert$server)
ser
#> < TLS server config | auth mode: optional >

cli <- tls_config(client = cert$client)
cli
#> < TLS client config | auth mode: required >

s <- socket(listen = "tls+tcp://127.0.0.1:5558", tls = ser)
s1 <- socket(dial = "tls+tcp://127.0.0.1:5558", tls = cli)

# secure TLS connection established

close(s1)
close(s)
```

### 5. Request Reply Protocol

`nanonext` implements remote procedure calls (RPC) using NNG’s req/rep
protocol for distributed computing. Use this for
computationally-expensive calculations or I/O-bound operations in
separate server processes.

**\[S\] Server process:**
[`reply()`](https://nanonext.r-lib.org/reference/reply.md) waits for a
message, applies a function, and sends back the result. Started in a
background ‘mirai’ process.

``` r
m <- mirai::mirai({
  library(nanonext)
  rep <- socket("rep", listen = "tcp://127.0.0.1:6556")
  reply(context(rep), execute = rnorm, send_mode = "raw")
  Sys.sleep(2) # linger period to flush system socket send
})
```

**\[C\] Client process:**
[`request()`](https://nanonext.r-lib.org/reference/request.md) performs
async send/receive, returning immediately with a `recvAio` object.

``` r
library(nanonext)
req <- socket("req", dial = "tcp://127.0.0.1:6556")
aio <- request(context(req), data = 1e8, recv_mode = "double")
```

The client can now run additional code while the server processes the
request.

``` r
# do more...
```

When the result is needed, call the recvAio using
[`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md) to
retrieve the value at `$data`.

``` r
call_aio(aio)$data |> str()
#>  num [1:100000000] -1.532 -1.493 0.499 0.478 -0.118 ...
```

Since [`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md)
blocks, alternatively query `aio$data` directly, which returns
‘unresolved’ (logical NA) if incomplete.

For server-side operations (e.g., writing to disk), calling or querying
the value confirms completion and provides the function’s return value
(typically NULL or an exit code).

The [`mirai`](https://doi.org/10.5281/zenodo.7912722) package
(<https://mirai.r-lib.org/>) uses `nanonext` as the back-end to provide
asynchronous execution of arbitrary R code using the RPC model.

### 6. Publisher Subscriber Protocol

`nanonext` implements NNG’s pub/sub protocol. Subscribers can subscribe
to one or multiple topics broadcast by a publisher.

``` r
pub <- socket("pub", listen = "inproc://nanobroadcast")
sub <- socket("sub", dial = "inproc://nanobroadcast")

sub |> subscribe(topic = "examples")

pub |> send(c("examples", "this is an example"), mode = "raw")
#> [1] 0
sub |> recv(mode = "character")
#> [1] "examples"           "this is an example"

pub |> send("examples at the start of a single text message", mode = "raw")
#> [1] 0
sub |> recv(mode = "character")
#> [1] "examples at the start of a single text message"

pub |> send(c("other", "this other topic will not be received"), mode = "raw")
#> [1] 0
sub |> recv(mode = "character")
#> 'errorValue' int 8 | Try again

# specify NULL to subscribe to ALL topics
sub |> subscribe(topic = NULL)
pub |> send(c("newTopic", "this is a new topic"), mode = "raw")
#> [1] 0
sub |> recv("character")
#> [1] "newTopic"            "this is a new topic"

sub |> unsubscribe(topic = NULL)
pub |> send(c("newTopic", "this topic will now not be received"), mode = "raw")
#> [1] 0
sub |> recv("character")
#> 'errorValue' int 8 | Try again

# however the topics explicitly subscribed to are still received
pub |> send(c("examples will still be received"), mode = "raw")
#> [1] 0
sub |> recv(mode = "character")
#> [1] "examples will still be received"
```

The subscribed topic can be of any atomic type (not just character),
allowing integer, double, logical, complex and raw vectors to be sent
and received.

``` r
sub |> subscribe(topic = 1)
pub |> send(c(1, 10, 10, 20), mode = "raw")
#> [1] 0
sub |> recv(mode = "double")
#> [1]  1 10 10 20
pub |> send(c(2, 10, 10, 20), mode = "raw")
#> [1] 0
sub |> recv(mode = "double")
#> 'errorValue' int 8 | Try again

close(pub)
close(sub)
```

### 7. Surveyor Respondent Protocol

Useful for service discovery and similar applications. A surveyor
broadcasts a survey to all respondents, who may reply within a timeout
period. Late responses are discarded.

``` r
sur <- socket("surveyor", listen = "inproc://nanoservice")
res1 <- socket("respondent", dial = "inproc://nanoservice")
res2 <- socket("respondent", dial = "inproc://nanoservice")

# sur sets a survey timeout, applying to this and subsequent surveys
sur |> survey_time(value = 500)

# sur sends a message and then requests 2 async receives
sur |> send("service check")
#> [1] 0
aio1 <- sur |> recv_aio()
aio2 <- sur |> recv_aio()

# res1 receives the message and replies using an aio send function
res1 |> recv()
#> [1] "service check"
res1 |> send_aio("res1")

# res2 receives the message but fails to reply
res2 |> recv()
#> [1] "service check"

# checking the aio - only the first will have resolved
aio1$data
#> [1] "res1"
aio2$data
#> 'unresolved' logi NA

# after the survey expires, the second resolves into a timeout error
msleep(500)
aio2$data
#> 'errorValue' int 5 | Timed out

close(sur)
close(res1)
close(res2)
```

[`msleep()`](https://nanonext.r-lib.org/reference/msleep.md) is an
uninterruptible sleep function (using NNG) that takes a time in
milliseconds.

The final value resolves to a timeout error (integer 5 classed as
‘errorValue’). All error codes are classed as ‘errorValue’ for easy
distinction from integer message values.

### 8. ncurl: Async HTTP Client

[`ncurl()`](https://nanonext.r-lib.org/reference/ncurl.md) is a
minimalist http(s) client.
[`ncurl_aio()`](https://nanonext.r-lib.org/reference/ncurl_aio.md)
performs async requests, returning immediately with an ‘ncurlAio’.

Basic usage requires only a URL and can follow redirects.

``` r
ncurl("https://postman-echo.com/get")
#> $status
#> [1] 200
#> 
#> $headers
#> NULL
#> 
#> $data
#> [1] "{\"args\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\"},\"url\":\"https://postman-echo.com/get\"}"
```

Advanced usage supports additional HTTP methods (POST, PUT, etc.).

``` r
res <- ncurl_aio("https://postman-echo.com/post",
                 method = "POST",
                 headers = c(`Content-Type` = "application/json", Authorization = "Bearer APIKEY"),
                 data = '{"key": "value"}',
                 response = "date")
res
#> < ncurlAio | $status $headers $data >

call_aio(res)$headers
#> $date
#> [1] "Tue, 02 Dec 2025 12:02:22 GMT"

res$data
#> [1] "{\"args\":{},\"data\":{\"key\":\"value\"},\"files\":{},\"form\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\",\"content-type\":\"application/json\",\"authorization\":\"Bearer APIKEY\",\"content-length\":\"16\"},\"json\":{\"key\":\"value\"},\"url\":\"https://postman-echo.com/post\"}"
```

Provides a performant, lightweight method for REST API requests.

##### ncurl Promises

[`ncurl_aio()`](https://nanonext.r-lib.org/reference/ncurl_aio.md) works
anywhere that accepts a ‘promise’ from the promises package, including
Shiny ExtendedTask.

Promises resolve with a list of ‘status’, ‘headers’, and ‘data’, or
reject with an error message (e.g., ‘15 \| Address invalid’).

``` r
library(promises)

p <- ncurl_aio("https://postman-echo.com/get") |> then(\(x) cat(x$data))
is.promise(p)
#> [1] TRUE
```

##### ncurl Session

[`ncurl_session()`](https://nanonext.r-lib.org/reference/ncurl_session.md)
creates a reusable open connection for efficient repeated polling of an
API endpoint. Use
[`transact()`](https://nanonext.r-lib.org/reference/ncurl_session.md) to
request data multiple times. This enables polling frequencies that
exceed server connection limits (where permitted).

Specify `convert = FALSE` to receive binary data as a raw vector for
direct use with JSON parsers.

``` r
sess <- ncurl_session("https://postman-echo.com/get",
                      convert = FALSE,
                      headers = c(`Content-Type` = "application/json", Authorization = "Bearer APIKEY"),
                      response = c("Date", "Content-Type"))
sess
#> < ncurlSession > - transact() to return data

transact(sess)
#> $status
#> [1] 200
#> 
#> $headers
#> $headers$Date
#> [1] "Tue, 02 Dec 2025 12:02:22 GMT"
#> 
#> $headers$`Content-Type`
#> [1] "application/json; charset=utf-8"
#> 
#> 
#> $data
#>   [1] 7b 22 61 72 67 73 22 3a 7b 7d 2c 22 68 65 61 64 65 72 73 22 3a 7b 22 68 6f 73 74 22 3a
#>  [30] 22 70 6f 73 74 6d 61 6e 2d 65 63 68 6f 2e 63 6f 6d 22 2c 22 61 75 74 68 6f 72 69 7a 61
#>  [59] 74 69 6f 6e 22 3a 22 42 65 61 72 65 72 20 41 50 49 4b 45 59 22 2c 22 61 63 63 65 70 74
#>  [88] 2d 65 6e 63 6f 64 69 6e 67 22 3a 22 67 7a 69 70 2c 20 62 72 22 2c 22 78 2d 66 6f 72 77
#> [117] 61 72 64 65 64 2d 70 72 6f 74 6f 22 3a 22 68 74 74 70 73 22 2c 22 63 6f 6e 74 65 6e 74
#> [146] 2d 74 79 70 65 22 3a 22 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 22 7d 2c 22 75
#> [175] 72 6c 22 3a 22 68 74 74 70 73 3a 2f 2f 70 6f 73 74 6d 61 6e 2d 65 63 68 6f 2e 63 6f 6d
#> [204] 2f 67 65 74 22 7d
```

### 9. stream: Websocket Client

[`stream()`](https://nanonext.r-lib.org/reference/stream.md) exposes
NNG’s low-level byte stream interface for communicating with raw
sockets, including arbitrary non-NNG endpoints.

Use `textframes = TRUE` for websocket servers that use text frames
instead of binary frames.

``` r
# connecting to an echo service
s <- stream(dial = "wss://echo.websocket.org/", textframes = TRUE)
s
#> < nanoStream >
#>  - mode: dialer text frames
#>  - state: opened
#>  - url: wss://echo.websocket.org/
```

[`send()`](https://nanonext.r-lib.org/reference/send.md) and
[`recv()`](https://nanonext.r-lib.org/reference/recv.md), as well as
their asynchronous counterparts
[`send_aio()`](https://nanonext.r-lib.org/reference/send_aio.md) and
[`recv_aio()`](https://nanonext.r-lib.org/reference/recv_aio.md) can be
used on Streams in the same way as Sockets. This affords a great deal of
flexibility in ingesting and processing streaming data.

``` r
s |> recv()
#> [1] "Request served by 4d896d95b55478"

s |> send("initial message")
#> [1] 0

s |> recv()
#> [1] "initial message"

s |> recv_aio() -> r

s |> send("async message")
#> [1] 0

s |> send("final message")
#> [1] 0

s |> recv()
#> [1] "final message"

r$data
#> [1] "async message"

close(s)
```

### 10. Options, Serialization and Statistics

Use [`opt()`](https://nanonext.r-lib.org/reference/opt.md) and
[`'opt<-'()`](https://nanonext.r-lib.org/reference/opt.md) to get and
set options on Sockets, Contexts, Streams, Listeners, or Dialers. See
function documentation for available options.

To configure dialers or listeners after creation, specify
`autostart = FALSE` (configuration cannot be changed after starting).

``` r
s <- socket(listen = "inproc://options", autostart = FALSE)

# no maximum message size
opt(s$listener[[1]], "recv-size-max")
#> [1] 0

# enforce maximum message size to protect against denial-of-service attacks
opt(s$listener[[1]], "recv-size-max") <- 8192L

opt(s$listener[[1]], "recv-size-max")
#> [1] 8192

start(s$listener[[1]])
```

The special write-only option ‘serial’ sets a serialization
configuration via
[`serial_config()`](https://nanonext.r-lib.org/reference/serial_config.md).
This registers custom functions for serializing/unserializing reference
objects using R’s ‘refhook’ system, enabling transparent send/receive
with mode ‘serial’. Configurations apply to the Socket and all Contexts
created from it.

``` r
serial <- serial_config("obj_class", function(x) serialize(x, NULL), unserialize)
opt(s, "serial") <- serial

close(s)
```

Use [`stat()`](https://nanonext.r-lib.org/reference/stat.md) to access
NNG’s statistics framework. Query Sockets, Listeners, or Dialers for
statistics such as connection attempts and current connections. See
function documentation for available statistics.

``` r
s <- socket(listen = "inproc://stat")

# no active connections (pipes)
stat(s, "pipes")
#> [1] 0

s1 <- socket(dial = "inproc://stat")

# one now that the dialer has connected
stat(s, "pipes")
#> [1] 1

close(s)
```
