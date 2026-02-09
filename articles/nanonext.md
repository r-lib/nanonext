# nanonext - Quick Reference

## Core Concepts

**nanonext** provides bindings to NNG (Nanomsg Next Gen), a
high-performance messaging library for building distributed systems.

This is a cheatsheet. Refer to the other vignettes for detailed
introductions:

- [Messaging and Async
  I/O](https://nanonext.r-lib.org/articles/v01-messaging.md) -
  cross-language exchange, async operations, synchronisation
- [Scalability
  Protocols](https://nanonext.r-lib.org/articles/v02-protocols.md) -
  req/rep, pub/sub, surveyor/respondent
- [Configuration and
  Security](https://nanonext.r-lib.org/articles/v03-configuration.md) -
  TLS, options, serialization, statistics
- [Web Toolkit](https://nanonext.r-lib.org/articles/v04-web.md) - HTTP
  client/server, WebSocket, streaming

## Key Takeaways

- **Sockets** connect via URLs using scalability protocols (req/rep,
  pub/sub, etc.)
- **Transports**: `inproc://` (in-process), `ipc://` (inter-process),
  `tcp://`, `ws://`, `wss://`, `tls+tcp://`
- **Async I/O**:
  [`send_aio()`](https://nanonext.r-lib.org/reference/send_aio.md) /
  [`recv_aio()`](https://nanonext.r-lib.org/reference/recv_aio.md)
  return immediately; access results via `$data` or `$result`
- **Modes**: `"serial"` (R objects), `"raw"` (bytes), `"double"`,
  `"integer"`, `"character"`, etc.
- **Condition variables**:
  [`cv()`](https://nanonext.r-lib.org/reference/cv.md) for zero-latency
  event synchronisation

## 1. Sockets and Connections

### Create Sockets

``` r
library(nanonext)

# Functional interface
s <- socket("pair")
listen(s, "tcp://127.0.0.1:5555")
dial(s, "tcp://127.0.0.1:5555")

# Object-oriented interface
n <- nano("pair", listen = "tcp://127.0.0.1:5555")
n$dial("tcp://127.0.0.1:5556")

# Close when done
close(s)
n$close()
```

### Protocols

| Protocol     | Description          | Socket Types                 |
|--------------|----------------------|------------------------------|
| **Pair**     | 1-to-1 bidirectional | `"pair"`                     |
| **Poly**     | Polyamorous pair     | `"poly"`                     |
| **Pipeline** | One-way data flow    | `"push"`, `"pull"`           |
| **Req/Rep**  | RPC pattern          | `"req"`, `"rep"`             |
| **Pub/Sub**  | Broadcast/subscribe  | `"pub"`, `"sub"`             |
| **Survey**   | Query all peers      | `"surveyor"`, `"respondent"` |
| **Bus**      | Many-to-many mesh    | `"bus"`                      |

### Transports

| URL Scheme             | Description                              |
|------------------------|------------------------------------------|
| `inproc://name`        | In-process (fastest, same process)       |
| `ipc:///path`          | Inter-process (Unix socket / named pipe) |
| `tcp://host:port`      | TCP/IP network                           |
| `ws://host:port/path`  | WebSocket                                |
| `wss://host:port/path` | WebSocket over TLS                       |
| `tls+tcp://host:port`  | TLS encrypted TCP                        |

## 2. Send and Receive

### Synchronous

``` r
# Send R object (serialized)
send(s, data.frame(a = 1, b = 2))

# Receive R object
recv(s)

# Send raw bytes (for cross-language exchange)
send(s, c(1.1, 2.2, 3.3), mode = "raw")

# Receive as specific type
recv(s, mode = "double")
recv(s, mode = "character")
recv(s, mode = "raw")
```

### Receive Modes

| Mode                | Description                        |
|---------------------|------------------------------------|
| `"serial"` / `1`    | R serialization (default)          |
| `"character"` / `2` | Coerce to character                |
| `"complex"` / `3`   | Coerce to complex                  |
| `"double"` / `4`    | Coerce to double                   |
| `"integer"` / `5`   | Coerce to integer                  |
| `"logical"` / `6`   | Coerce to logical                  |
| `"numeric"` / `7`   | Coerce to numeric                  |
| `"raw"` / `8`       | Raw bytes                          |
| `"string"` / `9`    | Fast option for length-1 character |

## 3. Async I/O

### Basic Async

``` r
# Async send - returns immediately
res <- send_aio(s, data)
res$result          # 0 = success, error code otherwise

# Async receive - returns immediately
msg <- recv_aio(s)
msg$data            # Value when resolved, 'unresolved' NA otherwise

# Check if resolved
unresolved(msg)     # TRUE while pending

# Wait for resolution
call_aio(msg)       # Blocks, returns Aio object
collect_aio(msg)    # Blocks, returns value directly
msg[]               # Blocks (user-interruptible), returns value
```

### Non-blocking Patterns

``` r
# Poll while doing other work
while (unresolved(msg)) {
  # do other tasks
}
result <- msg$data

# Multiple async operations
msg1 <- recv_aio(s1)
msg2 <- recv_aio(s2)
# Both run concurrently
```

## 4. Condition Variables

### Basics

``` r
# Create condition variable
cv <- cv()

# Check/signal
cv_value(cv)        # Get counter value
cv_signal(cv)       # Increment counter
cv_reset(cv)        # Reset to zero

# Wait (blocks until counter > 0, then decrements)
wait(cv)

# Wait with timeout (ms), returns FALSE on timeout
until(cv, 1000)
```

### Pipe Notifications

``` r
# Signal on connection/disconnection
pipe_notify(socket, cv = cv, add = TRUE, remove = TRUE)

# Distinguish message vs disconnect with flag
pipe_notify(socket, cv = cv, remove = TRUE, flag = TRUE)
r <- recv_aio(socket, cv = cv)
wait(cv) || stop("disconnected")  # FALSE = pipe event
```

### Async with CV

``` r
cv <- cv()
msg <- recv_aio(s, cv = cv)
wait(cv)            # Wake on receive completion
msg$data
```

## 5. Request/Reply (RPC)

### Server

``` r
rep <- socket("rep", listen = "tcp://127.0.0.1:5555")
ctx <- context(rep)

# reply() blocks, waiting for request
reply(ctx, execute = my_function, send_mode = "raw")

close(rep)
```

### Client

``` r
req <- socket("req", dial = "tcp://127.0.0.1:5555")
ctx <- context(req)

# request() returns immediately
aio <- request(ctx, data = args, recv_mode = "double")

# Do other work while server processes...

# Get result when needed
result <- aio[]

close(req)
```

## 6. Pub/Sub

``` r
pub <- socket("pub", listen = "inproc://pubsub")
sub <- socket("sub", dial = "inproc://pubsub")

# Subscribe to topic (prefix matching)
subscribe(sub, topic = "news")
subscribe(sub, topic = NULL)      # All topics

# Unsubscribe
unsubscribe(sub, topic = "news")

# Publish (topic is message prefix)
send(pub, c("news", "headline"), mode = "raw")

# Receive (includes topic)
recv(sub, mode = "character")

close(pub)
close(sub)
```

## 7. Surveyor/Respondent

``` r
sur <- socket("surveyor", listen = "inproc://survey")
res1 <- socket("respondent", dial = "inproc://survey")
res2 <- socket("respondent", dial = "inproc://survey")

# Set survey timeout (ms)
survey_time(sur, 500)

# Broadcast survey
send(sur, "ping")

# Collect responses (async)
aio1 <- recv_aio(sur)
aio2 <- recv_aio(sur)

# Respondents reply
recv(res1)
send(res1, "pong1")

# Late/missing responses timeout (errorValue 5)
msleep(500)
aio2$data           # errorValue if no response

close(sur)
close(res1)
close(res2)
```

## 8. TLS Secure Connections

### Self-signed Certificates

``` r
# Generate certificate (cn must match URL host exactly)
cert <- write_cert(cn = "127.0.0.1")

# Create TLS configs
server_tls <- tls_config(server = cert$server)
client_tls <- tls_config(client = cert$client)

# Use with tls+tcp:// or wss://
s1 <- socket(listen = "tls+tcp://127.0.0.1:5555", tls = server_tls)
s2 <- socket(dial = "tls+tcp://127.0.0.1:5555", tls = client_tls)
```

### CA Certificates

``` r
# Client with CA cert file
client_tls <- tls_config(client = "/path/to/ca-cert.pem")

# Server with cert + key
server_tls <- tls_config(server = c("/path/to/cert.pem", "/path/to/key.pem"))
```

## 9. Options and Statistics

### Get/Set Options

``` r
# Delayed start for configuration
s <- socket(listen = "tcp://127.0.0.1:5555", autostart = FALSE)

# Get option
opt(s$listener[[1]], "recv-size-max")

# Set option
opt(s$listener[[1]], "recv-size-max") <- 8192L

# Start after configuration
start(s$listener[[1]])
```

### Common Options

| Option                 | Description                      |
|------------------------|----------------------------------|
| `"recv-size-max"`      | Max message size (0 = unlimited) |
| `"send-timeout"`       | Send timeout (ms)                |
| `"recv-timeout"`       | Receive timeout (ms)             |
| `"reconnect-time-min"` | Min reconnect interval (ms)      |
| `"reconnect-time-max"` | Max reconnect interval (ms)      |
| `"req:resend-time"`    | Request retry interval           |
| `"sub:prefnew"`        | Prefer newer messages            |

### Custom Serialization

``` r
# Register custom serializer for a class
serial <- serial_config(
  "class_name",
  function(x) serialize(x, NULL),  # serialize
  unserialize                      # unserialize
)
opt(socket, "serial") <- serial
```

### Statistics

``` r
stat(socket, "pipes")      # Active connections
stat(listener, "accept")   # Connection attempts
stat(dialer, "reject")     # Rejected connections
```

## 10. Contexts

Contexts enable concurrent operations on a single socket (for req/rep,
surveyor/respondent).

``` r
s <- socket("req", dial = "tcp://127.0.0.1:5555")

# Create independent contexts
ctx1 <- context(s)
ctx2 <- context(s)

# Concurrent requests
aio1 <- request(ctx1, data1)
aio2 <- request(ctx2, data2)

# Close contexts (or they close with socket)
close(ctx1)
close(ctx2)
close(s)
```

## 11. Cross-language Exchange

### R to Python (NumPy)

``` r
# R: send raw doubles
n <- nano("pair", dial = "ipc:///tmp/nanonext")
n$send(c(1.1, 2.2, 3.3), mode = "raw")
result <- n$recv(mode = "double")
```

``` python
# Python: receive as NumPy array
import numpy as np
import pynng
socket = pynng.Pair0(listen="ipc:///tmp/nanonext")
array = np.frombuffer(socket.recv())
socket.send(array.tobytes())
```

## 12. Error Handling

``` r
# Errors return as 'errorValue' class
result <- recv(s, block = FALSE)

# Check for errors
is_error_value(result)

# Error codes
# 5  = Timed out
# 6  = Connection refused
# 8  = Try again (non-blocking, no message)

# Get error message
nng_error(5)        # "Timed out"
```

## 13. Utilities

``` r
# Sleep (uninterruptible, ms)
msleep(100)

# Random bytes
random(8)                          # 8 random bytes as hex string
random(8, convert = FALSE)         # As raw vector

# Parse URL
parse_url("tcp://127.0.0.1:5555")
```
