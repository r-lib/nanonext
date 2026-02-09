# nanonext - Web Toolkit

``` r
library(nanonext)
```

nanonext provides high-performance HTTP/WebSocket client and server
capabilities built on NNG’s networking stack with Mbed TLS for secure
connections.

### 1. HTTP Client

#### ncurl: Basic Requests

[`ncurl()`](https://nanonext.r-lib.org/reference/ncurl.md) is a
minimalist HTTP(S) client. Basic usage requires only a URL.

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

Advanced usage supports all HTTP methods (POST, PUT, DELETE, etc.),
custom headers, and request bodies.

``` r
ncurl("https://postman-echo.com/post",
      method = "POST",
      headers = c(`Content-Type` = "application/json", Authorization = "Bearer APIKEY"),
      data = '{"key": "value"}',
      response = "date")
#> $status
#> [1] 200
#> 
#> $headers
#> $headers$date
#> [1] "Sun, 08 Feb 2026 11:22:45 GMT"
#> 
#> 
#> $data
#> [1] "{\"args\":{},\"data\":{\"key\":\"value\"},\"files\":{},\"form\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\",\"content-type\":\"application/json\",\"authorization\":\"Bearer APIKEY\",\"content-length\":\"16\"},\"json\":{\"key\":\"value\"},\"url\":\"https://postman-echo.com/post\"}"
```

Specify `response = TRUE` to return all response headers.

``` r
ncurl("https://postman-echo.com/get",
      response = TRUE)
#> $status
#> [1] 200
#> 
#> $headers
#> $headers$Date
#> [1] "Sun, 08 Feb 2026 11:22:45 GMT"
#> 
#> $headers$`Content-Type`
#> [1] "application/json; charset=utf-8"
#> 
#> $headers$`Content-Length`
#> [1] "143"
#> 
#> $headers$Connection
#> [1] "close"
#> 
#> $headers$`CF-RAY`
#> [1] "9caac0420a1dc16b-LHR"
#> 
#> $headers$etag
#> [1] "W/\"8f-7zN8nSad8A9WlFJjKQZB04z5nHE\""
#> 
#> $headers$vary
#> [1] "Accept-Encoding"
#> 
#> $headers$`Set-Cookie`
#> [1] "sails.sid=s%3A3tYl-iuzp8jF0j82bxVHtxrx87HF8PoG.ykEiyyCKGOB1tWjbdRBXQQN7R2JwAHxl%2FkpAWvaV%2FIs; Path=/; HttpOnly, __cf_bm=xmba.Nkum1545BuZtIF1AkAAJzxI0VLZrdSg2QarH6M-1770549765-1.0.1.1-Twtq9B6vpPFSSJbuRQ9AaEDUB83Sprl4keRU_kvVk7PZqFGUZc1cVqFvyfN14NRX1CG5qT1idcqkSWejx03q6v3KYkPgCga6vJiifoRoVUs; path=/; expires=Sun, 08-Feb-26 11:52:45 GMT; domain=.postman-echo.com; HttpOnly; Secure, _cfuvid=u2FHSl3lIzG1PMEmFIe9J58inYS1BQ8KH5f7Y3RV1Nk-1770549765548-0.0.1.1-604800000; path=/; domain=.postman-echo.com; HttpOnly; Secure; SameSite=None"
#> 
#> $headers$`x-envoy-upstream-service-time`
#> [1] "5"
#> 
#> $headers$`cf-cache-status`
#> [1] "DYNAMIC"
#> 
#> $headers$Server
#> [1] "cloudflare"
#> 
#> 
#> $data
#> [1] "{\"args\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\"},\"url\":\"https://postman-echo.com/get\"}"
```

#### ncurl_aio: Async Requests

[`ncurl_aio()`](https://nanonext.r-lib.org/reference/ncurl_aio.md)
performs asynchronous requests, returning immediately with an ‘ncurlAio’
object that resolves when the response arrives.

``` r
res <- ncurl_aio("https://postman-echo.com/post",
                 method = "POST",
                 headers = c(`Content-Type` = "application/json"),
                 data = '{"async": true}',
                 response = "date")
res
#> < ncurlAio | $status $headers $data >

call_aio(res)$headers
#> $date
#> [1] "Sun, 08 Feb 2026 11:22:45 GMT"

res$status
#> [1] 200

res$data
#> [1] "{\"args\":{},\"data\":{\"async\":true},\"files\":{},\"form\":{},\"headers\":{\"host\":\"postman-echo.com\",\"content-type\":\"application/json\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\",\"content-length\":\"15\"},\"json\":{\"async\":true},\"url\":\"https://postman-echo.com/post\"}"
```

##### Promises Integration

‘ncurlAio’ objects work anywhere that accepts a ‘promise’ from the
promises package, including Shiny ExtendedTask.

``` r
library(promises)

p <- ncurl_aio("https://postman-echo.com/get") |> then(\(x) cat(x$data))
is.promise(p)
#> [1] TRUE
```

#### ncurl_session: Persistent Connections

[`ncurl_session()`](https://nanonext.r-lib.org/reference/ncurl_session.md)
creates a reusable connection for efficient repeated requests to an API
endpoint. Use
[`transact()`](https://nanonext.r-lib.org/reference/ncurl_session.md) to
send requests over the session.

``` r
sess <- ncurl_session("https://postman-echo.com/get",
                      convert = FALSE,
                      headers = c(`Content-Type` = "application/json"),
                      response = c("Date", "Content-Type"))
sess
#> < ncurlSession > - transact() to return data

transact(sess)
#> $status
#> [1] 200
#> 
#> $headers
#> $headers$Date
#> [1] "Sun, 08 Feb 2026 11:22:46 GMT"
#> 
#> $headers$`Content-Type`
#> [1] "application/json; charset=utf-8"
#> 
#> 
#> $data
#>   [1] 7b 22 61 72 67 73 22 3a 7b 7d 2c 22 68 65 61 64 65 72 73 22 3a 7b 22 68 6f 73 74 22 3a
#>  [30] 22 70 6f 73 74 6d 61 6e 2d 65 63 68 6f 2e 63 6f 6d 22 2c 22 61 63 63 65 70 74 2d 65 6e
#>  [59] 63 6f 64 69 6e 67 22 3a 22 67 7a 69 70 2c 20 62 72 22 2c 22 78 2d 66 6f 72 77 61 72 64
#>  [88] 65 64 2d 70 72 6f 74 6f 22 3a 22 68 74 74 70 73 22 2c 22 63 6f 6e 74 65 6e 74 2d 74 79
#> [117] 70 65 22 3a 22 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e 22 7d 2c 22 75 72 6c 22
#> [146] 3a 22 68 74 74 70 73 3a 2f 2f 70 6f 73 74 6d 61 6e 2d 65 63 68 6f 2e 63 6f 6d 2f 67 65
#> [175] 74 22 7d

close(sess)
```

### 2. WebSocket Client

[`stream()`](https://nanonext.r-lib.org/reference/stream.md) provides a
low-level byte stream interface for communicating with WebSocket servers
and other non-NNG endpoints.

Use `textframes = TRUE` for servers that expect text frames (most
WebSocket servers).

``` r
s <- stream(dial = "wss://echo.websocket.org/", textframes = TRUE)
s
#> < nanoStream >
#>  - mode: dialer text frames
#>  - state: opened
#>  - url: wss://echo.websocket.org/
```

[`send()`](https://nanonext.r-lib.org/reference/send.md) and
[`recv()`](https://nanonext.r-lib.org/reference/recv.md), along with
their async counterparts
[`send_aio()`](https://nanonext.r-lib.org/reference/send_aio.md) and
[`recv_aio()`](https://nanonext.r-lib.org/reference/recv_aio.md), work
on Streams just like Sockets.

``` r
s |> recv()
#> [1] "Request served by 4d896d95b55478"

s |> send("hello websocket")
#> [1] 0

s |> recv()
#> [1] "hello websocket"

s |> recv_aio() -> r

s |> send("async message")
#> [1] 0

r[]
#> [1] "async message"

close(s)
```

### 3. Unified HTTP/WebSocket Server

[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md)
creates a single server that can handle HTTP requests, WebSocket
connections, and HTTP streaming, all on the same port.

A single call to
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md)
sets up one NNG server instance with a list of handlers. HTTP routes,
WebSocket endpoints, streaming endpoints, and static file handlers all
share the same underlying server – there is no need to run separate
processes or bind additional ports. WebSocket clients connect via the
standard HTTP upgrade mechanism, so a browser can load a page over HTTP
and open a WebSocket connection to the same origin without any
cross-origin configuration.

``` r
server <- http_server(
  url = "http://127.0.0.1:8080",
  handlers = list(
    handler("/", function(req) {
      list(status = 200L, body = "Hello from nanonext!")
    }),
    handler("/api/data", function(req) {
      list(
        status = 200L,
        headers = c("Content-Type" = "application/json"),
        body = '{"value": 42}'
      )
    }, method = "GET")
  )
)
server$start()
# Process requests: repeat later::run_now(Inf)
server$close()
```

Specifying port `0` in the URL lets the OS assign an available port. The
actual port is reflected in `server$url` after `$start()`, making it
easy to set up test servers without port conflicts.

#### Handler Types

All handler types can be freely mixed in a single server’s handler list:

| Handler                                                                            | Purpose                                                      |
|:-----------------------------------------------------------------------------------|:-------------------------------------------------------------|
| [`handler()`](https://nanonext.r-lib.org/reference/handler.md)                     | HTTP request/response with R callback                        |
| [`handler_ws()`](https://nanonext.r-lib.org/reference/handler_ws.md)               | WebSocket with `on_message`, `on_open`, `on_close` callbacks |
| [`handler_stream()`](https://nanonext.r-lib.org/reference/handler_stream.md)       | Chunked HTTP streaming (SSE, NDJSON, custom)                 |
| [`handler_file()`](https://nanonext.r-lib.org/reference/handler_file.md)           | Serve a single static file                                   |
| [`handler_directory()`](https://nanonext.r-lib.org/reference/handler_directory.md) | Serve a directory tree with automatic MIME types             |
| [`handler_inline()`](https://nanonext.r-lib.org/reference/handler_inline.md)       | Serve in-memory content                                      |
| [`handler_redirect()`](https://nanonext.r-lib.org/reference/handler_redirect.md)   | HTTP redirect                                                |

#### HTTP Request Handlers

[`handler()`](https://nanonext.r-lib.org/reference/handler.md) creates
HTTP route handlers. The callback receives a request list with `method`,
`uri`, `headers`, and `body`, and returns a response list with `status`,
optional `headers`, and `body`.

``` r
# GET endpoint
h1 <- handler("/hello", function(req) {
  list(status = 200L, body = "Hello!")
})

# POST endpoint echoing the request body
h2 <- handler("/echo", function(req) {
  list(status = 200L, body = req$body)
}, method = "POST")

# Catch-all for any method under a path prefix
h3 <- handler("/api", function(req) {
  list(
    status = 200L,
    headers = c("Content-Type" = "application/json"),
    body = sprintf('{"method":"%s","uri":"%s"}', req$method, req$uri)
  )
}, method = "*", prefix = TRUE)
```

#### Static Content Handlers

``` r
# Serve a single file
h_file <- handler_file("/favicon.ico", "path/to/favicon.ico")

# Serve a directory tree (automatic MIME type detection)
h_dir <- handler_directory("/static", "www/assets")

# Serve inline content
h_inline <- handler_inline("/robots.txt", "User-agent: *\nDisallow:",
                           content_type = "text/plain")

# Redirect requests
h_redirect <- handler_redirect("/old-page", "/new-page", status = 301L)
```

#### WebSocket Handlers

WebSockets provide full bidirectional communication – the server can
push messages to the client, and the client can send messages back.

[`handler_ws()`](https://nanonext.r-lib.org/reference/handler_ws.md)
creates WebSocket endpoints. NNG handles the HTTP upgrade handshake and
all WebSocket framing (RFC 6455) automatically. Because WebSocket
handlers share the same server as HTTP handlers, the browser can load a
page and open a WebSocket to the same host and port with no additional
setup.

``` r
clients <- list()

server <- http_server(
  url = "http://127.0.0.1:8080",
  handlers = list(
    handler_ws(
      "/chat",
      on_message = function(ws, data) {
        # Broadcast to all connected clients
        for (client in clients) client$send(data)
      },
      on_open = function(ws) {
        clients[[as.character(ws$id)]] <<- ws
      },
      on_close = function(ws) {
        clients[[as.character(ws$id)]] <<- NULL
      },
      textframes = TRUE
    )
  )
)
server$start()
```

The `ws` connection object provides:

- `ws$send(data)` - Send a message to the client
- `ws$close()` - Close the connection
- `ws$id` - Unique integer connection identifier

Multiple WebSocket endpoints can coexist on the same server, each with
independent callbacks and connection tracking. Connection IDs are unique
across the entire server, so they are safe to use as keys in a shared
data structure spanning multiple handlers.

#### HTTP Streaming Handlers

When you only need to push data in one direction – server to client –
streaming is a lighter-weight alternative to WebSockets. It works over
plain HTTP, so any client that speaks HTTP can consume the stream
without needing a WebSocket library.

[`handler_stream()`](https://nanonext.r-lib.org/reference/handler_stream.md)
enables HTTP streaming using chunked transfer encoding, supporting
Server-Sent Events (SSE), newline-delimited JSON (NDJSON), and custom
streaming formats. Like WebSocket handlers, streaming endpoints share
the same server as all other handlers.

``` r
conns <- list()

server <- http_server(
  url = "http://127.0.0.1:8080",
  handlers = list(
    # SSE endpoint
    handler_stream("/events",
      on_request = function(conn, req) {
        conn$set_header("Content-Type", "text/event-stream")
        conn$set_header("Cache-Control", "no-cache")
        conns[[as.character(conn$id)]] <<- conn
        conn$send(format_sse(data = "connected", id = "1"))
      },
      on_close = function(conn) {
        conns[[as.character(conn$id)]] <<- NULL
      }
    ),
    # Trigger broadcast via POST
    handler("/broadcast", function(req) {
      msg <- format_sse(data = rawToChar(req$body), event = "message")
      lapply(conns, function(c) c$send(msg))
      list(status = 200L, body = "sent")
    }, method = "POST")
  )
)
server$start()
```

#### Server-Sent Events

[`format_sse()`](https://nanonext.r-lib.org/reference/format_sse.md)
formats messages according to the SSE specification for browser
`EventSource` clients.

``` r
format_sse(data = "Hello")
#> [1] "data: Hello\n\n"

format_sse(data = "Update available", event = "notification", id = "42")
#> [1] "event: notification\nid: 42\ndata: Update available\n\n"

format_sse(data = "Line 1\nLine 2")
#> [1] "data: Line 1\ndata: Line 2\n\n"
```

The streaming connection object provides:

- `conn$send(data)` - Send a data chunk
- `conn$close()` - Close the connection
- `conn$set_status(code)` - Set HTTP status (before first send)
- `conn$set_header(name, value)` - Set response header (before first
  send)
- `conn$id` - Unique connection identifier

### 4. Secure Connections (TLS)

All web functions support TLS for secure HTTPS/WSS connections via
[`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md).

#### Public Internet HTTPS

When making HTTPS requests over the public internet, you should supply a
TLS configuration to validate server certificates.

Root CA certificates in PEM format may be found at:

- Linux: `/etc/ssl/certs/ca-certificates.crt` or
  `/etc/pki/tls/certs/ca-bundle.crt`
- macOS: `/etc/ssl/cert.pem`
- Windows: download from the [Common CA
  Database](https://www.ccadb.org/resources) site run by Mozilla (select
  the Server Authentication SSL/TLS certificates text file). *This link
  is not endorsed; use at your own risk.*

``` r
tls <- tls_config(client = "/etc/ssl/cert.pem")
ncurl("https://www.google.com", tls = tls)
```

#### Self-Signed Certificates

For internal services or testing, generate self-signed certificates
using
[`write_cert()`](https://nanonext.r-lib.org/reference/write_cert.md).

``` r
# Generate self-signed certificate for testing
cert <- write_cert(cn = "127.0.0.1")

# Server TLS configuration
ser <- tls_config(server = cert$server)

# Client TLS configuration
cli <- tls_config(client = cert$client)
```

Use the configurations with servers and clients:

``` r
# HTTPS server
server <- http_server(
  url = "https://127.0.0.1:0",
  handlers = list(
    handler("/", function(req) list(status = 200L, body = "Secure!"))
  ),
  tls = ser
)
server$start()
server
#> < nanoServer >
#>  - url: https://127.0.0.1:50715 
#>  - state: started

# HTTPS client request
aio <- ncurl_aio(paste0(server$url, "/"), tls = cli)
while (unresolved(aio)) later::run_now(1)
#> {"args":{},"headers":{"host":"postman-echo.com","accept-encoding":"gzip, br","x-forwarded-proto":"https"},"url":"https://postman-echo.com/get"}
aio$status
#> [1] 200
aio$data
#> [1] "Secure!"

server$close()
```

### 5. Client Example: Shiny ExtendedTask

This example demonstrates using
[`ncurl_aio()`](https://nanonext.r-lib.org/reference/ncurl_aio.md) with
Shiny’s ExtendedTask for non-blocking HTTP requests.

If your Shiny app calls an external API, a slow or unresponsive endpoint
will block the R process and freeze the app for *all* users, not just
the one who triggered the request.
[`ncurl_aio()`](https://nanonext.r-lib.org/reference/ncurl_aio.md)
avoids this – it performs the HTTP call on a background thread and
returns a promise, so the R process stays free to serve other sessions.
It works anywhere that accepts a promise, including Shiny’s
ExtendedTask:

``` r
library(shiny)
library(bslib)
library(nanonext)

ui <- page_fluid(
  p("The time is ", textOutput("current_time", inline = TRUE)),
  hr(),
  input_task_button("btn", "Fetch data"),

  verbatimTextOutput("result")
)

server <- function(input, output, session) {
  output$current_time <- renderText({
    invalidateLater(1000)
    format(Sys.time(), "%H:%M:%S %p")
  })

  task <- ExtendedTask$new(
    function() ncurl_aio("https://postman-echo.com/get", response = TRUE)
  ) |> bind_task_button("btn")

  observeEvent(input$btn, task$invoke())
  output$result <- renderPrint(task$result()$headers)
}

shinyApp(ui, server)
```

### 6. Server Example: Quarto Site with Dynamic API

This example shows how the unified server architecture makes it
straightforward to combine HTTP or WebSocket handlers to serve different
content over the same port.

If you’ve rendered a Quarto website and want to serve it locally – but
also expose a dynamic API endpoint alongside it, that’s possible with a
single
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md)
call:

``` r
library(nanonext)

server <- http_server(
  url = "http://127.0.0.1:0",
  handlers = list(
    # Serve your rendered Quarto site
    handler_directory("/", "_site"),

    # Add a prediction API endpoint
    handler("/api/predict", function(req) {
      input <- secretbase::jsondec(req$body)
      pred <- predict(model, newdata = input)
      list(
        status = 200L,
        headers = c("Content-Type" = "application/json"),
        body = secretbase::jsonenc(list(prediction = pred))
      )
    }, method = "POST")
  )
)

server$start()
server$url
# Browse to the URL to see your Quarto site with a live API behind it
```

Static pages are served at native speed by NNG while the prediction
endpoint is handled by R – no separate processes or ports required.
Adding TLS is a single argument.
