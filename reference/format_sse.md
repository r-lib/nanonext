# Format Server-Sent Event

Helper function to format messages according to the Server-Sent Events
(SSE) specification. Use with
[`handler_stream()`](https://nanonext.r-lib.org/reference/handler_stream.md)
to create SSE endpoints.

## Usage

``` r
format_sse(data, event = NULL, id = NULL, retry = NULL)
```

## Arguments

- data:

  The data payload. Will be prefixed with "data: " on each line.

- event:

  \[default NULL\] Optional event type (e.g., "message", "error").

- id:

  \[default NULL\] Optional event ID for client reconnection.

- retry:

  \[default NULL\] Optional retry interval in milliseconds.

## Value

A character string formatted as an SSE message, ready to pass to
`conn$send()`.

## Details

Server-Sent Events is a W3C standard for server-to-client streaming over
HTTP, supported natively by browsers via the `EventSource` API. SSE is
commonly used for real-time updates, notifications, and LLM token
streaming.

SSE messages have this format:

    event: <event-type>
    id: <event-id>
    retry: <milliseconds>
    data: <data-line-1>
    data: <data-line-2>

Each message ends with two newlines. Multi-line data is split and each
line prefixed with "data: ".

When using SSE with
[`handler_stream()`](https://nanonext.r-lib.org/reference/handler_stream.md),
set the appropriate headers:

- `Content-Type: text/event-stream`

- `Cache-Control: no-cache`

- `X-Accel-Buffering: no` (prevents proxy buffering)

## See also

[`handler_stream()`](https://nanonext.r-lib.org/reference/handler_stream.md)
for creating streaming HTTP endpoints.

## Examples

``` r
format_sse(data = "Hello")
#> [1] "data: Hello\n\n"
#> "data: Hello\n\n"

format_sse(data = "Hello", event = "greeting")
#> [1] "event: greeting\ndata: Hello\n\n"
#> "event: greeting\ndata: Hello\n\n"

format_sse(data = "Line 1\nLine 2")
#> [1] "data: Line 1\ndata: Line 2\n\n"
#> "data: Line 1\ndata: Line 2\n\n"

# Typical SSE endpoint setup
h <- handler_stream("/events", function(conn, req) {
  conn$set_header("Content-Type", "text/event-stream")
  conn$set_header("Cache-Control", "no-cache")
  conn$set_header("X-Accel-Buffering", "no")
  conn$send(format_sse(data = "connected", id = "1"))
})
```
