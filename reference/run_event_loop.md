# Run the Event Loop

Runs the later event loop, blocking until the next event and dispatching
any scheduled callbacks. Used to process a server's (see
[`http_server()`](https://nanonext.r-lib.org/reference/http_server.md))
or other asynchronous operations' callbacks on R's main thread.

## Usage

``` r
run_event_loop(timeout = Inf)
```

## Arguments

- timeout:

  maximum time to wait in milliseconds. The default `Inf` blocks until
  an event occurs.

## Value

Logical `TRUE` if a callback was executed, `FALSE` otherwise.

## Details

Requires the later package.
