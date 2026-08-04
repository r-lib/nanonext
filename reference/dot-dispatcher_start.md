# Start In-Process Dispatcher

Start In-Process Dispatcher

## Usage

``` r
.dispatcher_start(url, disp_url, tls, serial, stream, capacity, cvar = NULL)
```

## Arguments

- url:

  URL to listen at for daemon connections.

- disp_url:

  inproc:// URL for host REQ socket.

- tls:

  TLS configuration or NULL.

- serial:

  Serialization configuration (list or NULL).

- stream:

  RNG stream integer vector (.Random.seed).

- capacity:

  Memory budget in MB (metric, 1 MB = 1,000,000 bytes) for queued task
  payloads. `NULL`, 0, non-finite, or negative values are treated as
  unlimited.

- cvar:

  Unused; accepted for compatibility and ignored.

## Value

External pointer to dispatcher handle.
