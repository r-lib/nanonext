# Start In-Process Dispatcher

Start In-Process Dispatcher

## Usage

``` r
.dispatcher_start(url, disp_url, tls, serial, stream, limit, cvar)
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

- limit:

  Maximum in-flight tasks (NULL for unlimited).

- cvar:

  Shared condition variable for limit signaling.

## Value

External pointer to dispatcher handle.
