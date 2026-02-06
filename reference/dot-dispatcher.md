# Dispatcher

Run the dispatcher event loop for mirai task distribution.

## Usage

``` r
.dispatcher(sock, psock, monitor, reset, serial, envir, next_stream)
```

## Arguments

- sock:

  REP socket for host communication.

- psock:

  POLY socket for daemon communication.

- monitor:

  Monitor object for pipe events (its CV is used for signaling).

- reset:

  Pre-serialized connection reset error (raw vector).

- serial:

  Serialization configuration (list or NULL).

- envir:

  Environment containing RNG stream state.

- next_stream:

  Function to get next RNG stream, called as next_stream(envir).

## Value

Integer status code (0 = normal exit).
