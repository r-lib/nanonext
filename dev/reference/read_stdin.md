# Read stdin

Reads `stdin` from a background thread, allowing the stream to be
accessed as messages from an NNG 'inproc' socket. As the read is
blocking, it can only be used in non-interactive sessions. Closing
`stdin` causes the background thread to exit and the socket connection
to end.

## Usage

``` r
read_stdin()
```

## Value

a Socket.

## Details

A 'pull' protocol socket is returned, and hence can only be used with
receive functions.
