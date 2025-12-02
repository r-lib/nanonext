# Close Connection

Close Connection on a Socket, Context, Dialer, Listener, Stream, Pipe,
or ncurl Session.

## Usage

``` r
# S3 method for class 'nanoContext'
close(con, ...)

# S3 method for class 'nanoDialer'
close(con, ...)

# S3 method for class 'nanoListener'
close(con, ...)

# S3 method for class 'ncurlSession'
close(con, ...)

# S3 method for class 'nanoSocket'
close(con, ...)

# S3 method for class 'nanoStream'
close(con, ...)
```

## Arguments

- con:

  a Socket, Context, Dialer, Listener, Stream, or 'ncurlSession'.

- ...:

  not used.

## Value

Invisibly, an integer exit code (zero on success).

## Details

Closing an object explicitly frees its resources. An object can also be
removed directly in which case its resources are freed when the object
is garbage collected.

Closing a Socket associated with a Context also closes the Context.

Dialers and Listeners are implicitly closed when the Socket they are
associated with is closed.

Closing a Socket or a Context: messages that have been submitted for
sending may be flushed or delivered, depending upon the transport.
Closing the Socket while data is in transmission will likely lead to
loss of that data. There is no automatic linger or flush to ensure that
the Socket send buffers have completely transmitted.

Closing a Stream: if any send or receive operations are pending, they
will be terminated and any new operations will fail after the connection
is closed.

Closing an 'ncurlSession' closes the http(s) connection.

## See also

[`reap()`](https://nanonext.r-lib.org/dev/reference/reap.md)
