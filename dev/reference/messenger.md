# Messenger

Multi-threaded, console-based, 2-way instant messaging system with
authentication, based on NNG scalability protocols.

## Usage

``` r
messenger(url, auth = NULL)
```

## Arguments

- url:

  a URL to connect to, specifying the transport and address as a
  character string e.g. 'tcp://127.0.0.1:5555' (see
  [transports](https://nanonext.r-lib.org/dev/reference/transports.md)).

- auth:

  \[default NULL\] an R object (possessed by both parties) which serves
  as a pre-shared key on which to authenticate the communication. Note:
  the object is never sent, only a random subset of its md5 hash after
  serialization.

## Value

Invisible NULL.

## Note

The authentication protocol is an experimental proof of concept which is
not secure, and should not be used for critical applications.

## Usage

Type outgoing messages and hit return to send.

The timestamps of outgoing messages are prefixed by `>` and that of
incoming messages by `<`.

`:q` is the command to quit.

Both parties must supply the same argument for `auth`, otherwise the
party trying to connect will receive an 'authentication error' and be
immediately disconnected.
