# Get Statistic for a Socket, Listener or Dialer

Obtain value of a statistic for a Socket, Listener or Dialer. This
function exposes the stats interface of NNG.

## Usage

``` r
stat(object, name)
```

## Arguments

- object:

  a Socket, Listener or Dialer.

- name:

  character name of statistic to return.

## Value

The value of the statistic (character or double depending on the type of
statistic requested) if available, or else NULL.

## Details

Note: the values of individual statistics are guaranteed to be atomic,
but due to the way statistics are collected there may be discrepancies
between them at times. For example, statistics counting bytes and
messages received may not reflect the same number of messages, depending
on when the snapshot is taken. This potential inconsistency arises as a
result of optimisations to minimise the impact of statistics on actual
operations.

## Stats

The following stats may be requested for a Socket:

- 'id' - numeric id of the socket.

- 'name' - character socket name.

- 'protocol' - character protocol type e.g. 'bus'.

- 'pipes' - numeric number of pipes (active connections).

- 'dialers' - numeric number of listeners attached to the socket.

- 'listeners' - numeric number of dialers attached to the socket.

The following stats may be requested for a Listener / Dialer:

- 'id' - numeric id of the listener / dialer.

- 'socket' - numeric id of the socket of the listener / dialer.

- 'url' - character URL address.

- 'pipes' - numeric number of pipes (active connections).

The following additional stats may be requested for a Listener:

- 'accept' - numeric total number of connection attempts, whether
  successful or not.

- 'reject' - numeric total number of rejected connection attempts e.g.
  due to incompatible protocols.

The following additional stats may be requested for a Dialer:

- 'connect' - numeric total number of connection attempts, whether
  successful or not.

- 'reject' - numeric total number of rejected connection attempts e.g.
  due to incompatible protocols.

- 'refused' - numeric total number of refused connections e.g. when
  starting synchronously with no listener on the other side.

## Examples

``` r
s <- socket("bus", listen = "inproc://stats")
stat(s, "pipes")
#> [1] 0

s1 <- socket("bus", dial = "inproc://stats")
stat(s, "pipes")
#> [1] 1

close(s1)
stat(s, "pipes")
#> [1] 0

close(s)
```
