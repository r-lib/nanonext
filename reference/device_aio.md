# Device (Async)

Create an asynchronous device: a zero-copy forwarder that relays raw
messages between two Sockets. This is the building block for brokers and
proxies, such as a publisher/subscriber relay or a pair-to-pair bridge.

## Usage

``` r
device_aio(s1, s2 = s1)
```

## Arguments

- s1:

  a Socket, in raw mode.

- s2:

  a Socket, in raw mode, using the complementary protocol to `s1`. If
  not supplied, defaults to `s1` to create a reflector.

## Value

A 'sendAio' (object of class 'sendAio') (invisibly).

## Details

A device runs on background threads and relays messages until it is
stopped or an error occurs. The returned 'sendAio' resolves only at that
point: its `$result` is an 'unresolved' logical NA while the device is
running, and otherwise the integer exit code (usually the error that
caused it to stop, such as a Socket being closed).

Both Sockets must be opened in raw mode (see
[`socket()`](https://nanonext.r-lib.org/reference/socket.md)) and use
complementary protocols, that is the peer protocol of each must be the
protocol of the other (for example two 'pair' Sockets, or a 'pub' and a
'sub' Socket). The same Socket may be supplied for both arguments to
create a reflector.

To stop the device, use
[`stop_aio()`](https://nanonext.r-lib.org/reference/stop_aio.md), or
close either of the Sockets. To block and wait for the device to stop,
use [`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md).

## See also

[`send_aio()`](https://nanonext.r-lib.org/reference/send_aio.md) for the
structure of the returned 'sendAio'.

## Examples

``` r
s1 <- socket("pair", listen = "inproc://device1", raw = TRUE)
s2 <- socket("pair", listen = "inproc://device2", raw = TRUE)

dev <- device_aio(s1, s2)
dev$result
#> 'unresolved' logi NA

stop_aio(dev)
dev$result
#> 'errorValue' int 20 | Operation canceled
close(s1)
close(s2)
```
