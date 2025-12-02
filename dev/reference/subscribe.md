# Subscribe / Unsubscribe Topic

For a socket or context using the sub protocol in a publisher/subscriber
pattern. Set a topic to subscribe to, or remove a topic from the
subscription list.

## Usage

``` r
subscribe(con, topic = NULL)

unsubscribe(con, topic = NULL)
```

## Arguments

- con:

  a Socket or Context using the 'sub' protocol.

- topic:

  \[default NULL\] an atomic type or `NULL`. The default `NULL`
  subscribes to all topics / unsubscribes from all topics (if all topics
  were previously subscribed).

## Value

Invisibly, the passed Socket or Context.

## Details

To use pub/sub the publisher must:

- specify `mode = 'raw'` when sending.

- ensure the sent vector starts with the topic.

The subscriber should then receive specifying the correct mode.

## Examples

``` r
pub <- socket("pub", listen = "inproc://nanonext")
sub <- socket("sub", dial = "inproc://nanonext")

subscribe(sub, "examples")

send(pub, c("examples", "this is an example"), mode = "raw")
#> [1] 0
recv(sub, "character")
#> [1] "examples"           "this is an example"
send(pub, "examples will also be received", mode = "raw")
#> [1] 0
recv(sub, "character")
#> [1] "examples will also be received"
send(pub, c("other", "this other topic will not be received"), mode = "raw")
#> [1] 0
recv(sub, "character")
#> 'errorValue' int 8 | Try again
unsubscribe(sub, "examples")
send(pub, c("examples", "this example is no longer received"), mode = "raw")
#> [1] 0
recv(sub, "character")
#> 'errorValue' int 8 | Try again

subscribe(sub, 2)
send(pub, c(2, 10, 10, 20), mode = "raw")
#> [1] 0
recv(sub, "double")
#> [1]  2 10 10 20
unsubscribe(sub, 2)
send(pub, c(2, 10, 10, 20), mode = "raw")
#> [1] 0
recv(sub, "double")
#> 'errorValue' int 8 | Try again

close(pub)
close(sub)
```
