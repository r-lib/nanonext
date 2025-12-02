# Set Survey Time

For a socket or context using the surveyor protocol in a
surveyor/respondent pattern. Set the survey timeout in milliseconds
(remains valid for all subsequent surveys). Messages received by the
surveyor after the timer has ended are discarded.

## Usage

``` r
survey_time(con, value = 1000L)
```

## Arguments

- con:

  a Socket or Context using the 'surveyor' protocol.

- value:

  \[default 1000L\] integer survey timeout in milliseconds.

## Value

Invisibly, the passed Socket or Context.

## Details

After using this function, to start a new survey, the surveyor must:

- send a message.

- switch to receiving responses.

To respond to a survey, the respondent must:

- receive the survey message.

- send a reply using
  [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md)
  before the survey has timed out (a reply can only be sent after
  receiving a survey).

## Examples

``` r
sur <- socket("surveyor", listen = "inproc://nanonext")
res <- socket("respondent", dial = "inproc://nanonext")

survey_time(sur, 1000)

send(sur, "reply to this survey")
#> [1] 0
aio <- recv_aio(sur)

recv(res)
#> [1] "reply to this survey"
s <- send_aio(res, "replied")

call_aio(aio)$data
#> [1] "replied"

close(sur)
close(res)
```
