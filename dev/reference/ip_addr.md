# IP Address

Returns a character string comprising the local network IPv4 address, or
vector if there are multiple addresses from multiple network adapters,
or an empty character string if unavailable.

## Usage

``` r
ip_addr()
```

## Value

A named character string.

## Details

The IP addresses will be named by interface (adapter friendly name on
Windows) e.g. 'eth0' or 'en0'.

## Examples

``` r
ip_addr()
#>         eth0      docker0 
#> "10.1.0.152" "172.17.0.1" 
```
