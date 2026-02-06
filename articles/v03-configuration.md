# nanonext - Configuration and Security

``` r
library(nanonext)
```

### 1. TLS Secure Connections

Secure connections use NNG and Mbed TLS libraries. Enable them by:

1.  Specifying a secure `tls+tcp://` or `wss://` URL
2.  Passing a TLS configuration object to the ‘tls’ argument of
    [`listen()`](https://nanonext.r-lib.org/reference/listen.md) or
    [`dial()`](https://nanonext.r-lib.org/reference/dial.md)

Create TLS configurations with
[`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md): -
Client configuration: requires PEM-encoded CA certificate to verify
server identity - Server configuration: requires certificate and private
key

Certificates may be supplied as files or character vectors. Valid X.509
certificates from Certificate Authorities are supported.

The convenience function
[`write_cert()`](https://nanonext.r-lib.org/reference/write_cert.md)
generates a 4096-bit RSA key pair and self-signed X.509 certificate. The
‘cn’ argument must match exactly the hostname/IP address of the URL
(e.g., use ‘127.0.0.1’ throughout, or ‘localhost’ throughout, not
mixed).

``` r
cert <- write_cert(cn = "127.0.0.1")
str(cert)
#> List of 2
#>  $ server: chr [1:2] "-----BEGIN CERTIFICATE-----\nMIIFOTCCAyGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQDDAkxMjcu\nMC4wLjExETAPBgNV"| __truncated__ "-----BEGIN RSA PRIVATE KEY-----\nMIIJKAIBAAKCAgEA7bh7hshxv3wfY81Gkct1ffRlFB4XJj3vAH+wiM1l8Q9WAllX\nIfyEVwGdC665"| __truncated__
#>  $ client: chr [1:2] "-----BEGIN CERTIFICATE-----\nMIIFOTCCAyGgAwIBAgIBATANBgkqhkiG9w0BAQsFADA0MRIwEAYDVQQDDAkxMjcu\nMC4wLjExETAPBgNV"| __truncated__ ""

ser <- tls_config(server = cert$server)
ser
#> < TLS server config | auth mode: optional >

cli <- tls_config(client = cert$client)
cli
#> < TLS client config | auth mode: required >

s <- socket(listen = "tls+tcp://127.0.0.1:5558", tls = ser)
s1 <- socket(dial = "tls+tcp://127.0.0.1:5558", tls = cli)

# secure TLS connection established

close(s1)
close(s)
```

### 2. Options

Use [`opt()`](https://nanonext.r-lib.org/reference/opt.md) and
[`'opt<-'()`](https://nanonext.r-lib.org/reference/opt.md) to get and
set options on Sockets, Contexts, Streams, Listeners, or Dialers. See
function documentation for available options.

To configure dialers or listeners after creation, specify
`autostart = FALSE` (configuration cannot be changed after starting).

``` r
s <- socket(listen = "inproc://options", autostart = FALSE)

# no maximum message size
opt(s$listener[[1]], "recv-size-max")
#> [1] 0

# enforce maximum message size to protect against denial-of-service attacks
opt(s$listener[[1]], "recv-size-max") <- 8192L

opt(s$listener[[1]], "recv-size-max")
#> [1] 8192

start(s$listener[[1]])
```

### 3. Custom Serialization

The special write-only option ‘serial’ sets a serialization
configuration via
[`serial_config()`](https://nanonext.r-lib.org/reference/serial_config.md).
This registers custom functions for serializing/unserializing reference
objects using R’s ‘refhook’ system, enabling transparent send/receive
with mode ‘serial’. Configurations apply to the Socket and all Contexts
created from it.

``` r
serial <- serial_config("obj_class", function(x) serialize(x, NULL), unserialize)
opt(s, "serial") <- serial

close(s)
```

### 4. Statistics

Use [`stat()`](https://nanonext.r-lib.org/reference/stat.md) to access
NNG’s statistics framework. Query Sockets, Listeners, or Dialers for
statistics such as connection attempts and current connections. See
function documentation for available statistics.

``` r
s <- socket(listen = "inproc://stat")

# no active connections (pipes)
stat(s, "pipes")
#> [1] 0

s1 <- socket(dial = "inproc://stat")

# one now that the dialer has connected
stat(s, "pipes")
#> [1] 1

close(s)
```
