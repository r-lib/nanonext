# Generate Self-Signed Certificate and Key

Generate self-signed x509 certificate and 4096 bit RSA private/public
key pair for use with authenticated, encrypted TLS communications.

## Usage

``` r
write_cert(cn = "127.0.0.1", valid = "20301231235959")
```

## Arguments

- cn:

  \[default '127.0.0.1'\] character issuer common name (CN) for the
  certificate. This can be either a hostname or an IP address, but must
  match the actual server URL as client authentication will depend on
  it.

- valid:

  \[default '20301231235959'\] character 'not after' date-time in
  'yyyymmddhhmmss' format. The certificate is not valid after this time.

## Value

A list of length 2, comprising `$server` and `$client`. These may be
passed directly to the relevant argument of
[`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md).

## Details

Note that it can take a second or two for the key and certificate to be
generated.

## Examples

``` r
if (FALSE) { # interactive()
cert <- write_cert(cn = "127.0.0.1")
ser <- tls_config(server = cert$server)
cli <- tls_config(client = cert$client)

s <- socket(listen = "tls+tcp://127.0.0.1:5555", tls = ser)
s1 <- socket(dial = "tls+tcp://127.0.0.1:5555", tls = cli)

# secure TLS connection established

close(s1)
close(s)

cert
}
```
