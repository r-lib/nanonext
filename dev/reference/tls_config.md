# Create TLS Configuration

Create a TLS configuration object to be used for secure connections.
Specify `client` to create a client configuration or `server` to create
a server configuration.

## Usage

``` r
tls_config(client = NULL, server = NULL, pass = NULL, auth = is.null(server))
```

## Arguments

- client:

  **either** the character path to a file containing X.509
  certificate(s) in PEM format, comprising the certificate authority
  certificate chain (and revocation list if present), used to validate
  certificates presented by peers,  
  **or** a length 2 character vector comprising \[i\] the certificate
  authority certificate chain and \[ii\] the certificate revocation
  list, or empty string `""` if not applicable.

- server:

  **either** the character path to a file containing the PEM-encoded TLS
  certificate and associated private key (may contain additional
  certificates leading to a validation chain, with the leaf certificate
  first),  
  **or** a length 2 character vector comprising \[i\] the TLS
  certificate (optionally certificate chain) and \[ii\] the associated
  private key.

- pass:

  (optional) required only if the secret key supplied to `server` is
  encrypted with a password. For security, consider providing through a
  function that returns this value, rather than directly.

- auth:

  logical value whether to require authentication - by default TRUE for
  client and FALSE for server configurations. If TRUE, the session is
  only allowed to proceed if the peer has presented a certificate and it
  has been validated. If FALSE, authentication is optional, whereby a
  certificate is validated if presented by the peer, but the session
  allowed to proceed otherwise. If neither `client` nor `server` are
  supplied, then no authentication is performed and this argument has no
  effect.

## Value

A 'tlsConfig' object.

## Details

Specify one of `client` or `server` only, or neither (in which case an
empty client configuration is created), as a configuration can only be
of one type.

For creating client configurations for public internet usage, root CA
ceritficates may usually be found at
`/etc/ssl/certs/ca-certificates.crt` on Linux systems. Otherwise, root
CA certificates in PEM format are available at the Common CA Database
site run by Mozilla: <https://www.ccadb.org/resources> (select the
Server Authentication SSL/TLS certificates text file). *This link is not
endorsed; use at your own risk.*

## Examples

``` r
tls <- tls_config()
tls
#> < TLS client config | auth mode: none >
ncurl("https://postman-echo.com/get", timeout = 1000L, tls = tls)
#> $status
#> [1] 200
#> 
#> $headers
#> NULL
#> 
#> $data
#> [1] "{\"args\":{},\"headers\":{\"host\":\"postman-echo.com\",\"accept-encoding\":\"gzip, br\",\"x-forwarded-proto\":\"https\"},\"url\":\"https://postman-echo.com/get\"}"
#> 
```
