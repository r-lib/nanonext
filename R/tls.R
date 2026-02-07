# nanonext - TLS Configuration -------------------------------------------------

#' Create TLS Configuration
#'
#' Create a TLS configuration object to be used for secure connections. Specify
#' `client` to create a client configuration or `server` to create a server
#' configuration.
#'
#' Specify one of `client` or `server` only, or neither (in which case an empty
#' client configuration is created), as a configuration can only be of one type.
#'
#' @section Public Internet HTTPS:
#'
#' When making HTTPS requests over the public internet, you should supply a TLS
#' configuration to validate server certificates.
#'
#' Root CA certificates in PEM format may be found at:
#'
#' - Linux: \file{/etc/ssl/certs/ca-certificates.crt} or
#'   \file{/etc/pki/tls/certs/ca-bundle.crt}
#' - macOS: \file{/etc/ssl/cert.pem}
#' - Windows: download from the Common CA Database site run by Mozilla:
#'   <https://www.ccadb.org/resources> (select the Server Authentication SSL/TLS
#'   certificates text file). *This link is not endorsed; use at your own risk.*
#'
#' @param client **either** the character path to a file containing X.509
#'   certificate(s) in PEM format, comprising the certificate authority
#'   certificate chain (and revocation list if present), used to validate
#'   certificates presented by peers,\cr
#'   **or** a length 2 character vector comprising \[i\] the certificate
#'   authority certificate chain and \[ii\] the certificate revocation list, or
#'   empty string `""` if not applicable.
#' @param server **either** the character path to a file containing the
#'   PEM-encoded TLS certificate and associated private key (may contain
#'   additional certificates leading to a validation chain, with the leaf
#'   certificate first),\cr
#'   **or** a length 2 character vector comprising \[i\] the TLS certificate
#'   (optionally certificate chain) and \[ii\] the associated private key.
#' @param pass (optional) required only if the secret key supplied to `server`
#'   is encrypted with a password. For security, consider providing through a
#'   function that returns this value, rather than directly.
#' @param auth logical value whether to require authentication - by default TRUE
#'   for client and FALSE for server configurations. If TRUE, the session is
#'   only allowed to proceed if the peer has presented a certificate and it has
#'   been validated. If FALSE, authentication is optional, whereby a certificate
#'   is validated if presented by the peer, but the session allowed to proceed
#'   otherwise. If neither `client` nor `server` are supplied, then no
#'   authentication is performed and this argument has no effect.
#'
#' @return A 'tlsConfig' object.
#'
#' @examples
#' tls <- tls_config()
#' tls
#' ncurl("https://postman-echo.com/get", timeout = 1000L, tls = tls)
#'
#' # client TLS configuration for public internet HTTPS on Linux
#' # tls <- tls_config(client = "/etc/ssl/certs/ca-certificates.crt")
#'
#' @export
#'
tls_config <- function(client = NULL, server = NULL, pass = NULL, auth = is.null(server))
  .Call(rnng_tls_config, client, server, pass, auth)

# nanonext - Key Gen and Certificates ------------------------------------------

#' Generate Self-Signed Certificate and Key
#'
#' Generate self-signed x509 certificate and 4096 bit RSA private/public key
#' pair for use with authenticated, encrypted TLS communications.
#'
#' Note that it can take a second or two for the key and certificate to be
#' generated.
#'
#' @param cn \[default '127.0.0.1'\] character issuer common name (CN) for the
#'   certificate. This can be either a hostname or an IP address, but must match
#'   the actual server URL as client authentication will depend on it.
#' @param valid \[default '20301231235959'\] character 'not after' date-time in
#'   'yyyymmddhhmmss' format. The certificate is not valid after this time.
#'
#' @return A list of length 2, comprising `$server` and `$client`. These may be
#'   passed directly to the relevant argument of [tls_config()].
#'
#' @examplesIf interactive()
#' cert <- write_cert(cn = "127.0.0.1")
#' ser <- tls_config(server = cert$server)
#' cli <- tls_config(client = cert$client)
#'
#' s <- socket(listen = "tls+tcp://127.0.0.1:5555", tls = ser)
#' s1 <- socket(dial = "tls+tcp://127.0.0.1:5555", tls = cli)
#'
#' # secure TLS connection established
#'
#' close(s1)
#' close(s)
#'
#' cert
#'
#' @export
#'
write_cert <- function(cn = "127.0.0.1", valid = "20301231235959")
  .Call(rnng_write_cert, cn, valid)
