% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/tls.R
\name{tls_config}
\alias{tls_config}
\title{Create TLS Configuration}
\usage{
tls_config(client = NULL, server = NULL, pass = NULL, auth = is.null(server))
}
\arguments{
\item{client}{\strong{either} the character path to a file containing X.509
certificate(s) in PEM format, comprising the certificate authority
certificate chain (and revocation list if present), used to validate
certificates presented by peers,\cr
\strong{or} a length 2 character vector comprising [i] the certificate
authority certificate chain and [ii] the certificate revocation list, or
empty string \code{""} if not applicable.}

\item{server}{\strong{either} the character path to a file containing the
PEM-encoded TLS certificate and associated private key (may contain
additional certificates leading to a validation chain, with the leaf
certificate first),\cr
\strong{or} a length 2 character vector comprising [i] the TLS certificate
(optionally certificate chain) and [ii] the associated private key.}

\item{pass}{(optional) required only if the secret key supplied to \code{server}
is encrypted with a password. For security, consider providing through a
function that returns this value, rather than directly.}

\item{auth}{logical value whether to require authentication - by default TRUE
for client and FALSE for server configurations. If TRUE, the session is
only allowed to proceed if the peer has presented a certificate and it has
been validated. If FALSE, authentication is optional, whereby a certificate
is validated if presented by the peer, but the session allowed to proceed
otherwise. If neither \code{client} nor \code{server} are supplied, then no
authentication is performed and this argument has no effect.}
}
\value{
A 'tlsConfig' object.
}
\description{
Create a TLS configuration object to be used for secure connections. Specify
\code{client} to create a client configuration or \code{server} to create a server
configuration.
}
\details{
Specify one of \code{client} or \code{server} only, or neither (in which case an empty
client configuration is created), as a configuration can only be of one type.

For creating client configurations for public internet usage, root CA
ceritficates may usually be found at \file{/etc/ssl/certs/ca-certificates.crt}
on Linux systems. Otherwise, root CA certificates in PEM format are available
at the Common CA Database site run by Mozilla:
\url{https://www.ccadb.org/resources} (select the Server Authentication
SSL/TLS certificates text file).
\emph{This link is not endorsed; use at your own risk.}
}
\examples{
tls <- tls_config()
tls
ncurl("https://postman-echo.com/get", timeout = 1000L, tls = tls)

}
