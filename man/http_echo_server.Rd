\name{http_echo_server}
\alias{http_echo_server}
\title{Start an in-process NNG HTTP echo server (experimental)}
\description{
Starts a minimal HTTP server that echoes received data.
Returns a condition variable for synchronization.
}
\usage{
http_echo_server(port = 8080L)
}
\arguments{
  \item{port}{Port to listen on (integer)}
}
\value{
An external pointer to a condition variable.
}
\examples{
cv <- http_echo_server(8080L)
}