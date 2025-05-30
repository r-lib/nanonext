% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/listdial.R
\name{listen}
\alias{listen}
\title{Listen to an Address from a Socket}
\usage{
listen(
  socket,
  url = "inproc://nanonext",
  tls = NULL,
  autostart = TRUE,
  fail = c("warn", "error", "none")
)
}
\arguments{
\item{socket}{a Socket.}

\item{url}{[default 'inproc://nanonext'] a URL to dial, specifying the
transport and address as a character string e.g. 'inproc://anyvalue' or
'tcp://127.0.0.1:5555' (see \link{transports}).}

\item{tls}{[default NULL] for secure tls+tcp:// or wss:// connections only,
provide a TLS configuration object created by \code{\link[=tls_config]{tls_config()}}.}

\item{autostart}{[default TRUE] whether to start the listener. Set to FALSE
if setting configuration options on the listener as it is not generally
possible to change these once started.}

\item{fail}{[default 'warn'] failure mode - a character value or integer
equivalent, whether to warn (1L), error (2L), or for none (3L) just return
an 'errorValue' without any corresponding warning.}
}
\value{
Invisibly, an integer exit code (zero on success). A new Listener
(object of class 'nanoListener' and 'nano') is created and bound to the
Socket if successful.
}
\description{
Creates a new Listener and binds it to a Socket.
}
\details{
To view all Listeners bound to a socket use \verb{$listener} on the socket,
which returns a list of Listener objects. To access any individual Listener
(e.g. to set options on it), index into the list e.g. \verb{$listener[[1]]}
to return the first Listener.

A listener is an external pointer to a listener object, which accepts
incoming connections. A given listener object may have many connections at
the same time, much like an HTTP server can have many connections to multiple
clients simultaneously.
}
\section{Further details}{


Dialers and Listeners are always associated with a single socket. A given
socket may have multiple Listeners and/or multiple Dialers.

The client/server relationship described by dialer/listener is completely
orthogonal to any similar relationship in the protocols. For example, a rep
socket may use a dialer to connect to a listener on an req socket. This
orthogonality can lead to innovative solutions to otherwise challenging
communications problems.

Any configuration options on the dialer/listener should be set by \code{\link[=opt<-]{opt<-()}}
before starting the dialer/listener with \code{\link[=start]{start()}}.

Dialers/Listeners may be destroyed by \code{\link[=close]{close()}}. They are also closed when
their associated socket is closed.
}

\examples{
socket <- socket("req")
listen(socket, url = "inproc://nanolisten", autostart = FALSE)
socket$listener
start(socket$listener[[1]])
socket$listener
close(socket$listener[[1]])
close(socket)

nano <- nano("bus")
nano$listen(url = "inproc://nanolisten", autostart = FALSE)
nano$listener
nano$listener_start()
nano$listener
close(nano$listener[[1]])
nano$close()

}
