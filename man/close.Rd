% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/context.R, R/listdial.R, R/ncurl.R, R/socket.R,
%   R/stream.R
\name{close.nanoContext}
\alias{close.nanoContext}
\alias{close.nanoDialer}
\alias{close.nanoListener}
\alias{close.ncurlSession}
\alias{close}
\alias{close.nanoSocket}
\alias{close.nanoStream}
\title{Close Connection}
\usage{
\method{close}{nanoContext}(con, ...)

\method{close}{nanoDialer}(con, ...)

\method{close}{nanoListener}(con, ...)

\method{close}{ncurlSession}(con, ...)

\method{close}{nanoSocket}(con, ...)

\method{close}{nanoStream}(con, ...)
}
\arguments{
\item{con}{a Socket, Context, Dialer, Listener, Stream, or 'ncurlSession'.}

\item{...}{not used.}
}
\value{
Invisibly, an integer exit code (zero on success).
}
\description{
Close Connection on a Socket, Context, Dialer, Listener, Stream, Pipe, or
ncurl Session.
}
\details{
Closing an object explicitly frees its resources. An object can also be
removed directly in which case its resources are freed when the object is
garbage collected.

Closing a Socket associated with a Context also closes the Context.

Dialers and Listeners are implicitly closed when the Socket they are
associated with is closed.

Closing a Socket or a Context: messages that have been submitted for sending
may be flushed or delivered, depending upon the transport. Closing the Socket
while data is in transmission will likely lead to loss of that data. There is
no automatic linger or flush to ensure that the Socket send buffers have
completely transmitted.

Closing a Stream: if any send or receive operations are pending, they will be
terminated and any new operations will fail after the connection is closed.

Closing an 'ncurlSession' closes the http(s) connection.
}
\seealso{
\code{\link[=reap]{reap()}}
}
