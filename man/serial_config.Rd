% Generated by roxygen2: do not edit by hand
% Please edit documentation in R/utils.R
\name{serial_config}
\alias{serial_config}
\title{Create Serialization Configuration}
\usage{
serial_config(class, sfunc, ufunc)
}
\arguments{
\item{class}{a character string (or vector) of the class of object custom
serialization functions are applied to, e.g. \code{'ArrowTabular'} or
\code{c('torch_tensor', 'ArrowTabular')}.}

\item{sfunc}{a function (or list of functions) that accepts a reference
object inheriting from \code{class} and returns a raw vector.}

\item{ufunc}{a function (or list of functions) that accepts a raw vector and
returns a reference object.}
}
\value{
A list comprising the configuration. This should be set on a Socket
using \code{\link[=opt<-]{opt<-()}} with option name \code{"serial"}.
}
\description{
Returns a serialization configuration, which may be set on a Socket for
custom serialization and unserialization of non-system reference objects,
allowing these to be sent and received between different R sessions. Once
set, the functions apply to all send and receive operations performed in mode
'serial' over the Socket, or Context created from the Socket.
}
\details{
This feature utilises the 'refhook' system of R native serialization.
}
\examples{
cfg <- serial_config("test_cls", function(x) serialize(x, NULL), unserialize)
cfg

cfg <- serial_config(
  c("class_one", "class_two"),
  list(function(x) serialize(x, NULL), function(x) serialize(x, NULL)),
  list(unserialize, unserialize)
)
cfg

s <- socket()
opt(s, "serial") <- cfg

# provide an empty list to remove registered functions
opt(s, "serial") <- list()

close(s)

}
