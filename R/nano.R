# nanonext - Core - Nano Object and S3 Methods ---------------------------------

#' Create Nano Object
#'
#' Create a nano object, encapsulating a Socket, Dialers/Listeners and
#' associated methods.
#'
#' This function encapsulates a Socket, Dialer and/or Listener, and its
#' associated methods.
#'
#' The Socket may be accessed by `$socket`, and the Dialer or Listener by
#' `$dialer[[1]]` or `$listener[[1]]` respectively.
#'
#' The object's methods may be accessed by `$` e.g. `$send()` or `$recv()`.
#' These methods mirror their functional equivalents, with the same arguments
#' and defaults, apart from that the first argument of the functional equivalent
#' is mapped to the object's encapsulated socket (or context, if active) and
#' does not need to be supplied.
#'
#' More complex network topologies may be created by binding further dialers or
#' listeners using the object's `$dial()` and `$listen()` methods. The new
#' dialer/listener will be attached to the object e.g. if the object already has
#' a dialer, then at `$dialer[[2]]` etc.
#'
#' Note that `$dialer_opt()` and `$listener_opt()` methods will be available
#' once dialers/listeners are attached to the object. These methods get or apply
#' settings for all dialers or listeners equally. To get or apply settings for
#' individual dialers/listeners, access them directly via `$dialer[[2]]` or
#' `$listener[[2]]` etc.
#'
#' The methods `$opt()`, and also `$dialer_opt()` or `$listener_opt()` as may be
#' applicable, will get the requested option if a single argument `name` is
#' provided, and will set the value for the option if both arguments `name` and
#' `value` are provided.
#'
#' For Dialers or Listeners not automatically started, the `$dialer_start()` or
#' `$listener_start()` methods will be available. These act on the most recently
#' created Dialer or Listener respectively.
#'
#' For applicable protocols, new contexts may be created by using the
#' `$context_open()` method. This will attach a new context at `$context` as
#' well as a `$context_close()` method. While a context is active, all object
#' methods use the context rather than the socket. A new context may be created
#' by calling `$context_open()`, which will replace any existing context. It is
#' only necessary to use `$context_close()` to close the existing context and
#' revert to using the socket.
#'
#' @inheritParams socket
#'
#' @return A nano object of class 'nanoObject'.
#'
#' @examples
#' nano <- nano("bus", listen = "inproc://nanonext")
#' nano
#' nano$socket
#' nano$listener[[1]]
#'
#' nano$opt("send-timeout", 1500)
#' nano$opt("send-timeout")
#'
#' nano$listen(url = "inproc://nanonextgen")
#' nano$listener
#'
#' nano1 <- nano("bus", dial = "inproc://nanonext")
#' nano$send("example test", mode = "raw")
#' nano1$recv("character")
#'
#' nano$close()
#' nano1$close()
#'
#' @export
#'
nano <- function(protocol = c("bus", "pair", "poly", "push", "pull", "pub",
                              "sub", "req", "rep", "surveyor", "respondent"),
                 dial = NULL,
                 listen = NULL,
                 tls = NULL,
                 autostart = TRUE) {

  nano <- `class<-`(new.env(hash = FALSE), "nanoObject")
  socket <- socket(protocol)
  sock2 <- NULL
  makeActiveBinding(sym = "socket",
                    fun = function(x) if (length(sock2)) sock2 else socket,
                    env = nano)
  is_poly <- attr(socket, "protocol") == "poly"

  if (length(dial)) {
    r <- dial(socket, url = dial, tls = tls, autostart = autostart)
    if (r == 0L) {
      nano[["dialer"]] <- attr(socket, "dialer")
      nano[["dialer_opt"]] <- function(name, value)
        if (missing(value))
          lapply(.subset2(nano, "dialer"), opt, name = name) else
            invisible(lapply(.subset2(nano, "dialer"), `opt<-`, name = name, value = value))
      if (isFALSE(autostart)) nano[["dialer_start"]] <- function(async = TRUE) {
        s <- start.nanoDialer(.subset2(nano, "dialer")[[1L]], async = async)
        if (s == 0L) rm("dialer_start", envir = nano)
        invisible(s)
      }
    }
  }

  if (length(listen)) {
    r <- listen(socket, url = listen, tls = tls, autostart = autostart)
    if (r == 0L) {
      nano[["listener"]] <- attr(socket, "listener")
      nano[["listener_opt"]] <- function(name, value)
        if (missing(value))
          lapply(.subset2(nano, "listener"), opt, name = name) else
            invisible(lapply(.subset2(nano, "listener"), `opt<-`, name = name, value = value))
      if (isFALSE(autostart)) nano[["listener_start"]] <- function() {
        s <- start.nanoListener(.subset2(nano, "listener")[[1L]])
        if (s == 0L) rm("listener_start", envir = nano)
        invisible(s)
      }
    }
  }

  nano[["close"]] <- function() close(.subset2(nano, "socket"))

  nano[["dial"]] <- function(url = "inproc://nanonext", tls = NULL, autostart = TRUE) {
    r <- dial(socket, url = url, tls = tls, autostart = autostart)
    if (r == 0L) {
      nano[["dialer"]] <- attr(socket, "dialer")
      nano[["dialer_opt"]] <- function(name, value)
        if (missing(value))
          lapply(.subset2(nano, "dialer"), opt, name = name) else
            invisible(lapply(.subset2(nano, "dialer"), `opt<-`, name = name, value = value))
      if (isFALSE(autostart)) nano[["dialer_start"]] <- function(async = TRUE) {
        s <- start.nanoDialer((d <- .subset2(nano, "dialer"))[[length(d)]], async = async)
        if (s == 0L) rm("dialer_start", envir = nano)
        invisible(s)
      }
    }
    invisible(r)
  }

  nano[["listen"]] <- function(url = "inproc://nanonext", tls = NULL, autostart = TRUE) {
    r <- listen(socket, url = url, tls = tls, autostart = autostart)
    if (r == 0L) {
      nano[["listener"]] <- attr(socket, "listener")
      nano[["listener_opt"]] <- function(name, value)
        if (missing(value))
          lapply(.subset2(nano, "listener"), opt, name = name) else
            invisible(lapply(.subset2(nano, "listener"), `opt<-`, name = name, value = value))
      if (isFALSE(autostart)) nano[["listener_start"]] <- function() {
        s <- start.nanoListener((l <- .subset2(nano, "listener"))[[length(l)]])
        if (s == 0L) rm("listener_start", envir = nano)
        invisible(s)
      }
    }
    invisible(r)
  }

  nano[["recv"]] <- function(mode = c("serial", "character", "complex", "double",
                                      "integer", "logical", "numeric", "raw", "string"),
                             block = NULL)
    recv(socket, mode = mode, block = block)

  nano[["recv_aio"]] <- function(mode = c("serial", "character", "complex", "double",
                                          "integer", "logical", "numeric", "raw", "string"),
                                 timeout = NULL)
    recv_aio(socket, mode = mode, timeout = timeout)

  nano[["send"]] <- if (is_poly) {
    function(data, mode = c("serial", "raw"), block = NULL, pipe = 0L)
      send(socket, data = data, mode = mode, block = block, pipe = pipe)
  } else {
    function(data, mode = c("serial", "raw"), block = NULL)
      send(socket, data = data, mode = mode, block = block)
  }

  nano[["send_aio"]] <- if (is_poly) {
    function(data, mode = c("serial", "raw"), timeout = NULL, pipe = 0L)
      send_aio(socket, data = data, mode = mode, timeout = timeout, pipe = pipe)
  } else {
    function(data, mode = c("serial", "raw"), timeout = NULL)
      send_aio(socket, data = data, mode = mode, timeout = timeout)
  }

  nano[["opt"]] <- function(name, value)
    if (missing(value)) opt(socket, name = name) else
      invisible(`opt<-`(socket, name = name, value = value))

  nano[["stat"]] <- function(name) stat(socket, name = name)

  switch(attr(socket, "protocol"),
         req = ,
         rep = {
           nano[["context_open"]] <- function() {
             if (is.null(sock2)) sock2 <<- socket
             nano[["context_close"]] <- function() if (length(sock2)) {
               r <- close(socket)
               socket <<- sock2
               sock2 <<- NULL
               rm(list = c("context", "context_close"), envir = nano)
               r
             }
            socket <<- nano[["context"]] <- context(sock2)
           }
         },
         sub = {
           nano[["context_open"]] <- function() {
             if (is.null(sock2)) sock2 <<- socket
             nano[["context_close"]] <- function() if (length(sock2)) {
               r <- close(socket)
               socket <<- sock2
               sock2 <<- NULL
               rm(list = c("context", "context_close"), envir = nano)
               r
             }
             socket <<- nano[["context"]] <- context(sock2)
           }
           nano[["subscribe"]] <- function(topic = NULL)
             subscribe(socket, topic = topic)
           nano[["unsubscribe"]] <- function(topic = NULL)
             unsubscribe(socket, topic = topic)
         },
         surveyor = {
           nano[["context_open"]] <- function() {
             if (is.null(sock2)) sock2 <<- socket
             nano[["context_close"]] <- function() if (length(sock2)) {
               r <- close(socket)
               socket <<- sock2
               sock2 <<- NULL
               rm(list = c("context", "context_close"), envir = nano)
               r
             }
             socket <<- nano[["context"]] <- context(sock2)
           }
           nano[["survey_time"]] <- function(value = 1000L)
             survey_time(socket, value = value)
         },
         respondent = {
           nano[["context_open"]] <- function() {
             if (is.null(sock2)) sock2 <<- socket
             nano[["context_close"]] <- function() if (length(sock2)) {
               r <- close(socket)
               socket <<- sock2
               sock2 <<- NULL
               rm(list = c("context", "context_close"), envir = nano)
               r
             }
             socket <<- nano[["context"]] <- context(sock2)
           }
         },
         NULL)

  nano

}

#' @export
#'
print.nanoObject <- function(x, ...) {

  cat(sprintf("< nano object >\n - socket id: %d\n - state: %s\n - protocol: %s\n",
      attr(.subset2(x, "socket"), "id"), attr(.subset2(x, "socket"), "state"),
      attr(.subset2(x, "socket"), "protocol")), file = stdout())
  if (length(.subset2(x, "listener")))
    cat(" - listener:", as.character(lapply(.subset2(x, "listener"), attr, "url")), sep = "\n    ", file = stdout())
  if (length(.subset2(x, "dialer")))
    cat(" - dialer:", as.character(lapply(.subset2(x, "dialer"), attr, "url")), sep = "\n    ", file = stdout())
  invisible(x)

}

#' @export
#'
print.nanoSocket <- function(x, ...) {

  cat(sprintf("< nanoSocket >\n - id: %d\n - state: %s\n - protocol: %s\n",
              attr(x, "id"), attr(x, "state"), attr(x, "protocol")), file = stdout())
  if (length(attr(x, "listener")))
    cat(" - listener:", as.character(lapply(attr(x, "listener"), attr, "url")), sep = "\n    ", file = stdout())
  if (length(attr(x, "dialer")))
    cat(" - dialer:", as.character(lapply(attr(x, "dialer"), attr, "url")), sep = "\n    ", file = stdout())
  invisible(x)

}

#' @export
#'
print.nanoContext <- function(x, ...) {

  cat(sprintf("< nanoContext >\n - id: %d\n - socket: %d\n - state: %s\n - protocol: %s\n",
              attr(x, "id"), attr(x, "socket"), attr(x, "state"), attr(x, "protocol")), file = stdout())
  invisible(x)

}

#' @export
#'
print.nanoDialer <- function(x, ...) {

  cat(sprintf("< nanoDialer >\n - id: %d\n - socket: %d\n - state: %s\n - url: %s\n",
              attr(x, "id"), attr(x, "socket"), attr(x, "state"), attr(x, "url")), file = stdout())
  invisible(x)

}

#' @export
#'
print.nanoListener <- function(x, ...) {

  cat(sprintf("< nanoListener >\n - id: %d\n - socket: %d\n - state: %s\n - url: %s\n",
              attr(x, "id"), attr(x, "socket"), attr(x, "state"), attr(x, "url")), file = stdout())
  invisible(x)

}

#' @export
#'
print.nanoStream <- function(x, ...) {

  cat(sprintf("< nanoStream >\n - mode: %s\n - state: %s\n - url: %s\n",
              attr(x, "mode"), attr(x, "state"), attr(x, "url")), file = stdout())
  invisible(x)

}

#' @export
#'
print.nanoMonitor <- function(x, ...) {

  cat(sprintf("< nanoMonitor >\n - socket: %s\n", attr(x, "socket")), file = stdout())
  invisible(x)

}

#' @export
#'
print.recvAio <- function(x, ...) {

  cat("< recvAio | $data >\n", file = stdout())
  invisible(x)

}

#' @export
#'
print.sendAio <- function(x, ...) {

  cat("< sendAio | $result >\n", file = stdout())
  invisible(x)

}

#' @export
#'
print.ncurlAio <- function(x, ...) {

  cat("< ncurlAio | $status $headers $data >\n", file = stdout())
  invisible(x)

}

#' @export
#'
print.ncurlSession <- function(x, ...) {

  cat(sprintf("< ncurlSession > - %s\n", if (is.null(attr(x, "state"))) "transact() to return data" else "not active"), file = stdout())
  invisible(x)

}

#' @export
#'
print.unresolvedValue <- function(x, ...) {

  cat("'unresolved' logi NA\n", file = stdout())
  invisible(x)

}

#' @export
#'
print.errorValue <- function(x, ...) {

  cat(sprintf("'errorValue' int %s\n", nng_error(x)), file = stdout())
  invisible(x)

}

#' @export
#'
print.conditionVariable <- function(x, ...) {

  cat("< conditionVariable >\n", file = stdout())
  invisible(x)

}

#' @export
#'
print.tlsConfig <- function(x, ...) {

  cat(sprintf("< TLS %s config | auth mode: %s >\n", attr(x, "spec"), attr(x, "mode")), file = stdout())
  invisible(x)

}

#' @export
#'
`[[.nano` <- function(x, i, exact = TRUE)
  attr(x, i, exact = exact)

#' @export
#'
`[.nano` <- function(x, i, exact = TRUE)
  attr(x, deparse(substitute(i)), exact = exact)

#' @export
#'
`$.nano` <- function(x, name)
  attr(x, name, exact = TRUE)

#' @export
#'
`$<-.nano` <- function(x, name, value) x

#' @export
#'
`$<-.nanoObject` <- function(x, name, value) x

#' @export
#'
`[.recvAio` <- function(x, i) collect_aio_(x)

#' @export
#'
`$<-.recvAio` <- function(x, name, value) x

#' @export
#'
`[.sendAio` <- function(x, i) collect_aio_(x)

#' @export
#'
`$<-.sendAio` <- function(x, name, value) x

#' @exportS3Method utils::.DollarNames
#'
.DollarNames.nano <- function(x, pattern = "")
  grep(pattern, names(attributes(x)), value = TRUE, fixed = TRUE)

#' @exportS3Method utils::.DollarNames
#'
.DollarNames.recvAio <- function(x, pattern = "")
  if (startsWith("data", pattern)) "data" else character()

#' @exportS3Method utils::.DollarNames
#'
.DollarNames.sendAio <- function(x, pattern = "")
  if (startsWith("result", pattern)) "result" else character()

#' @exportS3Method utils::.DollarNames
#'
.DollarNames.ncurlAio <- function(x, pattern = "")
  grep(pattern, c("status", "headers", "data"), value = TRUE, fixed = TRUE)
