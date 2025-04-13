# nanonext - Package -----------------------------------------------------------

#' nanonext: NNG (Nanomsg Next Gen) Lightweight Messaging Library
#'
#' R binding for NNG (Nanomsg Next Gen), a successor to ZeroMQ. NNG is a socket
#' library for reliable, high-performance messaging over in-process, IPC, TCP,
#' WebSocket and secure TLS transports. Implements 'Scalability Protocols', a
#' standard for common communications patterns including publish/subscribe,
#' request/reply and service discovery. As its own threaded concurrency
#' framework, provides a toolkit for asynchronous programming and distributed
#' computing. Intuitive 'aio' objects resolve automatically when asynchronous
#' operations complete, and synchronisation primitives allow R to wait upon
#' events signalled by concurrent threads.
#'
#' @section Usage notes:
#'
#' \pkg{nanonext} offers 2 equivalent interfaces: a functional interface, and an
#' object-oriented interface.
#'
#' The primary object in the functional interface is the Socket. Use [socket()]
#' to create a socket and dial or listen at an address. The socket is then
#' passed as the first argument of subsequent actions such as `send()` or
#' `recv()`.
#'
#' The primary object in the object-oriented interface is the nano object. Use
#' [nano()] to create a nano object which encapsulates a Socket and
#' Dialer/Listener. Methods such as `$send()` or `$recv()` can then be accessed
#' directly from the object.
#'
#' @section Documentation:
#'
#' Guide to the implemented protocols for sockets: [protocols]
#'
#' Guide to the supported transports for dialers and listeners:
#' [transports]
#'
#' Guide to the options that can be inspected and set using: [opt] /
#' [opt<-]
#'
#' @section Reference Manual:
#'
#' `vignette("nanonext", package = "nanonext")`
#'
#' @section Conceptual overview:
#'
#' NNG presents a socket view of networking. A socket implements precisely one
#' protocol, such as 'bus', etc.
#'
#' Each socket can be used to send and receive messages (if the protocol
#' supports it, and implements the appropriate protocol semantics). For example,
#' the 'sub' protocol automatically filters incoming messages to discard topics
#' that have not been subscribed.
#'
#' NNG sockets are message-oriented, and messages are either delivered wholly,
#' or not at all. Partial delivery is not possible. Furthermore, NNG does not
#' provide any other delivery or ordering guarantees: messages may be dropped or
#' reordered (some protocols, such as 'req' may offer stronger guarantees by
#' performing their own retry and validation schemes).
#'
#' Each socket can have zero, one, or many endpoints, which are either listeners
#' or dialers (a given socket may use listeners, dialers, or both). These
#' endpoints provide access to underlying transports, such as TCP, etc.
#'
#' Each endpoint is associated with a URL, which is a service address. For
#' dialers, this is the service address that is contacted, whereas for listeners
#' this is where new connections will be accepted.
#'
#' @section Links:
#'
#' NNG: <https://nng.nanomsg.org/> \cr
#' Mbed TLS: <https://www.trustedfirmware.org/projects/mbed-tls/>
#'
#' @useDynLib nanonext, .registration = TRUE
#'
"_PACKAGE"
