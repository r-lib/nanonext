# Package index

## Core

Socket and nano object creation

- [`nanonext`](https://nanonext.r-lib.org/reference/nanonext-package.md)
  [`nanonext-package`](https://nanonext.r-lib.org/reference/nanonext-package.md)
  : nanonext: NNG (Nanomsg Next Gen) Lightweight Messaging Library
- [`socket()`](https://nanonext.r-lib.org/reference/socket.md) : Open
  Socket
- [`nano()`](https://nanonext.r-lib.org/reference/nano.md) : Create Nano
  Object
- [`context()`](https://nanonext.r-lib.org/reference/context.md) : Open
  Context
- [`dial()`](https://nanonext.r-lib.org/reference/dial.md) : Dial an
  Address from a Socket
- [`listen()`](https://nanonext.r-lib.org/reference/listen.md) : Listen
  to an Address from a Socket
- [`start(`*`<nanoListener>`*`)`](https://nanonext.r-lib.org/reference/start.md)
  [`start(`*`<nanoDialer>`*`)`](https://nanonext.r-lib.org/reference/start.md)
  : Start Listener/Dialer
- [`close(`*`<nanoContext>`*`)`](https://nanonext.r-lib.org/reference/close.md)
  [`close(`*`<nanoDialer>`*`)`](https://nanonext.r-lib.org/reference/close.md)
  [`close(`*`<nanoListener>`*`)`](https://nanonext.r-lib.org/reference/close.md)
  [`close(`*`<ncurlSession>`*`)`](https://nanonext.r-lib.org/reference/close.md)
  [`close(`*`<nanoServer>`*`)`](https://nanonext.r-lib.org/reference/close.md)
  [`close(`*`<nanoSocket>`*`)`](https://nanonext.r-lib.org/reference/close.md)
  [`close(`*`<nanoStream>`*`)`](https://nanonext.r-lib.org/reference/close.md)
  : Close Connection
- [`protocols`](https://nanonext.r-lib.org/reference/protocols.md) :
  Protocols (Documentation)
- [`transports`](https://nanonext.r-lib.org/reference/transports.md) :
  Transports (Documentation)

## Communication

Send and receive operations

- [`send()`](https://nanonext.r-lib.org/reference/send.md) : Send
- [`recv()`](https://nanonext.r-lib.org/reference/recv.md) : Receive
- [`send_aio()`](https://nanonext.r-lib.org/reference/send_aio.md) :
  Send Async
- [`recv_aio()`](https://nanonext.r-lib.org/reference/recv_aio.md) :
  Receive Async
- [`request()`](https://nanonext.r-lib.org/reference/request.md) :
  Request over Context (RPC Client for Req/Rep Protocol)
- [`reply()`](https://nanonext.r-lib.org/reference/reply.md) : Reply
  over Context (RPC Server for Req/Rep Protocol)
- [`subscribe()`](https://nanonext.r-lib.org/reference/subscribe.md)
  [`unsubscribe()`](https://nanonext.r-lib.org/reference/subscribe.md) :
  Subscribe / Unsubscribe Topic
- [`survey_time()`](https://nanonext.r-lib.org/reference/survey_time.md)
  : Set Survey Time

## Async I/O

Asynchronous operations and promises

- [`call_aio()`](https://nanonext.r-lib.org/reference/call_aio.md)
  [`call_aio_()`](https://nanonext.r-lib.org/reference/call_aio.md) :
  Call the Value of an Asynchronous Aio Operation
- [`collect_aio()`](https://nanonext.r-lib.org/reference/collect_aio.md)
  [`collect_aio_()`](https://nanonext.r-lib.org/reference/collect_aio.md)
  : Collect Data of an Aio or List of Aios
- [`stop_aio()`](https://nanonext.r-lib.org/reference/stop_aio.md) :
  Stop Asynchronous Aio Operation
- [`stop_request()`](https://nanonext.r-lib.org/reference/stop_request.md)
  : Stop Request Operation
- [`race_aio()`](https://nanonext.r-lib.org/reference/race_aio.md) :
  Race Aio
- [`unresolved()`](https://nanonext.r-lib.org/reference/unresolved.md) :
  Query if an Aio is Unresolved
- [`is_aio()`](https://nanonext.r-lib.org/reference/is_aio.md)
  [`is_nano()`](https://nanonext.r-lib.org/reference/is_aio.md)
  [`is_ncurl_session()`](https://nanonext.r-lib.org/reference/is_aio.md)
  : Validators
- [`as.promise(`*`<recvAio>`*`)`](https://nanonext.r-lib.org/reference/as.promise.recvAio.md)
  : Make recvAio Promise
- [`as.promise(`*`<ncurlAio>`*`)`](https://nanonext.r-lib.org/reference/as.promise.ncurlAio.md)
  : Make ncurlAio Promise

## Synchronization

Condition variables and pipe events

- [`cv()`](https://nanonext.r-lib.org/reference/cv.md)
  [`wait()`](https://nanonext.r-lib.org/reference/cv.md)
  [`wait_()`](https://nanonext.r-lib.org/reference/cv.md)
  [`until()`](https://nanonext.r-lib.org/reference/cv.md)
  [`until_()`](https://nanonext.r-lib.org/reference/cv.md)
  [`cv_value()`](https://nanonext.r-lib.org/reference/cv.md)
  [`cv_reset()`](https://nanonext.r-lib.org/reference/cv.md)
  [`cv_signal()`](https://nanonext.r-lib.org/reference/cv.md) :
  Condition Variables
- [`` `%~>%` ``](https://nanonext.r-lib.org/reference/grapes-twiddle-greater-than-grapes.md)
  : Signal Forwarder
- [`pipe_notify()`](https://nanonext.r-lib.org/reference/pipe_notify.md)
  : Pipe Notify
- [`pipe_id()`](https://nanonext.r-lib.org/reference/pipe_id.md) : Get
  the Pipe ID of a recvAio
- [`monitor()`](https://nanonext.r-lib.org/reference/monitor.md)
  [`read_monitor()`](https://nanonext.r-lib.org/reference/monitor.md) :
  Monitor a Socket for Pipe Changes

## HTTP Client

HTTP requests and sessions

- [`ncurl()`](https://nanonext.r-lib.org/reference/ncurl.md) : ncurl
- [`ncurl_aio()`](https://nanonext.r-lib.org/reference/ncurl_aio.md) :
  ncurl Async
- [`ncurl_session()`](https://nanonext.r-lib.org/reference/ncurl_session.md)
  [`transact()`](https://nanonext.r-lib.org/reference/ncurl_session.md)
  : ncurl Session
- [`status_code()`](https://nanonext.r-lib.org/reference/status_code.md)
  : Translate HTTP Status Codes

## WebSocket Client

WebSocket and byte stream connections

- [`stream()`](https://nanonext.r-lib.org/reference/stream.md) : Open
  Stream

## HTTP/WebSocket Server

Server creation and request handlers

- [`http_server()`](https://nanonext.r-lib.org/reference/http_server.md)
  : Create HTTP/WebSocket Server
- [`handler()`](https://nanonext.r-lib.org/reference/handler.md) :
  Create HTTP Handler
- [`handler_ws()`](https://nanonext.r-lib.org/reference/handler_ws.md) :
  Create WebSocket Handler
- [`handler_stream()`](https://nanonext.r-lib.org/reference/handler_stream.md)
  : Create HTTP Streaming Handler
- [`handler_file()`](https://nanonext.r-lib.org/reference/handler_file.md)
  : Create Static File Handler
- [`handler_directory()`](https://nanonext.r-lib.org/reference/handler_directory.md)
  : Create Static Directory Handler
- [`handler_inline()`](https://nanonext.r-lib.org/reference/handler_inline.md)
  : Create Inline Static Content Handler
- [`handler_redirect()`](https://nanonext.r-lib.org/reference/handler_redirect.md)
  : Create HTTP Redirect Handler
- [`format_sse()`](https://nanonext.r-lib.org/reference/format_sse.md) :
  Format Server-Sent Event

## TLS

Secure connections

- [`tls_config()`](https://nanonext.r-lib.org/reference/tls_config.md) :
  Create TLS Configuration
- [`write_cert()`](https://nanonext.r-lib.org/reference/write_cert.md) :
  Generate Self-Signed Certificate and Key

## Options and Statistics

Configuration and monitoring

- [`opt()`](https://nanonext.r-lib.org/reference/opt.md)
  [`` `opt<-`() ``](https://nanonext.r-lib.org/reference/opt.md) : Get
  and Set Options for a Socket, Context, Stream, Listener or Dialer
- [`stat()`](https://nanonext.r-lib.org/reference/stat.md) : Get
  Statistic for a Socket, Listener or Dialer

## Serialization

Custom serialization configuration

- [`serial_config()`](https://nanonext.r-lib.org/reference/serial_config.md)
  : Create Serialization Configuration

## Utilities

Helper functions

- [`parse_url()`](https://nanonext.r-lib.org/reference/parse_url.md) :
  Parse URL
- [`nng_error()`](https://nanonext.r-lib.org/reference/nng_error.md) :
  Translate Error Codes
- [`nng_version()`](https://nanonext.r-lib.org/reference/nng_version.md)
  : NNG Library Version
- [`is_error_value()`](https://nanonext.r-lib.org/reference/is_error_value.md)
  [`is_nul_byte()`](https://nanonext.r-lib.org/reference/is_error_value.md)
  : Error Validators
- [`ip_addr()`](https://nanonext.r-lib.org/reference/ip_addr.md) : IP
  Address
- [`random()`](https://nanonext.r-lib.org/reference/random.md) : Random
  Data Generation
- [`mclock()`](https://nanonext.r-lib.org/reference/mclock.md) : Clock
  Utility
- [`msleep()`](https://nanonext.r-lib.org/reference/msleep.md) : Sleep
  Utility
- [`messenger()`](https://nanonext.r-lib.org/reference/messenger.md) :
  Messenger
- [`reap()`](https://nanonext.r-lib.org/reference/reap.md) : Reap
- [`read_stdin()`](https://nanonext.r-lib.org/reference/read_stdin.md) :
  Read stdin
- [`write_stdout()`](https://nanonext.r-lib.org/reference/write_stdout.md)
  : Write to Stdout
