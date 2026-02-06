# Changelog

## nanonext (development version)

##### New Features

- Adds
  [`http_server()`](https://nanonext.r-lib.org/dev/reference/http_server.md)
  for creating HTTP and WebSocket servers with TLS/SSL support.
- Adds
  [`handler()`](https://nanonext.r-lib.org/dev/reference/handler.md) for
  dynamic HTTP request handling with custom callbacks.
- Adds
  [`handler_ws()`](https://nanonext.r-lib.org/dev/reference/handler_ws.md)
  for WebSocket connections with `on_message`, `on_open`, and `on_close`
  callbacks.
- Adds
  [`handler_stream()`](https://nanonext.r-lib.org/dev/reference/handler_stream.md)
  for HTTP streaming using chunked transfer encoding, supporting
  Server-Sent Events (SSE), NDJSON, and custom streaming formats.
- Adds
  [`format_sse()`](https://nanonext.r-lib.org/dev/reference/format_sse.md)
  helper for formatting Server-Sent Events messages.
- Adds static content handlers:
  [`handler_file()`](https://nanonext.r-lib.org/dev/reference/handler_file.md)
  and
  [`handler_directory()`](https://nanonext.r-lib.org/dev/reference/handler_directory.md)
  for serving files,
  [`handler_inline()`](https://nanonext.r-lib.org/dev/reference/handler_inline.md)
  for in-memory content, and
  [`handler_redirect()`](https://nanonext.r-lib.org/dev/reference/handler_redirect.md)
  for HTTP redirects.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) and
  variants now accept `response = TRUE` to return all response headers.
- Adds
  [`race_aio()`](https://nanonext.r-lib.org/dev/reference/race_aio.md)
  to wait for and return the index of the first resolved Aio in a list
  of Aios.

##### Updates

- Closing an already closed stream now returns ‘errorValue’ 7 \| Object
  closed rather than error.
- [`random()`](https://nanonext.r-lib.org/dev/reference/random.md) now
  only accepts ‘n’ between 1 and 1024. Supplying 0 will error
  ([\#238](https://github.com/r-lib/nanonext/issues/238)).
- Fixes a potential crash when
  [`random()`](https://nanonext.r-lib.org/dev/reference/random.md) or
  [`write_cert()`](https://nanonext.r-lib.org/dev/reference/write_cert.md)
  is called in a fresh session before any other TLS-related functions
  have been called, and nanonext has been compiled against a system Mbed
  TLS with PSA crypto enabled.
  ([\#242](https://github.com/r-lib/nanonext/issues/242)).
- Fixes a potential crash when a serialization hook errors
  ([\#225](https://github.com/r-lib/nanonext/issues/225)).
- Performance improvements for serialization, streaming, and async
  sends.
- Bundled ‘libmbedtls’ updated to latest 3.6.5 LTS branch release
  ([\#234](https://github.com/r-lib/nanonext/issues/234)).
- Building from source no longer requires `xz`.

## nanonext 1.7.2

CRAN release: 2025-11-03

##### Updates

- `pipe_notify(flag = tools::SIGTERM)` will now raise the signal with a
  200ms grace period to allow a process to exit normally
  ([\#212](https://github.com/r-lib/nanonext/issues/212)).
- [`parse_url()`](https://nanonext.r-lib.org/dev/reference/parse_url.md)
  drops ‘rawurl’, ‘host’ and ‘requri’ from the output vector as these
  can be derived from the other parts
  ([\#209](https://github.com/r-lib/nanonext/issues/209)).

## nanonext 1.7.1

CRAN release: 2025-10-01

##### Updates

- [`stop_aio()`](https://nanonext.r-lib.org/dev/reference/stop_aio.md)
  now resets the R interrupt flags
  ([\#194](https://github.com/r-lib/nanonext/issues/194)).
- The `cv` arguments at
  [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
  and [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  have been simplified to accept just a ‘conditionVariable’ or NULL.

## nanonext 1.7.0

CRAN release: 2025-09-01

##### Behavioural Changes

- The promises method for `ncurlAio` has been updated for ease of use
  ([\#176](https://github.com/r-lib/nanonext/issues/176)):
  - Returns a list of ‘status’, ‘headers’ and ‘data’.
  - Rejects only if an NNG error is returned (all HTTP status codes are
    resolved).
- Improved behaviour when using
  [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md)
  configurations applied to a socket. If the serialization hook function
  errors or otherwise fails to return a raw vector, this will error out
  rather than be silently ignored
  ([\#173](https://github.com/r-lib/nanonext/issues/173)).

##### New Features

- A ‘recvAio’ returned by
  [`request()`](https://nanonext.r-lib.org/dev/reference/request.md) now
  has an attribute `id`, which is the integer ID of the context passed
  to it.

##### Updates

- [`opt()`](https://nanonext.r-lib.org/dev/reference/opt.md) for a
  boolean NNG option now correctly returns a logical value instead of an
  integer ([\#186](https://github.com/r-lib/nanonext/issues/186)).
- [`as.promise()`](https://rstudio.github.io/promises/reference/is.promise.html)
  method for `recvAio` and `ncurlAio` objects made robust for
  high-throughput cases
  ([\#171](https://github.com/r-lib/nanonext/issues/171)).

## nanonext 1.6.2

CRAN release: 2025-07-14

##### Updates

- Fixes extremely rare cases of `unresolvedValue` being returned by
  fulfilled promises
  ([\#163](https://github.com/r-lib/nanonext/issues/163)).

## nanonext 1.6.1

CRAN release: 2025-06-23

##### Updates

- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) and
  variants now accept request data supplied as a raw vector (thanks
  [@thomasp85](https://github.com/thomasp85),
  [\#158](https://github.com/r-lib/nanonext/issues/158)).
- [`cv_reset()`](https://nanonext.r-lib.org/dev/reference/cv.md) now
  correctly resets the flag in the case a flag event has already been
  registered with
  [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md).
- The previous
  [`listen()`](https://nanonext.r-lib.org/dev/reference/listen.md) and
  [`dial()`](https://nanonext.r-lib.org/dev/reference/dial.md) argument
  `error`, removed in v1.6.0, is now defunct.
- The previous
  [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md)
  argument `vec`, unutilised since v1.6.0, is removed.
- Fixes package installation with ‘libmbedtls’ in a non-standard
  filesystem location, even if known to the compiler (thanks
  [@tdhock](https://github.com/tdhock),
  [\#150](https://github.com/r-lib/nanonext/issues/150)).
- Bundled ‘libnng’ updated to 1.11.0 release.

## nanonext 1.6.0

CRAN release: 2025-05-19

##### New Features

- [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md)
  now accepts vector arguments to register multiple custom serialization
  configurations.
- Adds
  [`ip_addr()`](https://nanonext.r-lib.org/dev/reference/ip_addr.md) for
  returning the local network IPv4 address of all network adapters,
  named by interface.
- Adds
  [`pipe_id()`](https://nanonext.r-lib.org/dev/reference/pipe_id.md) for
  returning the integer pipe ID for a resolved ‘recvAio’.
- Adds
  [`write_stdout()`](https://nanonext.r-lib.org/dev/reference/write_stdout.md)
  which performs a non-buffered write to `stdout`, to avoid interleaved
  messages when used concurrently by different processes.
- Adds
  [`read_stdin()`](https://nanonext.r-lib.org/dev/reference/read_stdin.md)
  which performs a read from `stdin` on a background thread, relayed via
  an ‘inproc’ socket so that it may be consumed via
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md) or
  [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md).
- [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  gains integer argument `id`. This may be specified to have a special
  payload sent asynchronously upon timeout (to communicate with the
  connected party).

##### Updates

- [`listen()`](https://nanonext.r-lib.org/dev/reference/listen.md) and
  [`dial()`](https://nanonext.r-lib.org/dev/reference/dial.md) argument
  `error` is replaced with `fail` to specify the failure mode - ‘warn’,
  ‘error’, or ‘none’ to just return an ‘errorValue’.
  - Any existing usage of `error = TRUE` will work only until the next
    release.
- Partial matching is no longer enabled for the `mode` argument to
  send/receive functions.
- [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md)
  without keeping a reference to the return value no longer potentially
  drops sends (thanks [@wch](https://github.com/wch),
  [\#129](https://github.com/r-lib/nanonext/issues/129)).
- [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
  no longer requires any particular sequencing of closing the socket and
  garbage collection of the socket / ‘conditionVariable’
  ([\#143](https://github.com/r-lib/nanonext/issues/143)).
- More robust interruption on non-Windows platforms when
  [`tools::SIGINT`](https://rdrr.io/r/tools/pskill.html) is supplied to
  the `flag` argument of
  [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
  (thanks [@LennardLux](https://github.com/LennardLux),
  [\#97](https://github.com/r-lib/nanonext/issues/97)).
- Installation from source specifying ‘INCLUDE_DIR’ and ‘LIB_DIR’
  environment variables works again, correcting a regression in v1.5.2
  ([\#104](https://github.com/r-lib/nanonext/issues/104)).
- Windows bi-arch source builds for R \<= 4.1 using rtools40 and earlier
  work again (regression since v1.5.1) (thanks
  [@daroczig](https://github.com/daroczig),
  [\#107](https://github.com/r-lib/nanonext/issues/107)).
- Bundled ‘libnng’ 1.10.2 pre-release updated with latest patches.
- Package is re-licensed under the MIT license.

## nanonext 1.5.2

CRAN release: 2025-03-18

##### Updates

- [`write_cert()`](https://nanonext.r-lib.org/dev/reference/write_cert.md)
  argument ‘cn’ now defaults to ‘127.0.0.1’ instead of ‘localhost’.
- [`messenger()`](https://nanonext.r-lib.org/dev/reference/messenger.md)
  now exits cleanly, correcting a regression in nanonext 1.5.0
  ([\#87](https://github.com/r-lib/nanonext/issues/87)).
- Promises created from ‘recvAio’ and ‘ncurlAio’ now reject in exactly
  the same way whether or not they were resolved at time of creation
  ([\#89](https://github.com/r-lib/nanonext/issues/89)).
- Bundled ‘libnng’ updated to 1.10.2 pre-release.
  - With this library version, a ‘req’ socket with option
    ‘req:resend-time’ set as 0 now frees the message as soon as the send
    has completed without waiting for the reply.

## nanonext 1.5.1

CRAN release: 2025-02-16

##### Updates

- [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
  drops argument ‘cv2’ for signalling 2 condition variables on one pipe
  event. Use signal forwarders `%~>%` instead.
- The abillity to `lock()` and `unlock()` sockets is removed.
- Renders it safe to serialize ‘nano’ and ‘aio’ objects - they will be
  inactive when unserialized.
- Unified Windows build system now compiles ‘libmbedtls’ and ‘libnng’
  from source even on R \<= 4.1 using Rtools40 or earlier.
- Minimum supported ‘libnng’ version increased to 1.9.0.

## nanonext 1.5.0

CRAN release: 2025-01-27

##### Library Updates

- Bundled ‘libnng’ updated to latest 1.10.1 release.
- Bundled ‘libmbedtls’ updated to latest 3.6.2 LTS branch release.

##### Updates

- [`nano()`](https://nanonext.r-lib.org/dev/reference/nano.md) updated
  with the ‘poly’ protocol, with ‘pipe’ argument enabled for the send
  methods.
- [`write_cert()`](https://nanonext.r-lib.org/dev/reference/write_cert.md)
  no longer displays a status message when interactive (thanks
  [@wlandau](https://github.com/wlandau),
  [\#74](https://github.com/r-lib/nanonext/issues/74)).
- Removes partial matching when using `$`, `[[` or `[` on an object
  inheriting from class ‘nano’.
- Fixes a rare hang on socket close that was possible on Windows
  platforms for IPC connections
  ([\#76](https://github.com/r-lib/nanonext/issues/76)).

## nanonext 1.4.0

CRAN release: 2024-12-02

##### New Features

- New interface to Pipes moves to using integer pipe IDs rather than
  Pipe (external pointer) objects:
  - [`send()`](https://nanonext.r-lib.org/dev/reference/send.md) and
    [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md)
    gain the argument ‘pipe’ which accepts an integer pipe ID for
    directed sends (currently only supported by Sockets using the ‘poly’
    protocol).
  - A ‘recvAio’ now records the integer pipe ID, where successful, at
    `$aio` upon resolution.
  - Pipe objects (of class ‘nanoPipe’) are obsoleted.
- Adds
  [`monitor()`](https://nanonext.r-lib.org/dev/reference/monitor.md) and
  [`read_monitor()`](https://nanonext.r-lib.org/dev/reference/monitor.md)
  for easy monitoring of connection changes (pipe additons and removals)
  at a Socket.

##### Updates

- `collect_pipe()` is removed given the pipe interface changes.

## nanonext 1.3.2

CRAN release: 2024-11-14

##### Updates

- Hotfix for CRAN (updates to tests only).

## nanonext 1.3.1

CRAN release: 2024-11-13

##### Updates

- Performs interruptible ‘aio’ waits using a single dedicated thread,
  rather than launching new threads, for higher performance and
  efficiency.
- Performance enhancements for ‘ncurlAio’ and ‘recvAio’ promises
  methods.
- Updates bundled ‘libnng’ to v1.9.0 stable release.
- The package has a shiny new hex logo.

## nanonext 1.3.0

CRAN release: 2024-10-04

##### New Features

- Adds support for threaded dispatcher in `mirai`.
- Adds ‘recvAio’ method for
  [`promises::as.promise()`](https://rstudio.github.io/promises/reference/is.promise.html)
  and
  [`promises::is.promising()`](https://rstudio.github.io/promises/reference/is.promise.html)
  to enable ‘recvAio’ promises.

##### Updates

- [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md)
  now validates all arguments and returns them as a list. Full
  validation is also performed when the option is set for additional
  safety.
- Warning messages for unserialization or conversion failures of
  received data are now suppressable.
- Upgrades
  [`reply()`](https://nanonext.r-lib.org/dev/reference/reply.md) to
  always return even when there is an evaluation error. This allows it
  to be used safely in a loop without exiting early, for example.
- Removes deprecated and defunct `next_config()`.
- Internal performance enhancements.
- Updates bundled ‘libnng’ v1.8.0 with latest patches.

## nanonext 1.2.1

CRAN release: 2024-08-19

##### Updates

- Re-optimizes custom serialization (whilst addressing CRAN clang-UBSAN
  checks).

## nanonext 1.2.0

CRAN release: 2024-08-17

##### New Features

- Adds
  [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md)
  to create configurations that can be set on Sockets to make use of
  custom serialization and unserialization functions for reference
  objects (plugs into the ‘refhook’ system of native R serialization).
- [`'opt<-'()`](https://nanonext.r-lib.org/dev/reference/opt.md) now
  accepts the special option ‘serial’ for Sockets, which takes a
  configuration returned from
  [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md).
- Adds the ‘poly’ protocol for one-to-one of many socket connections
  (NNG’s pair v1 polyamorous mode).
- Adds
  [`is_ncurl_session()`](https://nanonext.r-lib.org/dev/reference/is_aio.md)
  as a validation function.
- Adds `collect_pipe()` for obtaining the underlying Pipe from a
  ‘recvAio’. This affords more granular control of connections, with the
  ability to close individual pipes.
- [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md)
  now accept a Pipe to direct messages to a specific peer for supported
  protocols such as ‘poly’.

##### Updates

- Send mode ‘next’ is folded into the default ‘serial’, with custom
  serialization functions applying automatically if they have been
  registered.
- The session-wide `next_config()` is now deprecated and defunct, in
  favour of the new
  [`serial_config()`](https://nanonext.r-lib.org/dev/reference/serial_config.md).
- [`ncurl_session()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
  now returns ‘errorValue’ 7 (Object closed) when attempting to transact
  over a closed session or closing a closed session, rather than
  throwing an error.
- [`collect_aio()`](https://nanonext.r-lib.org/dev/reference/collect_aio.md)
  and
  [`collect_aio_()`](https://nanonext.r-lib.org/dev/reference/collect_aio.md)
  no longer append empty names when acting on lists of Aios where there
  were none in the first place.
- Removes hard dependency on `stats` and `utils` base packages.
- Requires R \>= 3.6.

## nanonext 1.1.1

CRAN release: 2024-06-23

##### New Features

- Adds ‘ncurlAio’ method for
  [`promises::as.promise()`](https://rstudio.github.io/promises/reference/is.promise.html)
  and
  [`promises::is.promising()`](https://rstudio.github.io/promises/reference/is.promise.html)
  to enable ‘ncurlAio’ promises.
- Adds `x[]` as a new method for an Aio `x` equivalent to
  `collect_aio_(x)`, which waits for and collects the data.

##### Updates

- [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  specifying argument ‘cv’ other than NULL or a ‘conditionVariable’ will
  cause the pipe connection to be dropped when the reply is
  (asynchronously) completed.
- Removes deprecated functions `strcat()`, `recv_aio_signal()` and
  `request_signal()`.
- Drops `base64enc()` and `base64dec()` in favour of those from the
  {secretbase} package.
- [`msleep()`](https://nanonext.r-lib.org/dev/reference/msleep.md) now
  ignores negative values rather than taking the absolute value.
- `later` is now relaxed to a soft ‘suggests’ dependency (only required
  if using promises).
- `promises` is added as a soft ‘enhances’ dependency.

## nanonext 1.1.0

CRAN release: 2024-06-04

##### New Features

- Adds
  [`collect_aio()`](https://nanonext.r-lib.org/dev/reference/collect_aio.md)
  and
  [`collect_aio_()`](https://nanonext.r-lib.org/dev/reference/collect_aio.md)
  to wait for and collect the data of an Aio or list of Aios.
- [`unresolved()`](https://nanonext.r-lib.org/dev/reference/unresolved.md),
  [`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md),
  `call_aio()_` and
  [`stop_aio()`](https://nanonext.r-lib.org/dev/reference/stop_aio.md)
  now all accept a list of Aios.
- [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
  gains the ability to specify ‘cv’ as NULL to cancel previously-set
  signals.
- [`ncurl_aio()`](https://nanonext.r-lib.org/dev/reference/ncurl_aio.md)
  modified internally to support conversion of ‘ncurlAio’ to
  event-driven promises.

##### Updates

- [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
  and [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  add argument ‘cv’ allowing optional signalling of a condition
  variable. The separate functions `recv_aio_signal()` and
  `request_signal()` are deprecated.
- `strcat()` is deprecated as considered non-core - it is recommended to
  replace usage with [`sprintf()`](https://rdrr.io/r/base/sprintf.html).
- [`status_code()`](https://nanonext.r-lib.org/dev/reference/status_code.md)
  now returns the status code combined with the explanation as a
  character string.
- Performance enhancements for
  [`unresolved()`](https://nanonext.r-lib.org/dev/reference/unresolved.md),
  [`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md)
  and
  [`call_aio_()`](https://nanonext.r-lib.org/dev/reference/call_aio.md).
- Updates bundled ‘libnng’ v1.8.0 with latest patches.

## nanonext 1.0.0

CRAN release: 2024-05-01

##### New Features

- Integrates with the `later` package to provide the foundation for
  truly event-driven (non-polling) promises (thanks
  [@jcheng5](https://github.com/jcheng5) for the initial prototype in
  [\#28](https://github.com/r-lib/nanonext/issues/28)), where
  side-effects are enacted asynchronously upon aio completion.
  - [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
    and `request_signal()` modified internally to support conversion of
    ‘recvAio’ to event-driven promises.
  - `later` dependency ensures asynchronous R code is always run on the
    main R thread.
  - `later` is lazily loaded the first time a promise is used, and hence
    does not impact the load time of `nanonext` or dependent packages.

##### Updates

- [`stop_aio()`](https://nanonext.r-lib.org/dev/reference/stop_aio.md)
  now causes the ‘aio’ to resolve to an ‘errorValue’ of 20 (Operation
  canceled) if successfully stopped.
- [`nng_error()`](https://nanonext.r-lib.org/dev/reference/nng_error.md)
  now returns the error code combined with the message as a character
  string.
- Integer file descriptors are no longer appended to ‘nanoSocket’
  attributes.
- Adds ‘xz’ to SystemRequirements (as was the case previously but not
  explicitly specified) (thanks
  [@gaborcsardi](https://github.com/gaborcsardi)).
- Re-aligns bundled ‘libmbedtls’ to v3.5.2 and optimises bundle size.
- Updates minimum ‘libnng’ version requirement to v1.6.0.
- Upgrades bundled ‘libnng’ to v1.8.0.

## nanonext 0.13.5.2

CRAN release: 2024-04-06

##### Updates

- Safer and more efficient memory reads for ‘next’ serialization
  corrects for CRAN UBSAN-clang check errors.

## nanonext 0.13.5.1

CRAN release: 2024-04-05

##### New Features

- `next_config()` gains argument ‘class’ and ‘vec’, enabling custom
  serialization for all reference object types supported by R
  serialization.
- An integer file descriptor is appended to ‘nanoSockets’ as the
  attribute ‘fd’ - see updated documentation for
  [`socket()`](https://nanonext.r-lib.org/dev/reference/socket.md).

##### Updates

- Removes SHA-2 cryptographic hash functions (please use the streaming
  implementation in the secretbase package).

## nanonext 0.13.2

CRAN release: 2024-03-01

##### Updates

- Fixes cases of ‘built for newer macOS version than being linked’
  installation warnings on MacOS.
- Upgrades bundled ‘libnng’ to v1.7.2.

## nanonext 0.13.0

CRAN release: 2024-02-07

##### Updates

*Please note the following potentially breaking changes, and only update
when ready:*

- Default behaviour of
  [`send()`](https://nanonext.r-lib.org/dev/reference/send.md) and
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md) aligned
  to non-blocking for both Sockets and Contexts (facilitated by
  synchronous context sends in NNG since v1.6.0).
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md),
  [`ncurl_aio()`](https://nanonext.r-lib.org/dev/reference/ncurl_aio.md)
  and
  [`ncurl_session()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
  now restrict ‘header’ and ‘response’ arguments to character vectors
  only, no longer accepting lists (for safety and performance).
- Unserialization / decoding errors where the received message cannot be
  translated to the specified mode will output a message to stderr, but
  no longer generate a warning.
- SHA functions now skip serialization headers for serialized R objects
  (ensuring portability as these contain R version and encoding
  information). This means that, for serialized objects, hashes will be
  different to those obtained using prior package versions.
- `sha1()` is removed as a hash option.

*Other changes:*

- [`messenger()`](https://nanonext.r-lib.org/dev/reference/messenger.md)
  specifying ‘auth’ now works reliably on endpoints using different R
  versions/platforms due to the above hashing portability fix.
- Internal memory-efficiency and performance enhancements.
- Upgrades bundled ‘libmbedtls’ to v3.5.2.

## nanonext 0.12.0

CRAN release: 2024-01-10

*This is a major performance and stability release bundling the ‘libnng’
v1.7.0 source code.*

##### New Features

- [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
  argument ‘flag’ allows supplying a signal to be raised on a flag being
  set upon a pipe event.

##### Updates

- More compact print methods for ‘recvAio’, ‘sendAio’, ‘ncurlAio’,
  ‘ncurlSession’ and ‘tlsConfig’ objects.
- [`random()`](https://nanonext.r-lib.org/dev/reference/random.md) now
  explicitly limits argument ‘n’ to values between 0 and 1024.
- `next_config()` now returns a pairlist (of the registered
  serialization functions) rather than a list (for efficiency).
- Using mode ‘next’, serialization functions with incorrect signatures
  are now simply ignored rather than raise errors.
- ‘nanoStream’ objects simplified internally with updated attributes
  ‘mode’ and ‘state’.
- Deprecated function `.until()` is removed.
- Eliminates potential memory leaks along certain error paths.
- Fixes bug which prevented much higher TLS performance when using the
  bundled ‘libnng’ source.
- Upgrades bundled ‘libnng’ to v1.7.0 release.

## nanonext 0.11.0

CRAN release: 2023-12-04

*This is a major stability release bundling the ‘libnng’ v1.6.0 source
code.*

##### New Features

- Introduces
  [`call_aio_()`](https://nanonext.r-lib.org/dev/reference/call_aio.md),
  a user-interruptible version of
  [`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md)
  suitable for interactive use.
- Introduces [`wait_()`](https://nanonext.r-lib.org/dev/reference/cv.md)
  and [`until_()`](https://nanonext.r-lib.org/dev/reference/cv.md)
  user-interruptible versions of
  [`wait()`](https://nanonext.r-lib.org/dev/reference/cv.md) and
  [`until()`](https://nanonext.r-lib.org/dev/reference/cv.md) suitable
  for interactive use.
- Implements `%~>%` signal forwarder from one ‘conditionVariable’ to
  another.

##### Updates

- `next_config()` replaces `nextmode()` with the following improvements:
  - simplified ‘refhook’ argument takes a pair of serialization and
    unserialization functions as a list.
  - registered ‘refhook’ functions apply to external pointer type
    objects only.
  - no longer returns invisibly for easier confimation that the correct
    functions have been registered.
- [`until()`](https://nanonext.r-lib.org/dev/reference/cv.md) updated to
  be identical to `.until()`, returning FALSE instead of TRUE if the
  timeout has been reached.
- [`reap()`](https://nanonext.r-lib.org/dev/reference/reap.md) updated
  to no longer warn in cases it returns an ‘errorValue’.
- [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
  arguments ‘add’, ‘remove’ and ‘flag’ now default to FALSE instead of
  TRUE for easier selective specification of the events to signal.
- Fixes regression in release 0.10.4 that caused a potential segfault
  using [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md)
  with ‘follow’ set to TRUE when the server returns a missing or invalid
  relocation address.
- The weak references interface is removed as ‘non-core’.
- Upgrades bundled ‘libnng’ to v1.6.0 release.
- Upgrades bundled ‘libmbedtls’ to v3.5.1.

## nanonext 0.10.4

CRAN release: 2023-11-03

##### New Features

- `nextmode()` configures settings for send mode ‘next’. Registers hook
  functions for custom serialization and unserialization of reference
  objects (such as those accessed via an external pointer).
- `.until()` contains revised behaviour for this synchronisation
  primitive, returning FALSE instead of TRUE if the timeout has been
  reached. This function will replace
  [`until()`](https://nanonext.r-lib.org/dev/reference/cv.md) in a
  future package version.

##### Updates

- `lock()` supplying ‘cv’ has improved behaviour which locks the socket
  whilst allowing for both initial connections and re-connections (when
  the ‘cv’ is registered for both add and remove pipe events).
- Improves listener / dialer logic for TLS connections, allowing *inter
  alia* synchronous dials.
- [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  argument ‘ack’ removed due to stability considerations.
- Fixes memory leaks detected with valgrind.
- Upgrades bundled ‘libmbedtls’ to v3.5.0.

## nanonext 0.10.2

CRAN release: 2023-09-27

##### Updates

- Addresses one case of memory access error identified by CRAN.

## nanonext 0.10.1

CRAN release: 2023-09-26

##### New Features

- [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  adds logical argument ‘ack’, which sends an ack(nowledgement) back to
  the rep node upon a successful async message receive.
- [`reap()`](https://nanonext.r-lib.org/dev/reference/reap.md)
  implemented as a faster alternative to
  [`close()`](https://nanonext.r-lib.org/dev/reference/close.md) for
  Sockets, Contexts, Listeners and Dialers - avoiding S3 method
  dispatch, hence works for unclassed external pointers created by
  [`.context()`](https://nanonext.r-lib.org/dev/reference/dot-context.md).
- [`random()`](https://nanonext.r-lib.org/dev/reference/random.md)
  updated to use the Mbed TLS library to generate random bytes. Adds a
  ‘convert’ argument for specifying whether to return a raw vector or
  character string.
- Adds ‘next’ as a mode for send functions, as a 100% compatible R
  serialisation format (may be received using mode ‘serial’).

##### Updates

- [`write_cert()`](https://nanonext.r-lib.org/dev/reference/write_cert.md)
  has been optimised for higher efficiency and faster operation.
- [`send()`](https://nanonext.r-lib.org/dev/reference/send.md) and
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md) over
  contexts now use more efficient synchronous methods where available.
- Fixes package installation failures where the R default C compiler
  command contains additional flags (thanks
  [@potash](https://github.com/potash)
  [\#16](https://github.com/r-lib/nanonext/issues/16)).
- Performance improvements due to simplification of the internal
  structure of ‘aio’ objects.
- Rolls forward bundled ‘libnng’ to v1.6.0 alpha (a54820f).

## nanonext 0.10.0

CRAN release: 2023-08-31

##### New Features

- [`ncurl_aio()`](https://nanonext.r-lib.org/dev/reference/ncurl_aio.md)
  has been separated into a dedicated function for async http requests.
- Receive functions add `mode = 'string'` as a faster alternative to
  ‘character’ when receiving a scalar value.

##### Updates

*Please review the following potentially breaking changes, and only
update when ready:*

- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md)
  argument ‘async’ is retired. Please use
  [`ncurl_aio()`](https://nanonext.r-lib.org/dev/reference/ncurl_aio.md)
  for asynchronous requests.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) now
  always returns the response message body at `$data` whether convert is
  TRUE or FALSE.
- The argument ‘keep.raw’ for all receive functions
  (previously-deprecated) is removed.
- [`cv_reset()`](https://nanonext.r-lib.org/dev/reference/cv.md) and
  [`cv_signal()`](https://nanonext.r-lib.org/dev/reference/cv.md) now
  both return invisible zero rather than NULL.
- Function `device()` is removed partially due to its non-interruptible
  blocking behaviour.

*Other changes:*

- Improvements to recv (mode = ‘serial’) and
  [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md):
  - Failure to unserialize, or convert to character, automatically saves
    the data as a raw vector for recovery, generating a warning instead
    of an error (as was the case prior to v0.9.2).
- Improvements to vector send/recv (mode = ‘raw’):
  - Higher performance sending of vector data.
  - Permits sending of NULL, in which case an empty vector of the
    corresponding mode is received.
  - Character vectors containing empty characters in the middle are now
    received correctly.
  - For character vectors, respects original encoding and no longer
    performs automatic conversion to UTF8.
- Base64 and SHA hash functions now always use big-endian representation
  for serialization (where this is performed) to ensure consistency
  across all systems (fixes
  [\#14](https://github.com/r-lib/nanonext/issues/14), a regression in
  nanonext 0.9.2).
- Package installation now succeeds in certain environments where
  ‘cmake’ failed to make ‘libmbedtls’ detectable after building (thanks
  [@kendonB](https://github.com/kendonB)
  [\#13](https://github.com/r-lib/nanonext/issues/13)).
- Source bundles for ‘libmbedtls’ and ‘libnng’ slimmed down for smaller
  package and installed sizes.
- Configures bundled ‘libmbedtls’ v3.4.0 for higher performance.
- Supported ‘libmbedtls’ version increased to \>= 2.5.

## nanonext 0.9.2

CRAN release: 2023-08-07

*This version contains performance enhancements which have resulted in
potentially breaking changes; please review carefully and only update
when ready.*

##### New Features

- `base64dec()` argument ‘convert’ now accepts NA as an input, which
  unserializes back to the original object.

##### Updates

- The argument ‘keep.raw’ for all receive functions is deprecated. This
  is as raw vectors are no longer created as part of unserialisation or
  data conversion.
- Higher performance send and receive of serialized R objects.
  - For receive functions, attempting to unserialise a non-serialised
    message will now error with ‘unknown input format’ rather than fall
    back to a raw message vector.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) etc.
  gain higher performance raw to character conversion, resulting in the
  following changes:
  - Attempting to convert non-text data with embedded nuls will now
    error instead of silently returning NULL.
  - For efficiency, when ‘convert’ = TRUE, a raw vector is no longer
    stored at `$raw`.
- Higher performance cryptographic hash and base64 conversion functions.
  - Attributes are now taken into account for scalar strings and raw
    vectors to ensure unique hashes.
- Experimental threaded function `timed_signal()` removed.
- Requires R \>= 3.5 to ensure R serialization version 3.

## nanonext 0.9.1

CRAN release: 2023-07-12

##### New Features

- Enables secure TLS transports `tls+tcp://` and `wss://` for
  scalability protocols.
  - [`listen()`](https://nanonext.r-lib.org/dev/reference/listen.md) and
    [`dial()`](https://nanonext.r-lib.org/dev/reference/dial.md) gain
    the argument ‘tls’ for supplying a TLS configuration object
  - [`write_cert()`](https://nanonext.r-lib.org/dev/reference/write_cert.md)
    generates 4096 bit RSA keys and self-signed X.509 certificates for
    use with
    [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md).
- `weakref()`, `weakref_key()` and `weakref_value()` implement an
  interface to R’s weak reference system. These may be used for
  synchronising the lifetimes of objects with reference objects such as
  Sockets or Aios, or creating read-only objects accessible by the
  weakref value alone.
- `strcat()` provides a simple, fast utility to concatenate two strings.

##### Updates

- [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md)
  now accepts a relative path if filenames are supplied for the ‘client’
  or ‘server’ arguments.
- ‘tlsConfig’ objects no longer have a ‘source’ attribute.
- Fix cases where `base64enc()` failed for objects exceeding a certain
  size.
- [`stream()`](https://nanonext.r-lib.org/dev/reference/stream.md) has
  been updated internally for additional robustness.
- Updates bundled ‘libmbedtls’ v3.4.0 source configuration for threading
  support.
- Updates bundled ‘libnng’ to v1.6.0 alpha (c5e9d8a) again, having
  resolved previous issues.

## nanonext 0.9.0

CRAN release: 2023-05-28

*The package is now compatible (again) with currently released ‘libnng’
versions. It will attempt to use system ‘libnng’ versions \>= 1.5 where
detected, and only compile the bundled library where necessary.*

##### New Features

- Implements
  [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md)
  to create re-usable TLS configurations from certificate / key files
  (or provided directly as text).

##### Updates

- ‘pem’ argument of
  [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md),
  [`ncurl_session()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
  and [`stream()`](https://nanonext.r-lib.org/dev/reference/stream.md)
  retired in favour of ‘tls’ which takes a TLS Configuration object
  created by
  [`tls_config()`](https://nanonext.r-lib.org/dev/reference/tls_config.md)
  rather than a PEM certificate directly.
- Removes `nanonext_version()` in favour of the existing
  [`nng_version()`](https://nanonext.r-lib.org/dev/reference/nng_version.md),
  along with
  [`utils::packageVersion()`](https://rdrr.io/r/utils/packageDescription.html)
  if required, for greater flexibility.
- Removes `...` argument for
  [`context()`](https://nanonext.r-lib.org/dev/reference/context.md) -
  retained for compatibility with the ‘verify’ argument, which was
  removed in the previous release.
- Package widens compatibility to support system ‘libnng’ versions \>=
  1.5.0.
- Bundled ‘libnng’ source rolled back to v1.6.0 pre-release (8e1836f)
  for stability.

## nanonext 0.8.3

CRAN release: 2023-05-06

##### New Features

- Implements
  [`cv_signal()`](https://nanonext.r-lib.org/dev/reference/cv.md) and
  `timed_signal()` for signalling a condition variable, the latter after
  a specified time (from a newly-created thread).
- Implements
  [`.context()`](https://nanonext.r-lib.org/dev/reference/dot-context.md),
  a performance alternative to
  [`context()`](https://nanonext.r-lib.org/dev/reference/context.md)
  that does not create the full object.
- Adds utility `nanonext_version()` for providing the package version,
  NNG and mbed TLS library versions in a single string.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) gains a
  ‘timeout’ argument.

##### Updates

- Removes ‘verify’ argument of
  [`context()`](https://nanonext.r-lib.org/dev/reference/context.md)
  (changed to ‘…’ for compatibility) as
  [`request()`](https://nanonext.r-lib.org/dev/reference/request.md) and
  `request_signal()` have been rendered safe internally for use with
  timeouts.
- The name of the single argument to
  [`msleep()`](https://nanonext.r-lib.org/dev/reference/msleep.md) has
  been changed to ‘time’ from ‘msec’.
- Functions
  [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md),
  `lock()` and `unlock()` now error if unsuccessful rather than
  returning with a warning.
- For compiling bundled ‘libmbedtls’ and ‘libnng’ libraries from source,
  R’s configured C compiler is now chosen over the system default where
  this is different.
- Bundled ‘libnng’ source updated to v1.6.0 alpha (c5e9d8a).
- Bundled ‘libmbedtls’ source updated to v3.4.0.

## nanonext 0.8.2

CRAN release: 2023-04-14

##### New Features

- `lock()` and `unlock()` implemented to prevent further pipe
  connections from being established at a socket, optionally tied to the
  value of a condition variable.

##### Updates

- [`context()`](https://nanonext.r-lib.org/dev/reference/context.md)
  gains the argument ‘verify’ with a default of TRUE. This adds
  additional protection to notably the
  [`request()`](https://nanonext.r-lib.org/dev/reference/request.md) and
  `request_signal()` functions when using timeouts, as these require a
  connection to be present.
- Sending and hashing of language objects and symbols is now possible
  after fixes to serialisation.
- [`until()`](https://nanonext.r-lib.org/dev/reference/cv.md) now works
  as intended.
- Removes recently-introduced `msg_pipe()` and `'weakref<-'()` to
  maintain simplicity of user interface.
- Internal performance enhancements.

## nanonext 0.8.1

CRAN release: 2023-03-27

##### New Features

- Implements synchronisation primitives from the NNG library. Condition
  variables allow the R execution thread to wait until it is signalled
  by an incoming message or pipe event.
  - adds core functions
    [`cv()`](https://nanonext.r-lib.org/dev/reference/cv.md),
    [`wait()`](https://nanonext.r-lib.org/dev/reference/cv.md),
    [`until()`](https://nanonext.r-lib.org/dev/reference/cv.md),
    [`cv_value()`](https://nanonext.r-lib.org/dev/reference/cv.md), and
    [`cv_reset()`](https://nanonext.r-lib.org/dev/reference/cv.md).
  - adds signalling receive functions `recv_aio_signal()` and
    `request_signal()`.
  - [`pipe_notify()`](https://nanonext.r-lib.org/dev/reference/pipe_notify.md)
    signals up to 2 condition variables whenever pipes are added or
    removed at a socket.
- Adds `msg_pipe()` to return the pipe connection associated with a
  ‘recvAio’ message.
- Exposes the `sha1()` cryptographic hash and HMAC generation function
  from the ‘Mbed TLS’ library (for secure applications, use one of the
  SHA-2 algorithms instead).
- Utility function `'weakref<-'()` exposes `R_MakeWeakRef` from R’s C
  API. Useful for keeping objects alive for as long as required by a
  dependent object.

##### Updates

- [`ncurl_session()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
  gains a ‘timeout’ argument, and returns an ‘errorValue’ with warning
  upon error.
- [`listen()`](https://nanonext.r-lib.org/dev/reference/listen.md) and
  [`dial()`](https://nanonext.r-lib.org/dev/reference/dial.md) gain the
  new logical argument ‘error’ to govern the function behaviour upon
  error.
- Internal performance enhancements.

## nanonext 0.8.0

CRAN release: 2023-03-03

##### New Features

- Implements
  [`stat()`](https://nanonext.r-lib.org/dev/reference/stat.md), an
  interface to the NNG statistics framework. Can be used to return the
  number of currently connected pipes for a socket, connection attempts
  for a listener/dialer etc.
- Implements
  [`parse_url()`](https://nanonext.r-lib.org/dev/reference/parse_url.md),
  which parses a URL as per NNG. Provides a fast and standardised method
  for obtaining parts of a URL string.

##### Updates

*Please review the following potentially breaking changes, and only
update when ready:*

- Using [`socket()`](https://nanonext.r-lib.org/dev/reference/socket.md)
  specifying either ‘dial’ or ‘listen’, a failure to either dial or
  listen (due to an invalid URL for example) will now error rather than
  return a socket with a warning. This is safer behaviour that should
  make it easier to detect bugs in user code.
- [`opt()`](https://nanonext.r-lib.org/dev/reference/opt.md) and
  [`'opt<-'()`](https://nanonext.r-lib.org/dev/reference/opt.md) have
  been implemented as more ergonomic options getter and setter functions
  to replace `getopt()` and `setopt()`. These will error if the option
  does not exist / input value is invalid etc.
- [`subscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md),
  [`unsubscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md)
  and
  [`survey_time()`](https://nanonext.r-lib.org/dev/reference/survey_time.md)
  now return the Socket or Context invisibly rather than an exit code,
  and will error upon invalid input etc.
- [`survey_time()`](https://nanonext.r-lib.org/dev/reference/survey_time.md)
  argument name is now ‘value’, with a default of 1000L.
- nano Object methods `$opt`, `$listener_opt`, and `$dialer_opt`
  re-implemented to either get or set values depending on whether the
  ‘value’ parameter has been supplied.

*Other changes:*

- Bundled ‘libnng’ source updated to v1.6.0 pre-release (8e1836f).
- Supported R version amended to \>= 2.12, when person() adopted the
  current format used for package description.
- Internal performance enhancements.

## nanonext 0.7.3

CRAN release: 2023-01-22

##### New Features

- Implements
  [`ncurl_session()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
  and
  [`transact()`](https://nanonext.r-lib.org/dev/reference/ncurl_session.md)
  providing high-performance, re-usable http(s) connections.

##### Updates

- For dialers, the ‘autostart’ argument to
  [`dial()`](https://nanonext.r-lib.org/dev/reference/dial.md),
  [`socket()`](https://nanonext.r-lib.org/dev/reference/socket.md) and
  [`nano()`](https://nanonext.r-lib.org/dev/reference/nano.md) now
  accepts NA for starting the dialer synchronously - this is less
  resilient if a connection is not immediately possible, but avoids
  subtle errors from attempting to use the socket before an asynchronous
  dial has completed.
- Closing a stream now renders it inactive safely, without the need to
  strip all attributes on the object (as was the case previously).
- [`messenger()`](https://nanonext.r-lib.org/dev/reference/messenger.md)
  is faster to connect and exits gracefully in case of a connection
  error.
- Removes defunct function `nano_init()`.
- Bundled ‘libnng’ source updated to v1.6.0 pre-release (539e559).
- Fixes CRAN ‘additional issue’ (clang-UBSAN).

## nanonext 0.7.2

CRAN release: 2022-12-12

##### Updates

- For raw to character hash conversion, uses snprintf instead of sprintf
  for CRAN compliance.

## nanonext 0.7.1

CRAN release: 2022-11-16

##### New Features

- Implements `getopt()`, the counterpart to `setopt()` for retrieving
  the value of options on objects.

##### Updates

- The `setopt()` interface is simplified, with the type now inferred
  from the value supplied.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) now
  returns redirect addresses as the response header ‘Location’. This is
  so that HTTP data can also be returned at `$data` where this is
  provided.
- Eliminates CRAN ‘additional issue’ (clang/gcc-UBSAN).
- Internal performance optimisations.

## nanonext 0.7.0

CRAN release: 2022-11-07

##### New Features

- [`status_code()`](https://nanonext.r-lib.org/dev/reference/status_code.md)
  utility returns a translation of HTTP response status codes.

##### Updates

*Please review the following potentially breaking changes, and only
update when ready:*

- The API has been re-engineered to ensure stability of return types:
  - [`socket()`](https://nanonext.r-lib.org/dev/reference/socket.md),
    [`context()`](https://nanonext.r-lib.org/dev/reference/context.md)
    and [`stream()`](https://nanonext.r-lib.org/dev/reference/stream.md)
    will now error rather than return an ‘errorValue’. The error value
    is included in the error message.
  - [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md)
    and
    [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
    now always return an integer ‘errorValue’ at `$result` and `$data`
    respectively.
  - [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md) and
    [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
    now return an integer ‘errorValue’ at each of `$raw` and `$data`
    when ‘keep.raw’ is set to TRUE.
  - [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) now
    returns an integer ‘errorValue’ at each of `$status`, `$headers`,
    `$raw` and `$data` for both sync and async. Where redirects are not
    followed, the address is now returned as a character string at
    `$data`.
- For functions that send and receive messages
  i.e. [`send()`](https://nanonext.r-lib.org/dev/reference/send.md),
  [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md),
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md),
  [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
  and [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md),
  ‘errorValues’ are now returned silently without an accompanying
  warning. Use
  [`is_error_value()`](https://nanonext.r-lib.org/dev/reference/is_error_value.md)
  to explicitly check for errors.
- `nano_init()` is deprecated due to the above change in behaviour.
- [`send()`](https://nanonext.r-lib.org/dev/reference/send.md) no longer
  has a ‘…’ argument. This has had no effect since 0.6.0, but will now
  error if additional arguments are provided (please check and remove
  previous uses of the argument ‘echo’). Also no longer returns
  invisibly for consistency with
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md).
- [`listen()`](https://nanonext.r-lib.org/dev/reference/listen.md) and
  [`dial()`](https://nanonext.r-lib.org/dev/reference/dial.md) now only
  take a socket as argument; for nano objects, the `$listen()` and
  `$dial()` methods must be used instead.
- [`nano()`](https://nanonext.r-lib.org/dev/reference/nano.md) now
  creates a nano object with method `$context_open()` for applicable
  protocols. Opening a context will attach a context at `$context` and a
  `$context_close()` method. When a context is active, all object
  methods apply to the context instead of the socket. Method
  `$socket_setopt()` renamed to `$setopt()` as it can be used on the
  socket or active context as applicable.
- Non-logical values supplied to logical arguments will now error: this
  is documented for each function where this is applicable.

*Other changes:*

- Integer
  [`send()`](https://nanonext.r-lib.org/dev/reference/send.md)/[`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md)
  arguments for ‘mode’ implemented in 0.5.3 are now documented and
  considered part of the API. This is a performance feature that skips
  matching the character argument value.
- Fixes bug introduced in 0.6.0 where Aios returning ‘errorValues’ are
  not cached with the class, returning only integer values when accessed
  subsequently.
- Fixes potential crash when `base64dec()` encounters invalid input
  data. Error messages have been revised to be more accurate.
- Fixes the `$` method for ‘recvAio’ objects for when the object has
  been stopped using
  [`stop_aio()`](https://nanonext.r-lib.org/dev/reference/stop_aio.md).
- Using the `$listen()` or `$dial()` methods of a nano object specifying
  ‘autostart = FALSE’ now attaches the `$listener_start()` or
  `$dialer_start()` method for the most recently added listener/dialer.
- `device()` no longer prompts for confirmation in interactive
  environments - as device creation is only successful when binding 2
  raw mode sockets, there is little scope for accidental use.
- Print method for ‘errorValue’ now also provides the human translation
  of the error code.
- Bundled ‘libnng’ source updated to v1.6.0 pre-release (5385b78).
- Internal performance enhancements.

## nanonext 0.6.0

CRAN release: 2022-10-09

##### New Features

- Implements `base64enc()` and `base64dec()` base64 encoding and
  decoding using the ‘Mbed TLS’ library.
- `sha224()`, `sha256()`, `sha384()` and `sha512()` functions gain an
  argument ‘convert’ to control whether to return a raw vector or
  character string.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) gains
  the argument ‘follow’ (default FALSE) to control whether redirects are
  automatically followed.

##### Updates

*Please review the following potentially breaking changes, and only
update when ready:*

- [`send()`](https://nanonext.r-lib.org/dev/reference/send.md) now
  returns an integer exit code in all cases. The ‘echo’ argument has
  been replaced by ‘…’, and specifying ‘echo’ no longer has any effect.
- [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md),
  [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
  and [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  now default to ‘keep.raw’ = FALSE to return only the sent object.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md)
  argument ‘request’ renamed to ‘response’ for specifying response
  headers to return (to avoid confusion); new argument ‘follow’ (placed
  between ‘convert’ and ‘method’) controls whether redirects are
  followed, and there is no longer a user prompt in interactive
  environments.
- `sha224()`, `sha256()`, `sha384()` and `sha512()` functions no longer
  return ‘nanoHash’ objects, but a raw vector or character string
  depending on the new argument ‘convert’.

*Other changes:*

- [`socket()`](https://nanonext.r-lib.org/dev/reference/socket.md) and
  [`nano()`](https://nanonext.r-lib.org/dev/reference/nano.md) now
  accept non-missing NULL ‘listen’ and ‘dial’ arguments, allowing easier
  programmatic use.
- Functions
  [`send()`](https://nanonext.r-lib.org/dev/reference/send.md),
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md),
  [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md),
  [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md),
  `setopt()`,
  [`subscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md),
  [`unsubscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md)
  and
  [`survey_time()`](https://nanonext.r-lib.org/dev/reference/survey_time.md)
  are no longer S3 generics for enhanced performance.
- [`messenger()`](https://nanonext.r-lib.org/dev/reference/messenger.md)
  uses longer SHA-512 hash for authentication; fixes errors creating a
  connnection not being shown.
- The source code of ‘libnng’ v1.6.0 pre-release (722bf46) and
  ‘libmbedtls’ v3.2.1 now comes bundled rather than downloaded - this is
  much more efficient as unused portions have been stripped out.
- Detects and uses system installations of ‘libnng’ \>= 1.6.0
  pre-release 722bf46 and ‘libmbedtls’ \>= 2 where available, only
  compiling from source when required.
- R \>= 4.2 on Windows now performs source compilation of the bundled
  ‘libnng’ and ‘libmbedtls’ using the rtools42 toolchain. Installation
  falls back to pre-compiled libraries for older R releases.
- Supported R version amended to \>= 2.5, when the current
  [`new.env()`](https://rdrr.io/r/base/environment.html) interface was
  implemented.
- Internal performance enhancements.

## nanonext 0.5.5

CRAN release: 2022-09-04

##### Updates

- Installation succeeds under Linux where library path uses ‘lib64’
  instead of ‘lib’, and fails gracefully if ‘cmake’ is not found.

## nanonext 0.5.4

CRAN release: 2022-09-02

##### New Features

- Implements `sha224()`, `sha256()`, `sha384()` and `sha512()` series of
  fast, optimised cryptographic hash and HMAC generation functions using
  the ‘Mbed TLS’ library.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) and
  [`stream()`](https://nanonext.r-lib.org/dev/reference/stream.md) gain
  the argmument ‘pem’ for optionally specifying a certificate authority
  certificate chain PEM file for authenticating secure sites.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) gains
  the argument ‘request’ for specifying response headers to return.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) now
  returns additional `$status` (response status code) and `$headers`
  (response headers) fields.
- [`messenger()`](https://nanonext.r-lib.org/dev/reference/messenger.md)
  gains the argument ‘auth’ for authenticating communications based on a
  pre-shared key.
- [`random()`](https://nanonext.r-lib.org/dev/reference/random.md) gains
  the argument ‘n’ for generating a vector of random numbers.

##### Updates

- ‘libmbedtls’ is now built from source upon install so the package
  always has TLS support and uses the latest v3.2.1 release. Windows
  binaries also updated to include TLS support.
- [`nng_version()`](https://nanonext.r-lib.org/dev/reference/nng_version.md)
  now returns the ‘Mbed TLS’ library version number.
- `device()` gains a confirmation prompt when running interactively for
  more safety.
- Fixes issue with
  [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) that
  caused a 26 cryptography error with certain secure sites using SNI.

## nanonext 0.5.3

CRAN release: 2022-08-08

##### Updates

- Configure script provides more information by default.
- Allows integer send/recv ‘mode’ arguments (note: this is an
  undocumented performance feature with no future guarantees).
- Aio ‘timeout’ arguments now default to NULL for applying the socket
  default, although non-breaking as -2L will also work.
- [`msleep()`](https://nanonext.r-lib.org/dev/reference/msleep.md) made
  safe (does not block) in case of non-numeric input.
- Internal performance optimisations.

## nanonext 0.5.2

CRAN release: 2022-07-07

##### New Features

- Adds [`mclock()`](https://nanonext.r-lib.org/dev/reference/mclock.md),
  [`msleep()`](https://nanonext.r-lib.org/dev/reference/msleep.md) and
  [`random()`](https://nanonext.r-lib.org/dev/reference/random.md)
  utilities exposing the library functions for timing and cryptographic
  RNG respectively.
- [`socket()`](https://nanonext.r-lib.org/dev/reference/socket.md) gains
  the ability to open ‘raw’ mode sockets. Please note: this is not for
  general use - do not set this argument unless you have a specific
  need, such as for use with `device()` (refer to NNG documentation).
- Implements `device()` which creates a socket forwarder or proxy.
  Warning: use this in a separate process as this function blocks with
  no ability to interrupt.

##### Updates

- Internal performance optimisations.

## nanonext 0.5.1

CRAN release: 2022-06-10

##### Updates

- Upgrades NNG library to 1.6.0 pre-release (locked to version 722bf46).
  This version incorporates a feature simplifying the aio implementation
  in nanonext.
- Configure script updated to always download and build ‘libnng’ from
  source (except on Windows where pre-built libraries are downloaded).
  The script still attempts to detect a system ‘libmbedtls’ library to
  link against.
- Environment variable ‘NANONEXT_SYS’ introduced to permit use of a
  system ‘libnng’ install in `/usr/local`. Note that this is a manual
  setting allowing for custom NNG builds, and requires a version of NNG
  at least as recent as 722bf46.
- Fixes a bug involving the `unresolvedValue` returned by Aios (thanks
  [@lionel-](https://github.com/lionel-)
  [\#3](https://github.com/r-lib/nanonext/issues/3)).

## nanonext 0.5.0

CRAN release: 2022-05-10

##### New Features

- `$context()` method added for creating new contexts from nano Objects
  using supported protocols (i.e. req, rep, sub, surveyor, respondent) -
  this replaces the
  [`context()`](https://nanonext.r-lib.org/dev/reference/context.md)
  function for nano Objects.
- [`subscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md)
  and
  [`unsubscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md)
  now accept a topic of any atomic type (not just character), allowing
  pub/sub to be used with integer, double, logical, complex, or raw
  vectors.
- Sending via the “pub” protocol, the topic no longer needs to be
  separated from the rest of the message, allowing character scalars to
  be sent as well as vectors.
- Added convenience auxiliary functions
  [`is_nano()`](https://nanonext.r-lib.org/dev/reference/is_aio.md) and
  [`is_aio()`](https://nanonext.r-lib.org/dev/reference/is_aio.md).

##### Updates

- Protocol-specific helpers
  [`subscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md),
  [`unsubscribe()`](https://nanonext.r-lib.org/dev/reference/subscribe.md),
  and
  [`survey_time()`](https://nanonext.r-lib.org/dev/reference/survey_time.md)
  gain nanoContext methods.
- Default protocol is now ‘bus’ when opening a new Socket or nano
  Object - the choices are ordered more logically.
- Closing a stream now strips all attributes on the object rendering it
  a nil external pointer - this is for safety, eliminating a potential
  crash if attempting to re-use a closed stream.
- For receives, if an error occurs in unserialisation or data conversion
  (e.g. mode was incorrectly specified), the received raw vector is now
  available at both `$raw` and `$data` if `keep.raw = TRUE`.
- Setting ‘NANONEXT_TLS=1’ now allows the downloaded NNG library to be
  built against a system mbedtls installation.
- Setting ‘NANONEXT_ARM’ is no longer required on platforms such as
  Raspberry Pi - the package configure script now detects platforms
  requiring the libatomic linker flag automatically.
- Deprecated `send_ctx()`, `recv_ctx()` and logging removed.
- All-round internal performance optimisations.

## nanonext 0.4.0

CRAN release: 2022-04-10

##### New Features

- New [`stream()`](https://nanonext.r-lib.org/dev/reference/stream.md)
  interface exposes low-level byte stream functionality in the NNG
  library, intended for communicating with non-NNG endpoints, including
  but not limited to websocket servers.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) adds an
  ‘async’ option to perform HTTP requests asynchronously, returning
  immediately with a ‘recvAio’. Adds explicit arguments for HTTP method,
  headers (which takes a named list or character vector) and request
  data, as well as to specify if conversion from raw bytes is required.
- New
  [`messenger()`](https://nanonext.r-lib.org/dev/reference/messenger.md)
  function implements a multi-threaded console-based messaging system
  using NNG’s scalability protocols (currently as proof of concept).
- New `nano_init()` function intended to be called immediately after
  package load to set global options.

##### Updates

- Behavioural change: messages have been upgraded to warnings across the
  package to allow for enhanced reporting of the originating call
  e.g. via [`warnings()`](https://rdrr.io/r/base/warnings.html) and
  flexibility in handling via setting
  [`options()`](https://rdrr.io/r/base/options.html).
- Returned NNG error codes are now all classed as ‘errorValue’ across
  the package.
- Unified [`send()`](https://nanonext.r-lib.org/dev/reference/send.md)
  and [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md)
  functions, and their asynchronous counterparts
  [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md)
  and
  [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md),
  are now S3 generics and can be used across Sockets, Contexts and
  Streams.
- Revised ‘block’ argument for
  [`send()`](https://nanonext.r-lib.org/dev/reference/send.md) and
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md) now
  allows an integer value for setting a timeout.
- `send_ctx()` and `recv_ctx()` are deprecated and will be removed in a
  future package version - the methods for
  [`send()`](https://nanonext.r-lib.org/dev/reference/send.md) and
  [`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md) should be
  used instead.
- To allow for more flexible practices, logging is now deprecated and
  will be removed entirely in the next package version. Logging can
  still be enabled via ‘NANONEXT_LOG’ prior to package load but
  `logging()` is now defunct.
- Internal performance optimisations.

## nanonext 0.3.0

CRAN release: 2022-03-10

##### New Features

- Aio values `$result`, `$data` and `$raw` now resolve automatically
  without requiring
  [`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md).
  Access directly and an ‘unresolved’ logical NA value will be returned
  if the Aio operation is yet to complete.
- [`unresolved()`](https://nanonext.r-lib.org/dev/reference/unresolved.md)
  added as an auxiliary function to query whether an Aio is unresolved,
  for use in control flow statements.
- Integer error values generated by receive functions are now classed
  ‘errorValue’.
  [`is_error_value()`](https://nanonext.r-lib.org/dev/reference/is_error_value.md)
  helper function included.
- [`is_nul_byte()`](https://nanonext.r-lib.org/dev/reference/is_error_value.md)
  added as a helper function for request/reply setups.
- [`survey_time()`](https://nanonext.r-lib.org/dev/reference/survey_time.md)
  added as a convenience function for surveyor/respondent patterns.
- `logging()` function to specify a global package logging level -
  ‘error’ or ‘info’. Automatically checks the environment variable
  ‘NANONEXT_LOG’ on package load and then each time
  `logging(level = "check")` is called.
- [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md) adds a
  ‘…’ argument. Support for HTTP methods other than GET.

##### Updates

- [`listen()`](https://nanonext.r-lib.org/dev/reference/listen.md) and
  [`dial()`](https://nanonext.r-lib.org/dev/reference/dial.md) now
  return (invisible) zero rather than NULL upon success for consistency
  with other functions.
- Options documentation entry renamed to `opts` to avoid clash with base
  R ‘options’.
- Common format for NNG errors and informational events now starts with
  a timestamp for easier logging.
- Allows setting the environment variable ‘NANONEXT_ARM’ prior to
  package installation
  - Fixes installation issues on certain ARM architectures
- Package installation using a system ‘libnng’ now automatically detects
  ‘libmbedtls’, removing the need to manually set ‘NANONEXT_TLS’ in this
  case.
- More streamlined NNG build process eliminating unused options.
- Removes experimental `nng_timer()` utility as a non-essential
  function.
- Deprecated functions ‘send_vec’ and ‘recv_vec’ removed.

## nanonext 0.2.0

CRAN release: 2022-02-10

##### New Features

- Implements full async I/O capabilities
  - [`send_aio()`](https://nanonext.r-lib.org/dev/reference/send_aio.md)
    and
    [`recv_aio()`](https://nanonext.r-lib.org/dev/reference/recv_aio.md)
    now return Aio objects, for which the results may be called using
    [`call_aio()`](https://nanonext.r-lib.org/dev/reference/call_aio.md).
- New [`request()`](https://nanonext.r-lib.org/dev/reference/request.md)
  and [`reply()`](https://nanonext.r-lib.org/dev/reference/reply.md)
  functions implement the full logic of an RPC client/server, allowing
  processes to run concurrently on the client and server.
  - Designed to be run in separate processes, the reply server will
    await data and apply a function before returning a result.
  - The request client performs an async request to the server and
    returns immediately with an Aio.
- New [`ncurl()`](https://nanonext.r-lib.org/dev/reference/ncurl.md)
  minimalistic http(s) client.
- New `nng_timer()` utility as a demonstration of NNG’s multithreading
  capabilities.
- Allows setting the environment variable ‘NANONEXT_TLS’ prior to
  package installation
  - Enables TLS where the system NNG library has been built with TLS
    support (using Mbed TLS).

##### Updates

- Dialer/listener starts and close operations no longer print a message
  to stderr when successful for less verbosity by default.
- All send and receive functions,
  e.g. [`send()`](https://nanonext.r-lib.org/dev/reference/send.md)/[`recv()`](https://nanonext.r-lib.org/dev/reference/recv.md),
  gain a revised ‘mode’ argument.
  - This now permits R serialization as an option, consolidating the
    functionality of the ’\_vec’ series of functions.
- Functions ‘send_vec’ and ‘recv_vec’ are deprecated and will be removed
  in a future release.
- Functions ‘ctx_send’ and ‘ctx_recv’ have been renamed `send_ctx()` and
  `recv_ctx()` for consistency.
- The `$socket_close()` method of nano objects has been renamed
  `$close()` to better align with the functional API.

## nanonext 0.1.0

CRAN release: 2022-01-25

- Initial release to CRAN, rOpenSci R-universe and Github.
