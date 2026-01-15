# nanonext (development version)

#### New Features

* Adds `race_aio()` to wait for and return the index of the first resolved Aio in a list of Aios.

#### Updates

* `random()` now only accepts 'n' between 1 and 1024. Supplying 0 will error (#238).
* Fixes a potential crash when `random()` or `write_cert()` is called in a fresh session before any other TLS-related functions have been called, and nanonext has been compiled against a system Mbed TLS with PSA crypto enabled. (#242).
* Fixes a potential crash when a serialization hook errors (#225).
* Performance improvements for serialization, streaming, and async sends.
* Bundled 'libmbedtls' updated to latest 3.6.5 LTS branch release (#234).
* Building from source no longer requires `xz`.

# nanonext 1.7.2

#### Updates

* `pipe_notify(flag = tools::SIGTERM)` will now raise the signal with a 200ms grace period to allow a process to exit normally (#212).
* `parse_url()` drops 'rawurl', 'host' and 'requri' from the output vector as these can be derived from the other parts (#209).

# nanonext 1.7.1

#### Updates

* `stop_aio()` now resets the R interrupt flags (#194).
* The `cv` arguments at `recv_aio()` and `request()` have been simplified to accept just a 'conditionVariable' or NULL.

# nanonext 1.7.0

#### Behavioural Changes

* The promises method for `ncurlAio` has been updated for ease of use (#176):
  + Returns a list of 'status', 'headers' and 'data'.
  + Rejects only if an NNG error is returned (all HTTP status codes are resolved).
* Improved behaviour when using `serial_config()` configurations applied to a socket.
  If the serialization hook function errors or otherwise fails to return a raw vector, this will error out rather than be silently ignored (#173).

#### New Features

* A 'recvAio' returned by `request()` now has an attribute `id`, which is the integer ID of the context passed to it.

#### Updates

* `opt()` for a boolean NNG option now correctly returns a logical value instead of an integer (#186).
* `as.promise()` method for `recvAio` and `ncurlAio` objects made robust for high-throughput cases (#171).

# nanonext 1.6.2

#### Updates

* Fixes extremely rare cases of `unresolvedValue` being returned by fulfilled promises (#163).

# nanonext 1.6.1

#### Updates

* `ncurl()` and variants now accept request data supplied as a raw vector (thanks @thomasp85, #158).
* `cv_reset()` now correctly resets the flag in the case a flag event has already been registered with `pipe_notify()`.
* The previous `listen()` and `dial()` argument `error`, removed in v1.6.0, is now defunct.
* The previous `serial_config()` argument `vec`, unutilised since v1.6.0, is removed.
* Fixes package installation with 'libmbedtls' in a non-standard filesystem location, even if known to the compiler (thanks @tdhock, #150).
* Bundled 'libnng' updated to 1.11.0 release.

# nanonext 1.6.0

#### New Features

* `serial_config()` now accepts vector arguments to register multiple custom serialization configurations.
* Adds `ip_addr()` for returning the local network IPv4 address of all network adapters, named by interface.
* Adds `pipe_id()` for returning the integer pipe ID for a resolved 'recvAio'.
* Adds `write_stdout()` which performs a non-buffered write to `stdout`, to avoid interleaved messages when used concurrently by different processes.
* Adds `read_stdin()` which performs a read from `stdin` on a background thread, relayed via an 'inproc' socket so that it may be consumed via `recv()` or `recv_aio()`.
* `request()` gains integer argument `id`. This may be specified to have a special payload sent asynchronously upon timeout (to communicate with the connected party).

#### Updates

* `listen()` and `dial()` argument `error` is replaced with `fail` to specify the failure mode - 'warn', 'error', or 'none' to just return an 'errorValue'.
  + Any existing usage of `error = TRUE` will work only until the next release.
* Partial matching is no longer enabled for the `mode` argument to send/receive functions.
* `send_aio()` without keeping a reference to the return value no longer potentially drops sends (thanks @wch, #129).
* `pipe_notify()` no longer requires any particular sequencing of closing the socket and garbage collection of the socket / 'conditionVariable' (#143).
* More robust interruption on non-Windows platforms when `tools::SIGINT` is supplied to the `flag` argument of `pipe_notify()` (thanks @LennardLux, #97).
* Installation from source specifying 'INCLUDE_DIR' and 'LIB_DIR' environment variables works again, correcting a regression in v1.5.2 (#104).
* Windows bi-arch source builds for R <= 4.1 using rtools40 and earlier work again (regression since v1.5.1) (thanks @daroczig, #107).
* Bundled 'libnng' 1.10.2 pre-release updated with latest patches.
* Package is re-licensed under the MIT license.

# nanonext 1.5.2

#### Updates

* `write_cert()` argument 'cn' now defaults to '127.0.0.1' instead of 'localhost'.
* `messenger()` now exits cleanly, correcting a regression in nanonext 1.5.0 (#87).
* Promises created from 'recvAio' and 'ncurlAio' now reject in exactly the same way whether or not they were resolved at time of creation (#89).
* Bundled 'libnng' updated to 1.10.2 pre-release.
  + With this library version, a 'req' socket with option 'req:resend-time' set as 0 now frees the message as soon as the send has completed without waiting for the reply.

# nanonext 1.5.1

#### Updates

* `pipe_notify()` drops argument 'cv2' for signalling 2 condition variables on one pipe event. Use signal forwarders `%~>%` instead.
* The abillity to `lock()` and `unlock()` sockets is removed.
* Renders it safe to serialize 'nano' and 'aio' objects - they will be inactive when unserialized.
* Unified Windows build system now compiles 'libmbedtls' and 'libnng' from source even on R <= 4.1 using Rtools40 or earlier.
* Minimum supported 'libnng' version increased to 1.9.0.

# nanonext 1.5.0

#### Library Updates

* Bundled 'libnng' updated to latest 1.10.1 release.
* Bundled 'libmbedtls' updated to latest 3.6.2 LTS branch release.

#### Updates

* `nano()` updated with the 'poly' protocol, with 'pipe' argument enabled for the send methods.
* `write_cert()` no longer displays a status message when interactive (thanks @wlandau, #74).
* Removes partial matching when using `$`, `[[` or `[` on an object inheriting from class 'nano'.
* Fixes a rare hang on socket close that was possible on Windows platforms for IPC connections (#76).

# nanonext 1.4.0

#### New Features

* New interface to Pipes moves to using integer pipe IDs rather than Pipe (external pointer) objects:
  + `send()` and `send_aio()` gain the argument 'pipe' which accepts an integer pipe ID for directed sends (currently only supported by Sockets using the 'poly' protocol).
  + A 'recvAio' now records the integer pipe ID, where successful, at `$aio` upon resolution.
  + Pipe objects (of class 'nanoPipe') are obsoleted.
* Adds `monitor()` and `read_monitor()` for easy monitoring of connection changes (pipe additons and removals) at a Socket.

#### Updates

* `collect_pipe()` is removed given the pipe interface changes.

# nanonext 1.3.2

#### Updates

* Hotfix for CRAN (updates to tests only).

# nanonext 1.3.1

#### Updates

* Performs interruptible 'aio' waits using a single dedicated thread, rather than launching new threads, for higher performance and efficiency.
* Performance enhancements for 'ncurlAio' and 'recvAio' promises methods.
* Updates bundled 'libnng' to v1.9.0 stable release.
* The package has a shiny new hex logo.

# nanonext 1.3.0

#### New Features

* Adds support for threaded dispatcher in `mirai`.
* Adds 'recvAio' method for `promises::as.promise()` and `promises::is.promising()` to enable 'recvAio' promises.

#### Updates

* `serial_config()` now validates all arguments and returns them as a list. Full validation is also performed when the option is set for additional safety.
* Warning messages for unserialization or conversion failures of received data are now suppressable.
* Upgrades `reply()` to always return even when there is an evaluation error. This allows it to be used safely in a loop without exiting early, for example.
* Removes deprecated and defunct `next_config()`.
* Internal performance enhancements.
* Updates bundled 'libnng' v1.8.0 with latest patches.

# nanonext 1.2.1

#### Updates

* Re-optimizes custom serialization (whilst addressing CRAN clang-UBSAN checks).

# nanonext 1.2.0

#### New Features

* Adds `serial_config()` to create configurations that can be set on Sockets to make use of custom serialization and unserialization functions for reference objects (plugs into the 'refhook' system of native R serialization).
* `'opt<-'()` now accepts the special option 'serial' for Sockets, which takes a configuration returned from `serial_config()`.
* Adds the 'poly' protocol for one-to-one of many socket connections (NNG's pair v1 polyamorous mode).
* Adds `is_ncurl_session()` as a validation function.
* Adds `collect_pipe()` for obtaining the underlying Pipe from a 'recvAio'. This affords more granular control of connections, with the ability to close individual pipes.
* `send_aio()` now accept a Pipe to direct messages to a specific peer for supported protocols such as 'poly'.

#### Updates

* Send mode 'next' is folded into the default 'serial', with custom serialization functions applying automatically if they have been registered.
* The session-wide `next_config()` is now deprecated and defunct, in favour of the new `serial_config()`.
* `ncurl_session()` now returns 'errorValue' 7 (Object closed) when attempting to transact over a closed session or closing a closed session, rather than throwing an error.
* `collect_aio()` and `collect_aio_()` no longer append empty names when acting on lists of Aios where there were none in the first place.
* Removes hard dependency on `stats` and `utils` base packages.
* Requires R >= 3.6.

# nanonext 1.1.1

#### New Features

* Adds 'ncurlAio' method for `promises::as.promise()` and `promises::is.promising()` to enable 'ncurlAio' promises.
* Adds `x[]` as a new method for an Aio `x` equivalent to `collect_aio_(x)`, which waits for and collects the data.

#### Updates

* `request()` specifying argument 'cv' other than NULL or a 'conditionVariable' will cause the pipe connection to be dropped when the reply is (asynchronously) completed. 
* Removes deprecated functions `strcat()`, `recv_aio_signal()` and `request_signal()`.
* Drops `base64enc()` and `base64dec()` in favour of those from the {secretbase} package.
* `msleep()` now ignores negative values rather than taking the absolute value.
* `later` is now relaxed to a soft 'suggests' dependency (only required if using promises).
* `promises` is added as a soft 'enhances' dependency.

# nanonext 1.1.0

#### New Features

* Adds `collect_aio()` and `collect_aio_()` to wait for and collect the data of an Aio or list of Aios.
* `unresolved()`, `call_aio()`,  `call_aio()_` and `stop_aio()` now all accept a list of Aios.
* `pipe_notify()` gains the ability to specify 'cv' as NULL to cancel previously-set signals.
* `ncurl_aio()` modified internally to support conversion of 'ncurlAio' to event-driven promises.

#### Updates

* `recv_aio()` and `request()` add argument 'cv' allowing optional signalling of a condition variable. The separate functions `recv_aio_signal()` and `request_signal()` are deprecated.
* `strcat()` is deprecated as considered non-core - it is recommended to replace usage with `sprintf()`.
* `status_code()` now returns the status code combined with the explanation as a character string.
* Performance enhancements for `unresolved()`, `call_aio()` and `call_aio_()`.
* Updates bundled 'libnng' v1.8.0 with latest patches.

# nanonext 1.0.0

#### New Features

* Integrates with the `later` package to provide the foundation for truly event-driven (non-polling) promises (thanks @jcheng5 for the initial prototype in #28), where side-effects are enacted asynchronously upon aio completion.
  + `request()` and `request_signal()` modified internally to support conversion of 'recvAio' to event-driven promises.
  + `later` dependency ensures asynchronous R code is always run on the main R thread.
  + `later` is lazily loaded the first time a promise is used, and hence does not impact the load time of `nanonext` or dependent packages.

#### Updates

* `stop_aio()` now causes the 'aio' to resolve to an 'errorValue' of 20 (Operation canceled) if successfully stopped.
* `nng_error()` now returns the error code combined with the message as a character string.
* Integer file descriptors are no longer appended to 'nanoSocket' attributes.
* Adds 'xz' to SystemRequirements (as was the case previously but not explicitly specified) (thanks @gaborcsardi).
* Re-aligns bundled 'libmbedtls' to v3.5.2 and optimises bundle size.
* Updates minimum 'libnng' version requirement to v1.6.0.
* Upgrades bundled 'libnng' to v1.8.0.

# nanonext 0.13.5.2

#### Updates

* Safer and more efficient memory reads for 'next' serialization corrects for CRAN UBSAN-clang check errors.

# nanonext 0.13.5.1

#### New Features

* `next_config()` gains argument 'class' and 'vec', enabling custom serialization for all reference object types supported by R serialization.
* An integer file descriptor is appended to 'nanoSockets' as the attribute 'fd' - see updated documentation for `socket()`.

#### Updates

* Removes SHA-2 cryptographic hash functions (please use the streaming implementation in the secretbase package).

# nanonext 0.13.2

#### Updates

* Fixes cases of 'built for newer macOS version than being linked' installation warnings on MacOS.
* Upgrades bundled 'libnng' to v1.7.2.

# nanonext 0.13.0

#### Updates

*Please note the following potentially breaking changes, and only update when ready:*

* Default behaviour of `send()` and `recv()` aligned to non-blocking for both Sockets and Contexts (facilitated by synchronous context sends in NNG since v1.6.0).
* `ncurl()`, `ncurl_aio()` and `ncurl_session()` now restrict 'header' and 'response' arguments to character vectors only, no longer accepting lists (for safety and performance).
* Unserialization / decoding errors where the received message cannot be translated to the specified mode will output a message to stderr, but no longer generate a warning.
* SHA functions now skip serialization headers for serialized R objects (ensuring portability as these contain R version and encoding information). This means that, for serialized objects, hashes will be different to those obtained using prior package versions.
* `sha1()` is removed as a hash option.

*Other changes:*

* `messenger()` specifying 'auth' now works reliably on endpoints using different R versions/platforms due to the above hashing portability fix.
* Internal memory-efficiency and performance enhancements.
* Upgrades bundled 'libmbedtls' to v3.5.2.

# nanonext 0.12.0

*This is a major performance and stability release bundling the 'libnng' v1.7.0 source code.*

#### New Features

* `pipe_notify()` argument 'flag' allows supplying a signal to be raised on a flag being set upon a pipe event.

#### Updates

* More compact print methods for 'recvAio', 'sendAio', 'ncurlAio', 'ncurlSession' and 'tlsConfig' objects.
* `random()` now explicitly limits argument 'n' to values between 0 and 1024.
* `next_config()` now returns a pairlist (of the registered serialization functions) rather than a list (for efficiency).
* Using mode 'next', serialization functions with incorrect signatures are now simply ignored rather than raise errors.
* 'nanoStream' objects simplified internally with updated attributes 'mode' and 'state'.
* Deprecated function `.until()` is removed.
* Eliminates potential memory leaks along certain error paths.
* Fixes bug which prevented much higher TLS performance when using the bundled 'libnng' source.
* Upgrades bundled 'libnng' to v1.7.0 release.

# nanonext 0.11.0

*This is a major stability release bundling the 'libnng' v1.6.0 source code.*

#### New Features

* Introduces `call_aio_()`, a user-interruptible version of `call_aio()` suitable for interactive use.
* Introduces `wait_()` and `until_()` user-interruptible versions of `wait()` and `until()` suitable for interactive use.
* Implements `%~>%` signal forwarder from one 'conditionVariable' to another.

#### Updates

* `next_config()` replaces `nextmode()` with the following improvements:
  + simplified 'refhook' argument takes a pair of serialization and unserialization functions as a list.
  + registered 'refhook' functions apply to external pointer type objects only.
  + no longer returns invisibly for easier confimation that the correct functions have been registered.
* `until()` updated to be identical to `.until()`, returning FALSE instead of TRUE if the timeout has been reached.
* `reap()` updated to no longer warn in cases it returns an 'errorValue'.
* `pipe_notify()` arguments 'add', 'remove' and 'flag' now default to FALSE instead of TRUE for easier selective specification of the events to signal.
* Fixes regression in release 0.10.4 that caused a potential segfault using `ncurl()` with 'follow' set to TRUE when the server returns a missing or invalid relocation address.
* The weak references interface is removed as 'non-core'.
* Upgrades bundled 'libnng' to v1.6.0 release.
* Upgrades bundled 'libmbedtls' to v3.5.1.

# nanonext 0.10.4

#### New Features

* `nextmode()` configures settings for send mode 'next'. Registers hook functions for custom serialization and unserialization of reference objects (such as those accessed via an external pointer).
* `.until()` contains revised behaviour for this synchronisation primitive, returning FALSE instead of TRUE if the timeout has been reached. This function will replace `until()` in a future package version.

#### Updates

* `lock()` supplying 'cv' has improved behaviour which locks the socket whilst allowing for both initial connections and re-connections (when the 'cv' is registered for both add and remove pipe events).
* Improves listener / dialer logic for TLS connections, allowing *inter alia* synchronous dials.
* `request()` argument 'ack' removed due to stability considerations.
* Fixes memory leaks detected with valgrind.
* Upgrades bundled 'libmbedtls' to v3.5.0.

# nanonext 0.10.2

#### Updates

* Addresses one case of memory access error identified by CRAN.

# nanonext 0.10.1

#### New Features

* `request()` adds logical argument 'ack', which sends an ack(nowledgement) back to the rep node upon a successful async message receive.
* `reap()` implemented as a faster alternative to `close()` for Sockets, Contexts, Listeners and Dialers - avoiding S3 method dispatch, hence works for unclassed external pointers created by `.context()`.
* `random()` updated to use the Mbed TLS library to generate random bytes. Adds a 'convert' argument for specifying whether to return a raw vector or character string.
* Adds 'next' as a mode for send functions, as a 100% compatible R serialisation format (may be received using mode 'serial').

#### Updates

* `write_cert()` has been optimised for higher efficiency and faster operation.
* `send()` and `recv()` over contexts now use more efficient synchronous methods where available.
* Fixes package installation failures where the R default C compiler command contains additional flags (thanks @potash #16).
* Performance improvements due to simplification of the internal structure of 'aio' objects.
* Rolls forward bundled 'libnng' to v1.6.0 alpha (a54820f).

# nanonext 0.10.0

#### New Features

* `ncurl_aio()` has been separated into a dedicated function for async http requests.
* Receive functions add `mode = 'string'` as a faster alternative to 'character' when receiving a scalar value.

#### Updates

*Please review the following potentially breaking changes, and only update when ready:*

* `ncurl()` argument 'async' is retired. Please use `ncurl_aio()` for asynchronous requests.
* `ncurl()` now always returns the response message body at `$data` whether convert is TRUE or FALSE.
* The argument 'keep.raw' for all receive functions (previously-deprecated) is removed.
* `cv_reset()` and `cv_signal()` now both return invisible zero rather than NULL.
* Function `device()` is removed partially due to its non-interruptible blocking behaviour.

*Other changes:*

* Improvements to recv (mode = 'serial') and `ncurl()`:
  + Failure to unserialize, or convert to character, automatically saves the data as a raw vector for recovery, generating a warning instead of an error (as was the case prior to v0.9.2).
* Improvements to vector send/recv (mode = 'raw'):
  + Higher performance sending of vector data.
  + Permits sending of NULL, in which case an empty vector of the corresponding mode is received.
  + Character vectors containing empty characters in the middle are now received correctly.
  + For character vectors, respects original encoding and no longer performs automatic conversion to UTF8.
* Base64 and SHA hash functions now always use big-endian representation for serialization (where this is performed) to ensure consistency across all systems (fixes #14, a regression in nanonext 0.9.2).
* Package installation now succeeds in certain environments where 'cmake' failed to make 'libmbedtls' detectable after building (thanks @kendonB #13).
* Source bundles for 'libmbedtls' and 'libnng' slimmed down for smaller package and installed sizes.
* Configures bundled 'libmbedtls' v3.4.0 for higher performance.
* Supported 'libmbedtls' version increased to >= 2.5.

# nanonext 0.9.2

*This version contains performance enhancements which have resulted in potentially breaking changes; please review carefully and only update when ready.*

#### New Features

* `base64dec()` argument 'convert' now accepts NA as an input, which unserializes back to the original object.

#### Updates

* The argument 'keep.raw' for all receive functions is deprecated. This is as raw vectors are no longer created as part of unserialisation or data conversion.
* Higher performance send and receive of serialized R objects.
  + For receive functions, attempting to unserialise a non-serialised message will now error with 'unknown input format' rather than fall back to a raw message vector.
* `ncurl()` etc. gain higher performance raw to character conversion, resulting in the following changes:
  + Attempting to convert non-text data with embedded nuls will now error instead of silently returning NULL.
  + For efficiency, when 'convert' = TRUE, a raw vector is no longer stored at `$raw`.
* Higher performance cryptographic hash and base64 conversion functions.
  + Attributes are now taken into account for scalar strings and raw vectors to ensure unique hashes.
* Experimental threaded function `timed_signal()` removed.
* Requires R >= 3.5 to ensure R serialization version 3.

# nanonext 0.9.1

#### New Features

* Enables secure TLS transports `tls+tcp://` and `wss://` for scalability protocols.
  + `listen()` and `dial()` gain the argument 'tls' for supplying a TLS configuration object
  + `write_cert()` generates 4096 bit RSA keys and self-signed X.509 certificates for use with `tls_config()`.
* `weakref()`, `weakref_key()` and `weakref_value()` implement an interface to R's weak reference system. These may be used for synchronising the lifetimes of objects with reference objects such as Sockets or Aios, or creating read-only objects accessible by the weakref value alone.
* `strcat()` provides a simple, fast utility to concatenate two strings.

#### Updates

* `tls_config()` now accepts a relative path if filenames are supplied for the 'client' or 'server' arguments.
* 'tlsConfig' objects no longer have a 'source' attribute.
* Fix cases where `base64enc()` failed for objects exceeding a certain size.
* `stream()` has been updated internally for additional robustness.
* Updates bundled 'libmbedtls' v3.4.0 source configuration for threading support.
* Updates bundled 'libnng' to v1.6.0 alpha (c5e9d8a) again, having resolved previous issues.

# nanonext 0.9.0

*The package is now compatible (again) with currently released 'libnng' versions. It will attempt to use system 'libnng' versions >= 1.5 where detected, and only compile the bundled library where necessary.*

#### New Features

* Implements `tls_config()` to create re-usable TLS configurations from certificate / key files (or provided directly as text).

#### Updates

* 'pem' argument of `ncurl()`, `ncurl_session()` and `stream()` retired in favour of 'tls' which takes a TLS Configuration object created by `tls_config()` rather than a PEM certificate directly.
* Removes `nanonext_version()` in favour of the existing `nng_version()`, along with `utils::packageVersion()` if required, for greater flexibility.
* Removes `...` argument for `context()` - retained for compatibility with the 'verify' argument, which was removed in the previous release.
* Package widens compatibility to support system 'libnng' versions >= 1.5.0.
* Bundled 'libnng' source rolled back to v1.6.0 pre-release (8e1836f) for stability.

# nanonext 0.8.3

#### New Features

* Implements `cv_signal()` and `timed_signal()` for signalling a condition variable, the latter after a specified time (from a newly-created thread).
* Implements `.context()`, a performance alternative to `context()` that does not create the full object.
* Adds utility `nanonext_version()` for providing the package version, NNG and mbed TLS library versions in a single string.
* `ncurl()` gains a 'timeout' argument.

#### Updates

* Removes 'verify' argument of `context()` (changed to '...' for compatibility) as `request()` and `request_signal()` have been rendered safe internally for use with timeouts.
* The name of the single argument to `msleep()` has been changed to 'time' from 'msec'.
* Functions `pipe_notify()`, `lock()` and `unlock()` now error if unsuccessful rather than returning with a warning.
* For compiling bundled 'libmbedtls' and 'libnng' libraries from source, R's configured C compiler is now chosen over the system default where this is different.
* Bundled 'libnng' source updated to v1.6.0 alpha (c5e9d8a).
* Bundled 'libmbedtls' source updated to v3.4.0.

# nanonext 0.8.2

#### New Features

* `lock()` and `unlock()` implemented to prevent further pipe connections from being established at a socket, optionally tied to the value of a condition variable.

#### Updates

* `context()` gains the argument 'verify' with a default of TRUE. This adds additional protection to notably the `request()` and `request_signal()` functions when using timeouts, as these require a connection to be present.
* Sending and hashing of language objects and symbols is now possible after fixes to serialisation.
* `until()` now works as intended.
* Removes recently-introduced `msg_pipe()` and `'weakref<-'()` to maintain simplicity of user interface.
* Internal performance enhancements.

# nanonext 0.8.1

#### New Features

* Implements synchronisation primitives from the NNG library. Condition variables allow the R execution thread to wait until it is signalled by an incoming message or pipe event.
  + adds core functions `cv()`, `wait()`, `until()`, `cv_value()`, and `cv_reset()`.
  + adds signalling receive functions `recv_aio_signal()` and `request_signal()`.
  + `pipe_notify()` signals up to 2 condition variables whenever pipes are added or removed at a socket.
* Adds `msg_pipe()` to return the pipe connection associated with a 'recvAio' message.
* Exposes the `sha1()` cryptographic hash and HMAC generation function from the 'Mbed TLS' library (for secure applications, use one of the SHA-2 algorithms instead).
* Utility function `'weakref<-'()` exposes `R_MakeWeakRef` from R's C API. Useful for keeping objects alive for as long as required by a dependent object.

#### Updates

* `ncurl_session()` gains a 'timeout' argument, and returns an 'errorValue' with warning upon error.
* `listen()` and `dial()` gain the new logical argument 'error' to govern the function behaviour upon error.
* Internal performance enhancements.

# nanonext 0.8.0

#### New Features

* Implements `stat()`, an interface to the NNG statistics framework. Can be used to return the number of currently connected pipes for a socket, connection attempts for a listener/dialer etc.
* Implements `parse_url()`, which parses a URL as per NNG. Provides a fast and standardised method for obtaining parts of a URL string.

#### Updates

*Please review the following potentially breaking changes, and only update when ready:*

* Using `socket()` specifying either 'dial' or 'listen', a failure to either dial or listen (due to an invalid URL for example) will now error rather than return a socket with a warning. This is safer behaviour that should make it easier to detect bugs in user code.
* `opt()` and `'opt<-'()` have been implemented as more ergonomic options getter and setter functions to replace `getopt()` and `setopt()`. These will error if the option does not exist / input value is invalid etc.
* `subscribe()`, `unsubscribe()` and `survey_time()` now return the Socket or Context invisibly rather than an exit code, and will error upon invalid input etc.
* `survey_time()` argument name is now 'value', with a default of 1000L.
* nano Object methods `$opt`, `$listener_opt`, and `$dialer_opt` re-implemented to either get or set values depending on whether the 'value' parameter has been supplied.

*Other changes:*

* Bundled 'libnng' source updated to v1.6.0 pre-release (8e1836f).
* Supported R version amended to >= 2.12, when person() adopted the current format used for package description.
* Internal performance enhancements.

# nanonext 0.7.3

#### New Features

* Implements `ncurl_session()` and `transact()` providing high-performance, re-usable http(s) connections.

#### Updates

* For dialers, the 'autostart' argument to `dial()`, `socket()` and `nano()` now accepts NA for starting the dialer synchronously - this is less resilient if a connection is not immediately possible, but avoids subtle errors from attempting to use the socket before an asynchronous dial has completed.
* Closing a stream now renders it inactive safely, without the need to strip all attributes on the object (as was the case previously).
* `messenger()` is faster to connect and exits gracefully in case of a connection error.
* Removes defunct function `nano_init()`.
* Bundled 'libnng' source updated to v1.6.0 pre-release (539e559).
* Fixes CRAN 'additional issue' (clang-UBSAN).

# nanonext 0.7.2

#### Updates

* For raw to character hash conversion, uses snprintf instead of sprintf for CRAN compliance.

# nanonext 0.7.1

#### New Features

* Implements `getopt()`, the counterpart to `setopt()` for retrieving the value of options on objects.

#### Updates

* The `setopt()` interface is simplified, with the type now inferred from the value supplied.
* `ncurl()` now returns redirect addresses as the response header 'Location'. This is so that HTTP data can also be returned at `$data` where this is provided.
* Eliminates CRAN 'additional issue' (clang/gcc-UBSAN).
* Internal performance optimisations.

# nanonext 0.7.0

#### New Features

* `status_code()` utility returns a translation of HTTP response status codes.

#### Updates

*Please review the following potentially breaking changes, and only update when ready:*

* The API has been re-engineered to ensure stability of return types:
  + `socket()`, `context()` and `stream()` will now error rather than return an 'errorValue'. The error value is included in the error message.
  + `send_aio()` and `recv_aio()` now always return an integer 'errorValue' at `$result` and `$data` respectively.
  + `recv()` and `recv_aio()` now return an integer 'errorValue' at each of `$raw` and `$data` when 'keep.raw' is set to TRUE.
  + `ncurl()` now returns an integer 'errorValue' at each of `$status`, `$headers`, `$raw` and `$data` for both sync and async. Where redirects are not followed, the address is now returned as a character string at `$data`.
* For functions that send and receive messages i.e. `send()`, `send_aio()`, `recv()`, `recv_aio()` and `ncurl()`, 'errorValues' are now returned silently without an accompanying warning. Use `is_error_value()` to explicitly check for errors.
* `nano_init()` is deprecated due to the above change in behaviour.
* `send()` no longer has a '...' argument. This has had no effect since 0.6.0, but will now error if additional arguments are provided (please check and remove previous uses of the argument 'echo'). Also no longer returns invisibly for consistency with `recv()`.
* `listen()` and `dial()` now only take a socket as argument; for nano objects, the `$listen()` and `$dial()` methods must be used instead.
* `nano()` now creates a nano object with method `$context_open()` for applicable protocols. Opening a context will attach a context at `$context` and a `$context_close()` method. When a context is active, all object methods apply to the context instead of the socket. Method `$socket_setopt()` renamed to `$setopt()` as it can be used on the socket or active context as applicable.
* Non-logical values supplied to logical arguments will now error: this is documented for each function where this is applicable.

*Other changes:*

* Integer `send()`/`recv()` arguments for 'mode' implemented in 0.5.3 are now documented and considered part of the API. This is a performance feature that skips matching the character argument value.
* Fixes bug introduced in 0.6.0 where Aios returning 'errorValues' are not cached with the class, returning only integer values when accessed subsequently.
* Fixes potential crash when `base64dec()` encounters invalid input data. Error messages have been revised to be more accurate.
* Fixes the `$` method for 'recvAio' objects for when the object has been stopped using `stop_aio()`.
* Using the `$listen()` or `$dial()` methods of a nano object specifying 'autostart = FALSE' now attaches the `$listener_start()` or `$dialer_start()` method for the most recently added listener/dialer.
* `device()` no longer prompts for confirmation in interactive environments - as device creation is only successful when binding 2 raw mode sockets, there is little scope for accidental use.
* Print method for 'errorValue' now also provides the human translation of the error code.
* Bundled 'libnng' source updated to v1.6.0 pre-release (5385b78).
* Internal performance enhancements.

# nanonext 0.6.0

#### New Features

* Implements `base64enc()` and `base64dec()` base64 encoding and decoding using the 'Mbed TLS' library.
* `sha224()`, `sha256()`, `sha384()` and `sha512()` functions gain an argument 'convert' to control whether to return a raw vector or character string.
* `ncurl()` gains the argument 'follow' (default FALSE) to control whether redirects are automatically followed.

#### Updates

*Please review the following potentially breaking changes, and only update when ready:*

* `send()` now returns an integer exit code in all cases. The 'echo' argument has been replaced by '...', and specifying 'echo' no longer has any effect.
* `recv()`, `recv_aio()` and `request()` now default to 'keep.raw' = FALSE to return only the sent object.
* `ncurl()` argument 'request' renamed to 'response' for specifying response headers to return (to avoid confusion); new argument 'follow' (placed between 'convert' and 'method') controls whether redirects are followed, and there is no longer a user prompt in interactive environments.
* `sha224()`, `sha256()`, `sha384()` and `sha512()` functions no longer return 'nanoHash' objects, but a raw vector or character string depending on the new argument 'convert'.

*Other changes:*

* `socket()` and `nano()` now accept non-missing NULL 'listen' and 'dial' arguments, allowing easier programmatic use.
* Functions `send()`, `recv()`, `send_aio()`, `recv_aio()`, `setopt()`, `subscribe()`, `unsubscribe()` and `survey_time()` are no longer S3 generics for enhanced performance.
* `messenger()` uses longer SHA-512 hash for authentication; fixes errors creating a connnection not being shown.
* The source code of 'libnng' v1.6.0 pre-release (722bf46) and 'libmbedtls' v3.2.1 now comes bundled rather than downloaded - this is much more efficient as unused portions have been stripped out.
* Detects and uses system installations of 'libnng' >= 1.6.0 pre-release 722bf46 and 'libmbedtls' >= 2 where available, only compiling from source when required.
* R >= 4.2 on Windows now performs source compilation of the bundled 'libnng' and 'libmbedtls' using the rtools42 toolchain. Installation falls back to pre-compiled libraries for older R releases.
* Supported R version amended to >= 2.5, when the current `new.env()` interface was implemented.
* Internal performance enhancements.

# nanonext 0.5.5

#### Updates

* Installation succeeds under Linux where library path uses 'lib64' instead of 'lib', and fails gracefully if 'cmake' is not found.

# nanonext 0.5.4

#### New Features

* Implements `sha224()`, `sha256()`, `sha384()` and `sha512()` series of fast, optimised cryptographic hash and HMAC generation functions using the 'Mbed TLS' library.
* `ncurl()` and `stream()` gain the argmument 'pem' for optionally specifying a certificate authority certificate chain PEM file for authenticating secure sites.
* `ncurl()` gains the argument 'request' for specifying response headers to return.
* `ncurl()` now returns additional `$status` (response status code) and `$headers` (response headers) fields.
* `messenger()` gains the argument 'auth' for authenticating communications based on a pre-shared key.
* `random()` gains the argument 'n' for generating a vector of random numbers.

#### Updates

* 'libmbedtls' is now built from source upon install so the package always has TLS support and uses the latest v3.2.1 release. Windows binaries also updated to include TLS support.
* `nng_version()` now returns the 'Mbed TLS' library version number.
* `device()` gains a confirmation prompt when running interactively for more safety.
* Fixes issue with `ncurl()` that caused a 26 cryptography error with certain secure sites using SNI.

# nanonext 0.5.3

#### Updates

* Configure script provides more information by default.
* Allows integer send/recv 'mode' arguments (note: this is an undocumented performance feature with no future guarantees).
* Aio 'timeout' arguments now default to NULL for applying the socket default, although non-breaking as -2L will also work.
* `msleep()` made safe (does not block) in case of non-numeric input.
* Internal performance optimisations.

# nanonext 0.5.2

#### New Features

* Adds `mclock()`, `msleep()` and `random()` utilities exposing the library functions for timing and cryptographic RNG respectively.
* `socket()` gains the ability to open 'raw' mode sockets. Please note: this is not for general use - do not set this argument unless you have a specific need, such as for use with `device()` (refer to NNG documentation).
* Implements `device()` which creates a socket forwarder or proxy. Warning: use this in a separate process as this function blocks with no ability to interrupt.

#### Updates

* Internal performance optimisations.

# nanonext 0.5.1

#### Updates

* Upgrades NNG library to 1.6.0 pre-release (locked to version 722bf46). This version incorporates a feature simplifying the aio implementation in nanonext.
* Configure script updated to always download and build 'libnng' from source (except on Windows where pre-built libraries are downloaded). The script still attempts to detect a system 'libmbedtls' library to link against.
* Environment variable 'NANONEXT_SYS' introduced to permit use of a system 'libnng' install in `/usr/local`. Note that this is a manual setting allowing for custom NNG builds, and requires a version of NNG at least as recent as 722bf46.
* Fixes a bug involving the `unresolvedValue` returned by Aios (thanks @lionel- #3).

# nanonext 0.5.0

#### New Features

* `$context()` method added for creating new contexts from nano Objects using supported protocols (i.e. req, rep, sub, surveyor, respondent) - this replaces the `context()` function for nano Objects.
* `subscribe()` and `unsubscribe()` now accept a topic of any atomic type (not just character), allowing pub/sub to be used with integer, double, logical, complex, or raw vectors.
* Sending via the "pub" protocol, the topic no longer needs to be separated from the rest of the message, allowing character scalars to be sent as well as vectors.
* Added convenience auxiliary functions `is_nano()` and `is_aio()`.

#### Updates

* Protocol-specific helpers `subscribe()`, `unsubscribe()`, and `survey_time()` gain nanoContext methods.
* Default protocol is now 'bus' when opening a new Socket or nano Object - the choices are ordered more logically.
* Closing a stream now strips all attributes on the object rendering it a nil external pointer - this is for safety, eliminating a potential crash if attempting to re-use a closed stream.
* For receives, if an error occurs in unserialisation or data conversion (e.g. mode was incorrectly specified), the received raw vector is now available at both `$raw` and `$data` if `keep.raw = TRUE`.
* Setting 'NANONEXT_TLS=1' now allows the downloaded NNG library to be built against a system mbedtls installation.
* Setting 'NANONEXT_ARM' is no longer required on platforms such as Raspberry Pi - the package configure script now detects platforms requiring the libatomic linker flag automatically.
* Deprecated `send_ctx()`, `recv_ctx()` and logging removed.
* All-round internal performance optimisations.

# nanonext 0.4.0

#### New Features

* New `stream()` interface exposes low-level byte stream functionality in the NNG library, intended for communicating with non-NNG endpoints, including but not limited to websocket servers.
* `ncurl()` adds an 'async' option to perform HTTP requests asynchronously, returning immediately with a 'recvAio'. Adds explicit arguments for HTTP method, headers (which takes a named list or character vector) and request data, as well as to specify if conversion from raw bytes is required.
* New `messenger()` function implements a multi-threaded console-based messaging system using NNG's scalability protocols (currently as proof of concept).
* New `nano_init()` function intended to be called immediately after package load to set global options.

#### Updates

* Behavioural change: messages have been upgraded to warnings across the package to allow for enhanced reporting of the originating call e.g. via `warnings()` and flexibility in handling via setting `options()`.
* Returned NNG error codes are now all classed as 'errorValue' across the package.
* Unified `send()` and `recv()` functions, and their asynchronous counterparts `send_aio()` and `recv_aio()`, are now S3 generics and can be used across Sockets, Contexts and Streams.
* Revised 'block' argument for `send()` and `recv()` now allows an integer value for setting a timeout.
* `send_ctx()` and `recv_ctx()` are deprecated and will be removed in a future package version - the methods for `send()` and `recv()` should be used instead.
* To allow for more flexible practices, logging is now deprecated and will be removed entirely in the next package version. Logging can still be enabled via 'NANONEXT_LOG' prior to package load but `logging()` is now defunct. 
* Internal performance optimisations.

# nanonext 0.3.0

#### New Features

* Aio values `$result`, `$data` and `$raw` now resolve automatically without requiring `call_aio()`. Access directly and an 'unresolved' logical NA value will be returned if the Aio operation is yet to complete.
* `unresolved()` added as an auxiliary function to query whether an Aio is unresolved, for use in control flow statements.
* Integer error values generated by receive functions are now classed 'errorValue'. `is_error_value()` helper function included.
* `is_nul_byte()` added as a helper function for request/reply setups.
* `survey_time()` added as a convenience function for surveyor/respondent patterns.
* `logging()` function to specify a global package logging level - 'error' or 'info'. Automatically checks the environment variable 'NANONEXT_LOG' on package load and then each time `logging(level = "check")` is called.
* `ncurl()` adds a '...' argument. Support for HTTP methods other than GET.

#### Updates

* `listen()` and `dial()` now return (invisible) zero rather than NULL upon success for consistency with other functions.
* Options documentation entry renamed to `opts` to avoid clash with base R 'options'.
* Common format for NNG errors and informational events now starts with a timestamp for easier logging.
* Allows setting the environment variable 'NANONEXT_ARM' prior to package installation
  + Fixes installation issues on certain ARM architectures
* Package installation using a system 'libnng' now automatically detects 'libmbedtls', removing the need to manually set 'NANONEXT_TLS' in this case.
* More streamlined NNG build process eliminating unused options.
* Removes experimental `nng_timer()` utility as a non-essential function.
* Deprecated functions 'send_vec' and 'recv_vec' removed.

# nanonext 0.2.0

#### New Features

* Implements full async I/O capabilities 
  + `send_aio()` and `recv_aio()` now return Aio objects, for which the results may be called using `call_aio()`.
* New `request()` and `reply()` functions implement the full logic of an RPC client/server, allowing processes to run concurrently on the client and server.
  + Designed to be run in separate processes, the reply server will await data and apply a function before returning a result.
  + The request client performs an async request to the server and returns immediately with an Aio.
* New `ncurl()` minimalistic http(s) client.
* New `nng_timer()` utility as a demonstration of NNG's multithreading capabilities.
* Allows setting the environment variable 'NANONEXT_TLS' prior to package installation
  + Enables TLS where the system NNG library has been built with TLS support (using Mbed TLS).

#### Updates

* Dialer/listener starts and close operations no longer print a message to stderr when successful for less verbosity by default.
* All send and receive functions, e.g. `send()`/`recv()`, gain a revised 'mode' argument. 
  + This now permits R serialization as an option, consolidating the functionality of the '_vec' series of functions.
* Functions 'send_vec' and 'recv_vec' are deprecated and will be removed in a future release.
* Functions 'ctx_send' and 'ctx_recv' have been renamed `send_ctx()` and `recv_ctx()` for consistency.
* The `$socket_close()` method of nano objects has been renamed `$close()` to better align with the functional API.

# nanonext 0.1.0

* Initial release to CRAN, rOpenSci R-universe and Github.
