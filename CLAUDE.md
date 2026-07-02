# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## Overview

**nanonext** is an R package providing a binding to NNG (Nanomsg Next
Gen), a high-performance messaging library. The package is implemented
almost entirely in C, wrapping the NNG C library to provide R interfaces
for socket-based messaging, asynchronous I/O operations, HTTP/WebSocket
servers, and distributed computing primitives.

## Common Development Commands

``` bash
# Install package from source
R CMD INSTALL .

# Build tarball then run full CRAN checks (tests + docs + examples)
R CMD build . && R CMD check nanonext_*.tar.gz

# Run tests only (uses custom minitest framework, not testthat)
Rscript tests/tests.R

# Build roxygen2 documentation
Rscript -e 'devtools::document()'

# Precompile vignettes (must be done before R CMD build when vignettes change)
Rscript dev/vignettes/precompile.R
```

### Compilation

The `configure` script detects a system `libmbedtls` (\>= 3.0.0) and
`libnng` (\>= 1.12.0); if not found, the bundled sources are compiled
**directly into `nanonext.so`** via explicit per-object rules in
`src/Makevars` (no cmake, no static archives, no install step). To force
compilation of the bundled libraries: `Sys.setenv(NANONEXT_LIBS = 1)`.

`configure` ports NNG’s POSIX feature probes to portable shell (setting
the `NNG_HAVE_*` macros and selecting the poller / random-source
variant), then substitutes the include flags, defines, link flags and
bundled object lists into `src/Makevars.in`. Windows uses fully static
`src/Makevars.win` / `src/Makevars.ucrt` (no configure step). All three
Makevars are **generated artifacts** (“do not edit by hand”) produced by
`tools/generate_makevars.sh` from the `tools/*.list` source lists — the
single source of truth. See `## Build System` below.

### Testing

Tests are in `tests/tests.R` using a custom minitest framework (defined
at the top of the file). Available assertions: `test_true`,
`test_false`, `test_null`, `test_notnull`, `test_zero`, `test_type`,
`test_class`, `test_equal`, `test_identical`,
`test_error(expr, containing = "substring")`, `test_print`,
`test_library`. Some tests only run when `NOT_CRAN=true` or on specific
platforms.

## Core Architecture

### Dual Interface Design

1.  **Functional Interface**: Socket objects passed as first argument to
    functions like
    [`send()`](https://nanonext.r-lib.org/reference/send.md),
    [`recv()`](https://nanonext.r-lib.org/reference/recv.md),
    [`dial()`](https://nanonext.r-lib.org/reference/dial.md),
    [`listen()`](https://nanonext.r-lib.org/reference/listen.md)
2.  **Object-Oriented Interface**: Nano objects with methods accessible
    via `$send()`, `$recv()`, etc.

### C Source Organization

Each `.c` file defines a compilation unit guard macro (e.g.,
`NANONEXT_PROTOCOLS`, `NANONEXT_HTTP`, `NANONEXT_TLS`) before
`#include "nanonext.h"`, which conditionally includes the relevant NNG
headers for that compilation unit.

Key files: - `src/nanonext.h` - Main header: type definitions, macros,
all C function declarations - `src/core.c` -
Serialization/unserialization, refhook system - `src/proto.c` - Protocol
implementations (socket opening, option handling) - `src/aio.c` - Async
I/O operations, callbacks,
[`race_aio()`](https://nanonext.r-lib.org/reference/race_aio.md) -
`src/comms.c` - Send/receive operations and data marshaling -
`src/sync.c` - Synchronization primitives (condition variables,
mutexes) - `src/thread.c` - Thread management, interruptible waits -
`src/ncurl.c` - HTTP client (`ncurl`, `ncurl_aio`, `ncurl_session`) -
`src/server.c` - HTTP/WebSocket server, streaming handlers -
`src/dispatcher.c` - C-level task dispatcher (used by mirai package) -
`src/tls.c` - TLS configuration and certificate generation -
`src/init.c` - Package initialization, `.Call` registration, symbol
definitions

### R Source Organization

- `R/socket.R` - Socket creation (functional interface)
- `R/nano.R` - Nano object creation (OO interface)
- `R/sendrecv.R` - Send/receive operations
- `R/listdial.R` - Listener/Dialer management
  ([`dial()`](https://nanonext.r-lib.org/reference/dial.md),
  [`listen()`](https://nanonext.r-lib.org/reference/listen.md))
- `R/context.R` - Context and RPC operations
  ([`context()`](https://nanonext.r-lib.org/reference/context.md),
  [`request()`](https://nanonext.r-lib.org/reference/request.md),
  [`reply()`](https://nanonext.r-lib.org/reference/reply.md))
- `R/opts.R` - Option getting/setting
  ([`opt()`](https://nanonext.r-lib.org/reference/opt.md), `opt<-()`)
- `R/aio.R` - Async I/O wrappers (`send_aio`, `recv_aio`, `race_aio`,
  `collect_aio`)
- `R/server.R` - HTTP/WebSocket server (`http_server`, `handler`,
  `handler_ws`, `handler_stream`, `format_sse`)
- `R/dispatcher.R` - C-level dispatcher entry point (internal, for
  mirai)
- `R/ncurl.R` - HTTP client functions
- `R/stream.R` - Low-level WebSocket/stream interfaces
- `R/tls.R` - TLS configuration and certificate generation
- `R/sync.R` - Synchronization primitives (`cv`, `wait`, `pipe_notify`)

### External Dependencies

Bundled in source: - `libnng` v1.12.0 (messaging library) - in
`src/nng/` - `libmbedtls` v3.6.5 (TLS implementation) - in
`src/mbedtls/`

### Thread-to-R Callback Pattern

NNG callbacks run on background threads and cannot call R directly. The
package uses the `later` package (`Suggests`, lazily loaded) to schedule
R callbacks on the main thread. The `eln2` function pointer (set by
`nano_load_later()`) is the bridge. This pattern is used by: promise
resolution (`promises` package integration via `as.promise` methods for
`recvAio`/`ncurlAio`), WebSocket `on_message`/`on_open`/`on_close`
callbacks, HTTP streaming `on_request`/`on_close` callbacks.

## Key Implementation Details

### Object System

S3 classes backed by external pointers tagged with symbols (defined in
`src/init.c`, e.g. `nano_SocketSymbol`, `nano_CvSymbol`,
`nano_HttpServerSymbol`). External pointers are stored in pairlists (CAR
= pointer, CDR = protected data, TAG = type symbol). Finalizers handle C
resource cleanup. The `nano_precious` environment prevents premature GC
of R objects referenced by C code.

### Memory Management

- `NANO_ALLOC` / `NANO_FREE` macros for buffer management
- `nano_PreserveObject` / `nano_ReleaseObject` for protecting R objects
  from GC in the `nano_precious` environment
- Pointer validity checked via `NANO_PTR_CHECK(x, tag)` (verifies tag
  matches and pointer is non-NULL)

### Error Handling

- NNG errors are integer codes; `mk_error(xc)` creates objects of class
  `"errorValue"`
- `ERROR_OUT(xc)` macro calls `Rf_error()`, `ERROR_RET(xc)` returns an
  error value
- Functions generally return error values rather than throwing R errors

### HTTP/WebSocket Server Architecture

`src/server.c` implements a multi-handler HTTP server with WebSocket and
chunked streaming support. Handler types (discriminated by integer
`type` field): 1=HTTP callback, 2=WebSocket, 3=static file, 4=directory,
5=inline content, 6=redirect, 7=HTTP streaming. WebSocket and streaming
connections use a state machine (`CONN_STATE_OPEN` →
`CONN_STATE_CLOSING` → `CONN_STATE_CLOSED`) with mutex protection to
prevent races between NNG threads and R’s main thread.

### Vignettes

Vignettes are precompiled because they require live network connections.
Edit source files in `dev/vignettes/_*.Rmd` (not the compiled output in
`vignettes/*.Rmd`), then run `Rscript dev/vignettes/precompile.R` to
regenerate.

## Build System

The bundled NNG and Mbed TLS sources compile directly into
`nanonext.so`/`.dll` (no cmake, no static archives, no install step).
cmake is **not** a build dependency; it is used only by the vendoring
tooling as a verification oracle.

- `configure` - POSIX shell script for Unix-like systems. Detects system
  libs; if absent, ports NNG’s POSIX feature probes
  (`nng_check_func`/`sym`/`lib`/`struct_member`) to set the `NNG_HAVE_*`
  macros, selects the poller
  (`port_create`/`kqueue`/`epoll`+`eventfd`/`poll`) and random source
  (`arc4random`/`getrandom`/`urandom`), and substitutes flags + object
  lists into `src/Makevars.in`. No `configure.win`/`configure.ucrt`
  (Windows Makevars are static).
- Unsupported-platform fallback: when the bundled NNG is needed but the
  target lacks NNG’s POSIX threading/socket headers (a genuinely
  non-POSIX OS), `configure` builds a **stub** instead of failing. The
  probe is compile-only (header presence) by design —
  WebAssembly/Emscripten provides these headers and builds fine
  (`-pthread` only enables runtime threading), so a wasm build must not
  stub. `generate_stub` emits `src/stub.c` (a generated artifact)
  registering every routine from `src/init.c`’s `callMethods[]` bound to
  a single `Rf_error` stub, plus a trivial `OBJECTS = stub.o` Makevars;
  the package installs and loads but its functions error when called,
  keeping dependents installable. The probe only fires when a trivial
  compile succeeds (a broken compiler fails the real build loudly, not
  silently stubbed). Every platform CRAN checks has the POSIX layer, so
  the stub never displaces the real build there.
- `src/Makevars.in` (POSIX template), `src/Makevars.win` /
  `src/Makevars.ucrt` (static, identical, biarch via R’s per-sub-arch
  build) - **generated artifacts**, “do not edit by hand”.
- `tools/` - the single source of truth and maintenance contract:
  - `tools/*.list` - authoritative object lists (the only
    hand-/auto-maintained build inputs).
  - `tools/generate_makevars.sh` - emits the three Makevars from the
    `.list` files.
  - `tools/update_nng.sh` / `tools/update_mbedtls.sh` - re-vendor a
    pinned upstream tag, strip cmake, apply patches, regenerate lists +
    Makevars. `--verify` diffs the lists against a fresh cmake oracle
    (drift guard).
  - `tools/patch_nng.sh` / `tools/patch_mbedtls.sh` - idempotent patches
    neutering the compiled-code diagnostics (NNG debug
    `abort`/`vprintf`/`stderr` → `__builtin_trap`/no-ops; Mbed TLS
    `printf`/`fprintf`/`exit` → no-op `*_MACRO`s) so
    `tools:::check_compiled_code()` is clean.
- Symbol visibility: `PKG_CFLAGS = $(C_VISIBILITY)`
  (`-fvisibility=hidden`) reaches every object via `$(ALL_CFLAGS)`,
  hiding the bundled `nng_*`/`mbedtls_*` symbols (verify with `nm`).
- Environment variables: `INCLUDE_DIR`, `LIB_DIR`, `NANONEXT_LIBS`
  (force-bundled build).

## Code Style

- C functions registered for `.Call` use `rnng_` prefix
- Internal C functions and types use `nano_` prefix
- R code uses snake_case; internal functions use `.function` prefix
  (e.g., `.context`)
- C macros for common operations: `NANO_PTR`, `NANO_DATAPTR`,
  `NANO_STRING`, `NANO_VECTOR`
