# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**nanonext** is an R package providing a binding to NNG (Nanomsg Next Gen), a high-performance messaging library. The package is implemented almost entirely in C, wrapping the NNG C library to provide R interfaces for socket-based messaging, asynchronous I/O operations, HTTP/WebSocket servers, and distributed computing primitives.

## Common Development Commands

```bash
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

The configure script detects or compiles `libmbedtls` (>= 2.5.0) and `libnng` (>= 1.9.0), then generates `src/Makevars`. To force compilation of bundled libraries: `Sys.setenv(NANONEXT_LIBS = 1)`.

### Testing

Tests are in `tests/tests.R` using a custom minitest framework (defined at the top of the file). Available assertions: `test_true`, `test_false`, `test_null`, `test_zero`, `test_type`, `test_class`, `test_equal`, `test_identical`, `test_error(expr, containing = "substring")`, `test_print`. Some tests only run when `NOT_CRAN=true` or on specific platforms.

## Core Architecture

### Dual Interface Design

1. **Functional Interface**: Socket objects passed as first argument to functions like `send()`, `recv()`, `dial()`, `listen()`
2. **Object-Oriented Interface**: Nano objects with methods accessible via `$send()`, `$recv()`, etc.

### C Source Organization

Each `.c` file defines a compilation unit guard macro (e.g., `NANONEXT_PROTOCOLS`, `NANONEXT_HTTP`, `NANONEXT_TLS`) that controls which headers are included via `src/nanonext.h`. The guard is defined in `src/Makevars.in` per-file.

Key files:
- `src/nanonext.h` - Main header: type definitions, macros, all C function declarations
- `src/core.c` - Serialization/unserialization, refhook system
- `src/proto.c` - Protocol implementations (socket opening, option handling)
- `src/aio.c` - Async I/O operations, callbacks, `race_aio()`
- `src/comms.c` - Send/receive operations and data marshaling
- `src/sync.c` - Synchronization primitives (condition variables, mutexes)
- `src/thread.c` - Thread management, interruptible waits
- `src/ncurl.c` - HTTP client (`ncurl`, `ncurl_aio`, `ncurl_session`)
- `src/server.c` - HTTP/WebSocket server, streaming handlers
- `src/dispatcher.c` - C-level task dispatcher (used by mirai package)
- `src/tls.c` - TLS configuration and certificate generation
- `src/init.c` - Package initialization, `.Call` registration, symbol definitions

### R Source Organization

- `R/socket.R` - Socket creation (functional interface)
- `R/nano.R` - Nano object creation (OO interface)
- `R/sendrecv.R` - Send/receive operations
- `R/aio.R` - Async I/O wrappers (`send_aio`, `recv_aio`, `race_aio`, `collect_aio`)
- `R/server.R` - HTTP/WebSocket server (`http_server`, `handler`, `handler_ws`, `handler_stream`, `format_sse`)
- `R/dispatcher.R` - C-level dispatcher entry point (internal, for mirai)
- `R/ncurl.R` - HTTP client functions
- `R/stream.R` - Low-level WebSocket/stream interfaces
- `R/tls.R` - TLS configuration and certificate generation
- `R/sync.R` - Synchronization primitives (`cv`, `wait`, `pipe_notify`)

### External Dependencies

Bundled in source:
- `libnng` v1.11.0 (messaging library) - in `src/nng/`
- `libmbedtls` v3.6.5 (TLS implementation) - in `src/mbedtls/`

### Thread-to-R Callback Pattern

NNG callbacks run on background threads and cannot call R directly. The package uses the `later` package (lazily loaded) to schedule R callbacks on the main thread. The `eln2` function pointer (set by `nano_load_later()`) is the bridge. This pattern is used by: promise resolution, WebSocket `on_message`/`on_open`/`on_close` callbacks, HTTP streaming `on_request`/`on_close` callbacks.

## Key Implementation Details

### Object System

S3 classes backed by external pointers tagged with symbols (defined in `src/init.c`, e.g. `nano_SocketSymbol`, `nano_CvSymbol`, `nano_HttpServerSymbol`). External pointers are stored in pairlists (CAR = pointer, CDR = protected data, TAG = type symbol). Finalizers handle C resource cleanup. The `nano_precious` environment prevents premature GC of R objects referenced by C code.

### Memory Management

- `NANO_ALLOC` / `NANO_FREE` macros for buffer management
- `nano_PreserveObject` / `nano_ReleaseObject` for protecting R objects from GC in the `nano_precious` environment
- Pointer validity checked via `NANO_PTR_CHECK(x, tag)` (verifies tag matches and pointer is non-NULL)

### Error Handling

- NNG errors are integer codes; `mk_error(xc)` creates objects of class `"errorValue"`
- `ERROR_OUT(xc)` macro calls `Rf_error()`, `ERROR_RET(xc)` returns an error value
- Functions generally return error values rather than throwing R errors

### HTTP/WebSocket Server Architecture

`src/server.c` implements a multi-handler HTTP server with WebSocket and chunked streaming support. Handler types (discriminated by integer `type` field): 1=HTTP callback, 2=WebSocket, 3=static file, 4=directory, 5=inline content, 6=redirect, 7=HTTP streaming. WebSocket and streaming connections use a state machine (`CONN_STATE_OPEN` → `CONN_STATE_CLOSING` → `CONN_STATE_CLOSED`) with mutex protection to prevent races between NNG threads and R's main thread.

### Vignettes

Vignettes are precompiled because they require live network connections. Source files are in `dev/vignettes/_*.Rmd`, compiled output goes to `vignettes/*.Rmd`. Run `Rscript dev/vignettes/precompile.R` to regenerate.

## Build System

- `configure` - POSIX shell script for Unix-like systems
- `configure.win` / `configure.ucrt` - Windows configurations
- Requires `cmake` if compiling bundled libraries
- Environment variables: `INCLUDE_DIR`, `LIB_DIR`, `NANONEXT_LIBS`

## Code Style

- C functions registered for `.Call` use `rnng_` prefix
- Internal C functions and types use `nano_` prefix
- R code uses snake_case; internal functions use `.function` prefix (e.g., `.dispatcher`)
- C macros for common operations: `NANO_PTR`, `NANO_DATAPTR`, `NANO_STRING`, `NANO_VECTOR`
