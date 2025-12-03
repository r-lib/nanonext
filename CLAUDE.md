# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**nanonext** is an R package providing a binding to NNG (Nanomsg Next Gen), a high-performance messaging library. The package is implemented almost entirely in C, wrapping the NNG C library to provide R interfaces for socket-based messaging, asynchronous I/O operations, and distributed computing primitives.

## Core Architecture

### Dual Interface Design

The package provides two equivalent interfaces:

1. **Functional Interface**: Socket objects passed as first argument to functions like `send()`, `recv()`, `dial()`, `listen()`
2. **Object-Oriented Interface**: Nano objects with methods accessible via `$send()`, `$recv()`, etc.

### Key C Source Files

- `src/nanonext.h` - Main header with type definitions, macros, and function declarations
- `src/core.c` - Core serialization/unserialization, hooks, and fundamental utilities
- `src/proto.c` - Protocol implementations (socket opening, option handling)
- `src/aio.c` - Asynchronous I/O operations and callbacks
- `src/comms.c` - Send/receive operations and data marshaling
- `src/sync.c` - Synchronization primitives (condition variables, mutexes)
- `src/thread.c` - Thread management and concurrent operations
- `src/ncurl.c` - HTTP client implementation
- `src/net.c` - Network utilities (IP address retrieval)
- `src/tls.c` - TLS configuration and certificate handling
- `src/utils.c` - Utility functions
- `src/init.c` - Package initialization and registration

### Key R Source Files

- `R/socket.R` - Socket creation and management (functional interface)
- `R/nano.R` - Nano object creation (OO interface)
- `R/sendrecv.R` - Send/receive operations
- `R/aio.R` - Async I/O wrappers
- `R/context.R` - Context management for concurrent operations
- `R/sync.R` - Synchronization primitives
- `R/ncurl.R` - HTTP client functions
- `R/stream.R` - WebSocket and stream interfaces
- `R/tls.R` - TLS configuration

### External Dependencies

The package bundles and can compile:
- `libnng` v1.11.0 (messaging library) - in `src/nng/`
- `libmbedtls` v3.6.2 (TLS implementation) - in `src/mbedtls/`

These bundled libraries are compiled during installation if system libraries are not found or if `NANONEXT_LIBS=1` is set.

## Common Development Commands

### Building and Testing

```r
# Install package from source
R CMD INSTALL .

# Build package
R CMD build .

# Check package (run all tests and CRAN checks)
R CMD check nanonext_*.tar.gz

# Run tests only
Rscript tests/tests.R
```

### Development Workflow

```r
# In R session - load package for development
devtools::load_all()

# Build documentation
devtools::document()

# Run tests
devtools::test()

# Check package
devtools::check()
```

### Compilation

The package uses a configure script (`configure`) that:
1. Detects or compiles `libmbedtls` (requires >= 2.5.0)
2. Detects or compiles `libnng` (requires >= 1.9.0)
3. Generates `src/Makevars` with appropriate flags

For forced compilation of bundled libraries:
```bash
Sys.setenv(NANONEXT_LIBS = 1)
```

### Testing Notes

- Tests are in `tests/tests.R` using a minimal custom testing framework
- Tests cover: sockets, protocols, async I/O, serialization, HTTP client, TLS, streams, contexts
- Network-dependent tests may fail if external services are unavailable
- Some tests only run when `NOT_CRAN=true` or on specific platforms (Linux)

## Key Concepts

### Protocols

Implements scalability protocols:
- **Bus** (mesh): `"bus"`
- **Pair** (1-to-1): `"pair"`
- **Poly** (polyamorous 1-to-1): `"poly"`
- **Pipeline**: `"push"`, `"pull"`
- **Pub/Sub**: `"pub"`, `"sub"`
- **Request/Reply**: `"req"`, `"rep"`
- **Survey**: `"surveyor"`, `"respondent"`

### Transports

Supported URL schemes:
- `inproc://` - in-process (zero-copy)
- `ipc://` - inter-process
- `tcp://` - TCP/IP
- `ws://` - WebSocket
- `wss://` - WebSocket over TLS
- `tls+tcp://` - TLS over TCP

### Async I/O (AIO)

Async operations return "aio" objects that auto-resolve:
- `send_aio()`, `recv_aio()` - async send/receive
- `request()` - async request/reply
- `ncurl_aio()` - async HTTP
- Objects have `$data`, `$result` fields
- Use `call_aio()` to wait/retrieve results
- Use `unresolved()` to check status

### Serialization Modes

Data can be sent in multiple modes:
- `mode = "serial"` or `1` - R serialization (default, handles any R object)
- `mode = "raw"` or `2` - raw bytes (for atomic vectors)
- `mode = "string"` or `8` - character conversion
- Various receive modes for type coercion

Custom serialization supported via `serial_config()` for specific object classes.

### Object System

The package uses R's S3 object system with heavy use of external pointers tagged with specific symbols (defined in `src/init.c`):
- `nano_SocketSymbol` - Socket objects
- `nano_ContextSymbol` - Context objects
- `nano_AioSymbol` - AIO objects
- `nano_CvSymbol` - Condition variables
- etc.

External pointers are stored in pairlists with finalizers for automatic cleanup.

## Important Implementation Details

### Memory Management

- C code uses `NANO_ALLOC`, `NANO_FREE` macros for buffer management
- R objects protected via `nano_precious` environment (prevents GC)
- Finalizers registered for cleanup of C resources
- Careful use of `PROTECT`/`UNPROTECT` in C code

### Thread Safety

- Package implements its own threading via NNG's platform layer
- Condition variables (`cv()`) for cross-thread signaling
- Mutexes used internally for shared state
- R interrupt handling on both Unix (via `R_interrupts_pending`) and Windows

### Error Handling

- NNG errors returned as integer error codes
- `mk_error()` creates error values of class `"errorValue"`
- Error messages via `nng_strerror()`
- Use `ERROR_OUT()` macro to error, `ERROR_RET()` to return error value

### Configuration Options

Set/get socket/dialer/listener options via:
- `opt(object, "option-name")` - get
- `opt(object, "option-name") <- value` - set

Options are protocol-specific (e.g., `"req:resend-time"`, `"sub:prefnew"`).

## Build System

- `configure` - POSIX shell script for Unix-like systems
- `configure.win` - Windows configuration
- `configure.ucrt` - UCRT-specific Windows config
- Requires `cmake` if compiling bundled libraries (no longer requires `xz` as libraries are pre-extracted)
- Environment variables: `INCLUDE_DIR`, `LIB_DIR`, `NANONEXT_LIBS`

## Documentation

- Roxygen2-based documentation in R files
- Main vignette: `vignettes/nanonext.Rmd`
- Website: https://nanonext.r-lib.org
- Generated with pkgdown

## Code Style

- C code follows NNG conventions with `nano_` prefixes for package functions
- R code uses snake_case for functions
- Clear separation between user-facing and internal functions (`.function` prefix for internal)
- Extensive use of macros for code clarity (`NANO_PTR`, `NANO_DATAPTR`, etc.)
