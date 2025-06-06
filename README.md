
<!-- README.md is generated from README.Rmd. Please edit that file -->

# nanonext <a href="https://nanonext.r-lib.org/" alt="nanonext"><img src="man/figures/logo.png" alt="nanonext logo" align="right" width="120" /></a>

<!-- badges: start -->

[![CRAN
status](https://www.r-pkg.org/badges/version/nanonext)](https://CRAN.R-project.org/package=nanonext)
[![R-universe
status](https://r-lib.r-universe.dev/badges/nanonext?color=3f72af)](https://r-lib.r-universe.dev/nanonext)
[![R-CMD-check](https://github.com/r-lib/nanonext/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/r-lib/nanonext/actions/workflows/R-CMD-check.yaml)
[![Codecov test
coverage](https://codecov.io/gh/r-lib/nanonext/graph/badge.svg)](https://app.codecov.io/gh/r-lib/nanonext)
[![DOI](https://zenodo.org/badge/451104675.svg)](https://zenodo.org/badge/latestdoi/451104675)
<!-- badges: end -->

R binding for NNG (Nanomsg Next Gen), a successor to ZeroMQ. NNG is a
socket library for reliable, high-performance messaging over in-process,
IPC, TCP, WebSocket and secure TLS transports. Implements ‘Scalability
Protocols’, a standard for common communications patterns including
publish/subscribe, request/reply and service discovery.

As its own [threaded concurrency
framework](https://nanonext.r-lib.org/articles/nanonext.html#async-and-concurrency),
provides a toolkit for asynchronous programming and distributed
computing. Intuitive ‘aio’ objects resolve automatically when
asynchronous operations complete, and [synchronisation
primitives](https://nanonext.r-lib.org/articles/nanonext.html#synchronisation-primitives)
allow R to wait upon events signalled by concurrent threads.

Designed for performance and reliability,
[`nanonext`](https://doi.org/10.5281/zenodo.7903429) is a lightweight
wrapper around the NNG C library, and is itself implemented almost
entirely in C.

Provides the interface for code and processes to communicate with each
other - [receive data generated in Python, perform analysis in R, and
send results to a C++
program](https://nanonext.r-lib.org/articles/nanonext.html#cross-language-exchange)
– on the same computer or across networks spanning the globe.

Implemented scalability protocols:

- Bus (mesh networks)
- Pair (two-way radio)
- Poly (one-to-one of many)
- Push/Pull (one-way pipeline)
- [Publisher/Subscriber](https://nanonext.r-lib.org/articles/nanonext.html#publisher-subscriber-model)
  (topics & broadcast)
- [Request/Reply](https://nanonext.r-lib.org/articles/nanonext.html#rpc-and-distributed-computing)
  (RPC)
- [Surveyor/Respondent](https://nanonext.r-lib.org/articles/nanonext.html#surveyor-respondent-model)
  (voting & service discovery)

Supported transports:

- inproc (intra-process)
- IPC (inter-process)
- TCP (IPv4 or IPv6)
- WebSocket
- [TLS](https://nanonext.r-lib.org/articles/nanonext.html#tls-secure-connections)
  (over TCP and WebSocket)

Development of the TLS implementation was generously supported by the
<img src="https://r-consortium.org/images/RConsortium_Horizontal_Pantone.webp" alt="R Consortium" width="100" height="22" />
.

Web utilities:

- [ncurl](https://nanonext.r-lib.org/articles/nanonext.html#ncurl-async-http-client) -
  (async) http(s) client
- [stream](https://nanonext.r-lib.org/articles/nanonext.html#stream-websocket-client) -
  secure websockets client / generic low-level socket interface
- `ip_addr()` - for retrieving all local network IP addresses by
  interface
- `messenger()` - console-based instant messaging with authentication

### Quick Start

`nanonext` offers 2 equivalent interfaces: a functional interface, and
an object-oriented interface.

#### Functional Interface

The primary object in the functional interface is the Socket. Use
`socket()` to create a socket and dial or listen at an address. The
socket is then passed as the first argument of subsequent actions such
as `send()` or `recv()`.

*Example using Request/Reply (REQ/REP) protocol with inproc transport:*
<br /> (The inproc transport uses zero-copy where possible for a much
faster solution than alternatives)

Create sockets:

``` r
library(nanonext)

socket1 <- socket("req", listen = "inproc://nanonext")
socket2 <- socket("rep", dial = "inproc://nanonext")
```

Send message from ‘socket1’:

``` r
send(socket1, "hello world!")
#> [1] 0
```

Receive message using ‘socket2’:

``` r
recv(socket2)
#> [1] "hello world!"
```

#### Object-oriented Interface

The primary object in the object-oriented interface is the nano object.
Use `nano()` to create a nano object which encapsulates a Socket and
Dialer/Listener. Methods such as `$send()` or `$recv()` can then be
accessed directly from the object.

*Example using Pipeline (Push/Pull) protocol with TCP/IP transport:*

Create nano objects:

``` r
library(nanonext)

nano1 <- nano("push", listen = "tcp://127.0.0.1:5555")
nano2 <- nano("pull", dial = "tcp://127.0.0.1:5555")
```

Send message from ‘nano1’:

``` r
nano1$send("hello world!")
#> [1] 0
```

Receive message using ‘nano2’:

``` r
nano2$recv()
#> [1] "hello world!"
```

### Vignette

Please refer to the [nanonext
vignette](https://nanonext.r-lib.org/articles/nanonext.html) for full
package functionality.

This may be accessed within R by:

``` r
vignette("nanonext", package = "nanonext")
```

### Installation

Install the latest release from CRAN:

``` r
install.packages("nanonext")
```

Or the current development version from R-universe:

``` r
install.packages("nanonext", repos = "https://r-lib.r-universe.dev")
```

### Building from Source

#### Linux / Mac / Solaris

Installation from source requires ‘libnng’ \>= v1.9.0 and ‘libmbedtls’
\>= 2.5.0 (suitable installations are automatically detected), or else
‘cmake’ to compile ‘libnng’ v1.11.0 and ‘libmbedtls’ v3.6.2 included
within the package sources.

**It is recommended for optimal performance and stability to let the
package automatically compile bundled versions of ‘libmbedtls’ and
‘libnng’ during installation.** To ensure the libraries are compiled
from source even if system installations are present, set the
`NANONEXT_LIBS` environment variable prior to installation e.g. by
`Sys.setenv(NANONEXT_LIBS = 1)`.

As system libraries, ‘libnng’ is available as libnng-dev (deb) or
nng-devel (rpm), and ‘libmbedtls’ as libmbedtls-dev (deb) or
libmbedtls-devel (rpm). The `INCLUDE_DIR` and `LIB_DIR` environment
variables may be set prior to package installation to specify a custom
location for ‘libmbedtls’ or ‘libnng’ other than the standard filesystem
locations.

*Additional requirements for Solaris: (i) the ‘xz’ package - available
on OpenCSW, and (ii) a more recent version of ‘cmake’ than available on
OpenCSW - refer to the ‘cmake’ website for the latest source file.*

#### Windows

On Windows, ‘libnng’ v1.11.0 and ‘libmbedtls’ v3.6.2 will be compiled
from the package sources during installation and hence requires the
‘Rtools’ toolchain.

For R \>= 4.2 using the ‘Rtools42’ or newer toolchains, the prerequisite
‘cmake’ is included. For previous R versions using ‘Rtools40’ or
earlier, it may be necessary to separately install a version of ‘cmake’
in Windows and ensure that it is added to your system’s `PATH`.

### Acknowledgements and Links

We would like to acknowledge in particular:

- [Garrett D’Amore](https://github.com/gdamore), author of the NNG
  library, for generous advice and for implementing a feature request
  specifically for a more efficient ‘aio’ implementation in `nanonext`.
- The [R Consortium](https://r-consortium.org/) for funding the
  development of the secure TLS capabilities in the package, and [Henrik
  Bengtsson](https://github.com/HenrikBengtsson) and [Will
  Landau](https://github.com/wlandau/)’s roles in making this possible.
- [Joe Cheng](https://github.com/jcheng5/) for prototyping the
  integration of `nanonext` with `later` to support the next generation
  of completely event-driven ‘promises’.
- [Luke Tierney](https://github.com/ltierney/) (R Core) and [Mike
  Cheng](https://github.com/coolbutuseless) for meticulous documentation
  of the R serialization mechanism, which led to the package’s own
  implementation of a low-level interface to R serialization.
- [Travers Ching](https://github.com/traversc) for a novel idea in
  extending the original custom serialization support in the package.
- [Jeroen Ooms](https://github.com/jeroen) - for his ‘Anticonf (tm)’
  configure script, on which our original ‘configure’ was based,
  although much modified since.

Links:

◈ nanonext R package: <https://nanonext.r-lib.org/>

nanonext is listed in CRAN Task Views:

- High Performance Computing:
  <https://cran.r-project.org/view=HighPerformanceComputing>
- Web Technologies: <https://cran.r-project.org/view=WebTechnologies>

NNG: <https://nng.nanomsg.org/><br /> Mbed TLS:
<https://www.trustedfirmware.org/projects/mbed-tls/>

–

Please note that this project is released with a [Contributor Code of
Conduct](https://nanonext.r-lib.org/CODE_OF_CONDUCT.html). By
participating in this project you agree to abide by its terms.
