
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
<!-- badges: end -->

Fast, lightweight toolkit for messaging, concurrency, and the web in R.
Built on [NNG (Nanomsg Next Gen)](https://nng.nanomsg.org/) and
implemented almost entirely in C.

- **Scalability protocols** - pub/sub, req/rep, push/pull,
  surveyor/respondent, bus, pair
- **Multiple transports** - TCP, IPC, WebSocket, TLS, in-process
- **Async I/O** - non-blocking operations with auto-resolving ‘aio’
  objects
- **Cross-language** - exchange data with Python, C++, Go, Rust
- **Web toolkit** - unified HTTP, WebSocket, and streaming (SSE, NDJSON)
  on a single port

[![Ask
DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/r-lib/nanonext)

### Quick Start

``` r
library(nanonext)

# Open sockets
s1 <- socket("req", listen = "ipc:///tmp/nanonext")
s2 <- socket("rep", dial = "ipc:///tmp/nanonext")

# Send
s1 |> send("hello world")
#> [1] 0

# Receive on the other
s2 |> recv()
#> [1] "hello world"

close(s1)
close(s2)
```

### Async I/O

Non-blocking operations that resolve automatically:

``` r
s1 <- socket("rep", listen = "tcp://127.0.0.1:5556")
s2 <- socket("req", dial = "tcp://127.0.0.1:5556")

# Sender
s2 |> send("async request")
#> [1] 0

# Async operations return immediately
aio <- recv_aio(s1)
aio
#> < recvAio | $data >

# Retrieve result when ready
aio$data
#> [1] "async request"

close(s1)
close(s2)
```

### Web Toolkit

One server, one port – HTTP endpoints, WebSocket connections, and
streaming all coexist. Mbed TLS built in for HTTPS/WSS.

``` r
# Generate self-signed certificates
cert <- write_cert(cn = "127.0.0.1")

# HTTPS server (port 0 = auto-assign a free port)
server <- http_server(
  url = "https://127.0.0.1:0",
  handlers = list(
    handler("/", \(req) list(status = 200L, body = '{"status":"ok"}'))
  ),
  tls = tls_config(server = cert$server)
)
server$start()

# Async HTTPS client
aio <- ncurl_aio(server$url, tls = tls_config(client = cert$client))
while (unresolved(aio)) later::run_now(1)
aio$data
#> [1] "{\"status\":\"ok\"}"

server$close()
```

### Documentation

| Guide | Topics |
|:---|:---|
| [Quick Reference](https://nanonext.r-lib.org/articles/nanonext.html) | At-a-glance API overview |
| [Messaging](https://nanonext.r-lib.org/articles/v01-messaging.html) | Cross-language, async, synchronisation |
| [Protocols](https://nanonext.r-lib.org/articles/v02-protocols.html) | req/rep, pub/sub, surveyor/respondent |
| [Configuration](https://nanonext.r-lib.org/articles/v03-configuration.html) | TLS, options, serialization |
| [Web Toolkit](https://nanonext.r-lib.org/articles/v04-web.html) | HTTP client/server, WebSocket, streaming |

### Installation

``` r
# CRAN
install.packages("nanonext")

# Development version
install.packages("nanonext", repos = "https://r-lib.r-universe.dev")
```

### Building from Source

#### Linux / Mac / Solaris

Requires ‘libnng’ \>= v1.9.0 and ‘libmbedtls’ \>= 2.5.0, or ‘cmake’ to
compile bundled libraries (libnng v1.11.0, libmbedtls v3.6.5).

Recommended: Let the package compile bundled libraries for optimal
performance:

``` r
Sys.setenv(NANONEXT_LIBS = 1)
install.packages("nanonext")
```

System packages: libnng-dev / nng-devel, libmbedtls-dev /
libmbedtls-devel. Set `INCLUDE_DIR` and `LIB_DIR` for custom locations.

#### Windows

Requires Rtools. For R \>= 4.2, cmake is included. Earlier versions need
cmake installed separately and added to PATH.

### Links

[Documentation](https://nanonext.r-lib.org/) \|
[NNG](https://nng.nanomsg.org/) \| [Mbed
TLS](https://www.trustedfirmware.org/projects/mbed-tls/) \| [CRAN HPC
Task View](https://cran.r-project.org/view=HighPerformanceComputing) \|
[CRAN Web Technologies](https://cran.r-project.org/view=WebTechnologies)

### Acknowledgements

- [Garrett D’Amore](https://github.com/gdamore) (NNG author) for advice
  and implementing features for nanonext
- [R Consortium](https://r-consortium.org/) for funding TLS development,
  with support from [Henrik
  Bengtsson](https://github.com/HenrikBengtsson) and [Will
  Landau](https://github.com/wlandau/)
- [Joe Cheng](https://github.com/jcheng5/) for prototyping event-driven
  promises integration
- [Luke Tierney](https://github.com/ltierney/) and [Mike
  Cheng](https://github.com/coolbutuseless) for R serialization
  documentation
- [Travers Ching](https://github.com/traversc) for novel ideas on custom
  serialization
- [Jeroen Ooms](https://github.com/jeroen) for the Anticonf configure
  script

–

Please note that this project is released with a [Contributor Code of
Conduct](https://nanonext.r-lib.org/CODE_OF_CONDUCT.html). By
participating in this project you agree to abide by its terms.
