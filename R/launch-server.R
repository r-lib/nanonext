#' Launch a nanonext http server using the `_server.yml` standard
#'
#' Implements the `_server.yml` standard for R server frameworks, allowing a
#' deployment platform to launch a \pkg{nanonext} server without knowing
#' anything about its implementation. Reads the configuration, obtains the
#' handlers, and serves in blocking mode until interrupted.
#'
#' @param settings character path to a `_server.yml` file.
#' @param host default `NULL`. IP address or hostname to listen on, specified
#'   without a URL scheme. If `NULL`, the `HOST` environment variable is used,
#'   then the `host` option in `settings`, then "127.0.0.1".
#' @param port \[default NULL\] port to listen on. If NULL, the `PORT`
#'   environment variable is used, then the `port` option in `settings`, then
#'   8080.
#' @param ... additional arguments, currently unused.
#'
#' @return The server invisibly.
#'
#' @section Configuration:
#'
#' ```yaml
#' engine: nanonext
#' constructor: server.R
#' options:
#'   host: 127.0.0.1
#'   port: 8080
#'   tls:
#'     server: cert-and-key.pem
#' ```
#'
#' - `engine`: must be "nanonext".
#' - `constructor` (required): path to an R file whose final expression evaluates to a
#'   handler, or a list of handlers, as created by [handler()], [handler_ws()],
#'   [handler_stream()] etc. Note that the constructor **must not** create a server.
#' - `options` (optional): additional arguments passed to [http_server()]
#'   - `host`: the host to serve the http server on.
#'   - `port`: the port to serve the http server on.
#'   - `tls`: the tls configuration arguments passed to [tls_config()]. If set,
#'    the server will be served over https
#'
#' @details Requires the \pkg{yaml12} package.
#' @keywords internal
#' @noRd
launch_server <- function(settings, host = NULL, port = NULL, ...) {
  if (!is.character(settings)) {
    stop("`settings` must be a path to a `_server.yml` file.")
  }

  if (length(settings) != 1L) {
    stop("`settings` must be a scalar string.")
  }

  if (!file.exists(settings)) {
    stop(sprintf("the file `%s` does not exist.", settings))
  }

  if (!requireNamespace("yaml12", quietly = TRUE)) {
    stop("`launch_server()` requires `yaml12` to be installed.")
  }

  cfg <- yaml12::read_yaml(settings)

  # every path in the configuration, and every relative path the constructor
  # itself uses, is relative to the `_server.yml` file rather than the caller
  owd <- setwd(dirname(settings))
  on.exit(setwd(owd))

  if (!identical(cfg$engine, "nanonext")) {
    stop(sprintf(
      "`engine` must be \"nanonext\", not `%s`.",
      paste(format(cfg$engine), collapse = ", ")
    ))
  }

  if (is.null(cfg$constructor)) {
    stop("`settings` must specify a `constructor`.")
  }

  handlers <- constructor_handlers(cfg$constructor)

  if (!length(handlers)) {
    stop("`settings` did not produce any handlers.")
  }

  # only create the tls config if provided
  # we use `$` because it will be null if not provided
  cfg_tls <- cfg$options$tls
  tls_opts <- if (!is.null(cfg_tls)) {
    do.call(tls_config, tls_args(cfg_tls))
  }

  if (is.null(host)) {
    env_host <- Sys.getenv("HOST")
    host <- if (nzchar(env_host)) env_host else cfg$options$host
  }

  if (is.null(host)) {
    host <- "127.0.0.1"
  }

  if (is.null(port)) {
    env_port <- Sys.getenv("PORT")
    port <- if (nzchar(env_port)) {
      env_port
    } else {
      cfg$options$port
    }
  }

  if (is.null(port)) {
    port <- 8080L
  }

  if (!is.character(host) || length(host) != 1L) {
    stop("`host` must be a scalar string.")
  }

  if (grepl("://", host, fixed = TRUE)) {
    stop(sprintf("`host` must not include a URL scheme, found `%s`.", host))
  }

  # cast to integer
  port <- suppressWarnings(as.integer(port))

  if (length(port) != 1L || is.na(port) || port < 0L || port > 65535L) {
    stop("`port` must be a scalar integer between 0 and 65535.")
  }

  # if tls is configured we use https
  scheme <- if (is.null(cfg_tls$server)) {
    "http"
  } else {
    "https"
  }

  # combine the args into a string that we will validate with the parse_url fx from nanonext
  server_url <- sprintf("%s://%s:%d", scheme, host, port)
  tryCatch(parse_url(server_url), error = function(e) {
    stop(sprintf("unable to parse `%s` as a valid url.", server_url))
  })

  server <- http_server(server_url, handlers, tls = tls_opts)
  server$serve()
  invisible(server)
}

# utility handler to construct into
constructor_handlers <- function(constructor) {
  if (!is.character(constructor)) {
    stop("`constructor` must be a path to an R file.")
  }

  if (length(constructor) != 1L) {
    stop("`constructor` must be a scalar string.")
  }

  if (!file.exists(constructor)) {
    stop(sprintf("the constructor `%s` does not exist.", constructor))
  }

  # sourced in its own environment so it cannot see or clobber our locals
  env <- new.env(parent = globalenv())
  handlers <- source(constructor, local = env)$value

  # a single handler, rather than a list of them
  if (is.integer(handlers$type)) {
    handlers <- list(handlers)
  }

  if (!is.list(handlers) || !all(vapply(handlers, function(x) is.integer(x$type), logical(1L)))) {
    stop(sprintf(
      "the constructor `%s` must evaluate to a handler or list of handlers.",
      constructor
    ))
  }

  handlers
}

# validates the `tls` options as arguments to `tls_config()`.
tls_args <- function(cfg_tls) {
  if (!is.list(cfg_tls)) {
    stop("`options$tls` must be a list of arguments to `tls_config()`.")
  }

  unknown <- setdiff(names(cfg_tls), names(formals(tls_config)))
  if (length(unknown)) {
    stop(sprintf("`options$tls` does not accept: %s.", paste(unknown, collapse = ", ")))
  }

  cfg_tls
}
