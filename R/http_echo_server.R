http_echo_server <- function(port = 8080L) {
  .Call("rnng_http_echo_server", as.integer(port))
}