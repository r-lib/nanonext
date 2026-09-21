library(nanonext)

list(
  handler("/", function(req) {
    list(status = 200L, body = "Hello, World!")
  }),
  handler("/api/data", function(req) {
    list(status = 200L, headers = c("Content-Type" = "application/json"), body = '{"value": 42}')
  }),
  handler_ws("/ws", function(ws, data) ws$send(data), textframes = TRUE),
  handler_inline("/robots.txt", "User-agent: *\nDisallow:\n", content_type = "text/plain"),
  handler_directory("/static", "www")
)
