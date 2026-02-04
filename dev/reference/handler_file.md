# Create Static File Handler

Creates an HTTP handler that serves a single file. NNG handles MIME type
detection automatically.

## Usage

``` r
handler_file(path, file, prefix = FALSE)
```

## Arguments

- path:

  URI path to match (e.g., "/favicon.ico").

- file:

  Path to the file to serve.

- prefix:

  \[default FALSE\] Logical, if TRUE matches path as a prefix.

## Value

A handler object for use with
[`http_server()`](https://nanonext.r-lib.org/dev/reference/http_server.md).

## Examples

``` r
if (FALSE) { # interactive()
h <- handler_file("/favicon.ico", "~/favicon.ico")
}
```
