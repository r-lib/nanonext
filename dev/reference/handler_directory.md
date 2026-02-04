# Create Static Directory Handler

Creates an HTTP handler that serves files from a directory tree. NNG
handles MIME type detection automatically.

## Usage

``` r
handler_directory(path, directory)
```

## Arguments

- path:

  URI path prefix (e.g., "/static"). Requests to "/static/foo.js" will
  serve "directory/foo.js".

- directory:

  Path to the directory to serve.

## Value

A handler object for use with
[`http_server()`](https://nanonext.r-lib.org/dev/reference/http_server.md).

## Details

Directory handlers automatically match all paths under the prefix
(prefix matching is implicit). The URI path is mapped to the filesystem:

- Request to "/static/css/style.css" serves "directory/css/style.css"

- Request to "/static/" serves "directory/index.html" if it exists

Note: The trailing slash behavior depends on how clients make requests.
A request to "/static" (no trailing slash) will not automatically
redirect to "/static/". Consider using
[`handler_redirect()`](https://nanonext.r-lib.org/dev/reference/handler_redirect.md)
if you need this behavior.

## Examples

``` r
if (FALSE) { # interactive()
h <- handler_directory("/static", "www/assets")
}
```
