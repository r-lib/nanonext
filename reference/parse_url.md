# Parse URL

Parses a character string containing an RFC 3986 compliant URL as per
NNG.

## Usage

``` r
parse_url(url)
```

## Arguments

- url:

  character string containing a URL.

## Value

A named character vector of length 7, comprising:

- `scheme` - the URL scheme, such as "http" or "inproc" (always lower
  case).

- `userinfo` - the username and password (if supplied in the URL
  string).

- `hostname` - the name of the host.

- `port` - the port (if not specified, the default port if defined by
  the scheme).

- `path` - the path, typically used with HTTP or WebSocket.

- `query` - the query info (typically following ? in the URL).

- `fragment` - used for specifying an anchor, the part after \# in a
  URL.

Values that cannot be determined are represented by an empty string
`""`.

## Examples

``` r
parse_url("https://user:password@w3.org:8080/type/path?q=info#intro")
#>          scheme        userinfo        hostname            port 
#>         "https" "user:password"        "w3.org"          "8080" 
#>            path           query        fragment 
#>    "/type/path"        "q=info"         "intro" 
parse_url("tcp://192.168.0.2:5555")
#>        scheme      userinfo      hostname          port          path 
#>         "tcp"            "" "192.168.0.2"        "5555"            "" 
#>         query      fragment 
#>            ""            "" 
```
