# Create Serialization Configuration

Returns a serialization configuration, which may be set on a Socket for
custom serialization and unserialization of non-system reference
objects, allowing these to be sent and received between different R
sessions. Once set, the functions apply to all send and receive
operations performed in mode 'serial' over the Socket, or Context
created from the Socket.

## Usage

``` r
serial_config(class, sfunc, ufunc)
```

## Arguments

- class:

  a character string (or vector) of the class of object custom
  serialization functions are applied to, e.g. `'ArrowTabular'` or
  `c('torch_tensor', 'ArrowTabular')`.

- sfunc:

  a function (or list of functions) that accepts a reference object
  inheriting from `class` and returns a raw vector.

- ufunc:

  a function (or list of functions) that accepts a raw vector and
  returns a reference object.

## Value

A list comprising the configuration. This should be set on a Socket
using [`opt<-()`](https://nanonext.r-lib.org/dev/reference/opt.md) with
option name `"serial"`.

## Details

This feature utilises the 'refhook' system of R native serialization.

## Examples

``` r
cfg <- serial_config("test_cls", function(x) serialize(x, NULL), unserialize)
cfg
#> [[1]]
#> [1] "test_cls"
#> 
#> [[2]]
#> [[2]][[1]]
#> function (x) 
#> serialize(x, NULL)
#> <environment: 0x55714f073730>
#> 
#> 
#> [[3]]
#> [[3]][[1]]
#> function (connection, refhook = NULL) 
#> {
#>     if (typeof(connection) != "raw" && !is.character(connection) && 
#>         !inherits(connection, "connection")) 
#>         stop("'connection' must be a connection")
#>     .Internal(unserialize(connection, refhook))
#> }
#> <bytecode: 0x55714f0684f8>
#> <environment: namespace:base>
#> 
#> 

cfg <- serial_config(
  c("class_one", "class_two"),
  list(function(x) serialize(x, NULL), function(x) serialize(x, NULL)),
  list(unserialize, unserialize)
)
cfg
#> [[1]]
#> [1] "class_one" "class_two"
#> 
#> [[2]]
#> [[2]][[1]]
#> function (x) 
#> serialize(x, NULL)
#> <environment: 0x55714f073730>
#> 
#> [[2]][[2]]
#> function (x) 
#> serialize(x, NULL)
#> <environment: 0x55714f073730>
#> 
#> 
#> [[3]]
#> [[3]][[1]]
#> function (connection, refhook = NULL) 
#> {
#>     if (typeof(connection) != "raw" && !is.character(connection) && 
#>         !inherits(connection, "connection")) 
#>         stop("'connection' must be a connection")
#>     .Internal(unserialize(connection, refhook))
#> }
#> <bytecode: 0x55714f0684f8>
#> <environment: namespace:base>
#> 
#> [[3]][[2]]
#> function (connection, refhook = NULL) 
#> {
#>     if (typeof(connection) != "raw" && !is.character(connection) && 
#>         !inherits(connection, "connection")) 
#>         stop("'connection' must be a connection")
#>     .Internal(unserialize(connection, refhook))
#> }
#> <bytecode: 0x55714f0684f8>
#> <environment: namespace:base>
#> 
#> 

s <- socket()
opt(s, "serial") <- cfg

# provide an empty list to remove registered functions
opt(s, "serial") <- list()

close(s)
```
