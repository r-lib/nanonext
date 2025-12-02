# Serialization Headers and Markers

Internal package functions.

## Usage

``` r
.read_header(x)

.mark(bool = TRUE)

.read_marker(x)
```

## Arguments

- x:

  raw vector.

- bool:

  logical value.

## Value

For `.read_header()`: integer value.

For `.mark()`: the logical `bool` supplied.

For `.read_marker()`: logical value `TRUE` or `FALSE`.
