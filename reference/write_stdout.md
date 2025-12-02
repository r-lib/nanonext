# Write to Stdout

Performs a non-buffered write to `stdout` using the C function
`writev()` or equivalent. Avoids interleaved output when writing
concurrently from multiple processes.

## Usage

``` r
write_stdout(x)
```

## Arguments

- x:

  character string.

## Value

Invisible NULL. As a side effect, `x` is output to `stdout`.

## Details

This function writes to the C-level `stdout` of the process and hence
cannot be re-directed by [`sink()`](https://rdrr.io/r/base/sink.html).

A newline character is automatically appended to `x`, hence there is no
need to include this within the input string.

## Examples

``` r
write_stdout("")
```
