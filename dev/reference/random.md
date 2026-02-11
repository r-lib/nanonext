# Random Data Generation

Strictly not for use in statistical analysis. Non-reproducible and with
unknown statistical properties. Provides an alternative source of
randomness from the Mbed TLS library for purposes such as cryptographic
key generation. Mbed TLS uses a block-cipher in counter mode operation,
as defined in NIST SP800-90A: *Recommendation for Random Number
Generation Using Deterministic Random Bit Generators*. The
implementation uses AES-256 as the underlying block cipher, with a
derivation function, and an entropy collector combining entropy from
multiple sources including at least one strong entropy source.

## Usage

``` r
random(n = 1L, convert = TRUE)
```

## Arguments

- n:

  \[default 1L\] integer random bytes to generate (from 0 to 1024),
  coerced to integer if required. If a vector, the first element is
  taken.

- convert:

  \[default TRUE\] logical `FALSE` to return a raw vector, or `TRUE` to
  return the hex representation of the bytes as a character string.

## Value

A length `n` raw vector, or length one vector of `2n` random characters,
depending on the value of `convert` supplied.

## Note

Results obtained are independent of and do not alter the state of R's
own pseudo-random number generators.

## Examples

``` r
random()
#> [1] "07"
random(8L)
#> [1] "cbd4812e7f203929"
random(n = 8L, convert = FALSE)
#> [1] a9 72 63 19 44 e5 63 55
```
