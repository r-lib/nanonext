#!/bin/sh

# Apply nanonext's local patches to the vendored Mbed TLS sources.
#
# Usage: ./tools/patch_mbedtls.sh [MBEDTLS_DIR]
#   MBEDTLS_DIR defaults to the package's vendored tree (src/mbedtls).
#   tools/update_mbedtls.sh passes the staging tree instead.
#
# Idempotent. Purpose: clear the 'printf' (and latent 'fprintf'/'exit') that R's
# tools:::check_compiled_code() flags. Mbed TLS's library/platform.c initialises
# the mbedtls_printf / mbedtls_fprintf / mbedtls_exit function pointers to libc
# printf / fprintf / exit; those static initialisers are data relocations that
# import the libc symbols even though nothing calls the pointers (self-test off).
#
# Defining the *_MACRO forms (not *_ALT) makes platform.h alias mbedtls_printf
# et al. to these no-op macros and makes platform.c skip the pointer definitions
# entirely -- so no libc reference is emitted. (The *_ALT path does NOT help:
# platform.h still defaults MBEDTLS_PLATFORM_STD_PRINTF to libc printf, which the
# pointer initialiser then references.) check_config.h permits *_MACRO with
# MBEDTLS_PLATFORM_C set and no conflicting STD_* / *_ALT. Runtime behaviour is
# unchanged: the affected call sites are self-test / debug only and not compiled.

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MBEDTLS_DIR="${1:-$SCRIPT_DIR/../src/mbedtls}"
CONFIG="$MBEDTLS_DIR/include/mbedtls/mbedtls_config.h"

if [ ! -f "$CONFIG" ]; then
  echo "Error: mbedtls_config.h not found: $CONFIG" >&2
  exit 1
fi

echo "Patching Mbed TLS platform config ..."
if grep -q 'MBEDTLS_PLATFORM_PRINTF_MACRO' "$CONFIG" 2>/dev/null; then
  echo "  already patched: $CONFIG"
  exit 0
fi

awk '
  { print }
  /^#define MBEDTLS_PLATFORM_C[ \t]*$/ && !done {
    print "/* nanonext: alias printf/fprintf/exit to no-op macros so the compiled"
    print " * shared object imports none of these libc symbols (see tools/patch_mbedtls.sh)."
    print " * The (void) cast keeps statement-context calls free of -Wunused-value; the"
    print " * only compiled call site (mbedtls_mpi_write_file, MBEDTLS_FS_IO) ignores the"
    print " * return value, all others are self-test only. */"
    print "#define MBEDTLS_PLATFORM_PRINTF_MACRO(...) ((void) 0)"
    print "#define MBEDTLS_PLATFORM_FPRINTF_MACRO(...) ((void) 0)"
    print "#define MBEDTLS_PLATFORM_EXIT_MACRO(...) ((void) 0)"
    done = 1
  }
' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"
echo "  patched: $CONFIG"
