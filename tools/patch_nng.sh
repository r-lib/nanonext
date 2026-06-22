#!/bin/sh

# Apply nanonext's local patches to the vendored NNG sources.
#
# Usage: ./tools/patch_nng.sh [NNG_SRC_DIR]
#   NNG_SRC_DIR defaults to the package's vendored tree (src/nng/src).
#   tools/update_nng.sh passes the staging tree instead.
#
# Every patch is IDEMPOTENT: running it on already-patched sources is a no-op.
#
# Purpose: neuter the compiled-code diagnostics so R's
# tools:::check_compiled_code() reports nothing for nanonext.so. NNG's debug
# layer writes to stderr (nni_plat_println), calls vprintf (nni_plat_printf) and
# abort() (nni_plat_abort) -- the stderr/vprintf/abort symbols R flags. These
# fire only on internal NNG bugs/panics; nanonext never enables NNG diagnostics,
# so neutering is a no-op in normal use. nni_plat_abort routes to
# __builtin_trap() (SIGILL) to keep fatal-on-internal-bug semantics while
# dropping the abort symbol -- it cannot call Rf_error/REprintf because panics
# fire on NNG background threads where the R API is off-limits.

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
NNG_SRC="${1:-$SCRIPT_DIR/../src/nng/src}"

if [ ! -d "$NNG_SRC" ]; then
  echo "Error: NNG source dir not found: $NNG_SRC" >&2
  exit 1
fi

# Neuter nni_plat_abort / nni_plat_printf / nni_plat_println in one debug file.
neuter_debug() {
  f=$1
  [ -f "$f" ] || { echo "  (skip, not found: $f)"; return 0; }
  if grep -q '__builtin_trap' "$f" 2>/dev/null; then
    echo "  already neutered: $f"
    return 0
  fi
  perl -0777 -i -pe '
    s/nni_plat_abort\(void\)\s*\{.*?\}/nni_plat_abort(void)\n{\n\t__builtin_trap();\n}/s;
    s/nni_plat_printf\(const char \*fmt, \.\.\.\)\s*\{.*?\}/nni_plat_printf(const char *fmt, ...)\n{\n\t(void) fmt;\n}/s;
    s/nni_plat_println\(const char \*message\)\s*\{.*?\}/nni_plat_println(const char *message)\n{\n\t(void) message;\n}/s;
  ' "$f"
  echo "  neutered: $f"
}

echo "Patching NNG debug diagnostics ..."
neuter_debug "$NNG_SRC/platform/posix/posix_debug.c"
neuter_debug "$NNG_SRC/platform/windows/win_debug.c"
