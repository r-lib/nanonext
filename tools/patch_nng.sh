#!/bin/sh

# Apply nanonext's local patches to the vendored NNG sources.
#
# Usage: ./tools/patch_nng.sh [NNG_SRC_DIR]
#   NNG_SRC_DIR defaults to the package's vendored tree (src/nng/src).
#   tools/update_nng.sh passes the freshly-staged tree instead.
#
# Every patch is IDEMPOTENT: running it on already-patched sources is a no-op.
# This is the single replay of every nanonext edit to upstream NNG, so that
# re-vendoring a new upstream tag is just: stage upstream -> run this script.
#
# Sections:
#   1. Compiler-warning fixes -- surgical narrowing / sign-conversion casts and
#      a defensive NULL guard nanonext carries so the bundled sources compile
#      cleanly under strict diagnostics (-Wconversion / -Wsign-conversion).
#   2. Diagnostic-pragma removal -- CRAN does not permit compiler
#      diagnostic-suppression pragmas (#pragma GCC/clang diagnostic) in compiled
#      code, so strip them and replay nanonext's portable equivalent.
#   3. Diagnostics neutering -- route NNG's debug abort/printf/println (the
#      abort/vprintf/stderr symbols R's tools:::check_compiled_code() flags) to
#      __builtin_trap() / no-ops. These fire only on internal NNG panics, which
#      run on background threads where the R API is off-limits, so this is a
#      no-op in normal use.

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
NNG_SRC="${1:-$SCRIPT_DIR/../src/nng/src}"

if [ ! -d "$NNG_SRC" ]; then
  echo "Error: NNG source dir not found: $NNG_SRC" >&2
  exit 1
fi

# Apply an idempotent perl program (whole-file slurp mode) to a source file
# given relative to $NNG_SRC, reporting whether it changed anything.
patch_perl() {
  rel=$1; prog=$2
  f="$NNG_SRC/$rel"
  if [ ! -f "$f" ]; then echo "  skip (absent): $rel"; return 0; fi
  cp "$f" "$f.prepatch"
  perl -0777 -i -pe "$prog" "$f"
  if cmp -s "$f" "$f.prepatch"; then echo "  unchanged: $rel"; else echo "  patched:   $rel"; fi
  rm -f "$f.prepatch"
}

# ---------------------------------------------------------------------------
echo "1. Compiler-warning fixes (narrowing / sign-conversion casts) ..."

# POSIX I/O return values (ssize_t) narrowed to int.
patch_perl platform/posix/posix_udp.c '
  s/\(cnt = recvmsg\(/(cnt = (int) recvmsg(/;
  s/\bcnt = sendmsg\(udp->udp_fd/cnt = (int) sendmsg(udp->udp_fd/;
  s/\blen = nni_posix_nn2sockaddr\(&ss, nni_aio_get_input/len = (int) nni_posix_nn2sockaddr(&ss, nni_aio_get_input/;
  s/\(salen = nni_posix_nn2sockaddr\(/(salen = (int) nni_posix_nn2sockaddr(/;
  s/\bsz = nni_posix_nn2sockaddr\(&ss, sa\);/sz = (socklen_t) nni_posix_nn2sockaddr(&ss, sa);/;
'
patch_perl platform/posix/posix_tcpconn.c '
  s/\bn = sendmsg\(fd\b/n = (int) sendmsg(fd/;
  s/\bn = readv\(fd\b/n = (int) readv(fd/;
'
patch_perl platform/posix/posix_ipcconn.c '
  s/\bn = sendmsg\(fd\b/n = (int) sendmsg(fd/;
  s/\bn = readv\(fd\b/n = (int) readv(fd/;
'
patch_perl platform/posix/posix_sockfd.c '
  s/\bn = writev\(fd\b/n = (int) writev(fd/;
  s/\bn = readv\(fd\b/n = (int) readv(fd/;
'
# socklen_t / uint16_t / mode_t narrowing in the dial / listen / sockaddr code.
patch_perl platform/posix/posix_tcpdial.c '
  s/bind\(fd, \(void \*\) &d->src, d->srclen\)/bind(fd, (void *) &d->src, (socklen_t) d->srclen)/;
  s/connect\(fd, \(void \*\) &ss, sslen\)/connect(fd, (void *) &ss, (socklen_t) sslen)/;
'
patch_perl platform/posix/posix_ipcdial.c '
  s/connect\(fd, \(void \*\) &ss, len\)/connect(fd, (void *) &ss, (socklen_t) len)/;
  s/(s_abstract\.sa_len[ \t]*=[ \t]*)len;/${1}(uint16_t) len;/g;
'
patch_perl platform/posix/posix_tcplisten.c '
  s/\(len = nni_posix_nn2sockaddr\(&ss, sa\)/(len = (socklen_t) nni_posix_nn2sockaddr(&ss, sa)/;
'
patch_perl platform/posix/posix_ipclisten.c '
  s/\bl->perms = mode;/l->perms = (mode_t) mode;/;
  s/\(len = nni_posix_nn2sockaddr\(&ss, &l->sa\)/(len = (socklen_t) nni_posix_nn2sockaddr(&ss, &l->sa)/;
  s/\blen -= sizeof\(sa_family_t\);/len -= (socklen_t) sizeof(sa_family_t);/;
  s/(s_abstract\.sa_len[ \t]*=[ \t]*)len;/${1}(uint16_t) len;/g;
'
patch_perl platform/posix/posix_sockaddr.c '
  s/(nsabs->sa_len[ \t]*=[ \t]*)sz - 1;/${1}(uint16_t) (sz - 1);/;
'
patch_perl platform/posix/posix_thread.c '
  s/return \(sysconf\(_SC_NPROCESSORS_ONLN\)\);/return ((int) sysconf(_SC_NPROCESSORS_ONLN));/;
'
# clock: tv_nsec (long) and the usec*1000 product narrowed to the uint32_t
# *nsec out-param (both the timespec and gettimeofday code paths).
patch_perl platform/posix/posix_clock.c '
  s/\*nsec = ts\.tv_nsec;/*nsec = (uint32_t) ts.tv_nsec;/g;
  s/\*nsec = tv\.tv_usec \* 1000;/*nsec = (uint32_t) (tv.tv_usec * 1000);/;
'
# signed char passed to toupper(); narrow the int result back to char.
patch_perl core/url.c '
  s/out\[dst\+\+\] = toupper\(/out[dst++] = (char) toupper(/g;
'
# NNI_GET16: cast the assembled value back to uint16_t (shift promotes to int).
patch_perl core/defs.h '
  s/\Qv = (((uint16_t) ((uint8_t) (ptr)[0])) << 8u) +\E/v = (uint16_t) ((((uint16_t) ((uint8_t) (ptr)[0])) << 8u) +/;
  s/\Q(((uint16_t) (uint8_t) (ptr)[1]))\E$/(((uint16_t) (uint8_t) (ptr)[1])))/m;
'
# websocket: opcode narrowed to uint8_t for the frame header byte.
patch_perl supplemental/websocket/websocket.c '
  s/\bframe->head\[0\] = frame->op;/frame->head[0] = (uint8_t) frame->op;/;
'
# strs.c: guard nni_asprintf against a NULL format string (analyzer / -Wnonnull).
patch_perl core/strs.c '
  unless (/fmt == NULL/) {
    s/(\tva_start\(ap, fmt\);\n\tlen = vsnprintf\(NULL, 0, fmt, ap\);)/\tif (fmt == NULL) {\n\t\treturn (NNG_EINTERNAL);\n\t}\n$1/;
  }
'

# win_clock.c: upstream nni_time_get() uses C11 timespec_get()/TIME_UTC, which
# legacy (non-UCRT) MinGW lacks; upstream cmake hard-requires UCRT. nanonext
# still builds on non-UCRT toolchains (e.g. Rtools40 / R oldrel), so fall back
# to a FILETIME-based clock when TIME_UTC is unavailable. Windows always uses
# the bundled NNG, so this never affects a system libnng.
patch_perl platform/windows/win_clock.c '
  unless (/defined\(TIME_UTC\)/) {
    s|(\tstruct timespec ts;\n\tif \(timespec_get\(&ts, TIME_UTC\) == TIME_UTC\) \{\n.*?\n\treturn \(nni_win_error\(GetLastError\(\)\)\);\n)|#if defined(TIME_UTC)\n$1#else\n\t// legacy MinGW (non-UCRT) lacks C11 timespec_get(); use FILETIME instead\n\tFILETIME       ft;\n\tULARGE_INTEGER ui;\n\tuint64_t       ticks;\n\tGetSystemTimeAsFileTime(&ft);\n\tui.LowPart   = ft.dwLowDateTime;\n\tui.HighPart  = ft.dwHighDateTime;\n\t// FILETIME is 100ns ticks since 1601-01-01; rebase to the Unix epoch\n\tticks        = ui.QuadPart - 116444736000000000ULL;\n\t*seconds     = ticks / 10000000ULL;\n\t*nanoseconds = (uint32_t) ((ticks % 10000000ULL) * 100);\n\treturn (0);\n#endif\n|s;
  }
'

# win_udp.c: upstream multicast support uses the Windows-SDK uppercase typedefs
# IP_MREQ / IPV6_MREQ, which legacy (non-UCRT) MinGW headers do not define. Use
# the portable struct tags (as NNG'\''s own POSIX code does); members are identical.
patch_perl platform/windows/win_udp.c '
  s/\bIP_MREQ\s+mreq;/struct ip_mreq   mreq;/;
  s/\bIPV6_MREQ\s+mreq;/struct ipv6_mreq mreq;/;
'

# mbedtls TLS backend: use the non-deprecated mbedtls_ssl_conf_{min,max}_tls_version
# API with the mbedtls_ssl_protocol_version enum (MBEDTLS_SSL_VERSION_TLS1_2 / _3),
# replacing the deprecated major/minor mbedtls_ssl_conf_{min,max}_version forms
# (-Wdeprecated-declarations). nanonext requires Mbed TLS >= 3 (see configure), where
# TLS 1.0/1.1 are unsupported and the legacy MBEDTLS_SSL_{MAJOR,MINOR}_VERSION_* macros
# are gated behind MBEDTLS_DEPRECATED_REMOVED -- so the version handling is rewritten to
# use the protocol-version enum throughout (config struct fields included), dropping the
# now-dead 1.0/1.1 switch cases.
patch_perl supplemental/tls/mbedtls/tls.c '
  s/\tint +min_ver;\n\tint +max_ver;/\tmbedtls_ssl_protocol_version min_ver;\n\tmbedtls_ssl_protocol_version max_ver;/;
  s/cfg->min_ver = MBEDTLS_SSL_MINOR_VERSION_3;\n#ifdef MBEDTLS_SSL_PROTO_TLS1_3\n\tcfg->max_ver = MBEDTLS_SSL_MINOR_VERSION_4;\n#else\n\tcfg->max_ver = MBEDTLS_SSL_MINOR_VERSION_3;\n#endif\n\n\tmbedtls_ssl_conf_min_version\(\n\t    &cfg->cfg_ctx, MBEDTLS_SSL_MAJOR_VERSION_3, cfg->min_ver\);\n\tmbedtls_ssl_conf_max_version\(\n\t    &cfg->cfg_ctx, MBEDTLS_SSL_MAJOR_VERSION_3, cfg->max_ver\);/cfg->min_ver = MBEDTLS_SSL_VERSION_TLS1_2;\n#ifdef MBEDTLS_SSL_PROTO_TLS1_3\n\tcfg->max_ver = MBEDTLS_SSL_VERSION_TLS1_3;\n#else\n\tcfg->max_ver = MBEDTLS_SSL_VERSION_TLS1_2;\n#endif\n\n\tmbedtls_ssl_conf_min_tls_version(&cfg->cfg_ctx, cfg->min_ver);\n\tmbedtls_ssl_conf_max_tls_version(&cfg->cfg_ctx, cfg->max_ver);/;
  s/\tint v1, v2;\n\tint maj = MBEDTLS_SSL_MAJOR_VERSION_3;\n/\tmbedtls_ssl_protocol_version v1, v2;\n/;
  s/switch \(min_ver\) \{\n#ifdef MBEDTLS_SSL_MINOR_VERSION_1\n\tcase NNG_TLS_1_0:\n\t\tv1 = MBEDTLS_SSL_MINOR_VERSION_1;\n\t\tbreak;\n#endif\n#ifdef MBEDTLS_SSL_MINOR_VERSION_2\n\tcase NNG_TLS_1_1:\n\t\tv1 = MBEDTLS_SSL_MINOR_VERSION_2;\n\t\tbreak;\n#endif\n#ifdef MBEDTLS_SSL_MINOR_VERSION_3\n\tcase NNG_TLS_1_2:\n\t\tv1 = MBEDTLS_SSL_MINOR_VERSION_3;\n\t\tbreak;\n#endif\n#ifdef MBEDTLS_SSL_PROTO_TLS1_3\n\tcase NNG_TLS_1_3:\n\t\tv1 = MBEDTLS_SSL_MINOR_VERSION_4;\n\t\tbreak;\n#endif\n/switch (min_ver) {\n\tcase NNG_TLS_1_2:\n\t\tv1 = MBEDTLS_SSL_VERSION_TLS1_2;\n\t\tbreak;\n#ifdef MBEDTLS_SSL_PROTO_TLS1_3\n\tcase NNG_TLS_1_3:\n\t\tv1 = MBEDTLS_SSL_VERSION_TLS1_3;\n\t\tbreak;\n#endif\n/;
  s/switch \(max_ver\) \{\n#ifdef MBEDTLS_SSL_MINOR_VERSION_1\n\tcase NNG_TLS_1_0:\n\t\tv2 = MBEDTLS_SSL_MINOR_VERSION_1;\n\t\tbreak;\n#endif\n#ifdef MBEDTLS_SSL_MINOR_VERSION_2\n\tcase NNG_TLS_1_1:\n\t\tv2 = MBEDTLS_SSL_MINOR_VERSION_2;\n\t\tbreak;\n#endif\n#ifdef MBEDTLS_SSL_MINOR_VERSION_3\n\tcase NNG_TLS_1_2:\n\t\tv2 = MBEDTLS_SSL_MINOR_VERSION_3;\n\t\tbreak;\n#endif\n\tcase NNG_TLS_1_3:\n#ifdef MBEDTLS_SSL_PROTO_TLS1_3\n\t\tv2 = MBEDTLS_SSL_MINOR_VERSION_4;\n#else\n\t\tv2 = MBEDTLS_SSL_MINOR_VERSION_3;\n#endif\n\t\tbreak;\n/switch (max_ver) {\n\tcase NNG_TLS_1_2:\n\t\tv2 = MBEDTLS_SSL_VERSION_TLS1_2;\n\t\tbreak;\n\tcase NNG_TLS_1_3:\n#ifdef MBEDTLS_SSL_PROTO_TLS1_3\n\t\tv2 = MBEDTLS_SSL_VERSION_TLS1_3;\n#else\n\t\tv2 = MBEDTLS_SSL_VERSION_TLS1_2;\n#endif\n\t\tbreak;\n/;
  s/mbedtls_ssl_conf_min_version\(&cfg->cfg_ctx, maj, cfg->min_ver\);\n\tmbedtls_ssl_conf_max_version\(&cfg->cfg_ctx, maj, cfg->max_ver\);/mbedtls_ssl_conf_min_tls_version(&cfg->cfg_ctx, cfg->min_ver);\n\tmbedtls_ssl_conf_max_tls_version(&cfg->cfg_ctx, cfg->max_ver);/;
'

# mbedtls_pk_parse_key gained f_rng/p_rng parameters in Mbed TLS 3 and dropped them
# again in Mbed TLS 4. Upstream guards the 2.x form with MBEDTLS_VERSION_MAJOR < 3;
# nanonext requires >= 3, so retarget the guard to < 4 -- the 3.x (with-RNG) form for
# 3.x, the parameterless form for 4.x -- keeping the bundled backend buildable on both.
patch_perl supplemental/tls/mbedtls/tls.c '
  s/#if MBEDTLS_VERSION_MAJOR < 3\n\trv = mbedtls_pk_parse_key\(&p->key, pem, len, \(const uint8_t \*\) pass,\n\t    pass != NULL \? strlen\(pass\) : 0\);\n#else\n\trv = mbedtls_pk_parse_key\(&p->key, pem, len, \(const uint8_t \*\) pass,\n\t    pass != NULL \? strlen\(pass\) : 0, tls_random, NULL\);\n#endif/#if MBEDTLS_VERSION_MAJOR < 4\n\trv = mbedtls_pk_parse_key(&p->key, pem, len, (const uint8_t *) pass,\n\t    pass != NULL ? strlen(pass) : 0, tls_random, NULL);\n#else\n\trv = mbedtls_pk_parse_key(&p->key, pem, len, (const uint8_t *) pass,\n\t    pass != NULL ? strlen(pass) : 0);\n#endif/;
'

# ---------------------------------------------------------------------------
echo "2. Removing compiler diagnostic pragmas (not permitted on CRAN) ..."
# Strip every #pragma GCC/clang diagnostic line, then replay nanonext's portable
# substitutes for the warnings those pragmas had suppressed.
pragma_files=$(grep -rlE '#[[:space:]]*pragma[[:space:]]+(GCC|clang)[[:space:]]+diagnostic' "$NNG_SRC" 2>/dev/null || true)
if [ -n "$pragma_files" ]; then
  for f in $pragma_files; do
    perl -ni -e 'print unless /^\s*#\s*pragma\s+(GCC|clang)\s+diagnostic\b/' "$f"
    echo "  stripped pragmas: ${f#"$NNG_SRC"/}"
  done
else
  echo "  none found"
fi
# posix_pipe.c: upstream wrapped this write() in a -Wunused-result pragma; use
# the portable if-guard idiom instead (the pragma was removed just above).
patch_perl platform/posix/posix_pipe.c '
  s/\(void\) write\(wfd, &c, 1\);/if (write(wfd, &c, 1)) {}/;
'

# ---------------------------------------------------------------------------
echo "3. Neutering NNG debug diagnostics (abort / printf / println) ..."
neuter_debug() {
  f=$1
  [ -f "$f" ] || { echo "  skip (absent): $f"; return 0; }
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
neuter_debug "$NNG_SRC/platform/posix/posix_debug.c"
neuter_debug "$NNG_SRC/platform/windows/win_debug.c"

# core/log.c: stub the stderr logger. It is the only stderr reference in the
# tree (check_compiled_code() flags the stderr symbol). nanonext never enables
# NNG logging, so this is a no-op in normal use; nng_stderr_logger /
# nng_system_logger keep their symbols but become silent through the stub.
patch_perl core/log.c '
  s/(\nstderr_logger\([^{]*\bbool timechk\)\n\{).*?(\n\}\n\nvoid\nnng_stderr_logger)/${1}\n\t(void) level;\n\t(void) facility;\n\t(void) msgid;\n\t(void) msg;\n\t(void) timechk;${2}/s;
'

echo "=== patch_nng.sh complete ==="
