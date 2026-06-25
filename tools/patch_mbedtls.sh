#!/bin/sh

# Apply nanonext's local patches to the vendored Mbed TLS sources.
#
# Usage: ./tools/patch_mbedtls.sh [MBEDTLS_DIR]
#   MBEDTLS_DIR defaults to the package's vendored tree (src/mbedtls).
#   tools/update_mbedtls.sh passes the staging tree instead.
#
# Every patch is IDEMPOTENT: running it on already-patched sources is a no-op.
#
# Sections:
#   1. Platform config -- clear the 'printf' (and latent 'fprintf'/'exit') that
#      R's tools:::check_compiled_code() flags. Mbed TLS's library/platform.c
#      initialises the mbedtls_printf / mbedtls_fprintf / mbedtls_exit function
#      pointers to libc printf / fprintf / exit; those static initialisers are
#      data relocations that import the libc symbols even though nothing calls
#      the pointers (self-test off). Defining the *_MACRO forms (not *_ALT) makes
#      platform.h alias mbedtls_printf et al. to no-op macros and makes
#      platform.c skip the pointer definitions entirely -- so no libc reference
#      is emitted. check_config.h permits *_MACRO with MBEDTLS_PLATFORM_C set and
#      no conflicting STD_* / *_ALT. Runtime behaviour is unchanged: the affected
#      call sites are self-test / debug only and not compiled.
#   2. Compiler-warning fixes -- surgical narrowing casts that make explicit the
#      implicit narrowings Mbed TLS performs (assignments to small-int struct
#      members, etc.), so the bundled sources compile cleanly under strict
#      diagnostics (-Wconversion). The casts are behaviour-neutral.

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MBEDTLS_DIR="${1:-$SCRIPT_DIR/../src/mbedtls}"
CONFIG="$MBEDTLS_DIR/include/mbedtls/mbedtls_config.h"
LIB="$MBEDTLS_DIR/library"

if [ ! -f "$CONFIG" ]; then
  echo "Error: mbedtls_config.h not found: $CONFIG" >&2
  exit 1
fi

# Apply an idempotent perl program (whole-file slurp mode) to a library source
# file given relative to $LIB, reporting whether it changed anything.
patch_perl() {
  rel=$1; prog=$2
  f="$LIB/$rel"
  if [ ! -f "$f" ]; then echo "  skip (absent): $rel"; return 0; fi
  cp "$f" "$f.prepatch"
  perl -0777 -i -pe "$prog" "$f"
  if cmp -s "$f" "$f.prepatch"; then echo "  unchanged: $rel"; else echo "  patched:   $rel"; fi
  rm -f "$f.prepatch"
}

# ---------------------------------------------------------------------------
echo "1. Platform config (printf/fprintf/exit -> no-op macros) ..."
if grep -q 'MBEDTLS_PLATFORM_PRINTF_MACRO' "$CONFIG" 2>/dev/null; then
  echo "  already patched: $CONFIG"
else
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
fi

# ---------------------------------------------------------------------------
echo "2. Compiler-warning fixes (narrowing casts) ..."

patch_perl aes.c '
  s/\Q#define XTIME(x) (((x) << 1) ^ (((x) & 0x80) ? 0x1B : 0x00))\E/#define XTIME(x) ((uint8_t) (((x) << 1) ^ (((x) & 0x80) ? 0x1B : 0x00)))/;
  s/\Qy = (y << 1) | (y >> 7);\E/y = (uint8_t) ((y << 1) | (y >> 7));/g;
'
patch_perl asn1parse.c '
  s/\Q0xFF, tag, 0, 0,\E/0xFF, (unsigned char) tag, 0, 0,/;
'
patch_perl asn1write.c '
  s/\Qmbedtls_asn1_write_len_and_tag(p, start, len, tag)\E/mbedtls_asn1_write_len_and_tag(p, start, len, (unsigned char) tag)/g;
'
patch_perl bignum.c '
  s/\Q#define TO_SIGN(x) ((mbedtls_mpi_sint) (((mbedtls_mpi_uint) x) >> (biL - 1)) * -2 + 1)\E/#define TO_SIGN(x) ((short) ((mbedtls_mpi_sint) (((mbedtls_mpi_uint) x) >> (biL - 1)) * -2 + 1))/;
  s/\Qmbedtls_ct_mpi_sign_if(do_swap, s, Y->s)\E/mbedtls_ct_mpi_sign_if(do_swap, (short) s, Y->s)/;
  s/\QX->s = cmp == 0 ? 1 : s;\E/X->s = (short) (cmp == 0 ? 1 : s);/;
  s/\QX->s = -s;\E/X->s = (short) -s;/;
  s/\QX->s = s;\E/X->s = (short) s;/;
'
patch_perl ccm.c '
  s/\Qctx->ctr[0] = ctx->q - 1;\E/ctx->ctr[0] = (unsigned char) (ctx->q - 1);/;
'
patch_perl constant_time.c '
  s/\Qbuf[n] = mbedtls_ct_uint_if(no_op, current, next);\E/buf[n] = (unsigned char) mbedtls_ct_uint_if(no_op, current, next);/;
  s/\Qbuf[total-1] = mbedtls_ct_uint_if_else_0(no_op, buf[total-1]);\E/buf[total-1] = (unsigned char) mbedtls_ct_uint_if_else_0(no_op, buf[total-1]);/;
'
patch_perl ctr_drbg.c '
  s/\Qkey[i] = i;\E/key[i] = (unsigned char) i;/;
'
patch_perl ecp.c '
  s/\Qbuf[0] = 0x02 + mbedtls_mpi_get_bit(&P->Y, 0);\E/buf[0] = (unsigned char) (0x02 + mbedtls_mpi_get_bit(&P->Y, 0));/;
  s/\QT_size = 1U << (w - 1);\E/T_size = (unsigned char) (1U << (w - 1));/g;
  s{\Qi = 1U << (j / d);\E}{i = (unsigned char) (1U << (j / d));};
  s/\Qb = mbedtls_mpi_get_bit(m, i);\E/b = (unsigned char) mbedtls_mpi_get_bit(m, i);/;
'
patch_perl gcm.c '
  s/\Qctx->mode = mode;\E/ctx->mode = (unsigned char) mode;/;
'
patch_perl ssl_msg.c '
  s/\Qmsg->type = ssl->out_msgtype;\E/msg->type = (unsigned char) ssl->out_msgtype;/;
  s/\Qrec.type = ssl->out_msgtype;\E/rec.type = (uint8_t) ssl->out_msgtype;/;
  s/\Qssl_buffering_free_slot(ssl, offset);\E/ssl_buffering_free_slot(ssl, (uint8_t) offset);/;
  s/\Q~(tls_version - (tls_version == 0x0302 ? 0x0202 : 0x0201));\E/(uint16_t) ~(tls_version - (tls_version == 0x0302 ? 0x0202 : 0x0201));/;
  s/\Q~(tls_version - (tls_version == 0xfeff ? 0x0202 : 0x0201));\E/(uint16_t) ~(tls_version - (tls_version == 0xfeff ? 0x0202 : 0x0201));/;
'
patch_perl ssl_tls.c '
  s/\Qconf->ignore_unexpected_cid = ignore_other_cid;\E/conf->ignore_unexpected_cid = (uint8_t) ignore_other_cid;/;
  s/\Qssl->negotiate_cid = enable;\E/ssl->negotiate_cid = (uint8_t) enable;/;
  s/\Q*p = ((hash << 8) | MBEDTLS_SSL_SIG_ECDSA);\E/*p = (uint16_t) ((hash << 8) | MBEDTLS_SSL_SIG_ECDSA);/;
  s/\Q*p = ((hash << 8) | MBEDTLS_SSL_SIG_RSA);\E/*p = (uint16_t) ((hash << 8) | MBEDTLS_SSL_SIG_RSA);/;
  s/\Qconf->endpoint   = endpoint;\E/conf->endpoint   = (uint8_t) endpoint;/;
  s/\Qconf->transport = transport;\E/conf->transport = (uint8_t) transport;/;
  s/\Qconf->authmode   = authmode;\E/conf->authmode   = (uint8_t) authmode;/;
  s/\Qssl->handshake->sni_authmode = authmode;\E/ssl->handshake->sni_authmode = (uint8_t) authmode;/;
  s/\Qconf->allow_legacy_renegotiation = allow_legacy;\E/conf->allow_legacy_renegotiation = (uint8_t) allow_legacy;/;
  s/\Qconf->disable_renegotiation = renegotiation;\E/conf->disable_renegotiation = (uint8_t) renegotiation;/;
'
patch_perl ssl_tls12_server.c '
  s/\Qconf->respect_cli_pref = order;\E/conf->respect_cli_pref = (uint8_t) order;/;
'
patch_perl x509.c '
  s/\Qreturn (i < 10) ? (i + '\''0'\'') : (i - 10 + '\''A'\'');\E/return (char) ((i < 10) ? (i + '\''0'\'') : (i - 10 + '\''A'\''));/;
  s/\Qmbedtls_asn1_write_tag(&asn1_len_p, asn1_tag_len_buf, name->val.tag)\E/mbedtls_asn1_write_tag(&asn1_len_p, asn1_tag_len_buf, (unsigned char) name->val.tag)/;
'
patch_perl x509_create.c '
  s/\Q*(d++) = n;\E/*(d++) = (unsigned char) n;/;
  s/\Qder[i] = c;\E/der[i] = (unsigned char) c;/;
  s/\Qcur->val.p[0] = critical;\E/cur->val.p[0] = (unsigned char) critical;/;
'
patch_perl x509write.c '
  s/\QMBEDTLS_ASN1_CONTEXT_SPECIFIC | cur->node.type));\E/(unsigned char) (MBEDTLS_ASN1_CONTEXT_SPECIFIC | cur->node.type)));/;
'

echo "=== patch_mbedtls.sh complete ==="
