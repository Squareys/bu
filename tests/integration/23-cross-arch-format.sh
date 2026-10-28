#!/usr/bin/env bash
# 23-cross-arch-format.sh — a chain written on one architecture restores
# identically on another.
#
# The on-disk format is defined in explicit little-endian (bytes.hpp: every
# integer is an LEB128 varint or a byte-at-a-time LE field, never a native
# struct copy), and the chunk IDs are BLAKE3 of the content, so a chain is the
# same bytes whatever CPU wrote it. This test proves it from the other side:
# `fixtures/cross-arch/chain.bu` was written by an x86_64 build of bu (see
# fixtures/cross-arch/README), committed as data, and restored here on whatever
# architecture the suite runs on. The restored tree must match the committed
# manifest — content, mode, size, mtime and symlink target — exactly.
#
# The fixture is unencrypted (--no-key): that exercises the whole format a
# reader decodes (header, trailer, segment walk, the manifest's varints and
# delta program, the chunk table, CDC chunk boundaries and BLAKE3 chunk IDs)
# with no key material in the repository. The AES-256-GCM layer is the one part
# not exercised here; it is architecture-independent by construction and is
# proven so on every architecture by the known-answer vectors in
# tests/test_crypto.cpp (the aarch64 ARMv8-crypto and x86-64 AES-NI kernels are
# checked against the same GCM test vectors and OpenSSL-computed tags).
FX="$(cd "$(dirname "$0")/fixtures/cross-arch" && pwd)"
source "$(dirname "$0")/lib.sh"

[ -f "$FX/chain.bu" ] || fail "missing fixture $FX/chain.bu"
[ -f "$FX/MANIFEST" ] || fail "missing fixture $FX/MANIFEST"

# The whole chain authenticates (every record, every chunk re-hashed).
"$BU" check --no-key "$FX/chain.bu" 2> log || fail "check of the x86_64-written chain failed: $(cat log)"

# It lists the tree it holds.
"$BU" list "$FX/chain.bu" | grep -q "src/rand.bin" || fail "list did not show the backed-up tree"

# It restores, and the restored tree matches the manifest captured when the
# chain was written on the other architecture.
rm -rf out
"$BU" restore -C out --no-key "$FX/chain.bu" || fail "restore of the x86_64-written chain failed"
got=$(cd out/src && find . -mindepth 1 -printf '%p|%y|%m|%s|%T@|%l\n' | sort \
    | while IFS='|' read -r p t m s mt l; do
        if [ "$t" = f ]; then h=$(sha256sum "$p" | cut -c1-16); else h=-; fi
        if [ "$t" = d ]; then s=0; fi
        echo "$t $m $s $mt $l $p $h"
      done)
if ! diff <(cat "$FX/MANIFEST") <(printf '%s\n' "$got") >/dev/null; then
    diff <(cat "$FX/MANIFEST") <(printf '%s\n' "$got") | head -10 >&2
    fail "restored tree differs from the committed cross-architecture manifest"
fi

note "ok (restored an x86_64-written chain, $(size_of "$FX/chain.bu") bytes)"
