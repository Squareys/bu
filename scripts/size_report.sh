#!/usr/bin/env bash
# Size of the stripped release binary, and a per-component breakdown of its
# code and read-only data from the unstripped twin (backu_symbols, same
# objects and flags, minus -s). Symbols are attributed by name: the vendored
# libraries keep their C prefixes, everything in namespace bk (and main) is
# backu's own code, and the rest is compiler runtime / libc glue.
#
#   scripts/size_report.sh            build if needed, then report
set -euo pipefail
cd "$(dirname "$0")/.."
BUILD_DIR="$(scripts/build.sh --print-build-dir)"
scripts/build.sh >/dev/null
cmake --build "$BUILD_DIR" --target backu_symbols >/dev/null
BIN="$BUILD_DIR/backu"
SYM="$BUILD_DIR/backu_symbols"
echo "stripped binary: $(stat -c %s "$BIN") bytes ($BIN)"
size -A "$BIN" | awk '$1 ~ /^\.(text|rodata|data|bss|eh_frame|dynsym|dynstr|rela\.dyn)$/ { printf "  %-12s %7d\n", $1, $2 }'
echo "breakdown of symbol sizes (text + rodata), bytes:"
nm --size-sort -S -C "$SYM" | awk '
{
    size = strtonum("0x" $2); name = $0; sub(/^[^ ]+ [^ ]+ [^ ]+ /, "", name)
    if (name ~ /^blake3_/)                              c = "BLAKE3 (vendored)"
    else if (name ~ /^LZ4_|^LZ4/)                       c = "LZ4 (vendored)"
    else if (name ~ /aes256gcm|^gh_|^aes_gcm|^crypto_verify|^sodium_|^expand256|^encrypt|^precomp/) c = "AES-256-GCM (libsodium, vendored)"
    else if (name ~ /^bk::|^main$/)                     c = "backu (src/)"
    else                                                c = "other (crt, runtime glue)"
    if (name ~ /^bk::.*(kGear)/) c = "backu (src/)"
    sum[c] += size; total += size
}
END { for (c in sum) printf "  %-38s %7d\n", c, sum[c]; printf "  %-38s %7d\n", "total attributed", total }' | sort -k1,1
echo "largest symbols:"
nm --size-sort -S -C "$SYM" | tail -12 | awk '{ s = strtonum("0x" $2); $1=""; $2=""; $3=""; printf "  %7d %s\n", s, $0 }'
