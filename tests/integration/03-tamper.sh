#!/usr/bin/env bash
# 03-tamper.sh — a modified, truncated or foreign backup must fail LOUDLY,
# and the wrong key must be reported as the wrong key.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand t 2000000 > src/t.bin
seq 1 50000 > src/n.txt
"$BU" create --key key --index-out idx src > good.bk
SIZE=$(size_of good.bk)

flip() {   # flip FILE OFFSET -> copy with one byte inverted
    cp good.bk bad.bk
    local b
    b=$(dd if=bad.bk bs=1 skip="$2" count=1 status=none | od -An -tu1 | tr -d ' ')
    printf "$(printf '\\%03o' $(( (b ^ 0xff) & 0xff )))" | dd of=bad.bk bs=1 seek="$2" conv=notrunc status=none
}

# A byte inside a chunk record's ciphertext.
flip good.bk 100000
expect_fail "authentication failed" "$BU" check --key key bad.bk
expect_fail "authentication failed" "$BU" restore --key key -C out bad.bk
# Restore must not report success for any part of it.
[ ! -e out/src/t.bin ] || ! cmp -s out/src/t.bin src/t.bin || fail "tampered data restored intact?"

# The format version: refused as such, before any key is tried.
flip good.bk 8
expect_fail "unsupported format version" "$BU" check --key key bad.bk
# A byte in the header's salt: every key derived from it changes.
flip good.bk 20
expect_fail "wrong key" "$BU" check --key key bad.bk
# A byte in the trailer (just before the 16-byte footer).
flip good.bk $((SIZE - 20))
expect_fail "authentication failed" "$BU" list --key key bad.bk
# The footer itself.
flip good.bk $((SIZE - 6))
expect_fail "footer" "$BU" check --key key bad.bk
# Truncation.
head -c $((SIZE - 1000)) good.bk > bad.bk
expect_fail "" "$BU" check --key key bad.bk

# The wrong key.
(umask 077; "$BU" keygen > other)
expect_fail "wrong key" "$BU" restore --key other -C out good.bk
expect_fail "wrong key" "$BU" create --key other --base idx --index-out idx2 src
# Not a backup at all.
echo "hello" > junk.bk
expect_fail "" "$BU" check --key key junk.bk
head -c 200 /dev/urandom > junk.bk
expect_fail "not a bu file" "$BU" check --key key junk.bk

"$BU" check --key key good.bk
note ok
