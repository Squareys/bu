#!/usr/bin/env bash
# 03-tamper.sh — a modified, truncated or foreign chain must fail LOUDLY,
# the wrong key must be reported as the wrong key, and a create with the
# wrong key must leave the chain alone.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand t 2000000 > src/t.bin
seq 1 50000 > src/n.txt
"$BU" create "${K[@]}" good.bu src
SIZE=$(size_of good.bu)

flip() {   # flip FILE OFFSET -> copy with one byte inverted
    cp good.bu bad.bu
    local b
    b=$(dd if=bad.bu bs=1 skip="$2" count=1 status=none | od -An -tu1 | tr -d ' ')
    printf "$(printf '\\%03o' $(( (b ^ 0xff) & 0xff )))" | dd of=bad.bu bs=1 seek="$2" conv=notrunc status=none
}

# A byte inside a chunk record's ciphertext.
flip good.bu 100000
expect_fail "authentication failed" "$BU" check "${K[@]}" bad.bu
expect_fail "authentication failed" "$BU" restore "${K[@]}" -C out bad.bu
# The damaged chunk is never written: whichever file it belongs to (n.txt
# sorts first, so offset 100000 may be in either) cannot come back intact.
{ [ -e out/src/n.txt ] && cmp -s out/src/n.txt src/n.txt && [ -e out/src/t.bin ] && cmp -s out/src/t.bin src/t.bin; } \
    && fail "tampered data restored intact?"
# The first record's header (its sequence number): check reads every one.
flip good.bu 72
expect_fail "record header authentication failed" "$BU" check "${K[@]}" bad.bu
piped bad.bu expect_fail "authentication failed" "$BU" check "${K[@]}" -

# The format version: refused as such, before any key is tried.
flip good.bu 8
expect_fail "unsupported format version" "$BU" check "${K[@]}" bad.bu
# A byte in the header's salt: every key derived from it changes.
flip good.bu 20
expect_fail "wrong key" "$BU" check "${K[@]}" bad.bu
# A byte in the trailer's check value.
flip good.bu $((SIZE - 20))
expect_fail "trailer authentication failed" "$BU" list "${K[@]}" bad.bu
# The trailer's generation (covered by the check).
flip good.bu $((SIZE - 32))
expect_fail "trailer authentication failed" "$BU" list "${K[@]}" bad.bu
# The trailer's magic: no complete segment is left.
flip good.bu $((SIZE - 3))
expect_fail "no complete backup" "$BU" check "${K[@]}" bad.bu
# Truncation.
head -c $((SIZE - 1000)) good.bu > bad.bu
expect_fail "no complete backup" "$BU" check "${K[@]}" bad.bu
piped bad.bu expect_fail "ends inside a segment" "$BU" check "${K[@]}" -

# The wrong key (another key file, even under the same passphrase).
"$BU" key init --passphrase-file pass --kdf-memory 8 --kdf-time 1 other 2>/dev/null
expect_fail "wrong key" "$BU" restore --key other --passphrase-file pass -C out good.bu
cp good.bu before.bu
expect_fail "wrong key" "$BU" create --key other --passphrase-file pass good.bu src
cmp -s good.bu before.bu || fail "a create with the wrong key changed the chain"
# Not a backup at all, and never appended to.
echo "hello" > junk.bu
expect_fail "" "$BU" check "${K[@]}" junk.bu
head -c 200 /dev/urandom > junk.bu
cp junk.bu junk-before
expect_fail "not a bu file" "$BU" check "${K[@]}" junk.bu
expect_fail "not a bu file" "$BU" create "${K[@]}" junk.bu src
cmp -s junk.bu junk-before || fail "create appended to a file that is not a chain"

"$BU" check "${K[@]}" good.bu
note ok
