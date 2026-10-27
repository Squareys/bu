#!/usr/bin/env bash
# 16-no-key.sh — unencrypted chains (--no-key): the whole cycle without a
# key file, damage caught by the checksums, and no mixing with encrypted
# segments anywhere.
#
# Guards the mode switch: create needs --key or --no-key (never a default);
# readers learn the mode from the chain and refuse a --key that does not fit,
# so an unencrypted chain put in place of an encrypted one is refused.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand p 1000000 > src/p.bin
seq 1 50000 > src/n.txt
"$BU" create --no-key c.bu src
grep -q "50000" c.bu || fail "an unencrypted chain should hold the data in the clear"
echo more >> src/n.txt
"$BU" create --no-key --index-out idx c.bu src
"$BU" check -v c.bu 2> log && grep -q "check ok: 2 segments" log || fail "check: $(cat log)"
"$BU" check --no-key c.bu
"$BU" list c.bu | grep -q "src/n.txt" || fail "list"
rm -rf out && "$BU" restore -C out c.bu
assert_same_tree src out/src
rm -rf out && piped c.bu "$BU" restore --index idx -C out -
assert_same_tree src out/src
"$BU" merge -o m.bu c.bu
"$BU" check m.bu
rm -rf out && "$BU" restore -C out m.bu
assert_same_tree src out/src
grep -q "50000" m.bu || fail "merge should keep the chain unencrypted"

# Damage is caught: a chunk's content, a manifest's.
flip() {   # flip SRC DST OFFSET
    cp "$1" "$2"
    local b
    b=$(dd if="$2" bs=1 skip="$3" count=1 status=none | od -An -tu1 | tr -d ' ')
    printf "$(printf '\\%03o' $(( (b ^ 0xff) & 0xff )))" | dd of="$2" bs=1 seek="$3" conv=notrunc status=none
}
flip m.bu bad.bu 200000
expect_fail "does not match its ID\|does not decompress" "$BU" check bad.bu
expect_fail "does not match its ID\|does not decompress" "$BU" restore -C out2 bad.bu
piped bad.bu expect_fail "does not match its ID\|does not decompress" "$BU" check -
MAN=$(( $(size_of m.bu) - 200 ))       # inside the table or manifest at the end
flip m.bu bad.bu "$MAN"
expect_fail "authentication failed\|damaged" "$BU" check bad.bu

# No mixing, and the flags must fit the chain.
"$BU" create "${K[@]}" e.bu src
expect_fail "not encrypted" "$BU" check "${K[@]}" c.bu
expect_fail "is encrypted" "$BU" check --no-key e.bu
expect_fail "use --no-key" "$BU" create "${K[@]}" c.bu src
expect_fail "use --key" "$BU" create --no-key e.bu src
expect_fail "key KEYFILE is required" "$BU" restore -C out e.bu
cat e.bu c.bu > mixed.bu
expect_fail "unencrypted segment in an encrypted chain" "$BU" check "${K[@]}" mixed.bu
piped mixed.bu expect_fail "mixes encrypted and unencrypted" "$BU" check "${K[@]}" -
expect_fail "unencrypted and the chain before it is not" "$BU" check "${K[@]}" e.bu c.bu
expect_fail "idx is not encrypted" "$BU" create "${K[@]}" --base idx new.bu src
note ok
