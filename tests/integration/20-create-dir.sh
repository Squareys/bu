#!/usr/bin/env bash
# 20-create-dir.sh — create -C DIR reads the PATHs from DIR (tar's -C), so
# `-C data .` stores app.db, not data/app.db, while CHAIN, --base,
# --index-out and the key and passphrase files stay relative to where bu was
# started. Restore's -C then puts the tree back under its own DIR.
source "$(dirname "$0")/lib.sh"

mkdir -p data/memory/notes
prand app 200000 > data/app.db
prand mem 50000 > data/memory/notes/a.md
ln -s app.db data/link
sleep 1.1   # past the files-cache race guard, so the increment below may trust it
"$BU" create "${K[@]}" -C data --index-out c.idx c.bu .
[ -f c.bu ] && [ -f c.idx ] || fail "chain or index not written relative to the starting directory"
[ ! -e data/c.bu ] && [ ! -e data/c.idx ] || fail "chain or index written inside -C DIR"
paths=$("$BU" list "${K[@]}" c.bu | grep -v '^#' | sed 's/ -> .*//' | awk '{ print $NF }' | sort | tr '\n' ' ')
[ "$paths" = "app.db link memory memory/notes memory/notes/a.md " ] || fail "stored paths not relative to -C DIR: $paths"
"$BU" restore "${K[@]}" -C out c.bu
assert_same_tree data out

# An increment through -C reuses the files cache (same stored paths).
prand mem2 50000 > data/memory/notes/b.md
out=$("$BU" create "${K[@]}" -C data -v c.bu . 2>&1)
echo "$out" | grep -q " 1 files read" || fail "increment with -C did not use the files cache: $out"
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
assert_same_tree data out

# A relative PATH under -C, and a chain in another relative directory.
mkdir -p sub
"$BU" create "${K[@]}" -C data sub/m.bu memory
"$BU" list "${K[@]}" sub/m.bu | grep -v '^#' | awk '{ print $NF }' | grep -qx "memory/notes/a.md" \
    || fail "relative PATH under -C not stored as given"

# Streaming: --base and --index-out relative to the start, PATHs from -C.
"$BU" create "${K[@]}" -C data --base c.idx --index-out c2.idx - . > inc.bu
[ -f c2.idx ] || fail "--index-out not written relative to the starting directory with -C"
rm -rf out && "$BU" restore "${K[@]}" --index c2.idx -C out - < <(cat c.bu inc.bu)
assert_same_tree data out

# A chain inside -C DIR does not back itself up.
"$BU" create "${K[@]}" -C data data/self.bu .
"$BU" list "${K[@]}" data/self.bu | grep -v '^#' | grep -q 'self.bu' && fail "backup contains its own chain"
rm data/self.bu

# A -C DIR that is not there fails before the chain file is created.
rc=0
"$BU" create "${K[@]}" -C nope n.bu . 2> err || rc=$?
[ "$rc" = 1 ] || fail "expected exit 1 for a missing -C DIR, got $rc"
grep -q "nope" err || fail "missing -C DIR not named: $(cat err)"
[ ! -e n.bu ] || fail "chain file created although -C DIR is missing"
note ok
