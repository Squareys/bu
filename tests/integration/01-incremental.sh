#!/usr/bin/env bash
# 01-incremental.sh — a full backup, every kind of mutation, an increment
# appended to the chain, restore of the chain (one file, or its segments as
# separate files), and merge.
#
# Guards the core promise: the increment holds only what changed (byte bounds
# asserted), restore reproduces content AND metadata (modes, mtimes, symlinks),
# and a merged chain restores the same tree as the chain it replaced.
source "$(dirname "$0")/lib.sh"

mkdir -p src/docs src/data src/empty
prand big 8000000 > src/data/big.bin           # insert-at-start target
prand mid 2000000 > src/data/mid.bin           # edit-in-the-middle target
seq 1 200000 > src/docs/log.txt                # append target
prand gone 300000 > src/data/gone.bin          # delete target
echo "mode me" > src/docs/mode.txt
echo "keep" > src/docs/keep.txt
ln -s keep.txt src/docs/link-old
: > src/docs/empty-file

"$BU" create "${K[@]}" c.bu src
FULL=$(size_of c.bu)
note "full: $FULL bytes"
# 10.3 MB incompressible + 1.3 MB of digits (LZ4 roughly halves those).
assert_between "$FULL" 10300000 11700000 "full backup size"
"$BU" check "${K[@]}" c.bu
# Thread count changes speed, never the output: record order and nonces are
# fixed before workers run, so the chunk table (IDs, lengths, nonces, order)
# is identical. (The file bytes are not: every segment has a fresh salt.)
"$BU" create "${K[@]}" -j 1 j1.bu src
"$BU" create "${K[@]}" -j 7 j7.bu src
table() { "$BU" list "${K[@]}" "$1" | head -1 | grep -o 'table [0-9a-f]*'; }
[ "$(table c.bu)" = "$(table j1.bu)" ] && [ "$(table c.bu)" = "$(table j7.bu)" ] \
    || fail "chunk table depends on -j: $(table c.bu) / $(table j1.bu) / $(table j7.bu)"
[ "$("$BU" list "${K[@]}" j1.bu | tail -n +2)" = "$("$BU" list "${K[@]}" j7.bu | tail -n +2)" ] \
    || fail "listing depends on -j"

# ---- mutate
{ printf 'INSERTED!'; cat src/data/big.bin; } > tmp && mv tmp src/data/big.bin   # 9 bytes at the start
printf 'EDIT' | dd of=src/data/mid.bin bs=1 seek=1000000 conv=notrunc status=none
seq 200001 200100 >> src/docs/log.txt
rm src/data/gone.bin
prand new 100000 > src/data/new.bin
chmod 600 src/docs/mode.txt
ln -s ../data src/docs/link-new
rm src/docs/link-old
touch -d '2001-02-03 04:05:06' src/docs/keep.txt

sleep 1.1   # past the files-cache race guard for the untouched files
"$BU" create "${K[@]}" -v c.bu src 2> inc.log
INC=$(( $(size_of c.bu) - FULL ))
note "increment: $INC bytes ($(grep -o '[0-9]* chunks, [0-9]* new' inc.log))"
# new.bin (100 KB, incompressible) + a few chunks around each edit (<= 64 KiB
# each) + the moved bytes of big.bin's first chunk + manifest.
assert_between "$INC" 100000 500000 "increment size"
[ "$("$BU" list "${K[@]}" c.bu | grep -c '^# ')" = 2 ] || fail "chain should hold two segments"

rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
assert_same_tree src out/src
# The same chain as two files, one segment each, in either order.
head -c "$FULL" c.bu > full.bu
tail -c +$((FULL + 1)) c.bu > inc.bu
rm -rf out && "$BU" restore "${K[@]}" -C out full.bu inc.bu
assert_same_tree src out/src
rm -rf out && "$BU" restore "${K[@]}" -C out inc.bu full.bu
assert_same_tree src out/src

"$BU" merge "${K[@]}" -o merged.bu c.bu
MERGED=$(size_of merged.bu)
note "merged: $MERGED bytes"
# Holds the current tree only: gone.bin's 300 KB are gone.
assert_between "$MERGED" 10000000 11700000 "merged size"
"$BU" check "${K[@]}" merged.bu
rm -rf out && "$BU" restore "${K[@]}" -C out merged.bu
assert_same_tree src out/src

# PATHs after -- restore a subtree only.
rm -rf out && "$BU" restore "${K[@]}" -C out merged.bu -- src/docs
[ -f out/src/docs/log.txt ] && [ ! -e out/src/data ] || fail "partial restore restored the wrong set"
cmp out/src/docs/log.txt src/docs/log.txt

# The full backup alone still shows the old state (big.bin without the insert).
rm -rf out && "$BU" restore "${K[@]}" -C out full.bu
[ -f out/src/data/gone.bin ] || fail "full backup lost a file"
note ok
