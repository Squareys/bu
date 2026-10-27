#!/usr/bin/env bash
# 01-incremental.sh — full backup, every kind of mutation, an increment made
# from the index alone, restore of the chain, and merge(full, inc).
#
# Guards the core promise: the increment holds only what changed (byte bounds
# asserted), restore reproduces content AND metadata (modes, mtimes, symlinks),
# and a merged file restores the same tree as the chain it replaced.
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

"$BU" create --key key --index-out idx src > full.bk
FULL=$(size_of full.bk)
note "full: $FULL bytes"
# 10.3 MB incompressible + 1.3 MB of digits (LZ4 roughly halves those).
assert_between "$FULL" 10300000 11700000 "full backup size"
"$BU" check --key key full.bk
# Thread count changes speed, never the output: record order and nonces are
# fixed before workers run, so the chunk table (IDs, lengths, nonces, order)
# is identical. (The file bytes are not: every backup has a fresh salt.)
"$BU" create --key key --index-out idx-j1 -j 1 src > full-j1.bk
"$BU" create --key key --index-out idx-j7 -j 7 src > full-j7.bk
table() { "$BU" list --key key "$1" | head -1 | grep -o 'table [0-9a-f]*'; }
[ "$(table full.bk)" = "$(table full-j1.bk)" ] && [ "$(table full.bk)" = "$(table full-j7.bk)" ] \
    || fail "chunk table depends on -j: $(table full.bk) / $(table full-j1.bk) / $(table full-j7.bk)"
[ "$("$BU" list --key key full-j1.bk | tail -n +2)" = "$("$BU" list --key key full-j7.bk | tail -n +2)" ] \
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
"$BU" create --key key --base idx --index-out idx -v src > inc.bk 2> inc.log
INC=$(size_of inc.bk)
note "increment: $INC bytes ($(grep -o '[0-9]* chunks, [0-9]* new' inc.log))"
# new.bin (100 KB, incompressible) + a few chunks around each edit (<= 64 KiB
# each) + the moved bytes of big.bin's first chunk + manifest.
assert_between "$INC" 100000 500000 "increment size"

rm -rf out && "$BU" restore --key key -C out full.bk inc.bk
assert_same_tree src out/src
# Order on the command line does not matter.
rm -rf out && "$BU" restore --key key -C out inc.bk full.bk
assert_same_tree src out/src

"$BU" merge --key key full.bk inc.bk > merged.bk
MERGED=$(size_of merged.bk)
note "merged: $MERGED bytes"
# Holds the current tree only: gone.bin's 300 KB are gone.
assert_between "$MERGED" 10000000 11700000 "merged size"
"$BU" check --key key merged.bk
rm -rf out && "$BU" restore --key key -C out merged.bk
assert_same_tree src out/src

# --path restores a subtree only.
rm -rf out && "$BU" restore --key key -C out --path src/docs merged.bk
[ -f out/src/docs/log.txt ] && [ ! -e out/src/data ] || fail "--path restored the wrong set"
cmp out/src/docs/log.txt src/docs/log.txt

# The full-only restore still shows the old state (big.bin without the insert).
rm -rf out && "$BU" restore --key key -C out full.bk
[ -f out/src/data/gone.bin ] || fail "full backup lost a file"
note ok
