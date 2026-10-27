#!/usr/bin/env bash
# 02-chain-merge.sh — a chain rolled forward by merges, with increments made
# after each merge; and the same lineage kept as one file per segment (made
# with an index), merged a prefix at a time.
#
# Guards the merge design: nothing refers to a segment by file name or
# offset, a merged chain keeps its snapshot ID, and an increment made from
# snapshot N stays valid whatever has been merged in between.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand a 3000000 > src/a.bin
prand b 1000000 > src/b.bin
"$BU" create "${K[@]}" c.bu src
"$BU" create "${K[@]}" --index-out idx c0.bu src         # the separate-file lineage

prand c 500000 > src/c.bin
printf 'x' | dd of=src/a.bin bs=1 seek=1500000 conv=notrunc status=none
"$BU" create "${K[@]}" c.bu src
"$BU" create "${K[@]}" --base idx --index-out idx c1.bu src

rm src/b.bin
prand d 200000 > src/d.bin
"$BU" create "${K[@]}" c.bu src
"$BU" create "${K[@]}" --base idx --index-out idx c2.bu src

rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
assert_same_tree src out/src
rm -rf out && "$BU" restore "${K[@]}" -C out c0.bu c1.bu c2.bu
assert_same_tree src out/src

# Compact the chain in place, then keep appending to it.
"$BU" merge "${K[@]}" -o c.bu c.bu
[ "$("$BU" list "${K[@]}" c.bu | grep -c '^# ')" = 1 ] || fail "merged chain should hold one segment"
prand e 50000 > src/e.bin
"$BU" create "${K[@]}" c.bu src
"$BU" create "${K[@]}" --base idx --index-out idx c3.bu src
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
assert_same_tree src out/src
"$BU" check "${K[@]}" c.bu

# Separate files: m1 = c0+c1, then m2 = m1+c2. Old files deleted each time;
# c3, made from the index before any merge, keeps working.
"$BU" merge "${K[@]}" -o m1.bu c0.bu c1.bu
rm c0.bu c1.bu
rm -rf out && "$BU" restore "${K[@]}" -C out m1.bu c2.bu c3.bu
assert_same_tree src out/src
"$BU" merge "${K[@]}" m1.bu c2.bu > m2.bu
rm m1.bu c2.bu
rm -rf out && "$BU" restore "${K[@]}" -C out m2.bu c3.bu
assert_same_tree src out/src
"$BU" merge "${K[@]}" -o m3.bu m2.bu c3.bu
rm -rf out && "$BU" restore "${K[@]}" -C out m3.bu
assert_same_tree src out/src
"$BU" check "${K[@]}" m3.bu

# The merged chain holds only live chunks: b.bin (deleted) is not in it.
LIVE=$(du -cb src/*.bin | tail -1 | cut -f1)
M3=$(size_of m3.bu)
assert_between "$M3" "$LIVE" $((LIVE + LIVE / 20)) "fully merged size vs live data"

# merge does not overwrite a file that is not one of its inputs.
expect_fail "does not overwrite" "$BU" merge "${K[@]}" -o m3.bu c.bu
# A missing middle segment is reported as such, not as corruption.
"$BU" create "${K[@]}" --base idx --index-out idx c4.bu src
expect_fail "parent snapshot" "$BU" restore "${K[@]}" -C out m2.bu c4.bu
note ok
