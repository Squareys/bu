#!/usr/bin/env bash
# 02-chain-merge.sh — a three-step chain rolled forward twice, with
# increments made AFTER a merge from the same index lineage.
#
# Guards the merge design: nothing refers to a backup by file name, a merged
# file keeps its snapshot ID, and an index made from inc-N stays valid for the
# next increment whatever has been merged in between.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand a 3000000 > src/a.bin
prand b 1000000 > src/b.bin
"$BU" create --key key --index-out idx src > c0.bk

prand c 500000 > src/c.bin
printf 'x' | dd of=src/a.bin bs=1 seek=1500000 conv=notrunc status=none
"$BU" create --key key --base idx --index-out idx src > c1.bk

rm src/b.bin
prand d 200000 > src/d.bin
"$BU" create --key key --base idx --index-out idx src > c2.bk

rm -rf out && "$BU" restore --key key -C out c0.bk c1.bk c2.bk
assert_same_tree src out/src

# Roll forward: m1 = c0+c1, then m2 = m1+c2. Old files deleted each time.
"$BU" merge --key key c0.bk c1.bk > m1.bk
rm c0.bk c1.bk
rm -rf out && "$BU" restore --key key -C out m1.bk c2.bk
assert_same_tree src out/src
"$BU" check --key key m1.bk c2.bk

# An increment after the first merge, from the index of c2.
prand e 50000 > src/e.bin
"$BU" create --key key --base idx --index-out idx src > c3.bk
rm -rf out && "$BU" restore --key key -C out m1.bk c2.bk c3.bk
assert_same_tree src out/src

"$BU" merge --key key m1.bk c2.bk > m2.bk
rm m1.bk c2.bk
rm -rf out && "$BU" restore --key key -C out m2.bk c3.bk
assert_same_tree src out/src
"$BU" merge --key key m2.bk c3.bk > m3.bk
rm -rf out && "$BU" restore --key key -C out m3.bk
assert_same_tree src out/src
"$BU" check --key key m3.bk

# The merged file holds only live chunks: b.bin (deleted) is not in m3.
LIVE=$(du -cb src/*.bin | tail -1 | cut -f1)
M3=$(size_of m3.bk)
assert_between "$M3" "$LIVE" $((LIVE + LIVE / 20)) "fully merged size vs live data"

# A missing middle file is reported as such, not as corruption.
expect_fail "parent snapshot" "$BU" restore --key key -C out c3.bk
note ok
