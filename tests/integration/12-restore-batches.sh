#!/usr/bin/env bash
# 12-restore-batches.sh — restore and check of a tree that spans many restore
# batches and many read spans.
#
# Guards the batched read path: restore reads runs of consecutive records
# with one pread, gathers decoded chunks into larger writes, and creates the
# next batch's files while the previous batch's data is written; check reads
# the same spans. A low descriptor limit forces batches of a few files, so
# two batches are in flight all the time. Duplicates (which break a run of
# consecutive records), all-zero chunks (which must stay holes) and files
# that share one span all have to come back exactly, at any thread count.
source "$(dirname "$0")/lib.sh"

mkdir -p src/tiny src/dup src/big
for i in $(seq -w 1 600); do printf 'tiny file %s\n' "$i" > "src/tiny/t$i"; done
prand big 3000000 > src/big/a.bin
cp src/big/a.bin src/dup/copy-of-a.bin            # every chunk a duplicate
prand dup 70000 > src/dup/one.bin
for i in 1 2 3 4 5; do cp src/dup/one.bin "src/dup/one-$i.bin"; done
{ prand head 100000; head -c 600000 /dev/zero; prand tail 100000; } > src/big/holes.bin
truncate -s 2000000 src/big/sparse.bin

"$BU" create "${K[@]}" c.bu src
"$BU" check "${K[@]}" -v c.bu 2>check.log
grep -q "check ok" check.log || fail "check did not pass: $(cat check.log)"

for j in 1 3 8; do
    rm -rf "out-$j"
    # 300 descriptors: batches of ~20 files, about 50 of them.
    (ulimit -n 300 && "$BU" restore "${K[@]}" -C "out-$j" -j "$j" c.bu)
    assert_same_tree src "out-$j/src"
done
USED=$(du -k out-3/src/big/sparse.bin | cut -f1)
[ "$USED" -lt 64 ] || fail "all-zero file restored with ${USED} KiB allocated, expected a hole"
rm -rf out-dflt && "$BU" restore "${K[@]}" -C out-dflt c.bu
assert_same_tree src out-dflt/src

# A record damaged in the middle of a span fails check and restore loudly.
OFF=$(( $(size_of c.bu) / 3 ))
printf '\xff' | dd of=c.bu bs=1 seek="$OFF" conv=notrunc status=none
expect_fail "authentication failed\|record length" "$BU" check "${K[@]}" c.bu
expect_fail "authentication failed\|record length" "$BU" restore "${K[@]}" -C out-bad c.bu
note ok
