#!/usr/bin/env bash
# 05-files-cache.sh — unchanged files are not read; changed ones always are,
# even when the mtime is put back; the cache survives merges and an index
# rebuilt from the backups.
source "$(dirname "$0")/lib.sh"

files_read() { grep -o '[0-9]* files read' "$1" | cut -d' ' -f1; }

mkdir -p src/d
for i in 1 2 3 4 5; do prand "f$i" 200000 > "src/d/f$i.bin"; done
echo "same size A" > src/sneaky.txt
sleep 1.1   # files older than the race guard by the time the full runs

"$BACKU" create --key key --index-out idx -v src > c0.bk 2> log0
[ "$(files_read log0)" = 6 ] || fail "full backup should read all 6 files"

"$BACKU" create --key key --base idx --index-out idx1 -v src > c1.bk 2> log1
[ "$(files_read log1)" = 0 ] || fail "unchanged tree: expected 0 files read, got $(files_read log1)"
note "unchanged increment: $(size_of c1.bk) bytes, 0 files read"

# Same size, mtime put back with touch -r: only ctime gives it away.
cp -p src/sneaky.txt ref
echo "same size B" > src/sneaky.txt
touch -r ref src/sneaky.txt
sleep 1.1   # so later increments may trust the cache entry for it again
"$BACKU" create --key key --base idx1 --index-out idx2 -v src > c2.bk 2> log2
[ "$(files_read log2)" = 1 ] || fail "touch-back edit: expected 1 file read, got $(files_read log2)"
rm -rf out && "$BACKU" restore --key key -C out c0.bk c1.bk c2.bk
grep -q "same size B" out/src/sneaky.txt || fail "touch-back edit not captured"

# --no-files-cache reads everything (and still stores nothing new).
"$BACKU" create --key key --base idx2 --index-out idx3 --no-files-cache -v src > c3.bk 2> log3
[ "$(files_read log3)" = 6 ] || fail "--no-files-cache: expected 6 files read"
grep -q ' 0 new' log3 || fail "--no-files-cache re-stored unchanged chunks: $(cat log3)"

# After merging everything, the index from c3 still drives a correct,
# cache-using increment.
"$BACKU" merge --key key c0.bk c1.bk c2.bk c3.bk > m.bk
prand f9 100000 > src/d/f9.bin
sleep 1.1   # f9 older than c4's start, so the rebuilt index may trust it below
"$BACKU" create --key key --base idx3 --index-out idx4 -v src > c4.bk 2> log4
[ "$(files_read log4)" = 1 ] || fail "after merge: expected only the new file read, got $(files_read log4)"
rm -rf out && "$BACKU" restore --key key -C out m.bk c4.bk
assert_same_tree src out/src

# A lost index is rebuilt from the backups, files cache included.
"$BACKU" index --key key -o rebuilt m.bk c4.bk
"$BACKU" create --key key --base rebuilt --index-out idx5 -v src > c5.bk 2> log5
[ "$(files_read log5)" = 0 ] || fail "rebuilt index lost the files cache: $(files_read log5) files read"
rm -rf out && "$BACKU" restore --key key -C out m.bk c4.bk c5.bk
assert_same_tree src out/src
"$BACKU" list --key key idx5 | head -1 | grep -q 'index: snapshot' || fail "list of an index file"
note ok
