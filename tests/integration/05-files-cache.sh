#!/usr/bin/env bash
# 05-files-cache.sh — unchanged files are not read; changed ones always are,
# even when the mtime is put back; the cache survives a merge, an index
# rebuilt from the chain, and an increment written to a separate file.
source "$(dirname "$0")/lib.sh"

files_read() { grep -o '[0-9]* files read' "$1" | cut -d' ' -f1; }

mkdir -p src/d
for i in 1 2 3 4 5; do prand "f$i" 200000 > "src/d/f$i.bin"; done
echo "same size A" > src/sneaky.txt
sleep 1.1   # files older than the race guard by the time the full runs

"$BU" create "${K[@]}" -v c.bu src 2> log0
[ "$(files_read log0)" = 6 ] || fail "full backup should read all 6 files"

S0=$(size_of c.bu)
"$BU" create "${K[@]}" -v c.bu src 2> log1
[ "$(files_read log1)" = 0 ] || fail "unchanged tree: expected 0 files read, got $(files_read log1)"
note "unchanged increment: $(( $(size_of c.bu) - S0 )) bytes, 0 files read"

# Same size, mtime put back with touch -r: only ctime gives it away.
cp -p src/sneaky.txt ref
echo "same size B" > src/sneaky.txt
touch -r ref src/sneaky.txt
sleep 1.1   # so later increments may trust the cache entry for it again
"$BU" create "${K[@]}" -v c.bu src 2> log2
[ "$(files_read log2)" = 1 ] || fail "touch-back edit: expected 1 file read, got $(files_read log2)"
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
grep -q "same size B" out/src/sneaky.txt || fail "touch-back edit not captured"

# --no-files-cache reads everything (and still stores nothing new).
"$BU" create "${K[@]}" --no-files-cache -v c.bu src 2> log3
[ "$(files_read log3)" = 6 ] || fail "--no-files-cache: expected 6 files read"
grep -q ' 0 new' log3 || fail "--no-files-cache re-stored unchanged chunks: $(cat log3)"

# After merging the chain in place, the next increment still uses the cache.
"$BU" merge "${K[@]}" -o c.bu c.bu
prand f9 100000 > src/d/f9.bin
sleep 1.1   # f9 older than the next start, so the index below may trust it
"$BU" create "${K[@]}" -v c.bu src 2> log4
[ "$(files_read log4)" = 1 ] || fail "after merge: expected only the new file read, got $(files_read log4)"
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
assert_same_tree src out/src

# An index made from the chain drives an increment into a separate file,
# files cache included; the two files are a chain.
"$BU" index "${K[@]}" -o idx c.bu
"$BU" create "${K[@]}" --base idx --index-out idx2 -v next.bu src 2> log5
[ "$(files_read log5)" = 0 ] || fail "index from the chain lost the files cache: $(files_read log5) files read"
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu next.bu
assert_same_tree src out/src
"$BU" list "${K[@]}" idx2 | head -1 | grep -q 'index: snapshot' || fail "list of an index file"
# --base is for a new file: a chain is its own base.
expect_fail "its own base" "$BU" create "${K[@]}" --base idx c.bu src
note ok
