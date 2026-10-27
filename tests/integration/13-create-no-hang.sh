#!/usr/bin/env bash
# 13-create-no-hang.sh — create must finish when its readers outnumber the
# work left at the end of the file list.
#
# Guards a lost wake-up in create's read ring: readers waiting for a free slot
# were woken one at a time (signal), and nobody woke them when the last range
# was claimed, so some slept forever and the chunker, which finishes only when
# every reader has exited, waited with them. It needs many readers, few CPUs
# and many small files; on 4 CPUs with -j 16 (8 readers) the old code hung in
# about 7% of runs, so 40 runs catch it almost always.
source "$(dirname "$0")/lib.sh"

command -v taskset >/dev/null && [ "$(nproc)" -ge 4 ] || { note "skipped: needs taskset and 4 CPUs"; exit 0; }
mkdir -p src/s
prand big 6000000 > src/big.bin
seq 1 400000 > src/log.txt
for i in $(seq 1 300); do prand "s$i" $(( (i * 7919) % 120000 + 1 )) > "src/s/f$i"; done

for i in $(seq 1 40); do
    rm -f b.bu
    timeout 20 taskset -c 0-3 "$BU" create "${K[@]}" -j 16 b.bu src \
        || fail "create did not finish (run $i; exit $?)"
done
"$BU" check "${K[@]}" b.bu
note ok
