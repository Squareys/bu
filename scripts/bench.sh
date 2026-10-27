#!/usr/bin/env bash
# Benchmarks: primitive throughput, then end-to-end create on a generated
# ~1 GB tree at 1 thread and at N threads, then a 1% scattered change and the
# increment with and without the files cache, then restore.
#
#   scripts/bench.sh [--size-mb N] [--dir DIR] [--keep]
#
# The data set goes to DIR (default /tmp) and is deleted afterwards unless
# --keep. On tmpfs this measures CPU throughput (no disk in the way); point
# --dir at a real disk, after dropping caches, to see the I/O-bound picture.
set -euo pipefail
cd "$(dirname "$0")/.."
SIZE_MB=1024
DIR=/tmp
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        --dir) DIR="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "bench.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
done
BUILD_DIR="$(scripts/build.sh | tail -1)"
BU="$BUILD_DIR/bu"
NPROC=$(nproc)

echo "== primitives (one thread)"
"$BUILD_DIR/bu_bench" 512

W="$(mktemp -d "$DIR/bu-bench.XXXXXX")"
cleanup() { [ "$KEEP" = 1 ] && echo "(kept $W)" || rm -rf "$W"; }
trap cleanup EXIT
cd "$W"
prand() { { openssl enc -aes-128-ctr -pass "pass:$1" -nosalt -pbkdf2 -iter 1 </dev/zero 2>/dev/null || true; } | head -c "$2"; }

# The tree: 40% large incompressible files, 30% compressible text logs,
# 30% many small incompressible files (3000 x ~100 KB at 1 GB).
MB=$((1024 * 1024))
BIG=$((SIZE_MB * 4 / 10)); TXT=$((SIZE_MB * 3 / 10)); SMALL=$((SIZE_MB - BIG - TXT))
mkdir -p data/big data/logs data/small
for i in 1 2 3 4; do prand "big$i" $((BIG * MB / 4)) > "data/big/file$i.bin"; done
awk -v total=$((TXT * MB)) 'BEGIN { n = 0; i = 0; f = 0; out = "data/logs/app0.log"
    while (n < total) { line = sprintf("2026-10-25T%02d:%02d:%02d host app[%d]: request %d done in %d ms status=%d\n",
        int(i/3600)%24, int(i/60)%60, i%60, 4000+i%7, (i*7919)%100000, i%997, (i%13==0)?500:200)
        printf "%s", line > out; n += length(line); i++
        if (i % 1000000 == 0) { close(out); f++; out = "data/logs/app" f ".log" } } }'
NSMALL=$((SMALL * 3000 / 300))
SMALL_BYTES=$((SMALL * MB / NSMALL))
prand small $((SMALL * MB)) | split -b "$SMALL_BYTES" -a 4 - data/small/f
TOTAL=$(du -sb data | cut -f1)
echo "== data set: $(du -sh data | cut -f1) in $(find data -type f | wc -l) files under $W"
# A cheap key slot (8 MiB, one pass): the unlock is not what is measured.
printf 'bench passphrase\n' > pass
"$BU" key init --passphrase-file pass --kdf-memory 8 --kdf-time 1 key 2>/dev/null

mbps() { awk -v b="$1" -v s="$2" 'BEGIN { printf "%.0f", b / s / 1048576 }'; }
timeit() { local t0 t1; t0=$(date +%s.%N); "$@"; t1=$(date +%s.%N); awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.3f", b - a }'; }

echo "== create (full), thread scaling"
for j in 1 2 4 8 $NPROC; do
    S=$(timeit sh -c "\"$BU\" create --key key --passphrase-file pass --index-out idx-$j -j $j data > full-$j.bk")
    echo "  -j $j: $S s, $(mbps "$TOTAL" "$S") MiB/s, backup $(stat -c %s full-$j.bk) bytes"
done
cp idx-$NPROC idx
rm -f full-1.bk full-2.bk full-4.bk full-8.bk

echo "== increment of the UNCHANGED tree"
sleep 1.1   # past the files-cache race guard
S=$(timeit sh -c "\"$BU\" create --key key --passphrase-file pass --base idx --index-out idx-u -v data > u.bk 2> u.log")
echo "  with files cache:    $S s, increment $(stat -c %s u.bk) bytes  ($(grep -o '[0-9]* files read ([^)]*)' u.log))"
S=$(timeit sh -c "\"$BU\" create --key key --passphrase-file pass --base idx --index-out idx-u2 --no-files-cache -v data > u2.bk 2> u2.log")
echo "  without files cache: $S s, increment $(stat -c %s u2.bk) bytes  ($(grep -o '[0-9]* files read ([^)]*)' u2.log))"

echo "== 1% scattered change"
# 1% of the bytes: 4 KiB overwrites at random offsets in the big files, a few
# appended log lines, and 1% of the small files rewritten.
CHANGE=$((TOTAL / 100))
N4K=$((CHANGE * 4 / 10 / 4096))
python3 -I - "$N4K" <<'PY'
import os, random, sys
random.seed(1)
n = int(sys.argv[1]); files = sorted(os.listdir("data/big"))
for k in range(n):
    p = "data/big/" + files[k % len(files)]
    sz = os.path.getsize(p); off = random.randrange(0, sz - 4096)
    with open(p, "r+b") as f: f.seek(off); f.write(os.urandom(4096))
PY
for f in data/logs/*.log; do echo "2026-10-26T00:00:00 host app[1]: appended" >> "$f"; done
ls data/small | awk -v n="$NSMALL" 'NR % 100 == 0' | while read -r f; do prand "chg$f" "$SMALL_BYTES" > "data/small/$f"; done
sleep 1.1

S=$(timeit sh -c "\"$BU\" create --key key --passphrase-file pass --base idx --index-out idx-inc -v data > inc.bk 2> inc.log")
echo "  with files cache:    $S s, increment $(stat -c %s inc.bk) bytes  ($(grep -o '[0-9]* files read ([^)]*)' inc.log))"
S=$(timeit sh -c "\"$BU\" create --key key --passphrase-file pass --base idx --index-out idx-inc2 --no-files-cache -v data > inc2.bk 2> inc2.log")
echo "  without files cache: $S s, increment $(stat -c %s inc2.bk) bytes  ($(grep -o '[0-9]* files read ([^)]*)' inc2.log))"
echo "  (changed: ~$CHANGE bytes = 1% of $TOTAL)"

echo "== restore (full + increment)"
S=$(timeit "$BU" restore --key key --passphrase-file pass -C out full-$NPROC.bk inc.bk)
echo "  default -j: $S s, $(mbps "$TOTAL" "$S") MiB/s"
diff -rq data out/data >/dev/null && echo "  restored tree identical" || { echo "  RESTORE MISMATCH"; exit 1; }
rm -rf out
S=$(timeit "$BU" check --key key --passphrase-file pass full-$NPROC.bk inc.bk)
echo "== check: $S s, $(mbps "$TOTAL" "$S") MiB/s"
S=$(timeit sh -c "\"$BU\" merge --key key --passphrase-file pass full-$NPROC.bk inc.bk > merged.bk")
echo "== merge: $S s, $(mbps "$TOTAL" "$S") MiB/s, merged $(stat -c %s merged.bk) bytes"
