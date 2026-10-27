#!/usr/bin/env bash
# Disk-bound benchmark: bu next to the baselines it cannot beat (raw read of
# the source, raw write to the destination, a plain copy), on the same data
# and the same source and destination, with a cold page cache before every run.
#
#   scripts/bench_io.sh --src DIR --dst DIR [--size-mb N] [--runs N]
#                       [--ram-dir DIR] [--bu PATH] [--tsv FILE] [--no-single]
#
# --src      where the data set is generated (a new subdirectory, removed after)
# --dst      where copies, backups and restores are written (same)
# --size-mb  size of the tree, and of the single big file (default 2048)
# --runs     runs per case; the median is reported (default 3)
# --ram-dir  RAM-backed directory for the incompressible input of the raw
#            write test and the big file (default /dev/shm)
# --bu       the bu binary (default: scripts/build.sh Release)
# --tsv      also write every result as tab-separated lines to FILE
# --no-single  skip the single-big-file case
#
# Cold cache without root: `sync`, then posix_fadvise(POSIX_FADV_DONTNEED) on
# every file of the source and destination before each run (`sudo -n` drop_caches
# when that works non-interactively, in addition). This evicts file data; the
# dentry and inode caches stay warm without root. On tmpfs nothing can be
# evicted (the cache is the data), which is the point: tmpfs runs are CPU caps.
#
# Every timed command ends with `sync -f` on the destination, so buffered
# writes are paid for. GB/s is 10^9 bytes per second of logical data (the
# sum of the file sizes), wall time median of --runs.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/.."
SRC_PARENT=""
DST_PARENT=""
SIZE_MB=2048
RUNS=3
RAM_DIR=/dev/shm
BU=""
TSV=""
SINGLE=1
need() { [ $# -ge 2 ] && [ -n "$2" ] || { echo "bench_io.sh: option '$1' needs a value" >&2; exit 2; }; }
while [ $# -gt 0 ]; do
    case "$1" in
        --src) need "$@"; SRC_PARENT="$2"; shift 2 ;;
        --dst) need "$@"; DST_PARENT="$2"; shift 2 ;;
        --size-mb) need "$@"; SIZE_MB="$2"; shift 2 ;;
        --runs) need "$@"; RUNS="$2"; shift 2 ;;
        --ram-dir) need "$@"; RAM_DIR="$2"; shift 2 ;;
        --bu) need "$@"; BU="$2"; shift 2 ;;
        --tsv) need "$@"; TSV="$2"; shift 2 ;;
        --no-single) SINGLE=0; shift ;;
        *) echo "bench_io.sh: unknown argument '$1' (expected --src, --dst, --size-mb, --runs, --ram-dir, --bu, --tsv or --no-single)" >&2; exit 2 ;;
    esac
done
[ -n "$SRC_PARENT" ] || { echo "bench_io.sh: --src is required" >&2; exit 2; }
[ -n "$DST_PARENT" ] || { echo "bench_io.sh: --dst is required" >&2; exit 2; }
[[ "$SIZE_MB" =~ ^[0-9]+$ ]] && [ "$SIZE_MB" -ge 64 ] || { echo "bench_io.sh: --size-mb must be an integer >= 64" >&2; exit 2; }
[[ "$RUNS" =~ ^[0-9]+$ ]] && [ "$RUNS" -ge 1 ] || { echo "bench_io.sh: --runs must be a positive integer" >&2; exit 2; }
for d in "$SRC_PARENT" "$DST_PARENT" "$RAM_DIR"; do [ -d "$d" ] || { echo "bench_io.sh: '$d' is not a directory" >&2; exit 2; }; done
[ -x /usr/bin/time ] || { echo "bench_io.sh: needs /usr/bin/time (GNU time)" >&2; exit 1; }
if [ -z "$BU" ]; then BU="$(scripts/build.sh | tail -1)/bu"; fi
BU="$(realpath "$BU")"

MB=$((1024 * 1024))
SIZE=$((SIZE_MB * MB))
SAME_FS=0
[ "$(stat -c %d "$SRC_PARENT")" = "$(stat -c %d "$DST_PARENT")" ] && SAME_FS=1
free_mb() { df -Pm "$1" | awk 'NR == 2 { print $4 }'; }
# Peak use: source tree + backup (<= size) + restored tree on the destination;
# all on one file system when they share it. 512 MiB margin.
NEED_DST=$((SIZE_MB * 2 + 512)); NEED_SRC=$((SIZE_MB + 512))
[ "$SAME_FS" = 1 ] && NEED_DST=$((SIZE_MB * 3 + 512)) && NEED_SRC=$NEED_DST
[ "$(free_mb "$DST_PARENT")" -ge "$NEED_DST" ] || { echo "bench_io.sh: $DST_PARENT has $(free_mb "$DST_PARENT") MiB free, needs $NEED_DST" >&2; exit 1; }
[ "$(free_mb "$SRC_PARENT")" -ge "$NEED_SRC" ] || { echo "bench_io.sh: $SRC_PARENT has $(free_mb "$SRC_PARENT") MiB free, needs $NEED_SRC" >&2; exit 1; }
[ "$(free_mb "$RAM_DIR")" -ge $((SIZE_MB + 256)) ] || { echo "bench_io.sh: $RAM_DIR has too little room for a $SIZE_MB MiB file" >&2; exit 1; }

SRC="$(mktemp -d "$(realpath "$SRC_PARENT")/bu-io-src.XXXXXX")"
DST="$(mktemp -d "$(realpath "$DST_PARENT")/bu-io-dst.XXXXXX")"
RAM="$(mktemp -d "$(realpath "$RAM_DIR")/bu-io-ram.XXXXXX")"
LOG="$RAM/log"
cleanup() { rm -rf "$SRC" "$DST" "$RAM"; }
trap cleanup EXIT
export SRC DST RAM BU

DROP=0
sudo -n sh -c 'echo 1 > /proc/sys/vm/drop_caches' 2>/dev/null && DROP=1
evict() {
    sync
    [ "$DROP" = 1 ] && sudo -n sh -c 'echo 1 > /proc/sys/vm/drop_caches'
    python3 -I -c '
import os, sys
for top in sys.argv[1:]:
    for root, dirs, files in os.walk(top):
        for f in files:
            try:
                fd = os.open(os.path.join(root, f), os.O_RDONLY | os.O_NOFOLLOW)
            except OSError:
                continue
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            os.close(fd)
' "$SRC" "$DST"
}

# preadall [-t THREADS] PATH...: read every regular file under PATH (sorted
# walk) into a 1 MiB user buffer with read(2), THREADS files at a time. A
# plain reader with queue depth THREADS: no splice or copy_file_range
# shortcuts, which make `cat > /dev/null` free on tmpfs.
cat > "$RAM/preadall.c" <<'C'
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static char **paths; static size_t n, cap, next_i; static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static void add(const char *p) { if (n == cap) { cap = cap ? cap * 2 : 1024; paths = realloc(paths, cap * sizeof *paths); } paths[n++] = strdup(p); }
static void walk(const char *p) {
    struct stat st; if (lstat(p, &st) != 0) return;
    if (S_ISREG(st.st_mode)) { add(p); return; }
    if (!S_ISDIR(st.st_mode)) return;
    struct dirent **ents; int k = scandir(p, &ents, NULL, alphasort); if (k < 0) return;
    for (int i = 0; i < k; ++i) {
        if (strcmp(ents[i]->d_name, ".") && strcmp(ents[i]->d_name, "..")) {
            char *c; if (asprintf(&c, "%s/%s", p, ents[i]->d_name) < 0) exit(1); walk(c); free(c);
        }
        free(ents[i]);
    }
    free(ents);
}
static void *worker(void *arg) {
    (void)arg; char *buf = malloc(1 << 20);
    for (;;) {
        pthread_mutex_lock(&mu); size_t i = next_i++; pthread_mutex_unlock(&mu);
        if (i >= n) break;
        int fd = open(paths[i], O_RDONLY); if (fd < 0) { perror(paths[i]); exit(1); }
        ssize_t r; while ((r = read(fd, buf, 1 << 20)) > 0) {}
        if (r < 0) { perror(paths[i]); exit(1); }
        close(fd);
    }
    free(buf); return NULL;
}
int main(int argc, char **argv) {
    int t = 1, a = 1;
    if (argc > 2 && !strcmp(argv[1], "-t")) { t = atoi(argv[2]); a = 3; }
    for (; a < argc; ++a) walk(argv[a]);
    pthread_t th[64]; if (t < 1 || t > 64) return 2;
    for (int i = 0; i < t; ++i) pthread_create(&th[i], NULL, worker, NULL);
    for (int i = 0; i < t; ++i) pthread_join(th[i], NULL);
    return 0;
}
C
cc -O2 -pthread -o "$RAM/preadall" "$RAM/preadall.c" || { echo "bench_io.sh: cannot compile the read helper (needs cc)" >&2; exit 1; }

# ---- data
prand() { { openssl enc -aes-128-ctr -pass "pass:$1" -nosalt -pbkdf2 -iter 1 </dev/zero 2>/dev/null || true; } | head -c "$2"; }
textgen() { # $1 seed, $2 bytes: syslog-like lines, ~3.4x LZ4-compressible
    awk -v total="$2" -v seed="$1" 'BEGIN { n = 0; i = 0
        while (n < total) { line = sprintf("2026-10-25T%02d:%02d:%02d host app[%d]: request %d done in %d ms status=%d\n",
            int(i/3600)%24, int(i/60)%60, i%60, 4000+(i+seed)%7, (i*7919+seed)%100000, i%997, (i%13==0)?500:200)
            printf "%s", line; n += length(line); i++ } }' | head -c "$2"; }
# The tree: 40% in 4 large random files, 25% text logs (16 files), 25% random
# files of ~100 KiB, 10% text files of 8 KiB (source-tree-like).
BIG=$((SIZE * 4 / 10)); TXT=$((SIZE / 4)); SMALL=$((SIZE / 4)); TINY=$((SIZE - BIG - TXT - SMALL))
mkdir -p "$SRC/data/big" "$SRC/data/logs" "$SRC/data/small" "$SRC/data/tiny"
for i in 1 2 3 4; do prand "big$i" $((BIG / 4)) > "$SRC/data/big/file$i.bin"; done
for i in $(seq -w 1 16); do textgen "$i" $((TXT / 16)) > "$SRC/data/logs/app$i.log"; done
prand small "$SMALL" | split -b 102400 -a 5 - "$SRC/data/small/f"
textgen 99 "$TINY" | split -b 8192 -a 5 - "$SRC/data/tiny/t"
prand rawwrite "$SIZE" > "$RAM/rand.bin"
TOTAL=$(du -sb --apparent-size "$SRC/data" | cut -f1)
NFILES=$(find "$SRC/data" -type f | wc -l)
BIGBYTES=$(du -cb --apparent-size "$SRC"/data/big/*.bin | tail -1 | cut -f1)
# A cheap key slot (8 MiB, one pass): the unlock is not what is measured.
(umask 077; printf 'bench passphrase\n' > "$RAM/pass")
"$BU" key init --passphrase-file "$RAM/pass" --kdf-memory 8 --kdf-time 1 "$RAM/key" 2>/dev/null

fstype() { findmnt -no FSTYPE -T "$1"; }
echo "== bu bench_io: $(nproc) CPUs, $(uname -r)"
echo "   src $SRC ($(fstype "$SRC"), $(findmnt -no SOURCE -T "$SRC"))"
echo "   dst $DST ($(fstype "$DST"), $(findmnt -no SOURCE -T "$DST"))$([ "$SAME_FS" = 1 ] && echo ', SAME file system as src')"
echo "   tree: $TOTAL bytes in $NFILES files; cold cache by $([ "$DROP" = 1 ] && echo 'drop_caches + ')posix_fadvise DONTNEED; $RUNS runs, median"

# ---- timing
declare -A WALL CPU BYTES
ORDER=()
# case NAME BYTES PREP CMD: PREP (shell, untimed) runs before every run, then
# the cache is dropped, then CMD; `sync -f $DST` is inside the timing.
case_() {
    local name="$1" bytes="$2" prep="$3" cmd="$4" r walls=() line t0 t1
    for ((r = 0; r < RUNS; r++)); do
        bash -c "$prep"
        evict
        t0=$EPOCHREALTIME
        if ! /usr/bin/time -f '%e %U %S' -o "$RAM/t" bash -c "set -o pipefail; $cmd; sync -f \"\$DST\"" >"$LOG" 2>&1; then
            echo "bench_io.sh: case '$name' failed:" >&2; cat "$LOG" "$RAM/t" >&2; exit 1
        fi
        t1=$EPOCHREALTIME
        walls+=("$(awk -v a="$t0" -v b="$t1" '{ printf "%.3f %.2f", b - a, $2 + $3 }' "$RAM/t")")
    done
    line="$(printf '%s\n' "${walls[@]}" | sort -n | sed -n "$(((RUNS + 1) / 2))p")"
    WALL[$name]="${line% *}"; CPU[$name]="${line#* }"; BYTES[$name]="$bytes"; ORDER+=("$name")
    printf '   %-28s %7.3f s  %6s GB/s  cpu %6.2f s\n' "$name" "${WALL[$name]}" "$(gbps "$name")" "${CPU[$name]}"
}
gbps() { awk -v b="${BYTES[$1]}" -v s="${WALL[$1]}" 'BEGIN { if (b == 0) printf "-"; else printf "%.2f", b / (s > 0.005 ? s : 0.005) / 1e9 }'; }
pct() { # time of baseline / time of case: bu's speed as % of the baseline's
    [ -n "${WALL[$2]:-}" ] || { printf -- '-'; return; }
    awk -v a="${WALL[$1]}" -v b="${WALL[$2]}" 'BEGIN { printf "%.0f%%", 100 * b / (a > 0.005 ? a : 0.005) }'; }

echo "== baselines"
case_ "read: tar | cat" "$TOTAL" ":" 'cd "$SRC" && tar -cf - data | cat > /dev/null'
case_ "read: 1 stream, big files" "$BIGBYTES" ":" '"$RAM/preadall" "$SRC"/data/big/*.bin'
case_ "read: 1 stream, tree" "$TOTAL" ":" '"$RAM/preadall" "$SRC/data"'
case_ "read: 4 streams, tree" "$TOTAL" ":" '"$RAM/preadall" -t 4 "$SRC/data"'
case_ "read: 8 streams, tree" "$TOTAL" ":" '"$RAM/preadall" -t 8 "$SRC/data"'
if dd if="$SRC/data/big/file1.bin" of=/dev/null bs=4M count=1 iflag=direct status=none 2>/dev/null; then
    case_ "read: O_DIRECT big files" "$BIGBYTES" ":" 'for f in "$SRC"/data/big/*.bin; do dd if="$f" of=/dev/null bs=4M iflag=direct status=none; done'
fi
if dd if="$RAM/rand.bin" of="$DST/w" bs=4M count=1 oflag=direct status=none 2>/dev/null; then
    case_ "write: O_DIRECT" "$SIZE" 'rm -f "$DST/w"' 'dd if="$RAM/rand.bin" of="$DST/w" bs=4M oflag=direct status=none'
fi
case_ "write: buffered + fsync" "$SIZE" 'rm -f "$DST/w"' 'dd if="$RAM/rand.bin" of="$DST/w" bs=4M conv=fsync status=none'
rm -f "$DST/w"
case_ "copy: cp -a" "$TOTAL" 'rm -rf "$DST/cp"' 'cp -a --reflink=never "$SRC/data" "$DST/cp"'
rm -rf "$DST/cp"
case_ "copy: tar to file" "$TOTAL" 'rm -f "$DST/x.tar"' 'cd "$SRC" && tar -cf "$DST/x.tar" data'
case_ "copy: tar extract" "$TOTAL" 'rm -rf "$DST/xout"; mkdir "$DST/xout"' 'tar -xf "$DST/x.tar" -C "$DST/xout"'
rm -rf "$DST/xout" "$DST/x.tar"

echo "== bu"
sleep 1.1   # the tree's ctimes past the files-cache race guard of the full backup
case_ "bu create -j 1" "$TOTAL" 'rm -f "$DST/full.bk" "$DST/idx"' 'cd "$SRC" && "$BU" create --key "$RAM/key" --passphrase-file "$RAM/pass" --index-out "$DST/idx" -j 1 data > "$DST/full.bk"'
case_ "bu create" "$TOTAL" 'rm -f "$DST/full.bk" "$DST/idx"' 'cd "$SRC" && "$BU" create --key "$RAM/key" --passphrase-file "$RAM/pass" --index-out "$DST/idx" data > "$DST/full.bk"'
FULLBYTES=$(stat -c %s "$DST/full.bk")
sleep 1.1   # past the files-cache race guard
case_ "bu increment, unchanged" "0" 'rm -f "$DST/u.bk" "$DST/idx-u"' 'cd "$SRC" && "$BU" create --key "$RAM/key" --passphrase-file "$RAM/pass" --base "$DST/idx" --index-out "$DST/idx-u" data > "$DST/u.bk"'
case_ "bu restore -j 1" "$TOTAL" 'rm -rf "$DST/out"' '"$BU" restore --key "$RAM/key" --passphrase-file "$RAM/pass" -C "$DST/out" -j 1 "$DST/full.bk"'
case_ "bu restore" "$TOTAL" 'rm -rf "$DST/out"' '"$BU" restore --key "$RAM/key" --passphrase-file "$RAM/pass" -C "$DST/out" "$DST/full.bk"'
diff -rq "$SRC/data" "$DST/out/data" >/dev/null || { echo "bench_io.sh: restored tree differs" >&2; exit 1; }
rm -rf "$DST/out"
case_ "read: backup file" "$FULLBYTES" ":" '"$RAM/preadall" "$DST/full.bk"'
case_ "bu check -j 1" "$FULLBYTES" ":" '"$BU" check --key "$RAM/key" --passphrase-file "$RAM/pass" -j 1 "$DST/full.bk"'
case_ "bu check" "$FULLBYTES" ":" '"$BU" check --key "$RAM/key" --passphrase-file "$RAM/pass" "$DST/full.bk"'

# 1% of the files changed: every 100th file of the sorted list (from the
# 51st on, so none of the four big files: 236 files of ~100 KiB and 8 KiB),
# rewritten with new seeded bytes at the same size. The files cache skips the
# other 99% by inode, size and mtime; the changed ones are read in full.
python3 -I - "$SRC/data" <<'PY'
import os, random, sys
top = sys.argv[1]
rnd = random.Random(2)
files = sorted(os.path.join(r, f) for r, _, fs in os.walk(top) for f in fs)
for p in files[50::100]:
    n = os.path.getsize(p)
    with open(p, "wb") as h: h.write(rnd.randbytes(n))
PY
sleep 1.1   # the changed files' ctime past the race guard of the next base
case_ "bu increment, 1% of files" "0" 'rm -f "$DST/f.bk" "$DST/idx-f"' 'cd "$SRC" && "$BU" create --key "$RAM/key" --passphrase-file "$RAM/pass" --base "$DST/idx" --index-out "$DST/idx-f" -v data > "$DST/f.bk" 2> "$RAM/f.log"'
FILES_INFO="$(grep -o '[0-9]* files read ([^)]*)' "$RAM/f.log" || true), increment $(stat -c %s "$DST/f.bk") bytes"
echo "   ($FILES_INFO)"

# 1% scattered change, on top of the previous one (base: its index): 4 KiB
# overwrites in the big files, appended log lines, 1% of the ~100 KiB files
# rewritten. Deterministic (seeded).
python3 -I - "$SRC/data" "$((TOTAL / 100))" <<'PY'
import os, random, sys
top, change = sys.argv[1], int(sys.argv[2])
rnd = random.Random(1)
big = sorted(os.listdir(top + "/big"))
for k in range(change * 4 // 10 // 4096):
    p = top + "/big/" + big[k % len(big)]
    off = rnd.randrange(0, os.path.getsize(p) - 4096)
    with open(p, "r+b") as f: f.seek(off); f.write(rnd.randbytes(4096))
for f in sorted(os.listdir(top + "/logs")):
    with open(top + "/logs/" + f, "a") as h: h.write("2026-10-26T00:00:00 host app[1]: appended\n")
small = sorted(os.listdir(top + "/small"))
for f in small[::100]:
    p = top + "/small/" + f
    n = os.path.getsize(p)
    with open(p, "wb") as h: h.write(rnd.randbytes(n))
PY
sleep 1.1
case_ "bu increment, 1% scattered" "0" 'rm -f "$DST/inc.bk" "$DST/idx-i"' 'cd "$SRC" && "$BU" create --key "$RAM/key" --passphrase-file "$RAM/pass" --base "$DST/idx-f" --index-out "$DST/idx-i" -v data > "$DST/inc.bk" 2> "$RAM/inc.log"'
INC_INFO="$(grep -o '[0-9]* files read ([^)]*)' "$RAM/inc.log" || true), increment $(stat -c %s "$DST/inc.bk") bytes"
echo "   ($INC_INFO)"
rm -rf "$SRC/data" "$DST"/*

if [ "$SINGLE" = 1 ]; then
    echo "== single big file ($SIZE bytes, incompressible)"
    mkdir "$SRC/one"; cp "$RAM/rand.bin" "$SRC/one/big.bin"; sync
    case_ "1f read: 1 stream" "$SIZE" ":" '"$RAM/preadall" "$SRC/one/big.bin"'
    if dd if="$SRC/one/big.bin" of=/dev/null bs=4M count=1 iflag=direct status=none 2>/dev/null; then
        case_ "1f read: O_DIRECT" "$SIZE" ":" 'dd if="$SRC/one/big.bin" of=/dev/null bs=4M iflag=direct status=none'
    fi
    case_ "1f copy: cp" "$SIZE" 'rm -f "$DST/big.bin"' 'cp --reflink=never "$SRC/one/big.bin" "$DST/big.bin"'
    rm -f "$DST/big.bin"
    case_ "1f bu create -j 1" "$SIZE" 'rm -f "$DST/one.bk" "$DST/idx1"' 'cd "$SRC" && "$BU" create --key "$RAM/key" --passphrase-file "$RAM/pass" --index-out "$DST/idx1" -j 1 one > "$DST/one.bk"'
    case_ "1f bu create" "$SIZE" 'rm -f "$DST/one.bk" "$DST/idx1"' 'cd "$SRC" && "$BU" create --key "$RAM/key" --passphrase-file "$RAM/pass" --index-out "$DST/idx1" one > "$DST/one.bk"'
    case_ "1f bu restore" "$SIZE" 'rm -rf "$DST/out"' '"$BU" restore --key "$RAM/key" --passphrase-file "$RAM/pass" -C "$DST/out" "$DST/one.bk"'
    cmp -s "$SRC/one/big.bin" "$DST/out/one/big.bin" || { echo "bench_io.sh: restored file differs" >&2; exit 1; }
    rm -rf "$SRC/one" "$DST"/*
fi

# ---- table
# Each bu row against the baselines it is bounded by; pct = baseline time /
# bu time (100% = as fast as the baseline).
declare -A VS=(
    ["bu create -j 1"]="copy: tar to file|read: 8 streams, tree"
    ["bu create"]="copy: tar to file|read: 8 streams, tree"
    ["bu restore -j 1"]="copy: tar extract|copy: cp -a"
    ["bu restore"]="copy: tar extract|copy: cp -a"
    ["bu check -j 1"]="read: backup file|"
    ["bu check"]="read: backup file|"
    ["1f bu create -j 1"]="1f copy: cp|1f read: O_DIRECT"
    ["1f bu create"]="1f copy: cp|1f read: O_DIRECT"
    ["1f bu restore"]="1f copy: cp|"
)
echo
echo "== results (median of $RUNS; vs = baseline time / bu time)"
printf '| %-26s | %8s | %7s | %8s | %8s | %-30s |\n' case "wall s" "GB/s" "cpu u+s" "cpu/wall" "vs baselines"
printf '|%s|%s|%s|%s|%s|%s|\n' "$(printf -- '-%.0s' {1..28})" ---------- --------- ---------- ---------- "$(printf -- '-%.0s' {1..32})"
for n in "${ORDER[@]}"; do
    vs=""
    if [ -n "${VS[$n]:-}" ]; then
        a="${VS[$n]%%|*}"; b="${VS[$n]#*|}"
        vs="$(pct "$n" "$a") of $a"
        [ -n "$b" ] && vs="$vs, $(pct "$n" "$b") of $b"
    fi
    ratio="$(awk -v c="${CPU[$n]}" -v w="${WALL[$n]}" 'BEGIN { printf "%.2f", c / (w > 0.005 ? w : 0.005) }')"
    printf '| %-26s | %8.3f | %7s | %8.2f | %8s | %s |\n' "$n" "${WALL[$n]}" "$(gbps "$n")" "${CPU[$n]}" "$ratio" "$vs"
    [ -n "$TSV" ] && printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "${BYTES[$n]}" "${WALL[$n]}" "$(gbps "$n")" "${CPU[$n]}" "$ratio" "$vs" >> "$TSV"
done
echo "   tree $TOTAL bytes / $NFILES files; full backup $FULLBYTES bytes"
echo "   1% of files: $FILES_INFO; 1% scattered: $INC_INFO"

# Every tree row as a multiple of the time it takes to read every file once
# with the fastest plain reader: a backup cannot take less.
REF="read: 8 streams, tree"
echo
echo "== time relative to reading every file once ($REF, ${WALL[$REF]} s)"
for n in "read: tar | cat" "copy: cp -a" "copy: tar to file" "copy: tar extract" "bu create" "bu create -j 1" \
         "bu increment, unchanged" "bu increment, 1% of files" "bu increment, 1% scattered" \
         "bu restore" "bu restore -j 1" "bu check" "bu check -j 1"; do
    [ -n "${WALL[$n]:-}" ] || continue
    printf '   %-28s %7.3f s  %5.2fx\n' "$n" "${WALL[$n]}" "$(awk -v a="${WALL[$n]}" -v b="${WALL[$REF]}" 'BEGIN { printf "%.2f", a / b }')"
    [ -n "$TSV" ] && printf 'rel\t%s\t%s\t%s\n' "$n" "${WALL[$n]}" "$(awk -v a="${WALL[$n]}" -v b="${WALL[$REF]}" 'BEGIN { printf "%.2f", a / b }')" >> "$TSV"
done
