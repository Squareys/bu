#!/usr/bin/env bash
# 08-large-sparse.sh — a file larger than 4 GiB (sizes and offsets are 64-bit
# everywhere), mostly holes: zeros dedupe to one stored chunk, and restore
# writes them back as holes, so neither the backup nor the restore costs 5 GB.
source "$(dirname "$0")/lib.sh"

mkdir -p src
truncate -s 5G src/big.img
printf 'start' | dd of=src/big.img bs=1 seek=0 conv=notrunc status=none
printf 'past4G' | dd of=src/big.img bs=1 seek=$((4 * 1024 * 1024 * 1024 + 12345)) conv=notrunc status=none
printf 'end' | dd of=src/big.img bs=1 seek=$((5 * 1024 * 1024 * 1024 - 3)) conv=notrunc status=none

"$BACKU" create --key key --index-out idx src > b.bk
B=$(size_of b.bk)
note "5 GiB sparse file -> $B byte backup"
assert_between "$B" 1000 4000000 "backup of a sparse 5 GiB file"
rm -rf out && "$BACKU" restore --key key -C out b.bk
[ "$(size_of out/src/big.img)" = $((5 * 1024 * 1024 * 1024)) ] || fail "restored size"
cmp out/src/big.img src/big.img || fail "restored content differs"
USED=$(du -k out/src/big.img | cut -f1)
[ "$USED" -lt 10240 ] || fail "restored file is not sparse (${USED} KiB allocated)"
note ok
