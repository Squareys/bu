#!/usr/bin/env bash
# 17-lock.sh — one writer per chain. A create (or an in-place merge) holds an
# exclusive lock while it appends; a second one fails at once, naming the
# lock, and leaves the chain alone. Readers take no lock and go on reading.
source "$(dirname "$0")/lib.sh"
command -v flock >/dev/null || { note "SKIP: no flock(1)"; exit 0; }

mkdir -p src
prand a 500000 > src/a.bin
"$BU" create "${K[@]}" c.bu src
cp c.bu before.bu
echo b > src/b.txt

# This shell holds the lock, as a running create would.
exec 8< c.bu
flock -x 8
expect_fail "is locked" "$BU" create "${K[@]}" c.bu src
expect_fail "is locked" "$BU" merge "${K[@]}" -o c.bu c.bu
cmp -s c.bu before.bu || fail "a refused create changed the chain"
"$BU" check "${K[@]}" c.bu
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
flock -u 8
exec 8<&-

"$BU" create "${K[@]}" c.bu src
[ "$("$BU" list "${K[@]}" c.bu | grep -c '^# ')" = 2 ] || fail "create after the lock was released"
note ok
