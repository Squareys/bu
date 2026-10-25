#!/usr/bin/env bash
# 07-unreadable.sh — a file create cannot read is left out with a warning and
# exit status 1, and everything else is still backed up and restorable (the
# backup and the index are valid). Skipped as root, who can read anything.
source "$(dirname "$0")/lib.sh"
[ "$(id -u)" != 0 ] || { note "SKIP: running as root"; exit 0; }

mkdir -p src
prand ok 300000 > src/ok.bin
prand secret 300000 > src/secret.bin
chmod 000 src/secret.bin
rc=0
"$BACKU" create --key key --index-out idx src > b.bk 2> err || rc=$?
[ "$rc" = 1 ] || fail "expected exit 1 for a partial backup, got $rc"
grep -q "secret.bin" err || fail "no warning naming the unreadable file: $(cat err)"
"$BACKU" check --key key b.bk
rm -rf out && "$BACKU" restore --key key -C out b.bk
cmp out/src/ok.bin src/ok.bin || fail "readable file not restored"
[ ! -e out/src/secret.bin ] || fail "unreadable file restored from nothing"
# The next increment, once readable, picks it up.
chmod 600 src/secret.bin
"$BACKU" create --key key --base idx --index-out idx src > inc.bk
rm -rf out && "$BACKU" restore --key key -C out b.bk inc.bk
cmp out/src/secret.bin src/secret.bin || fail "file not picked up once readable"
note ok
