#!/usr/bin/env bash
# 07-unreadable.sh — a file create cannot read is left out with a warning and
# exit status 1, and everything else is still backed up and restorable (the
# segment is complete and the chain valid). Skipped as root, who can read anything.
source "$(dirname "$0")/lib.sh"
[ "$(id -u)" != 0 ] || { note "SKIP: running as root"; exit 0; }

mkdir -p src
prand ok 300000 > src/ok.bin
prand secret 300000 > src/secret.bin
chmod 000 src/secret.bin
rc=0
"$BU" create "${K[@]}" c.bu src 2> err || rc=$?
[ "$rc" = 1 ] || fail "expected exit 1 for a partial backup, got $rc"
grep -q "secret.bin" err || fail "no warning naming the unreadable file: $(cat err)"
"$BU" check "${K[@]}" c.bu
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
cmp out/src/ok.bin src/ok.bin || fail "readable file not restored"
[ ! -e out/src/secret.bin ] || fail "unreadable file restored from nothing"
# The next increment, once readable, picks it up.
chmod 600 src/secret.bin
"$BU" create "${K[@]}" c.bu src
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
cmp out/src/secret.bin src/secret.bin || fail "file not picked up once readable"
note ok
