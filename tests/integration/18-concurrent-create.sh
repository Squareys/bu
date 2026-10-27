#!/usr/bin/env bash
# 18-concurrent-create.sh — a create appending an increment keeps the chain's
# lock until it is done. It reads the chain it appends to through the very
# descriptor that holds the lock; probing that descriptor for a writer (a
# shared lock, then an unlock) once downgraded and released create's own
# lock, so a second create could append in the middle of the first.
#
# The first create is held at a known point without timing guesses: its
# passphrase comes from a FIFO (--passphrase-fd), and create reads it only
# after it has locked the chain and read the chain's first header. The
# second create runs while the first waits there; then the first gets its
# passphrase and finishes.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand a 300000 > src/a.bin
"$BU" create "${K[@]}" c.bu src
echo b > src/b.txt

mkfifo pp
# Bash opens the FIFO for reading before exec, which blocks until we open it
# for writing below; $! is bu's own pid.
"$BU" create --key key --passphrase-fd 9 c.bu src 9<pp &
first=$!
exec 7>pp

# Wait until the first create sleeps with the chain open: that is its read of
# the passphrase, past locking and opening the chain (a create still in
# exec, or one that has not yet opened the chain, does not match).
ready=0
for _ in $(seq 400); do
    if [ -r "/proc/$first/stat" ] && ls -l "/proc/$first/fd" 2>/dev/null | grep -q '/c\.bu$' \
        && [ "$(sed 's/^.*) //' "/proc/$first/stat" | cut -d' ' -f1)" = S ]; then
        ready=1
        break
    fi
    sleep 0.025
done
[ "$ready" = 1 ] || { exec 7>&-; wait "$first" || true; fail "the first create never reached its passphrase read"; }

if command -v flock >/dev/null; then
    if flock -x -n c.bu -c true; then
        exec 7>&-; wait "$first" || true
        fail "the chain is not locked while a create appends to it"
    fi
else
    note "no flock(1): skipping the lock check from the shell"
fi

before=$(size_of c.bu)
set +e
out=$("$BU" create "${K[@]}" c.bu src 2>&1 >/dev/null)
rc=$?
set -e
[ "$rc" = 1 ] || { exec 7>&-; wait "$first" || true; fail "second create exited $rc, expected 1: $out"; }
echo "$out" | grep -q "is locked" || { exec 7>&-; wait "$first" || true; fail "second create: expected 'is locked', got: $out"; }
[ "$(size_of c.bu)" = "$before" ] || fail "a refused create changed the chain"

cat pass >&7
exec 7>&-
wait "$first" || fail "the first create failed"

"$BU" check "${K[@]}" c.bu
[ "$("$BU" list "${K[@]}" c.bu | grep -c '^# ')" = 2 ] || fail "expected 2 snapshots in the chain"
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
assert_same_tree src out/src
note ok
