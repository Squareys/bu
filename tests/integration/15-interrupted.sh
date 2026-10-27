#!/usr/bin/env bash
# 15-interrupted.sh — a create that fails or is interrupted never leaves the
# chain unusable.
#
# A write error (here: the file size limit) and SIGTERM truncate the chain
# back to the byte where the new segment began. SIGKILL cannot be caught: it
# leaves a partial segment, which readers skip (check reports it), and the
# next create cuts off before appending.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand big 60000000 > src/big.bin
"$BU" create "${K[@]}" c.bu src
cp c.bu before.bu
S0=$(size_of c.bu)
prand big2 60000000 > src/big2.bin

# A write error: the file size limit allows a few MB more.
rc=0
( trap '' XFSZ; ulimit -f $(( S0 / 1024 + 4096 )); exec "$BU" create "${K[@]}" c.bu src ) 2> err || rc=$?
[ "$rc" = 1 ] || fail "write error: expected exit 1, got $rc: $(cat err)"
grep -q "unchanged" err || fail "write error not reported: $(cat err)"
cmp -s c.bu before.bu || fail "a failed create left bytes in the chain"

# Kill while it appends: wait until the chain has grown, then send the signal.
interrupt() {   # interrupt SIGNAL
    "$BU" create "${K[@]}" -j 1 c.bu src 2> err &
    local pid=$! i
    for i in $(seq 1 2000); do
        [ "$(size_of c.bu)" -gt $((S0 + 2000000)) ] && break
        sleep 0.005
    done
    kill "-$1" "$pid"
    wait "$pid" || true
}

interrupt TERM
cmp -s c.bu before.bu || fail "SIGTERM left $(( $(size_of c.bu) - S0 )) bytes in the chain"

interrupt KILL
TAIL=$(( $(size_of c.bu) - S0 ))
[ "$TAIL" -gt 0 ] || fail "the test did not catch create mid-append"
note "SIGKILL left $TAIL bytes"
cmp -s <(head -c "$S0" c.bu) before.bu || fail "SIGKILL changed the complete segments"
# Readers use the complete segments and say what they skip.
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu 2> rlog
grep -q "ignoring the last $TAIL bytes" rlog || fail "restore did not report the tail: $(cat rlog)"
cmp out/src/big.bin src/big.bin && [ ! -e out/src/big2.bin ] || fail "restore after SIGKILL"
expect_fail "incomplete backup" "$BU" check "${K[@]}" c.bu
# The next create removes the tail and appends.
"$BU" create "${K[@]}" c.bu src 2> clog
grep -q "removed $TAIL bytes" clog || fail "create did not remove the tail: $(cat clog)"
"$BU" check "${K[@]}" c.bu
rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
assert_same_tree src out/src

# An interrupted FIRST backup: nothing complete; create starts over.
head -c 3000000 c.bu > first.bu
expect_fail "no complete backup" "$BU" check "${K[@]}" first.bu
"$BU" create "${K[@]}" first.bu src 2> flog
grep -q "removed 3000000 bytes" flog || fail "interrupted first backup not removed: $(cat flog)"
"$BU" check "${K[@]}" first.bu
note ok
