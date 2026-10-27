#!/usr/bin/env bash
# 19-recover-cap.sh — finding the end of an unencrypted chain past a partial
# tail stays linear. Unencrypted, trailer magic inside the tail is skipped
# when no walk from it reaches offset 0; every such walk can cross many
# segments, so recovery gives up after 64 failed walks and calls the chain
# damaged instead of going quadratic.
#
# The tail here is junk followed by whole copies of a segment: the walk from
# each copy's trailer goes back through every copy before it and breaks on
# the junk.
source "$(dirname "$0")/lib.sh"

mkdir -p src
prand a 2000 > src/a.bin
"$BU" create --no-key c.bu src
S0=$(size_of c.bu)

tailed() {   # tailed COPIES > file
    cat c.bu
    prand junk 1000
    for _ in $(seq "$1"); do cat c.bu; done
    prand end 100
}

# A few candidates that do not walk: skipped, the real end is found.
tailed 10 > few.bu
TAIL=$(( $(size_of few.bu) - S0 ))
rm -rf out && "$BU" restore --no-key -C out few.bu 2> rlog
grep -q "ignoring the last $TAIL bytes" rlog || fail "restore did not find the real end: $(cat rlog)"
assert_same_tree src out/src

# Many: damaged, and quickly.
tailed 200 > many.bu
expect_fail "do not walk back to the start (damaged)" "$BU" check --no-key many.bu
expect_fail "do not walk back to the start (damaged)" "$BU" restore --no-key -C out2 many.bu
note ok
