#!/usr/bin/env bash
# 06-cli.sh — bad command lines are refused by name with exit status 2;
# nothing is guessed. (A typo'd --base must never become a full backup.)
source "$(dirname "$0")/lib.sh"

usage() {   # usage PATTERN args...
    local pat="$1"; shift
    local out rc=0
    out=$("$BU" "$@" 2>&1 >/dev/null) || rc=$?
    [ "$rc" = 2 ] || fail "expected exit 2 from 'bu $*', got $rc"
    echo "$out" | grep -q -- "$pat" || fail "expected '$pat' from 'bu $*', got: $out"
}

mkdir src && echo x > src/x
usage "unknown command 'craete'" craete
usage "unknown option '--bsae'" create --key key --bsae idx --index-out i src
usage "given twice" create --key key --key key --index-out i src
usage "needs a value" create --key key --index-out
usage -- "--key KEYFILE is required" restore x.bk
usage -- "--index-out INDEX is required" create --key key src
usage "at least one PATH" create --key key --index-out i
usage "1 to 1024" create --key key --index-out i -j 0 src
usage "1 to 1024" create --key key --index-out i -j 4x src
usage "'..' component" create --key key --index-out i ../x
usage "relative path" restore --key key --path ../x a.bk
usage "takes no arguments" keygen extra
"$BU" help | grep -q "bu create" || fail "help text"

# A key others can read is used, with a warning.
cp key loose && chmod 644 loose
"$BU" create --key loose --index-out i src 2>&1 >/dev/null | grep -q "accessible by other users" \
    || fail "no warning for a world-readable key"
# An index that cannot be written is refused before anything is read.
out=$("$BU" create --key key --index-out /nonexistent-dir/i src 2>&1 >/dev/null) && fail "unwritable index accepted"
echo "$out" | grep -q "cannot write the index" || fail "unwritable index: $out"
# A backup written into the tree it backs up does not contain itself.
"$BU" create --key key --index-out i . > self.bk
"$BU" list --key key self.bk | tail -n +2 | grep -q 'self.bk' && fail "backup contains its own output"
# A terminal on stdout is refused (only testable with script(1)).
if command -v script >/dev/null; then
    out=$(script -qec "$BU create --key key --index-out i src" /dev/null 2>&1 || true)
    echo "$out" | grep -q "refusing to write a backup to a terminal" || fail "tty not refused: $out"
fi
note ok
