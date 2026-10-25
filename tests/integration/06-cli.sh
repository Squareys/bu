#!/usr/bin/env bash
# 06-cli.sh — bad command lines are refused by name with exit status 2;
# nothing is guessed. (A typo'd --base must never become a full backup.)
source "$(dirname "$0")/lib.sh"

usage() {   # usage PATTERN args...
    local pat="$1"; shift
    local out rc=0
    out=$("$BACKU" "$@" 2>&1 >/dev/null) || rc=$?
    [ "$rc" = 2 ] || fail "expected exit 2 from 'backu $*', got $rc"
    echo "$out" | grep -q -- "$pat" || fail "expected '$pat' from 'backu $*', got: $out"
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
"$BACKU" help | grep -q "backu create" || fail "help text"
# A terminal on stdout is refused (only testable with script(1)).
if command -v script >/dev/null; then
    out=$(script -qec "$BACKU create --key key --index-out i src" /dev/null 2>&1 || true)
    echo "$out" | grep -q "refusing to write a backup to a terminal" || fail "tty not refused: $out"
fi
note ok
