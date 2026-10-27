#!/usr/bin/env bash
# 06-cli.sh — bad command lines are refused by name with exit status 2;
# nothing is guessed. (A typo'd option must never become a full backup.)
source "$(dirname "$0")/lib.sh"

usage() {   # usage PATTERN args...
    local pat="$1"; shift
    local out rc=0
    out=$("$BU" "$@" 2>&1 >/dev/null) || rc=$?
    [ "$rc" = 2 ] || fail "expected exit 2 from 'bu $*', got $rc"
    echo "$out" | grep -q -- "$pat" || fail "expected '$pat' from 'bu $*', got: $out"
}

mkdir src && echo x > src/x
"$BU" create "${K[@]}" c.bu src
"$BU" create --no-key p.bu src
usage "unknown command 'craete'" craete
usage "unknown option '--bsae'" create "${K[@]}" --bsae idx c.bu src
usage "given twice" create --key key --key key c.bu src
usage "needs a value" create "${K[@]}" c.bu src --index-out
usage -- "--key KEYFILE (encrypted) or --no-key" create c.bu src
usage "not both" create --key key --no-key c.bu src
usage "go with --key" create --no-key --passphrase-file pass c.bu src
usage "at least one PATH" create "${K[@]}" c.bu
usage "1 to 1024" create "${K[@]}" -j 0 c.bu src
usage "1 to 1024" create "${K[@]}" -j 4x c.bu src
usage "'..' component" create "${K[@]}" c.bu ../x
usage "relative path" restore "${K[@]}" -C out c.bu -- ../x
usage "name the CHAIN" restore "${K[@]}" -C out -- src
usage -- "--key KEYFILE is required" restore -C out c.bu
usage -- "--key KEYFILE is required" check c.bu
usage "not encrypted" check "${K[@]}" p.bu
usage "is encrypted" check --no-key c.bu
usage "not encrypted" create "${K[@]}" p.bu src
usage "is encrypted" create --no-key c.bu src
usage -- "--index is for a chain read from a pipe" restore "${K[@]}" --index idx -C out c.bu
usage "unknown subcommand 'frob'" key frob
usage "name exactly one KEYFILE" key init
usage "name exactly one KEYFILE" key info a b
usage "8 to 4096" key init --kdf-memory 4 k2
usage "1 to 100" key init --kdf-time 0 k2
usage "not both" key init --kdf-time 2 --kdf-target-ms 500 k2
usage "not both" list --key key --passphrase-file pass --passphrase-fd 0 c.bu
usage "0 to 7" key remove --slot 8 key
usage "unknown option '--slot'" key add --slot 1 key
"$BU" help | grep -q "bu create" || fail "help text"

# A key others can read is used, with a warning.
cp key loose && chmod 644 loose
"$BU" create --key loose --passphrase-file pass c.bu src 2>&1 >/dev/null | grep -q "accessible by other users" \
    || fail "no warning for a world-readable key"
# An index that cannot be written is refused before anything is read.
out=$("$BU" create "${K[@]}" --index-out /nonexistent-dir/i c.bu src 2>&1 >/dev/null) && fail "unwritable index accepted"
echo "$out" | grep -q "cannot write the index" || fail "unwritable index: $out"
# A chain written into the tree it backs up does not contain itself.
"$BU" create "${K[@]}" self.bu .
"$BU" list "${K[@]}" self.bu | grep -v '^#' | grep -q 'self.bu' && fail "backup contains its own chain"
# A directory or a FIFO is not a chain to append to.
expect_fail "is a directory" "$BU" create "${K[@]}" src src
# A terminal on stdout is refused (only testable with script(1)).
if command -v script >/dev/null; then
    out=$(script -qec "$BU create --key key --passphrase-file pass - src" /dev/null 2>&1 || true)
    echo "$out" | grep -q "refusing to write a backup to a terminal" || fail "tty not refused: $out"
fi
note ok
