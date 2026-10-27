# lib.sh — shared helpers for the integration tests (sourced, not run).
#
# Every test runs the real binary ($BU) in a fresh temp directory under
# $BU_TEST_TMP (default: a mktemp dir in /tmp), cd's into it, and is
# deleted afterwards unless KEEP=1. A test fails by exiting non-zero; `fail`
# says why. Paths stay relative inside the work dir so failure output is short.
set -euo pipefail

: "${BU:?BU must point at the bu binary (scripts/test.sh sets it)}"
WORK="$(mktemp -d "${BU_TEST_TMP:-/tmp}/bu-it.XXXXXX")"
cleanup() { if [ "${KEEP:-0}" = 1 ]; then echo "  (kept $WORK)"; else rm -rf "$WORK"; fi; }
trap cleanup EXIT
cd "$WORK"

fail() { echo "  FAIL: $*" >&2; exit 1; }
note() { echo "  $*"; }

size_of() { stat -c %s "$1"; }

# Deterministic pseudo-random bytes: `prand SEED BYTES > file`. Seeded, so a
# failing run reproduces byte for byte; incompressible, so sizes are honest.
prand() { { openssl enc -aes-128-ctr -pass "pass:$1" -nosalt -pbkdf2 -iter 1 </dev/zero 2>/dev/null || true; } | head -c "$2"; }

# A listing that captures what restore must reproduce: type, mode, size,
# mtime (ns), symlink target, and a content hash per file.
tree_manifest() {
    (cd "$1" && find . -mindepth 1 -printf '%p|%y|%m|%s|%T@|%l\n' | sort \
        | while IFS='|' read -r p t m s mt l; do
            if [ "$t" = f ]; then h=$(sha256sum "$p" | cut -c1-16); else h=-; fi
            if [ "$t" = d ]; then s=0; fi     # directory sizes are filesystem-specific
            echo "$t $m $s $mt $l $p $h"
        done)
}

# Assert restored tree $2 equals source tree $1 in content AND metadata.
assert_same_tree() {
    diff -r "$1" "$2" >/dev/null || fail "content of $2 differs from $1: $(diff -rq "$1" "$2" | head -3)"
    if ! diff <(tree_manifest "$1") <(tree_manifest "$2") >/dev/null; then
        diff <(tree_manifest "$1") <(tree_manifest "$2") | head -6 >&2
        fail "metadata of $2 differs from $1"
    fi
}

assert_between() {   # assert_between VALUE MIN MAX WHAT
    [ "$1" -ge "$2" ] && [ "$1" -le "$3" ] || fail "$4 = $1, expected between $2 and $3"
}

# Expect failure (non-zero) and a message matching a pattern on stderr.
expect_fail() {   # expect_fail PATTERN cmd...
    local pat="$1"; shift
    local out
    if out=$("$@" 2>&1 >/dev/null); then fail "expected failure from: $*"; fi
    echo "$out" | grep -qi -- "$pat" || fail "expected '$pat' in error from '$*', got: $out"
}

# Every test gets a key file with a cheap slot (8 MiB, one pass: a real
# slot costs seconds per unlock) and its passphrase in `pass`, which every
# command reads with --passphrase-file: there is no terminal here.
printf 'integration test passphrase\n' > pass
"$BU" key init --passphrase-file pass --kdf-memory 8 --kdf-time 1 key 2>/dev/null
