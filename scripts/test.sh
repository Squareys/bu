#!/usr/bin/env bash
# Run everything: build, unit tests, integration tests.
#
#   scripts/test.sh [--asan|--tsan] [--smoke] [FILTER]
#
# --asan runs the same suite against the AddressSanitizer + UBSan build (leak
# checking on), --tsan against the ThreadSanitizer build.
# --smoke runs the smoke tests: the unit tests and the quick end-to-end
# scripts in SMOKE below (create, increment, restore, merge, tamper, CLI),
# a few seconds in all. CI's build job runs them; the e2e job runs everything.
# FILTER (a substring) selects integration scripts by name; unit tests always
# run in full (they take well under a second).
set -euo pipefail
cd "$(dirname "$0")/.."
# The smoke subset: no sleeps, no 5 GiB sparse file, no Argon2 or terminal
# key tests.
SMOKE="01-incremental 02-chain-merge 03-tamper 06-cli 11-list-escape"
ASAN=""
FILTER=""
SMOKE_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --asan) ASAN="--asan" ;;
        --tsan) ASAN="--tsan" ;;
        --smoke) SMOKE_ONLY=1 ;;
        -*) echo "test.sh: unknown option '$arg' (expected --asan, --tsan, --smoke or a filter)" >&2; exit 2 ;;
        *) [ -z "$FILTER" ] || { echo "test.sh: one filter only" >&2; exit 2; }; FILTER="$arg" ;;
    esac
done
for s in $SMOKE; do   # a renamed script must not silently drop out of the smoke tests
    [ -f "tests/integration/$s.sh" ] || { echo "test.sh: smoke test '$s' does not exist" >&2; exit 2; }
done
# build.sh prints the build directory last; on failure show the compiler output.
if ! BUILD_LOG="$(scripts/build.sh $ASAN 2>&1)"; then
    printf '%s\n' "$BUILD_LOG" >&2
    echo "test.sh: build failed" >&2
    exit 1
fi
BUILD_DIR="$(printf '%s\n' "$BUILD_LOG" | tail -1)"
export BU="$BUILD_DIR/bu"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"

echo "== unit tests"
"$BUILD_DIR/bu_tests"

pass=0; failed=0; failures=""
for t in tests/integration/[0-9]*.sh; do
    [ -n "$FILTER" ] && [[ "$t" != *"$FILTER"* ]] && continue
    [ "$SMOKE_ONLY" = 1 ] && [[ " $SMOKE " != *" $(basename "$t" .sh) "* ]] && continue
    echo "== $t"
    if bash "$t"; then pass=$((pass + 1)); else failed=$((failed + 1)); failures="$failures $t"; fi
done
echo "integration: $pass passed, $failed failed"
[ "$failed" -eq 0 ] || { echo "failed:$failures"; exit 1; }
