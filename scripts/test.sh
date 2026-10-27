#!/usr/bin/env bash
# Run everything: build, unit tests, integration tests.
#
#   scripts/test.sh [--asan|--tsan] [FILTER]
#
# --asan runs the same suite against the AddressSanitizer + UBSan build (leak
# checking on), --tsan against the ThreadSanitizer build.
# FILTER (a substring) selects integration scripts by name; unit tests always
# run in full (they take well under a second).
set -euo pipefail
cd "$(dirname "$0")/.."
ASAN=""
FILTER=""
for arg in "$@"; do
    case "$arg" in
        --asan) ASAN="--asan" ;;
        --tsan) ASAN="--tsan" ;;
        -*) echo "test.sh: unknown option '$arg' (expected --asan, --tsan or a filter)" >&2; exit 2 ;;
        *) [ -z "$FILTER" ] || { echo "test.sh: one filter only" >&2; exit 2; }; FILTER="$arg" ;;
    esac
done
BUILD_DIR="$(scripts/build.sh $ASAN | tail -1)"
export BU="$BUILD_DIR/bu"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:abort_on_error=1}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1:second_deadlock_stack=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"

echo "== unit tests"
"$BUILD_DIR/bu_tests"

pass=0; failed=0; failures=""
for t in tests/integration/[0-9]*.sh; do
    [ -n "$FILTER" ] && [[ "$t" != *"$FILTER"* ]] && continue
    echo "== $t"
    if bash "$t"; then pass=$((pass + 1)); else failed=$((failed + 1)); failures="$failures $t"; fi
done
echo "integration: $pass passed, $failed failed"
[ "$failed" -eq 0 ] || { echo "failed:$failures"; exit 1; }
