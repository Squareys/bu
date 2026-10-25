#!/usr/bin/env bash
# Run everything: build, unit tests, integration tests.
#
#   scripts/test.sh [--asan] [FILTER]
#
# --asan runs the same suite against the AddressSanitizer + UBSan build.
# FILTER (a substring) selects integration scripts by name; unit tests always
# run in full (they take well under a second).
set -euo pipefail
cd "$(dirname "$0")/.."
ASAN=""
FILTER=""
for arg in "$@"; do
    case "$arg" in
        --asan) ASAN="--asan" ;;
        -*) echo "test.sh: unknown option '$arg' (expected --asan or a filter)" >&2; exit 2 ;;
        *) [ -z "$FILTER" ] || { echo "test.sh: one filter only" >&2; exit 2; }; FILTER="$arg" ;;
    esac
done
BUILD_DIR="$(scripts/build.sh $ASAN | tail -1)"
export BACKU="$BUILD_DIR/backu"
# Leak checking would flag the deliberate exit-without-free of one-shot commands.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"

echo "== unit tests"
"$BUILD_DIR/backu_tests"

pass=0; failed=0; failures=""
for t in tests/integration/[0-9]*.sh; do
    [ -n "$FILTER" ] && [[ "$t" != *"$FILTER"* ]] && continue
    echo "== $t"
    if bash "$t"; then pass=$((pass + 1)); else failed=$((failed + 1)); failures="$failures $t"; fi
done
echo "integration: $pass passed, $failed failed"
[ "$failed" -eq 0 ] || { echo "failed:$failures"; exit 1; }
