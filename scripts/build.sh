#!/usr/bin/env bash
# Build backu out of tree.
#
#   scripts/build.sh [Debug|Release] [--asan|--tsan] [--print-build-dir]
#
# The build directory is keyed on the source path, so two worktrees never
# share objects, and on the configuration, so an ASan build never hands its
# objects to a release build or the other way round (ninja would see them as
# up to date). Unknown arguments are refused by name, never guessed at.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_TYPE="Release"
SANITIZE=OFF
TSAN=OFF
PRINT=0
for arg in "$@"; do
    case "$arg" in
        Debug|Release) BUILD_TYPE="$arg" ;;
        --asan) SANITIZE=ON ;;
        --tsan) TSAN=ON ;;
        --print-build-dir) PRINT=1 ;;
        *) echo "build.sh: unknown argument '$arg' (expected Debug, Release, --asan, --tsan or --print-build-dir)" >&2; exit 2 ;;
    esac
done

KEY="$(printf %s "$SRC_DIR" | md5sum | cut -c1-8)"
SUFFIX=""
[ "$SANITIZE" = ON ] && SUFFIX="-asan"
[ "$TSAN" = ON ] && SUFFIX="-tsan"
if [ "$SANITIZE" = ON ] && [ "$TSAN" = ON ]; then echo "build.sh: --asan and --tsan are separate builds" >&2; exit 2; fi
BUILD_DIR="${BACKU_BUILD_ROOT:-$HOME/.cache}/backu-build-${BUILD_TYPE}-${KEY}${SUFFIX}"

if [ "$PRINT" = 1 ]; then echo "$BUILD_DIR"; exit 0; fi

cmake -S "$SRC_DIR" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DBK_SANITIZE="$SANITIZE" -DBK_TSAN="$TSAN" >/dev/null
cmake --build "$BUILD_DIR"
echo "$BUILD_DIR"
