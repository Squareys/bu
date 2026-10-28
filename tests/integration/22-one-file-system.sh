#!/usr/bin/env bash
# 22-one-file-system.sh — create -x / --one-file-system stores a mount point
# below a PATH as an empty directory and does not descend into it; without
# -x the walk crosses into the mount. Needs a mount: a tmpfs in a user and
# mount namespace (unshare -rm) where the kernel allows that, else an
# existing /dev/shm mount below /dev, else the test is skipped.
source "$(dirname "$0")/lib.sh"

# The stored paths, into a file first: grep -q stops reading at its first
# match, and a long listing written into the closed pipe fails with SIGPIPE.
listed() { "$BU" list "$@" | grep -v '^#' | awk '{ print $NF }' > listing; cat listing; }

if unshare -rm true 2>/dev/null; then
    mkdir -p src/mnt
    echo here > src/here.txt
    unshare -rm bash -c '
        set -e
        mount -t tmpfs none src/mnt
        echo inside > src/mnt/inside.txt
        "$BU" create --no-key -x a.bu src
        "$BU" create --no-key --one-file-system b.bu src
        "$BU" create --no-key c.bu src
    '
    for c in a.bu b.bu; do
        paths=$(listed "$c" | sort | tr '\n' ' ')
        [ "$paths" = "src src/here.txt src/mnt " ] || fail "$c with -x: $paths"
    done
    listed c.bu > /dev/null
    grep -qx "src/mnt/inside.txt" listing || fail "without -x the walk did not cross into the mount"
    rm -rf out && "$BU" restore -C out a.bu
    [ -d out/src/mnt ] && [ -z "$(ls -A out/src/mnt)" ] || fail "mount point not restored as an empty directory"
elif mountpoint -q /dev/shm 2>/dev/null && [ "$(stat -c %d /dev)" != "$(stat -c %d /dev/shm)" ] && [ -w /dev/shm ]; then
    note "no user namespaces: using /dev/shm below /dev"
    marker="/dev/shm/bu-it-$$"
    echo x > "$marker"
    trap 'rm -f "$marker"; cleanup' EXIT
    rc=0; "$BU" create --no-key -x a.bu /dev 2>/dev/null || rc=$?
    [ "$rc" = 0 ] || [ "$rc" = 3 ] || fail "create -x /dev failed with $rc"
    listed a.bu > /dev/null
    grep -qx "dev/shm" listing || fail "mount point dev/shm not stored"
    grep -q "^dev/shm/" listing && fail "-x descended into /dev/shm"
    rc=0; "$BU" create --no-key b.bu /dev 2>/dev/null || rc=$?
    listed b.bu > /dev/null
    grep -qx "dev/shm/bu-it-$$" listing || fail "without -x the walk did not cross into /dev/shm"
else
    note "SKIP: no user namespaces and no /dev/shm mount to test against"
    exit 0
fi
note ok
