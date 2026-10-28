#!/usr/bin/env bash
# 21-exclude.sh — create --exclude PATTERN, repeatable: a pattern without a
# / matches the last name at any depth, one with a / the whole stored path;
# an excluded directory is not descended into (an unreadable one inside it
# gives no warning); an excluded root is left out; empty patterns are refused.
source "$(dirname "$0")/lib.sh"

mkdir -p src/cache/deep src/a/cache src/keep src/logs/2026
prand k 30000 > src/keep/k.bin
prand c 30000 > src/cache/deep/c.bin
prand c2 30000 > src/a/cache/c.bin
echo t > src/keep/x.tmp
echo l > src/logs/2026/a.log
echo l > src/logs/top.log
echo l > src/keep/b.log
mkdir src/cache/locked && chmod 000 src/cache/locked
trap 'chmod 700 src/cache/locked 2>/dev/null || true; cleanup' EXIT

"$BU" create "${K[@]}" --exclude cache --exclude '*.tmp' --exclude 'src/logs/*' c.bu src
paths=$("$BU" list "${K[@]}" c.bu | grep -v '^#' | awk '{ print $NF }' | sort | tr '\n' ' ')
want="src src/a src/keep src/keep/b.log src/keep/k.bin src/logs "
[ "$paths" = "$want" ] || fail "excluded set wrong: got '$paths', want '$want'"

# A leading / anchors at the top of the stored tree, like a stored path.
"$BU" create "${K[@]}" -C src --exclude /cache c2.bu .
paths=$("$BU" list "${K[@]}" c2.bu | grep -v '^#' | awk '{ print $NF }' | sort | tr '\n' ' ')
case "$paths" in *"a/cache/c.bin"*) ;; *) fail "/cache excluded a nested cache: $paths" ;; esac
case "$paths" in *" cache "*|cache\ *) fail "/cache did not exclude the top-level cache: $paths" ;; esac

# An excluded PATH is left out; the rest of the command line is backed up.
"$BU" create "${K[@]}" --exclude keep c3.bu src/keep src/a
paths=$("$BU" list "${K[@]}" c3.bu | grep -v '^#' | awk '{ print $NF }' | sort | tr '\n' ' ')
[ "$paths" = "src/a src/a/cache src/a/cache/c.bin " ] || fail "excluded root: $paths"

# Restore round trip of what was kept.
"$BU" restore "${K[@]}" -C out c.bu
cmp out/src/keep/k.bin src/keep/k.bin || fail "kept file differs"

# Patterns that name nothing are refused by name.
rc=0; "$BU" create "${K[@]}" --exclude / x.bu src 2> err || rc=$?
[ "$rc" = 2 ] && grep -q -- "--exclude" err || fail "--exclude / not refused as a usage error (rc $rc): $(cat err)"
[ ! -e x.bu ] || fail "chain created for a refused command line"
note ok
