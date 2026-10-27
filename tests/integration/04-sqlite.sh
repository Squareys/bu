#!/usr/bin/env bash
# 04-sqlite.sh — SQLite databases are chunked at page boundaries, so an
# increment after scattered UPDATEs is about (changed pages x page size).
#
# The test counts the pages that actually differ between the two database
# files and reports increment / (changed pages x page size). Close to 1 means
# near-minimal; below 1 is LZ4 compressing the changed pages. Skipped without
# the sqlite3 CLI.
source "$(dirname "$0")/lib.sh"
command -v sqlite3 >/dev/null || { note "SKIP: sqlite3 not installed"; exit 0; }

mkdir -p src
sqlite3 src/app.db >/dev/null <<'SQL'
PRAGMA page_size = 4096;
PRAGMA journal_mode = DELETE;
CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL);
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 200000)
INSERT INTO t SELECT i, lower(hex(randomblob(60))) FROM n;
SQL
cp src/app.db before.db
DB=$(size_of src/app.db)
note "database: $DB bytes, $(sqlite3 src/app.db 'PRAGMA page_count') pages of 4096"

"$BU" create "${K[@]}" c.bu src
FULL=$(size_of c.bu)
note "full: $FULL bytes"

# ~2% of rows, scattered, rewritten in place: same length, so no page splits;
# upper() makes the new text as (in)compressible as the old.
sqlite3 src/app.db "UPDATE t SET v = upper(v) WHERE id IN (SELECT id FROM t ORDER BY random() LIMIT 4000);"
[ "$(size_of src/app.db)" = "$DB" ] || fail "database grew; the test assumes in-place updates"

"$BU" create "${K[@]}" c.bu src
INC=$(( $(size_of c.bu) - FULL ))
# cmp exits 1 because the files differ: expected, not a failure (pipefail).
CHANGED=$({ cmp -l before.db src/app.db || true; } | awk '{ p[int(($1 - 1) / 4096)] = 1 } END { print length(p) }')
IDEAL=$((CHANGED * 4096))
RATIO=$(awk -v a="$INC" -v b="$IDEAL" 'BEGIN { printf "%.3f", a / b }')
note "changed pages: $CHANGED ($IDEAL bytes); increment: $INC bytes; ratio $RATIO"
# Per changed page: one record (~45 B overhead), a table entry (~22 B) and a
# manifest NEW op (~19 B) — and LZ4 takes back more than that from hex text.
awk -v r="$RATIO" 'BEGIN { exit !(r > 0.3 && r < 1.10) }' || fail "increment/changed-pages ratio $RATIO out of range"

rm -rf out && "$BU" restore "${K[@]}" -C out c.bu
cmp out/src/app.db src/app.db || fail "restored database differs"
[ "$(sqlite3 out/src/app.db 'PRAGMA integrity_check')" = ok ] || fail "restored database fails integrity_check"
"$BU" merge "${K[@]}" -o merged.bu c.bu
rm -rf out && "$BU" restore "${K[@]}" -C out merged.bu
cmp out/src/app.db src/app.db || fail "database restored from the merge differs"
note ok
