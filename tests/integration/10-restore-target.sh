#!/usr/bin/env bash
# 10-restore-target.sh — restore into a target directory someone else has
# prepared. A name planted where a restored file goes is replaced, never
# opened: a hard link to a file outside the tree is not written through, and
# a FIFO does not hang the restore. Set-uid and set-gid bits come back only
# for root; directory modes still restore (set through a descriptor, not by
# name).
source "$(dirname "$0")/lib.sh"

mkdir -p src/sub
prand a 70000 > src/a.bin
echo hello > src/sub/b.txt
echo tool > src/tool && chmod 4755 src/tool
echo grp > src/grp && chmod 2750 src/grp
chmod 750 src/sub
"$BU" create --key key --passphrase-file pass --index-out idx src > full.bk

# A hard link planted at a restored file's name, pointing outside the tree.
echo "outside, must not change" > victim
mkdir -p out/src/sub
ln victim out/src/a.bin
# A FIFO planted at another: an O_TRUNC open would block forever.
mkfifo out/src/sub/b.txt
timeout 30 "$BU" restore --key key --passphrase-file pass -C out full.bk \
    || fail "restore into a prepared target failed (or hung on the FIFO)"
[ "$(cat victim)" = "outside, must not change" ] || fail "restore wrote through a planted hard link"
[ "$(stat -c %h victim)" = 1 ] || fail "planted hard link still shares the victim's inode"
[ -f out/src/sub/b.txt ] && [ ! -p out/src/sub/b.txt ] || fail "planted FIFO not replaced by the file"
cmp -s src/a.bin out/src/a.bin || fail "a.bin content"
cmp -s src/sub/b.txt out/src/sub/b.txt || fail "b.txt content"
[ "$(stat -c %a out/src/sub)" = 750 ] || fail "directory mode $(stat -c %a out/src/sub)"

# Set-uid / set-gid: kept for root, stripped for anyone else (like tar).
if [ "$(id -u)" = 0 ]; then
    [ "$(stat -c %a out/src/tool)" = 4755 ] || fail "root restore lost set-uid: $(stat -c %a out/src/tool)"
    [ "$(stat -c %a out/src/grp)" = 2750 ] || fail "root restore lost set-gid: $(stat -c %a out/src/grp)"
else
    [ "$(stat -c %a out/src/tool)" = 755 ] || fail "set-uid restored for a non-root user: $(stat -c %a out/src/tool)"
    [ "$(stat -c %a out/src/grp)" = 750 ] || fail "set-gid restored for a non-root user: $(stat -c %a out/src/grp)"
fi

# A normal overwrite still works: restoring again over the restored tree.
"$BU" restore --key key --passphrase-file pass -C out full.bk
cmp -s src/a.bin out/src/a.bin || fail "a.bin after a second restore"
# A directory where a file belongs is reported, not removed.
rm out/src/a.bin && mkdir out/src/a.bin
expect_fail "a.bin: File exists" "$BU" restore --key key --passphrase-file pass -C out full.bk
[ -d out/src/a.bin ] || fail "directory in the way was removed"
note ok
