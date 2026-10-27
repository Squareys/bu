#!/usr/bin/env bash
# 09-key.sh — the key file's lifecycle, driven as unattended runs would
# (--passphrase-file / --passphrase-fd, no terminal): init, add, passwd,
# remove and info; a wrong passphrase reported as one and damage as damage;
# key and passphrase files others can read warned about; a symlinked or
# hard-linked key path refused by the commands that rewrite the file;
# the last slot never removable; an existing file never overwritten; the old
# bu-key-1 plaintext format refused by name; and backups that keep opening
# through every passphrase change, because the master key never changes.
source "$(dirname "$0")/lib.sh"
umask 077    # passphrase files here are private unless a test says otherwise

CHEAP=(--kdf-memory 8 --kdf-time 1)
mkdir src && prand k 300000 > src/a.bin && echo hello > src/b.txt
"$BU" create "${K[@]}" full.bu src

# The file: 944 bytes, mode 0600, and it never contains the passphrase.
[ "$(size_of key)" = 944 ] || fail "key file is $(size_of key) bytes"
[ "$(stat -c %a key)" = 600 ] || fail "key file mode $(stat -c %a key)"
grep -q "integration test passphrase" key && fail "passphrase stored in the key file"
"$BU" key info key > info || fail "key info"
grep -q "^slot 0: passphrase, argon2id, 8 MiB, 1 pass (weak)$" info || fail "info slot 0: $(cat info)"
[ "$(grep -c ': empty$' info)" = 7 ] || fail "info: expected 7 empty slots"

# Never overwritten, and refused before any passphrase is asked for.
expect_fail "already exists" "$BU" key init --passphrase-file pass "${CHEAP[@]}" key

# A wrong passphrase is reported as one (file and fd sources alike).
printf 'not it\n' > wrong
expect_fail "wrong passphrase" "$BU" check --key key --passphrase-file wrong full.bu
expect_fail "wrong passphrase" "$BU" check --key key --passphrase-fd 3 full.bu 3< wrong
# The fd source: up to the first newline; the line ending is not part of it.
"$BU" check --key key --passphrase-fd 3 full.bu 3< pass
printf 'integration test passphrase' | "$BU" check --key key --passphrase-fd 0 full.bu
printf 'integration test passphrase\r\n' > pass-crlf
"$BU" check --key key --passphrase-file pass-crlf full.bu
: > empty
expect_fail "empty passphrase" "$BU" check --key key --passphrase-file empty full.bu
# No terminal and no passphrase source: a clear error, never a read of stdin.
if command -v setsid >/dev/null; then
    out=$(setsid -w "$BU" check --key key full.bu < pass 2>&1) && fail "unlocked without a passphrase source"
    echo "$out" | grep -q "no terminal to ask for the passphrase" || fail "no-tty error: $out"
fi

# Weak KDF parameters are warned about when a slot is written.
out=$("$BU" key init --passphrase-file pass "${CHEAP[@]}" weak.key 2>&1) || fail "key init: $out"
echo "$out" | grep -q "slot 0 is below 64 MiB / 3 passes" || fail "no weak-KDF warning: $out"

# Files others can read are warned about: the key file (by every command
# that reads it, key info included) and a passphrase file (its second factor
# in plaintext). Modes 600 give no warning.
out=$("$BU" check --key key --passphrase-file pass full.bu 2>&1) || fail "check: $out"
echo "$out" | grep -q "warning" && fail "warning for private files: $out"
cp pass pass-shared && chmod 644 pass-shared
out=$("$BU" check --key key --passphrase-file pass-shared full.bu 2>&1) || fail "check: $out"
echo "$out" | grep -q "warning: passphrase file pass-shared is accessible by other users" \
    || fail "no passphrase-file warning: $out"
cp key key-shared && chmod 640 key-shared
out=$("$BU" key info key-shared 2>&1) || fail "key info: $out"
echo "$out" | grep -q "warning: key file key-shared is accessible by other users" || fail "no key info warning: $out"

# A key path that is a symlink or has a second hard link is refused by the
# commands that rewrite it, before any passphrase is read: the rename would
# replace the link (or one name) and leave the real file with the old slots,
# so a "removed" passphrase would still open the key.
cp key real.key && ln -s real.key link.key
cp real.key real-before
expect_fail "is a symbolic link" "$BU" key passwd --passphrase-file pass --new-passphrase-file pass link.key
expect_fail "is a symbolic link" "$BU" key remove --passphrase-file pass link.key
expect_fail "is a symbolic link" "$BU" key add --passphrase-file pass --new-passphrase-file pass link.key
[ -L link.key ] || fail "symlinked key path replaced"
cmp -s real.key real-before || fail "real key file changed"
ln real.key hard.key
expect_fail "other hard links" "$BU" key remove --passphrase-file pass real.key
rm hard.key
# Reading through a link is fine.
"$BU" check --key link.key --passphrase-file pass full.bu

# add: a second passphrase opens the same key.
printf 'second passphrase\n' > pass2
"$BU" key add --passphrase-file pass --new-passphrase-file pass2 "${CHEAP[@]}" key 2>/dev/null
"$BU" key info key | grep -q "^slot 1: passphrase" || fail "slot 1 not added"
"$BU" restore --key key --passphrase-file pass2 -C out full.bu
assert_same_tree src out/src
cp key key-before-passwd

# passwd: the slot that opened gets the new passphrase; the old one is gone.
printf 'third passphrase\n' > pass3
"$BU" key passwd --passphrase-file pass2 --new-passphrase-fd 3 "${CHEAP[@]}" key 3< pass3 2>/dev/null
expect_fail "wrong passphrase" "$BU" check --key key --passphrase-file pass2 full.bu
"$BU" check --key key --passphrase-file pass3 full.bu
"$BU" check --key key --passphrase-file pass full.bu
# A copy made earlier still takes the old passphrase: a change edits this
# file only (README: keep track of copies, like LUKS header backups).
"$BU" check --key key-before-passwd --passphrase-file pass2 full.bu

# Backups made after the change are under the same master key: the chain
# continues.
echo more >> src/b.txt
"$BU" create --key key --passphrase-file pass3 full.bu src
rm -rf out && "$BU" restore "${K[@]}" -C out full.bu
assert_same_tree src out/src

# remove: by unlocking with that passphrase, or --slot N after unlocking
# with another one; never the last usable slot.
"$BU" key remove --passphrase-file pass --slot 1 key 2>/dev/null
expect_fail "wrong passphrase" "$BU" check --key key --passphrase-file pass3 full.bu
expect_fail "slot 1: that key slot is empty" "$BU" key remove --passphrase-file pass --slot 1 key
expect_fail "last usable key slot" "$BU" key remove --passphrase-file pass key
expect_fail "last usable key slot" "$BU" key remove --passphrase-file pass --slot 0 key
"$BU" check --key key --passphrase-file pass full.bu
"$BU" key add --passphrase-file pass --new-passphrase-file pass2 "${CHEAP[@]}" key 2>/dev/null
"$BU" key remove --passphrase-file pass2 key 2>/dev/null
"$BU" key info key | grep -q "^slot 1: empty$" || fail "remove by passphrase removed the wrong slot"

# All eight slots, then a ninth refused.
for i in 1 2 3 4 5 6 7; do
    "$BU" key add --passphrase-file pass --new-passphrase-file pass2 "${CHEAP[@]}" key 2>/dev/null
done
expect_fail "all 8 key slots are in use" "$BU" key add --passphrase-file pass --new-passphrase-file pass2 key

# Damage. A flipped byte inside slot 0 (its wrapped key) is a damaged slot,
# not a wrong passphrase; the other slots keep working.
flip() {   # flip SRC DST OFFSET
    cp "$1" "$2"
    local b
    b=$(dd if="$2" bs=1 skip="$3" count=1 status=none | od -An -tu1 | tr -d ' ')
    printf "$(printf '\\%03o' $(( (b ^ 0xff) & 0xff )))" | dd of="$2" bs=1 seek="$3" conv=notrunc status=none
}
flip key bad 120
expect_fail "damaged key slots were skipped" "$BU" check --key bad --passphrase-file pass full.bu
"$BU" check --key bad --passphrase-file pass2 full.bu
out=$("$BU" key info bad) && fail "key info exits 0 with a damaged slot"
echo "$out" | grep -q "^slot 0: DAMAGED (checksum mismatch)$" || fail "info on a damaged slot: $out"
# The damaged slot can be removed by number after unlocking with another.
"$BU" key remove --passphrase-file pass2 --slot 0 bad 2>/dev/null
"$BU" key info bad | grep -q "^slot 0: empty$" || fail "damaged slot not removed"
# The header (key ID) and the size.
flip key bad 20
expect_fail "damaged key file" "$BU" check --key bad --passphrase-file pass full.bu
expect_fail "damaged key file" "$BU" key info bad
head -c 900 key > bad
expect_fail "wrong size" "$BU" check --key bad --passphrase-file pass full.bu
# Not a key file at all, and the old plaintext format.
head -c 944 full.bu > notkey
expect_fail "not a bu key file" "$BU" check --key notkey --passphrase-file pass full.bu
printf 'bu-key-1 %064d\n' 0 > old.key
expect_fail "bu-key-1 plaintext key" "$BU" check --key old.key --passphrase-file pass full.bu

# The terminal path, when script(1) can give us one: the prompt goes to the
# terminal with echo off, so the passphrase never appears in the output.
if command -v script >/dev/null; then
    out=$( (sleep 0.5; echo "integration test passphrase") | script -qec "$BU check --key key full.bu" /dev/null 2>&1) \
        || fail "terminal unlock: $out"
    echo "$out" | grep -q "Passphrase for key:" || fail "no prompt: $out"
    echo "$out" | grep -q "integration test passphrase" && fail "passphrase echoed: $out"
    out=$( (sleep 0.5; echo "abc"; sleep 0.3; echo "abd") \
        | script -qec "$BU key init --kdf-memory 8 --kdf-time 1 tty.key" /dev/null 2>&1) || true
    echo "$out" | grep -q "did not match" || fail "mismatched new passphrases accepted: $out"
    [ ! -e tty.key ] || fail "key file written after a mismatch"
    # Ctrl-Z at the prompt must not stop bu with echo off (the shell the user
    # returns to would be silent): SIGTSTP is held until echo is back on.
    # `set -m` gives bu its own process group under a job-control shell, so a
    # SIGTSTP is not discarded as it would be in an orphaned group.
    if command -v pgrep >/dev/null && command -v ps >/dev/null; then
        mkfifo ttyin
        timeout 20 script -qec "bash -c 'set -m; $BU check --key key full.bu'" /dev/null < ttyin > tstp.out 2>&1 &
        exec 7> ttyin
        pid=""
        for _ in $(seq 50); do pid=$(pgrep -n -f "^$BU check --key key full.bu" || true); [ -n "$pid" ] && break; sleep 0.1; done
        [ -n "$pid" ] || fail "bu under script(1) did not start"
        sleep 0.3
        kill -TSTP "$pid"
        sleep 0.3
        st=$(ps -o stat= -p "$pid" || true)
        case "$st" in ""|T*) kill -KILL "$pid" 2>/dev/null || true; exec 7>&-; wait || true
                          fail "SIGTSTP at the prompt stopped bu with echo off (state '$st')" ;; esac
        (echo "integration test passphrase" >&7) 2>/dev/null || true
        exec 7>&-
        wait || true
    fi
fi
note ok
