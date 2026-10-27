#!/usr/bin/env bash
# 11-list-escape.sh — `bu list` prints names from the backup with control
# bytes escaped, so a file name cannot send escape sequences (or fake extra
# lines) to the terminal of whoever lists the backup.
source "$(dirname "$0")/lib.sh"

mkdir src
esc=$'\033'
echo a > "src/nl"$'\n'"fake 0 0 0 entry"
echo b > "src/${esc}]0;owned${esc}\\title"
echo c > 'src/back\slash'
echo d > "src/tab"$'\t'"ü"
ln -s "target${esc}[2J" "src/link"
"$BU" create "${K[@]}" --index-out idx c.bu src
"$BU" list "${K[@]}" c.bu > listing
"$BU" list "${K[@]}" idx >> listing
LC_ALL=C grep -q "$esc" listing && fail "an escape byte reached the listing"
[ "$(grep -c 'fake 0 0 0 entry' listing)" = 2 ] || fail "the newline name was not kept on one line"
grep -qF 'src/nl\nfake 0 0 0 entry' listing || fail "newline not shown as \\n: $(cat listing)"
grep -qF 'src/\x1b]0;owned\x1b\\title' listing || fail "ESC not shown as \\x1b: $(cat listing)"
grep -qF 'src/back\\slash' listing || fail "backslash not doubled"
grep -qF 'src/tab\tü' listing || fail "tab or UTF-8 mangled"
grep -qF -- '-> target\x1b[2J' listing || fail "symlink target not escaped"
note ok
