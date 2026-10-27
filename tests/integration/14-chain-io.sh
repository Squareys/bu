#!/usr/bin/env bash
# 14-chain-io.sh — where a chain can live and how it is read: appended in
# place, made of segments written separately and joined with cat, written to
# stdout (a file or a pipe), read by seeking (a path, or a file on stdin) or
# as a stream (a pipe), and restored in part.
#
# Guards chain files: segment offsets are relative, so `cat a b` is a chain;
# seek and stream readers agree; a pipe needs an index to restore and gets
# the same tree; a partial restore writes the named paths and nothing else.
source "$(dirname "$0")/lib.sh"

mkdir -p src/a src/b
prand x 1500000 > src/a/x.bin
seq 1 100000 > src/a/log.txt
prand y 300000 > src/b/y.bin
ln -s ../a/log.txt src/b/link

sleep 1.1   # older than the files-cache race guard
# Separate files with an index, the way an object store wants them ...
"$BU" create "${K[@]}" --index-out idx s0.bu src
prand z 200000 > src/b/z.bin
seq 100001 100500 >> src/a/log.txt
sleep 1.1
"$BU" create "${K[@]}" --base idx --index-out idx s1.bu src
# ... are a chain once joined: segments are self-contained, offsets relative.
cat s0.bu s1.bu > joined.bu
"$BU" check "${K[@]}" joined.bu
[ "$("$BU" list "${K[@]}" joined.bu | grep -c '^# ')" = 2 ] || fail "joined chain should hold two segments"
rm -rf out && "$BU" restore "${K[@]}" -C out joined.bu
assert_same_tree src out/src
# And appending to the joined file continues the chain.
echo more >> src/a/log.txt
sleep 1.1
"$BU" create "${K[@]}" -v joined.bu src 2> app.log
grep -q ' 1 files read' app.log || fail "append to a joined chain did not use its files cache: $(cat app.log)"
rm -rf out && "$BU" restore "${K[@]}" -C out joined.bu
assert_same_tree src out/src

# Seek mode from a file on stdin.
rm -rf out && "$BU" restore "${K[@]}" -C out - < joined.bu
assert_same_tree src out/src
# Stream mode from a pipe: check and list need nothing else ...
piped joined.bu "$BU" check "${K[@]}" -v - 2> check.log
grep -q "check ok: 3 segments" check.log || fail "stream check: $(cat check.log)"
unname() { sed 's/^# [^:]*:/#/'; }
[ "$(piped joined.bu "$BU" list "${K[@]}" - | unname)" = "$("$BU" list "${K[@]}" joined.bu | unname)" ] \
    || fail "stream list differs"
# ... restore needs the snapshot up front, from an index of this chain.
expect_fail "needs --index" piped joined.bu "$BU" restore "${K[@]}" -C out -
"$BU" index "${K[@]}" -o jidx joined.bu
rm -rf out && piped joined.bu "$BU" restore "${K[@]}" --index jidx -C out -
assert_same_tree src out/src
# An index of an older snapshot restores that one (with a note); an index of
# another chain is refused.
rm -rf out && piped joined.bu "$BU" restore "${K[@]}" --index idx -C out - 2> old.log
grep -q "restored generation 2" old.log || fail "older index not noted: $(cat old.log)"
"$BU" create "${K[@]}" --index-out other-idx other.bu src/b
rm -rf out && expect_fail "none of the stream's segments\|not in the stream" piped joined.bu "$BU" restore "${K[@]}" --index other-idx -C out -

# Partial restore: only the named paths, from a file and from a pipe.
rm -rf out && "$BU" restore "${K[@]}" -C out joined.bu -- src/b/y.bin src/a
[ -f out/src/b/y.bin ] && [ -f out/src/a/x.bin ] && [ ! -e out/src/b/z.bin ] && [ ! -e out/src/b/link ] \
    || fail "partial restore restored the wrong set: $(cd out && find . | sort | tr '\n' ' ')"
cmp out/src/b/y.bin src/b/y.bin && cmp out/src/a/log.txt src/a/log.txt
rm -rf out && piped joined.bu "$BU" restore "${K[@]}" --index jidx -C out - -- src/b/z.bin
[ -f out/src/b/z.bin ] && [ ! -e out/src/a ] || fail "partial stream restore restored the wrong set"
cmp out/src/b/z.bin src/b/z.bin
expect_fail "not in the backup" "$BU" restore "${K[@]}" -C out joined.bu -- src/nope

# create to stdout: a pipe streams a segment (base from an index) ...
"$BU" create "${K[@]}" - src | cat > piped.bu
"$BU" check "${K[@]}" piped.bu
echo again >> src/a/log.txt
"$BU" create "${K[@]}" --index-out pidx - src | cat > p0.bu
echo again2 >> src/a/log.txt
"$BU" create "${K[@]}" --base pidx --index-out pidx - src | cat > p1.bu
rm -rf out && "$BU" restore "${K[@]}" -C out p0.bu p1.bu
assert_same_tree src out/src
# ... and a file on stdout opened for appending is a chain like any other.
"$BU" create "${K[@]}" - src >> app.bu
echo again3 >> src/a/log.txt
"$BU" create "${K[@]}" - src >> app.bu
[ "$("$BU" list "${K[@]}" app.bu | grep -c '^# ')" = 2 ] || fail "create >> did not append"
rm -rf out && "$BU" restore "${K[@]}" -C out app.bu
assert_same_tree src out/src
note ok
