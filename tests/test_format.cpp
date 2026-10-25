// test_format.cpp — the container and manifest encodings.
//
// Guards: a record opens only with its own nonce, type and ID (no replay as a
// different record); a delta manifest decodes back to exactly the snapshot it
// encoded, for the edit patterns backups see (in-place page rewrites,
// insertions, deletions, new and removed files); and the decoder refuses
// unsafe paths, because restore trusts what the decoder accepted.

#include "core/bytes.hpp"
#include "format/codec.hpp"
#include "format/container.hpp"
#include "format/snapshot.hpp"
#include "test.hpp"

using namespace bk;

namespace {

ChunkId idOf(u32 v) {
    ChunkId id;
    memSet(id.b, 0, kIdBytes);
    storeU32LE(id.b, v * 2654435761u);
    storeU32LE(id.b + 8, v);
    return id;
}

void addFile(Snapshot& s, StringView path, const u32* ids, u32 n) {
    Entry e;
    e.type = kEntryFile;
    e.mode = 0644;
    e.size = n * 100;
    e.mtimeNs = 1700000000123456789ll;
    e.ctimeNs = -5;
    e.ino = 42; e.dev = 7;
    e.pathLen = path.count;
    e.pathOff = snapshotAddName(s, path);
    e.firstRef = s.refs.count;
    for (u32 i = 0; i < n; ++i) s.refs.push(idOf(ids[i]));
    e.refCount = n;
    s.entries.push(e);
}

bool sameRefs(const Snapshot& a, u32 ea, const Snapshot& b, u32 eb) {
    const Entry& x = a.entries[ea];
    const Entry& y = b.entries[eb];
    if (x.refCount != y.refCount) return false;
    for (u32 i = 0; i < x.refCount; ++i)
        if (!idEqual(a.refs[x.firstRef + i], b.refs[y.firstRef + i])) return false;
    return true;
}

} // namespace

BK_TEST(record_opens_only_with_its_own_nonce_type_and_id) {
    MasterKey k;
    memSet(k.master.b, 1, kKeyBytes);
    memSet(k.idKey.b, 2, kKeyBytes);
    u8 salt[kSaltBytes] = {9};
    ContainerKeys ck;
    containerKeysDerive(k, salt, ck);
    const u8 payload[5] = {0, 'h', 'e', 'l', 'o'};
    u8 rec[5 + kRecordOverhead];
    const ChunkId id = idOf(1), other = idOf(2);
    BK_REQUIRE(recordSeal(ck, 77, kRecChunk, &id, payload, 5, rec) == sizeof rec);
    BK_CHECK_EQ(loadU32LE(rec), 5u + kTagBytes);
    u8 out[5];
    BK_CHECK(recordOpen(ck, 77, kRecChunk, &id, rec + 4, 5 + kTagBytes, out) && memEqual(out, payload, 5));
    BK_CHECK(!recordOpen(ck, 78, kRecChunk, &id, rec + 4, 5 + kTagBytes, out));
    BK_CHECK(!recordOpen(ck, 77, kRecManifest, &id, rec + 4, 5 + kTagBytes, out));
    BK_CHECK(!recordOpen(ck, 77, kRecChunk, &other, rec + 4, 5 + kTagBytes, out));
    // Another salt is another key.
    salt[0] = 10;
    ContainerKeys ck2;
    containerKeysDerive(k, salt, ck2);
    BK_CHECK(!recordOpen(ck2, 77, kRecChunk, &id, rec + 4, 5 + kTagBytes, out));
}

BK_TEST(varint_reader_refuses_overlong_and_truncated) {
    const u8 overlong[11] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0};
    ByteReader r(overlong, 11);
    r.varint();
    BK_CHECK(r.failed);
    const u8 trunc[2] = {0x80, 0x80};
    ByteReader t(trunc, 2);
    t.varint();
    BK_CHECK(t.failed);
    ByteWriter w;
    w.varint(~u64(0)); w.svarint(-3); w.varint(300);
    ByteReader ok(w.buf.ptr, w.buf.count);
    BK_CHECK(ok.varint() == ~u64(0) && ok.svarint() == -3 && ok.varint() == 300 && ok.done() && !ok.failed);
}

BK_TEST(delta_manifest_roundtrips_edit_patterns) {
    Snapshot parent;
    memSet(parent.id, 0xaa, kSnapshotIdBytes);
    parent.gen = 1;
    const u32 db[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    const u32 log[] = {100, 101, 102};
    const u32 gone[] = {200};
    const u32 zeros[] = {0, 0, 0, 0, 5, 0, 0};
    addFile(parent, "a/db.sqlite"_s, db, 20);
    addFile(parent, "a/gone.txt"_s, gone, 1);
    addFile(parent, "a/log.txt"_s, log, 3);
    addFile(parent, "a/zeros"_s, zeros, 7);
    snapshotIndexPaths(parent);

    Snapshot cur;
    memSet(cur.id, 0xbb, kSnapshotIdBytes);
    memCopy(cur.parent, parent.id, kSnapshotIdBytes);
    cur.hasParent = true;
    cur.gen = 2;
    const u32 db2[] = {1, 2, 3, 50, 5, 6, 7, 8, 9, 10, 51, 12, 13, 14, 15, 16, 17, 18, 19, 20};  // pages rewritten
    const u32 log2[] = {99, 100, 101, 102, 103};                                               // insert + append
    const u32 neu[] = {300, 301};
    const u32 zeros2[] = {0, 0, 5, 0, 0, 0, 0, 0, 0};
    addFile(cur, "a/db.sqlite"_s, db2, 20);
    addFile(cur, "a/log.txt"_s, log2, 5);
    addFile(cur, "a/new.bin"_s, neu, 2);
    addFile(cur, "a/zeros"_s, zeros2, 9);

    ByteWriter delta, full;
    snapshotEncode(cur, &parent, delta);
    snapshotEncode(cur, nullptr, full);
    printf("    manifest: delta %u bytes, full %u bytes\n", delta.buf.count, full.buf.count);
    BK_CHECK(delta.buf.count < full.buf.count);

    Snapshot back;
    String err;
    BK_REQUIRE(snapshotDecode(delta.buf.ptr, delta.buf.count, &parent, back, err));
    BK_REQUIRE(back.entries.count == cur.entries.count);
    for (u32 i = 0; i < cur.entries.count; ++i) {
        BK_CHECK(entryPath(back, back.entries[i]) == entryPath(cur, cur.entries[i]));
        BK_CHECK(sameRefs(back, i, cur, i));
        BK_CHECK(back.entries[i].mtimeNs == cur.entries[i].mtimeNs && back.entries[i].ctimeNs == -5);
    }
    BK_CHECK(back.hasParent && back.gen == 2);

    // Without its parent a delta must not decode.
    Snapshot orphan;
    BK_CHECK(!snapshotDecode(delta.buf.ptr, delta.buf.count, nullptr, orphan, err));
}

BK_TEST(manifest_decoder_refuses_unsafe_paths) {
    BK_CHECK(pathIsSafe("a/b/c"_s));
    BK_CHECK(!pathIsSafe("/etc/passwd"_s));
    BK_CHECK(!pathIsSafe("a/../../x"_s));
    BK_CHECK(!pathIsSafe("a//b"_s));
    BK_CHECK(!pathIsSafe("./a"_s));
    BK_CHECK(!pathIsSafe(""_s));
    Snapshot s;
    const u32 ids[] = {1};
    addFile(s, "../escape"_s, ids, 1);
    ByteWriter w;
    snapshotEncode(s, nullptr, w);
    Snapshot back;
    String err;
    BK_CHECK(!snapshotDecode(w.buf.ptr, w.buf.count, nullptr, back, err));
}

BK_TEST(manifest_decoder_survives_every_truncation) {
    Snapshot s;
    const u32 ids[] = {1, 2, 3};
    addFile(s, "x/y"_s, ids, 3);
    addFile(s, "x/z"_s, ids, 2);
    ByteWriter w;
    snapshotEncode(s, nullptr, w);
    u32 accepted = 0;
    for (u32 n = 0; n < w.buf.count; ++n) {
        Snapshot back;
        String err;
        if (snapshotDecode(w.buf.ptr, n, nullptr, back, err)) ++accepted;
    }
    BK_CHECK_EQ(accepted, 0u);
}
