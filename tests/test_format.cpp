// test_format.cpp — the segment and manifest encodings.
//
// Guards: a record body opens only with its own nonce and type, and a record
// header only under its own ordinal (no replay as a different record, no
// reordering in a stream); an unencrypted record's checksum catches a flipped
// bit; the trailer authenticates itself and the header it belongs to, and a
// format-1 header is refused by version; the nonce spaces are disjoint; a
// delta manifest decodes back to exactly the snapshot it encoded, chunk sizes
// included, for the edit patterns backups see (in-place page rewrites,
// insertions, deletions, new and removed files), and a self-contained one
// with a parent decodes without it; and the decoder refuses unsafe paths,
// because restore trusts what the decoder accepted.

#include "core/bytes.hpp"
#include "format/codec.hpp"
#include "format/segment.hpp"
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
    e.size = 0;
    e.mtimeNs = 1700000000123456789ll;
    e.ctimeNs = -5;
    e.ino = 42; e.dev = 7;
    e.pathLen = path.count;
    e.pathOff = snapshotAddName(s, path);
    e.firstRef = s.refs.count;
    for (u32 i = 0; i < n; ++i) {
        s.refs.push(idOf(ids[i]));
        s.sizes.push(100 + ids[i] % 50);     // equal IDs, equal sizes
        e.size += 100 + ids[i] % 50;
    }
    e.refCount = n;
    s.entries.push(e);
}

bool sameRefs(const Snapshot& a, u32 ea, const Snapshot& b, u32 eb) {
    const Entry& x = a.entries[ea];
    const Entry& y = b.entries[eb];
    if (x.refCount != y.refCount) return false;
    for (u32 i = 0; i < x.refCount; ++i)
        if (!idEqual(a.refs[x.firstRef + i], b.refs[y.firstRef + i]) || a.sizes[x.firstRef + i] != b.sizes[y.firstRef + i])
            return false;
    return true;
}

} // namespace

BK_TEST(record_opens_only_with_its_own_nonce_type_and_ordinal) {
    MasterKey k;
    memSet(k.master.b, 1, kKeyBytes);
    memSet(k.idKey.b, 2, kKeyBytes);
    u8 salt[kSaltBytes] = {9};
    SegKeys ck;
    segKeysDerive(k, salt, ck);
    const u8 payload[5] = {0, 'h', 'e', 'l', 'o'};
    u8 rec[kRecPrefix + 5 + kTagBytes];
    const ChunkId id = idOf(1);
    const u32 bodyLen = bodySeal(ck, 77, kRecChunk, &id, payload, 5, rec + kRecPrefix);
    BK_REQUIRE(bodyLen == 5 + kTagBytes);
    recPrefixSeal(ck, 3, kRecChunk, 77, bodyLen, rec);
    BK_CHECK_EQ(loadU32LE(rec), kRecHeadBytes + bodyLen);
    u8 type = 0;
    u64 nonce = 0;
    u32 got = 0;
    BK_CHECK(recPrefixOpen(ck, 3, rec, type, nonce, got) && type == kRecChunk && nonce == 77 && got == bodyLen);
    BK_CHECK(!recPrefixOpen(ck, 4, rec, type, nonce, got));          // another place in the stream
    u8 out[5];
    BK_CHECK(bodyOpen(ck, 77, kRecChunk, rec + kRecPrefix, bodyLen, out) && memEqual(out, payload, 5));
    BK_CHECK(!bodyOpen(ck, 78, kRecChunk, rec + kRecPrefix, bodyLen, out));
    BK_CHECK(!bodyOpen(ck, 77, kRecManifest, rec + kRecPrefix, bodyLen, out));
    // Another salt is another key.
    salt[0] = 10;
    SegKeys ck2;
    segKeysDerive(k, salt, ck2);
    BK_CHECK(!bodyOpen(ck2, 77, kRecChunk, rec + kRecPrefix, bodyLen, out));
    BK_CHECK(!recPrefixOpen(ck2, 3, rec, type, nonce, got));
}

BK_TEST(unencrypted_records_carry_checksums) {
    MasterKey k;
    masterKeyPlain(k);
    u8 salt[kSaltBytes] = {1};
    SegKeys ck;
    segKeysDerive(k, salt, ck);
    BK_CHECK(ck.plain);
    const u8 payload[6] = {0, 'p', 'l', 'a', 'i', 'n'};
    u8 rec[kRecPrefix + 6 + kTagBytes];
    const u32 bodyLen = bodySeal(ck, kNonceManifest, kRecManifest, nullptr, payload, 6, rec + kRecPrefix);
    recPrefixSeal(ck, 0, kRecManifest, kNonceManifest, bodyLen, rec);
    // Readable as it is (no key), but every flipped bit is caught.
    BK_CHECK(memEqual(rec + kRecPrefix, payload, 6));
    u8 out[6], type = 0;
    u64 nonce = 0;
    u32 got = 0;
    BK_CHECK(bodyOpen(ck, kNonceManifest, kRecManifest, rec + kRecPrefix, bodyLen, out));
    BK_CHECK(recPrefixOpen(ck, 0, rec, type, nonce, got));
    for (u32 bit = 0; bit < 8 * sizeof rec; bit += 7) {
        if (bit / 8 < 4) continue;                       // the length prefix is checked by layout, not checksum
        rec[bit / 8] ^= u8(1 << (bit % 8));
        const bool prefixOk = recPrefixOpen(ck, 0, rec, type, nonce, got);
        const bool bodyOk = bodyOpen(ck, kNonceManifest, kRecManifest, rec + kRecPrefix, bodyLen, out);
        BK_CHECK(!(prefixOk && bodyOk));
        rec[bit / 8] ^= u8(1 << (bit % 8));
    }
    // A chunk body's tag is its ID (unkeyed BLAKE3 of the content).
    const u8 content[3] = {'a', 'b', 'c'};
    ChunkId id, tag;
    chunkIdOf(k, content, 3, id);
    u8 enc[1 + 3 + kTagBytes] = {0, 'a', 'b', 'c'};
    u8 chunk[sizeof enc];
    bodySeal(ck, 5, kRecChunk, &id, enc, 4, chunk);
    bodyTagId(chunk, sizeof chunk, tag);
    BK_CHECK(idEqual(id, tag));
    u8 raw[3];
    String why;
    BK_CHECK(chunkDecode(k, chunk, 4, 3, id, raw, why));
    chunk[2] ^= 1;
    BK_CHECK(!chunkDecode(k, chunk, 4, 3, id, raw, why));
}

BK_TEST(trailer_authenticates_itself_and_its_header) {
    static_assert(kNonceHeadBase > kNonceIndex && kNonceManifest >= (u64(1) << 63), "nonce spaces are disjoint");
    MasterKey k;
    memSet(k.master.b, 3, kKeyBytes);
    u8 salt[kSaltBytes] = {7};
    SegKeys ck;
    segKeysDerive(k, salt, ck);
    u8 h[kHeaderBytes];
    headerBuild(ck, kKindSegment, h);
    u16 kind = 0;
    bool plain = true;
    String why;
    BK_CHECK(headerParse(h, kind, plain, why) && kind == kKindSegment && !plain && headerVerify(ck, h));
    Trailer t;
    t.manOff = 1000; t.manLen = 100; t.tabOff = 1104; t.tabLen = 60; t.gen = 9;
    t.segLen = 1104 + 4 + 60 + kTrailerBytes;
    u8 tr[kTrailerBytes];
    trailerBuild(ck, h, t, tr);
    Trailer back;
    BK_CHECK(trailerParse(tr, back, why) && back.gen == 9 && back.segLen == t.segLen && trailerVerify(ck, h, tr));
    tr[32] ^= 1;                                            // the generation
    BK_CHECK(!trailerVerify(ck, h, tr));
    tr[32] ^= 1;
    h[20] ^= 1;                                             // its header
    BK_CHECK(!trailerVerify(ck, h, tr) && !headerVerify(ck, h));
    h[20] ^= 1;
    tr[0] ^= 1;                                             // a layout that does not tile
    BK_CHECK(!trailerParse(tr, back, why));
    // Format 1 is refused by its version.
    h[8] = 1;
    BK_CHECK(!headerParse(h, kind, plain, why));
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
    // A self-contained manifest with a parent (a checkpoint) decodes alone.
    Snapshot alone;
    BK_REQUIRE(snapshotDecode(full.buf.ptr, full.buf.count, nullptr, alone, err));
    BK_CHECK(alone.hasParent && !alone.delta && memEqual(alone.parent, parent.id, kSnapshotIdBytes));
    for (u32 i = 0; i < cur.entries.count; ++i) BK_CHECK(sameRefs(alone, i, cur, i));

    // The index: a snapshot and the checkpoint counters.
    IndexData d;
    d.snap = move(alone);
    d.deltaBytes = 123;
    d.fullBytes = 4567;
    ByteWriter ib;
    indexEncode(d, ib);
    IndexData back2;
    BK_REQUIRE(indexDecode(ib.buf.ptr, ib.buf.count, back2, err));
    BK_CHECK(back2.deltaBytes == 123 && back2.fullBytes == 4567 && back2.snap.entries.count == cur.entries.count);
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
