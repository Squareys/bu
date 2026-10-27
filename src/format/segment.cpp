// segment.cpp — see segment.hpp for the layout and the key/nonce scheme.

#include "format/segment.hpp"
#include "core/bytes.hpp"
#include "format/codec.hpp"

#include <string.h>

namespace bk {

namespace {

// The magic borrows PNG's trick: the CR LF and ^Z bytes make a text-mode
// transfer or a newline-converting pipe corrupt the very first bytes, so a
// mangled backup is reported as "not a bu file" instead of failing deep in
// a record with an authentication error.
constexpr u8 kMagic[8] = {'B', 'U', 'B', 'A', 'K', '\r', '\n', 0x1a};

// BLAKE3 derive_key contexts: hardcoded, globally unique, never reused for a
// different purpose (BLAKE3's own rule for this mode). Changing one is a format
// break, which is why they carry the date they were fixed.
constexpr StringView kCtxChunkId = "bu 2026-10-25 chunk id v1"_s;
constexpr StringView kCtxAead = "bu 2026-10-27 segment aes-256-gcm key v2"_s;
constexpr StringView kCtxCheck = "bu 2026-10-27 segment check v2"_s;

void nonceOf(u64 counter, u8 out[kNonceBytes]) {
    storeU64LE(out, counter);
    out[8] = out[9] = out[10] = out[11] = 0;
}

// The 16 check bytes of a header (n = 48) or of a header and trailer (the
// trailer's check covers the header it belongs to, n = 104).
void checkOf(const SegKeys& keys, const u8* data, usize n, u8 out[16]) {
    const HashPart part{data, n};
    blake3Parts(keys.plain ? nullptr : &keys.check, &part, 1, out, 16);
}

// An unencrypted body's tag: unkeyed BLAKE3 of nonce, type and payload.
void plainTag(u64 nonce, u8 type, const u8* payload, u32 n, u8 out[kTagBytes]) {
    u8 nb[kNonceBytes];
    nonceOf(nonce, nb);
    const HashPart parts[3] = {{nb, kNonceBytes}, {&type, 1}, {payload, n}};
    blake3Parts(nullptr, parts, 3, out, kTagBytes);
}

} // namespace

const u8 kTrailerMagic[8] = {'B', 'U', 'E', 'N', 'D', '\r', '\n', 0x1a};

// ---- keys -----------------------------------------------------------------

void masterKeyInit(const Key& master, MasterKey& out) {
    out.master = master;
    out.plain = false;
    blake3DeriveKey(kCtxChunkId, master.b, kKeyBytes, out.idKey);
}

void masterKeyPlain(MasterKey& out) {
    memSet(&out.master, 0, sizeof out.master);
    memSet(&out.idKey, 0, sizeof out.idKey);
    out.plain = true;
}

void chunkIdOf(const MasterKey& k, const u8* data, usize n, ChunkId& out) {
    if (k.plain) {
        const HashPart part{data, n};
        blake3Parts(nullptr, &part, 1, out.b, kIdBytes);
    } else {
        blake3Keyed(k.idKey, data, n, out.b, kIdBytes);
    }
}

void segKeysDerive(const MasterKey& k, const u8 salt[kSaltBytes], SegKeys& out) {
    memCopy(out.salt, salt, kSaltBytes);
    out.plain = k.plain;
    if (k.plain) {
        memSet(&out.aead, 0, sizeof out.aead);
        memSet(&out.check, 0, sizeof out.check);
        return;
    }
    u8 material[kKeyBytes + kSaltBytes];
    memCopy(material, k.master.b, kKeyBytes);
    memCopy(material + kKeyBytes, salt, kSaltBytes);
    Key aes;
    blake3DeriveKey(kCtxAead, material, sizeof material, aes);
    blake3DeriveKey(kCtxCheck, material, sizeof material, out.check);
    aeadInit(out.aead, aes);
    secureZero(aes.b, kKeyBytes);
    secureZero(material, sizeof material);
}

void headerBuild(const SegKeys& keys, u16 kind, u8 out[kHeaderBytes]) {
    memCopy(out, kMagic, 8);
    storeU16LE(out + 8, kFormatVersion);
    storeU16LE(out + 10, kind);
    storeU16LE(out + 12, keys.plain ? kFlagPlain : 0);
    storeU16LE(out + 14, 0);
    memCopy(out + 16, keys.salt, kSaltBytes);
    checkOf(keys, out, 48, out + 48);
}

bool headerParse(const u8 h[kHeaderBytes], u16& kind, bool& plain, String& why) {
    if (!memEqual(h, kMagic, 8)) return errSet(why, "not a bu file (bad magic)");
    const u16 version = loadU16LE(h + 8);
    if (version != kFormatVersion) {
        String v("unsupported format version ");
        v.appendU64(version);
        v.append(version < kFormatVersion ? " (made by an older bu; this one reads version "_s
                                          : " (made by a newer bu; this one reads version "_s);
        v.appendU64(kFormatVersion);
        v.append(')');
        why = move(v);
        return false;
    }
    kind = loadU16LE(h + 10);
    if (kind != kKindSegment && kind != kKindIndex) return errSet(why, "unknown file kind");
    const u16 flags = loadU16LE(h + 12);
    if ((flags & ~kFlagPlain) || loadU16LE(h + 14) != 0) return errSet(why, "unknown header flags (damaged?)");
    plain = flags & kFlagPlain;
    return true;
}

bool headerVerify(const SegKeys& keys, const u8 h[kHeaderBytes]) {
    // Not constant-time and need not be: the check value is a public function
    // of the header for whoever holds the key, and there is no oracle here.
    u8 check[16];
    checkOf(keys, h, 48, check);
    return memEqual(check, h + 48, 16);
}

// ---- records --------------------------------------------------------------

u32 bodySeal(const SegKeys& keys, u64 nonce, u8 type, const ChunkId* id, const u8* payload, u32 n, u8* out) {
    if (keys.plain) {
        memMove(out, payload, n);
        if (id) memCopy(out + n, id->b, kTagBytes);
        else plainTag(nonce, type, payload, n, out + n);
        return n + kTagBytes;
    }
    u8 nb[kNonceBytes];
    nonceOf(nonce, nb);
    aeadSeal(keys.aead, nb, &type, 1, payload, n, out);
    return n + kTagBytes;
}

bool bodyOpen(const SegKeys& keys, u64 nonce, u8 type, const u8* body, u32 len, u8* payload) {
    if (len < kTagBytes) return false;
    const u32 n = len - kTagBytes;
    if (keys.plain) {
        if (type != kRecChunk) {
            u8 tag[kTagBytes];
            plainTag(nonce, type, body, n, tag);
            if (!memEqual(tag, body + n, kTagBytes)) return false;
        }
        memMove(payload, body, n);
        return true;
    }
    u8 nb[kNonceBytes];
    nonceOf(nonce, nb);
    return aeadOpen(keys.aead, nb, &type, 1, body, n, payload);
}

void recPrefixSeal(const SegKeys& keys, u64 ordinal, u8 type, u64 bodyNonce, u32 bodyLen, u8 out[kRecPrefix]) {
    storeU32LE(out, kRecHeadBytes + bodyLen);
    u8 plain[kRecHeadPlain];
    plain[0] = type;
    storeU64LE(plain + 1, bodyNonce);
    const u64 nonce = kNonceHeadBase + ordinal;
    if (keys.plain) {
        memCopy(out + 4, plain, kRecHeadPlain);
        u8 nb[kNonceBytes];
        nonceOf(nonce, nb);
        const HashPart parts[2] = {{nb, kNonceBytes}, {plain, kRecHeadPlain}};
        blake3Parts(nullptr, parts, 2, out + 4 + kRecHeadPlain, kTagBytes);
        return;
    }
    u8 nb[kNonceBytes];
    nonceOf(nonce, nb);
    aeadSeal(keys.aead, nb, nullptr, 0, plain, kRecHeadPlain, out + 4);
}

bool recPrefixOpen(const SegKeys& keys, u64 ordinal, const u8 in[kRecPrefix], u8& type, u64& bodyNonce,
                          u32& bodyLen) {
    const u32 len = loadU32LE(in);
    if (len < kRecHeadBytes + kTagBytes) return false;
    u8 plain[kRecHeadPlain];
    u8 nb[kNonceBytes];
    nonceOf(kNonceHeadBase + ordinal, nb);
    if (keys.plain) {
        u8 tag[kTagBytes];
        const HashPart parts[2] = {{nb, kNonceBytes}, {in + 4, kRecHeadPlain}};
        blake3Parts(nullptr, parts, 2, tag, kTagBytes);
        if (!memEqual(tag, in + 4 + kRecHeadPlain, kTagBytes)) return false;
        memCopy(plain, in + 4, kRecHeadPlain);
    } else if (!aeadOpen(keys.aead, nb, nullptr, 0, in + 4, kRecHeadPlain, plain)) {
        return false;
    }
    type = plain[0];
    bodyNonce = loadU64LE(plain + 1);
    bodyLen = len - kRecHeadBytes;
    return true;
}

// ---- trailer ------------------------------------------------------------------

void trailerBuild(const SegKeys& keys, const u8 header[kHeaderBytes], const Trailer& t, u8 out[kTrailerBytes]) {
    storeU64LE(out, t.segLen);
    storeU64LE(out + 8, t.manOff);
    storeU64LE(out + 16, t.tabOff);
    storeU32LE(out + 24, t.manLen);
    storeU32LE(out + 28, t.tabLen);
    storeU64LE(out + 32, t.gen);
    u8 both[kHeaderBytes + 40];
    memCopy(both, header, kHeaderBytes);
    memCopy(both + kHeaderBytes, out, 40);
    checkOf(keys, both, sizeof both, out + 40);
    memCopy(out + 56, kTrailerMagic, 8);
}

bool trailerParse(const u8 in[kTrailerBytes], Trailer& t, String& why) {
    if (!memEqual(in + 56, kTrailerMagic, 8)) return errSet(why, "no segment trailer at the end");
    t.segLen = loadU64LE(in);
    t.manOff = loadU64LE(in + 8);
    t.tabOff = loadU64LE(in + 16);
    t.manLen = loadU32LE(in + 24);
    t.tabLen = loadU32LE(in + 28);
    t.gen = loadU64LE(in + 32);
    // The records must tile the segment exactly: manifest, table, trailer.
    // Every value is bounded before it is added, so nothing here overflows.
    const u64 maxSeg = u64(1) << 56;
    const bool ok = t.segLen <= maxSeg && t.manOff >= kHeaderBytes && t.manOff < maxSeg
                    && t.manLen >= kRecHeadBytes + kTagBytes && t.manLen <= kMaxMetaRecord
                    && t.tabOff == t.manOff + 4 + t.manLen && t.tabLen <= kMaxMetaRecord
                    && (t.tabLen == 0 || t.tabLen >= kRecHeadBytes + kTagBytes)
                    && t.segLen == t.tabOff + (t.tabLen ? 4 + u64(t.tabLen) : 0) + kTrailerBytes;
    if (!ok) return errSet(why, "segment trailer does not describe a valid layout (damaged)");
    return true;
}

bool trailerVerify(const SegKeys& keys, const u8 header[kHeaderBytes], const u8 in[kTrailerBytes]) {
    u8 both[kHeaderBytes + 40], check[16];
    memCopy(both, header, kHeaderBytes);
    memCopy(both + kHeaderBytes, in, 40);
    checkOf(keys, both, sizeof both, check);
    return memEqual(check, in + 40, 16);
}

bool chunkDecode(const MasterKey& k, const u8* payload, u32 n, u32 rawLen, const ChunkId& id, u8* out, String& why) {
    u32 claimed = 0;
    if (!codecRawLength(payload, n, kMaxChunk, claimed) || claimed != rawLen)
        return errSet(why, "chunk payload length does not match the chunk table");
    if (!codecDecode(payload, n, out, rawLen)) return errSet(why, "chunk does not decompress");
    // The tag proved the record is the one this segment sealed; the hash
    // proves the ID is the content's. Both, because the second is what makes
    // taking a chunk by ID from any segment trustworthy (restore, merge).
    ChunkId got;
    chunkIdOf(k, out, rawLen, got);
    if (!idEqual(got, id)) return errSet(why, "chunk content does not match its ID");
    return true;
}

// ---- writing --------------------------------------------------------------

bool writerBegin(SegWriter& w, OutStream& out, const MasterKey& k, u16 kind, String& err) {
    u8 salt[kSaltBytes];
    if (!randomBytes(salt, kSaltBytes, err)) return false;
    segKeysDerive(k, salt, w.keys);
    w.out = &out;
    w.kind = kind;
    w.base = out.written;
    w.ordinal = 0;
    w.chunks.clear();
    headerBuild(w.keys, kind, w.header);
    out.write(w.header, kHeaderBytes);
    return true;
}

u32 writerChunk(SegWriter& w, const ChunkId& id, u64 nonce, u32 rawLen, u8* rec, u32 bodyLen) {
    recPrefixSeal(w.keys, w.ordinal++, kRecChunk, nonce, bodyLen, rec);
    TableEntry& t = w.chunks.addDefault();
    t.id = id; t.nonce = nonce; t.recLen = kRecHeadBytes + bodyLen; t.rawLen = rawLen;
    return kRecPrefix + bodyLen;
}

namespace {

// Encode, seal and write one metadata record; returns its L.
u32 writeMeta(SegWriter& w, u8 type, u64 nonce, const u8* body, u32 n) {
    CodecState* st = static_cast<CodecState*>(defaultAllocator().alloc(sizeof(CodecState)));
    Array<u8> payload, rec;
    payload.resize(codecBound(n));
    payload.count = codecEncode(*st, body, n, payload.ptr);
    defaultAllocator().free(st);
    rec.resize(kRecPrefix + payload.count + kTagBytes);
    const u32 bodyLen = bodySeal(w.keys, nonce, type, nullptr, payload.ptr, payload.count, rec.ptr + kRecPrefix);
    recPrefixSeal(w.keys, w.ordinal++, type, nonce, bodyLen, rec.ptr);
    w.out->write(rec.ptr, rec.count);
    return kRecHeadBytes + bodyLen;
}

} // namespace

bool writerFinish(SegWriter& w, const u8* manifest, u32 n, u64 gen, String& err) {
    OutStream& out = *w.out;
    Trailer t;
    t.gen = gen;
    t.manOff = out.written - w.base;
    const bool index = w.kind == kKindIndex;
    t.manLen = writeMeta(w, index ? kRecIndex : kRecManifest, index ? kNonceIndex : kNonceManifest, manifest, n);
    t.tabOff = out.written - w.base;
    if (!index) {
        ByteWriter tb;
        tb.buf.reserve(w.chunks.count * 24 + 16);
        tb.varint(2);
        tb.varint(w.chunks.count);
        u64 prev = 0;
        for (const TableEntry& e : w.chunks) {
            tb.bytes(e.id.b, kIdBytes);
            tb.varint(e.recLen);
            tb.varint(e.nonce - prev);
            tb.varint(e.rawLen);
            prev = e.nonce;
        }
        t.tabLen = writeMeta(w, kRecTable, kNonceTable, tb.buf.ptr, tb.buf.count);
    }
    t.segLen = out.written - w.base + kTrailerBytes;
    u8 tr[kTrailerBytes];
    trailerBuild(w.keys, w.header, t, tr);
    out.write(tr, kTrailerBytes);
    if (!out.flush()) return errSet(err, "writing the backup: ", strerror(out.savedErrno));
    return true;
}

} // namespace bk
