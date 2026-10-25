// container.cpp — see container.hpp for the layout and the key/nonce scheme.

#include "format/container.hpp"
#include "core/bytes.hpp"
#include "format/codec.hpp"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bk {

namespace {

// The magic borrows PNG's trick: the CR LF and ^Z bytes make a text-mode
// transfer or a newline-converting pipe corrupt the very first bytes, so a
// mangled backup is reported as "not a backu file" instead of failing deep in
// a record with an authentication error.
constexpr u8 kMagic[8] = {'B', 'A', 'C', 'K', 'U', '\r', '\n', 0x1a};
constexpr u8 kFooterMagic[4] = {'B', 'K', 'F', 'T'};

// BLAKE3 derive_key contexts: hardcoded, globally unique, never reused for a
// different purpose (BLAKE3's own rule for this mode). Changing one is a format
// break, which is why they carry the date they were fixed.
constexpr StringView kCtxChunkId = "backu 2026-10-25 chunk id v1"_s;
constexpr StringView kCtxAead = "backu 2026-10-25 container aes-256-gcm key v1"_s;
constexpr StringView kCtxCheck = "backu 2026-10-25 container header check v1"_s;

constexpr StringView kKeyPrefix = "backu-key-1 "_s;

void nonceOf(u64 counter, u8 out[kNonceBytes]) {
    storeU64LE(out, counter);
    out[8] = out[9] = out[10] = out[11] = 0;
}

void adOf(u8 type, const ChunkId* id, u8 out[1 + kIdBytes]) {
    out[0] = type;
    if (id) memCopy(out + 1, id->b, kIdBytes); else memSet(out + 1, 0, kIdBytes);
}

bool fail(String& err, const Container& c, StringView what) {
    return errSet(err, c.path.view(), ": ", what);
}

} // namespace

// ---- keys -----------------------------------------------------------------

bool keyLoad(const char* path, MasterKey& out, String& err) {
    Array<u8> text;
    if (!readWholeFile(path, 4096, text, err)) return false;
    StringView s(reinterpret_cast<const char*>(text.ptr), text.count);
    while (!s.empty() && (s[s.count - 1] == '\n' || s[s.count - 1] == '\r')) s.count--;
    const bool ok = s.startsWith(kKeyPrefix) && hexDecode(s.from(kKeyPrefix.count), out.master.b, kKeyBytes);
    secureZero(text.ptr, text.count);
    if (!ok) return errSet(err, path, ": not a backu key file (expected one line: backu-key-1 <64 hex digits>)");
    blake3DeriveKey(kCtxChunkId, out.master.b, kKeyBytes, out.idKey);
    return true;
}

bool keyGenerate(String& out, String& err) {
    Key k;
    if (!randomBytes(k.b, kKeyBytes, err)) return false;
    char hex[2 * kKeyBytes];
    hexEncode(k.b, kKeyBytes, hex);
    out.assign(kKeyPrefix);
    out.append(StringView(hex, sizeof hex));
    out.append('\n');
    secureZero(k.b, kKeyBytes);
    secureZero(hex, sizeof hex);
    return true;
}

void chunkIdOf(const MasterKey& k, const u8* data, usize n, ChunkId& out) {
    blake3Keyed(k.idKey, data, n, out.b, kIdBytes);
}

void containerKeysDerive(const MasterKey& k, const u8 salt[kSaltBytes], ContainerKeys& out) {
    u8 material[kKeyBytes + kSaltBytes];
    memCopy(material, k.master.b, kKeyBytes);
    memCopy(material + kKeyBytes, salt, kSaltBytes);
    memCopy(out.salt, salt, kSaltBytes);
    Key aes;
    blake3DeriveKey(kCtxAead, material, sizeof material, aes);
    blake3DeriveKey(kCtxCheck, material, sizeof material, out.check);
    aeadInit(out.aead, aes);
    secureZero(aes.b, kKeyBytes);
    secureZero(material, sizeof material);
}

void headerBuild(const ContainerKeys& keys, u16 kind, u8 out[kHeaderBytes]) {
    memCopy(out, kMagic, 8);
    out[8] = u8(kFormatVersion); out[9] = u8(kFormatVersion >> 8);
    out[10] = u8(kind); out[11] = u8(kind >> 8);
    storeU32LE(out + 12, 0);
    memCopy(out + 16, keys.salt, kSaltBytes);
    blake3Keyed(keys.check, out, 48, out + 48, 16);
}

// ---- records --------------------------------------------------------------

u32 recordSeal(const ContainerKeys& keys, u64 nonce, u8 type, const ChunkId* id,
               const u8* payload, u32 n, u8* out) {
    u8 nb[kNonceBytes], ad[1 + kIdBytes];
    nonceOf(nonce, nb);
    adOf(type, id, ad);
    storeU32LE(out, n + kTagBytes);
    aeadSeal(keys.aead, nb, ad, sizeof ad, payload, n, out + 4);
    return n + kRecordOverhead;
}

bool recordOpen(const ContainerKeys& keys, u64 nonce, u8 type, const ChunkId* id,
                const u8* body, u32 len, u8* payload) {
    if (len < kTagBytes) return false;
    u8 nb[kNonceBytes], ad[1 + kIdBytes];
    nonceOf(nonce, nb);
    adOf(type, id, ad);
    return aeadOpen(keys.aead, nb, ad, sizeof ad, body, len - kTagBytes, payload);
}

// ---- reading --------------------------------------------------------------

Container::Container(Container&& o)
    : path(move(o.path)), fd(o.fd), fileSize(o.fileSize), kind(o.kind), keys(o.keys),
      chunks(move(o.chunks)), manifestOffset(o.manifestOffset), manifestLen(o.manifestLen),
      lastOffset(o.lastOffset), lastLen(o.lastLen) {
    o.fd = -1;
}

Container::~Container() {
    if (fd >= 0) ::close(fd);
    secureZero(&keys, sizeof keys);
}

namespace {

// Read a record at `offset`, check its length prefix against what the table
// says it is, authenticate it into `payload`.
bool readRecord(const Container& c, u64 offset, u32 len, u8 type, u64 nonce, const ChunkId* id,
                Array<u8>& scratch, Array<u8>& payload, String& err) {
    if (len < kTagBytes || offset + 4 + u64(len) > c.fileSize) return fail(err, c, "record outside the file (truncated or damaged)");
    scratch.resize(len + 4);
    if (!preadFull(c.fd, scratch.ptr, len + 4, offset, err)) return fail(err, c, err.view());
    if (loadU32LE(scratch.ptr) != len) return fail(err, c, "record length does not match the chunk table (damaged)");
    payload.resize(len - kTagBytes);
    if (!recordOpen(c.keys, nonce, type, id, scratch.ptr + 4, len, payload.ptr)) {
        String what("authentication failed for the record at offset ");
        what.appendU64(offset);
        what.append(" — the file was modified or damaged");
        return fail(err, c, what.view());
    }
    return true;
}

bool parseTrailer(Container& c, const u8* p, u32 n, String& err) {
    ByteReader r(p, n);
    if (r.varint() != 1) return fail(err, c, "unsupported trailer version");
    const u64 count = r.varintMax(u64(c.fileSize / kRecordOverhead));
    c.chunks.resize(u32(count));
    u64 off = kHeaderBytes, nonce = 0;
    for (u32 i = 0; i < count && !r.failed; ++i) {
        ChunkLoc& l = c.chunks[i];
        r.bytes(l.id.b, kIdBytes);
        l.recLen = u32(r.varintMax(kMaxChunk + 64));
        nonce += r.varint();
        l.nonce = nonce;
        l.rawLen = u32(r.varintMax(kMaxChunk));
        l.offset = off;
        off += 4 + u64(l.recLen);
        // Strictly increasing and below the metadata range: the writer never
        // reuses a nonce, so a table that claims otherwise is damaged.
        if ((i > 0 && l.nonce <= c.chunks[i - 1].nonce) || l.nonce >= kNonceMetaBase) r.failed = true;
    }
    c.manifestOffset = off;
    c.manifestLen = u32(r.varintMax(kMaxMetaRecord));
    if (r.failed || !r.done()) return fail(err, c, "malformed trailer");
    if (c.manifestOffset + 4 + c.manifestLen != c.lastOffset)
        return fail(err, c, "chunk table does not add up to the file layout (damaged)");
    return true;
}

} // namespace

bool containerOpen(const MasterKey& k, const char* path, Container& c, String& err) {
    c.path.assign(path);
    c.fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (c.fd < 0) return errSet(err, path, ": ", strerror(errno));
    struct stat st;
    if (fstat(c.fd, &st) != 0 || !S_ISREG(st.st_mode)) return fail(err, c, "not a regular file");
    c.fileSize = u64(st.st_size);
    if (c.fileSize < kHeaderBytes + kFooterBytes) return fail(err, c, "too short to be a backu file");

    u8 h[kHeaderBytes];
    if (!preadFull(c.fd, h, kHeaderBytes, 0, err)) return fail(err, c, err.view());
    if (!memEqual(h, kMagic, 8)) return fail(err, c, "not a backu file (bad magic)");
    const u16 version = u16(h[8] | (h[9] << 8));
    if (version != kFormatVersion) return fail(err, c, "unsupported format version");
    c.kind = u16(h[10] | (h[11] << 8));
    if (c.kind != kKindBackup && c.kind != kKindIndex) return fail(err, c, "unknown file kind");
    containerKeysDerive(k, h + 16, c.keys);
    u8 check[16];
    blake3Keyed(c.keys.check, h, 48, check, 16);
    // Not constant-time and need not be: the check value is a public function
    // of the header for whoever holds the key, and there is no oracle here.
    if (!memEqual(check, h + 48, 16)) return fail(err, c, "wrong key (or the header is damaged)");

    u8 f[kFooterBytes];
    if (!preadFull(c.fd, f, kFooterBytes, c.fileSize - kFooterBytes, err)) return fail(err, c, err.view());
    if (!memEqual(f + 8, kFooterMagic, 4)) return fail(err, c, "missing footer (truncated or still being written?)");
    c.lastOffset = loadU64LE(f);
    if (c.lastOffset < kHeaderBytes || c.lastOffset + 4 + kTagBytes + kFooterBytes > c.fileSize)
        return fail(err, c, "footer points outside the file (damaged)");
    u8 lp[4];
    if (!preadFull(c.fd, lp, 4, c.lastOffset, err)) return fail(err, c, err.view());
    c.lastLen = loadU32LE(lp);
    if (c.lastOffset + 4 + u64(c.lastLen) + kFooterBytes != c.fileSize)
        return fail(err, c, "last record does not end at the footer (damaged or truncated)");
    if (c.kind == kKindIndex) return true;

    Array<u8> body;
    if (!containerReadMeta(c, c.lastOffset, c.lastLen, kRecTrailer, kNonceTrailer, body, err)) return false;
    return parseTrailer(c, body.ptr, body.count, err);
}

bool containerReadMeta(const Container& c, u64 offset, u32 len, u8 type, u64 nonce,
                       Array<u8>& body, String& err) {
    if (len > kMaxMetaRecord) return fail(err, c, "metadata record too large (damaged)");
    Array<u8> scratch, payload;
    if (!readRecord(c, offset, len, type, nonce, nullptr, scratch, payload, err)) return false;
    u32 raw = 0;
    if (!codecRawLength(payload.ptr, payload.count, kMaxMetaRecord, raw)) return fail(err, c, "malformed metadata payload");
    body.resize(raw);
    if (!codecDecode(payload.ptr, payload.count, body.ptr, raw)) return fail(err, c, "metadata payload does not decompress");
    return true;
}

bool containerReadChunkPayload(const MasterKey& k, const Container& c, const ChunkLoc& loc,
                               Array<u8>& scratch, Array<u8>& payload, Array<u8>& raw, String& err) {
    if (!readRecord(c, loc.offset, loc.recLen, kRecChunk, loc.nonce, &loc.id, scratch, payload, err)) return false;
    u32 rawLen = 0;
    if (!codecRawLength(payload.ptr, payload.count, kMaxChunk, rawLen) || rawLen != loc.rawLen)
        return fail(err, c, "chunk payload length does not match the chunk table");
    raw.resize(rawLen);
    if (!codecDecode(payload.ptr, payload.count, raw.ptr, rawLen)) return fail(err, c, "chunk does not decompress");
    // GCM proved the record is the one this file sealed under this ID; the
    // keyed hash proves the ID is the content's. Both, because the second is
    // what makes dedupe across files trustworthy (merge copies by ID).
    ChunkId got;
    chunkIdOf(k, raw.ptr, rawLen, got);
    if (!idEqual(got, loc.id)) return fail(err, c, "chunk content does not match its ID");
    return true;
}

bool containerReadChunk(const MasterKey& k, const Container& c, const ChunkLoc& loc,
                        Array<u8>& scratch, Array<u8>& out, String& err) {
    Array<u8> payload;
    return containerReadChunkPayload(k, c, loc, scratch, payload, out, err);
}

// ---- writing --------------------------------------------------------------

bool writerBegin(ContainerWriter& w, OutStream& out, const MasterKey& k, String& err) {
    u8 salt[kSaltBytes];
    if (!randomBytes(salt, kSaltBytes, err)) return false;
    containerKeysDerive(k, salt, w.keys);
    w.out = &out;
    u8 h[kHeaderBytes];
    headerBuild(w.keys, kKindBackup, h);
    out.write(h, kHeaderBytes);
    return true;
}

void writerAddChunk(ContainerWriter& w, const ChunkId& id, u64 nonce, u32 rawLen, const u8* rec, u32 recTotal) {
    w.out->write(rec, recTotal);
    TrailerEntry& t = w.chunks.addDefault();
    t.id = id; t.nonce = nonce; t.recLen = recTotal - 4; t.rawLen = rawLen;
}

namespace {

void writeMeta(OutStream& out, const ContainerKeys& keys, u8 type, u64 nonce, const u8* body, u32 n) {
    CodecState* st = static_cast<CodecState*>(defaultAllocator().alloc(sizeof(CodecState)));
    Array<u8> payload, rec;
    payload.resize(codecBound(n));
    payload.count = codecEncode(*st, body, n, payload.ptr);
    defaultAllocator().free(st);
    rec.resize(payload.count + kRecordOverhead);
    recordSeal(keys, nonce, type, nullptr, payload.ptr, payload.count, rec.ptr);
    out.write(rec.ptr, rec.count);
}

void writeFooter(OutStream& out, u64 lastOffset) {
    u8 f[kFooterBytes];
    storeU64LE(f, lastOffset);
    memCopy(f + 8, kFooterMagic, 4);
    storeU32LE(f + 12, 0);
    out.write(f, kFooterBytes);
}

} // namespace

bool writerFinish(ContainerWriter& w, const u8* manifest, u32 n, String& err) {
    OutStream& out = *w.out;
    const u64 manifestOffset = out.written;
    writeMeta(out, w.keys, kRecManifest, kNonceManifest, manifest, n);
    const u32 manifestLen = u32(out.written - manifestOffset - 4);

    ByteWriter t;
    t.buf.reserve(w.chunks.count * 24 + 16);
    t.varint(1);
    t.varint(w.chunks.count);
    u64 prev = 0;
    for (const TrailerEntry& e : w.chunks) {
        t.bytes(e.id.b, kIdBytes);
        t.varint(e.recLen);
        t.varint(e.nonce - prev);
        t.varint(e.rawLen);
        prev = e.nonce;
    }
    t.varint(manifestLen);
    const u64 trailerOffset = out.written;
    writeMeta(out, w.keys, kRecTrailer, kNonceTrailer, t.buf.ptr, t.buf.count);
    writeFooter(out, trailerOffset);
    if (!out.flush()) return errSet(err, "writing the backup: ", strerror(out.savedErrno));
    return true;
}

bool indexFileWrite(const MasterKey& k, const char* path, const u8* body, u32 n, String& err) {
    ContainerKeys keys;
    u8 salt[kSaltBytes];
    if (!randomBytes(salt, kSaltBytes, err)) return false;
    containerKeysDerive(k, salt, keys);
    // Built whole in memory, then replaced atomically (writeFileAtomic): an
    // index is small next to the data it describes, and a torn one must never
    // be visible under the real name.
    Array<u8> payload;
    {
        CodecState* st = static_cast<CodecState*>(defaultAllocator().alloc(sizeof(CodecState)));
        payload.resize(codecBound(n));
        payload.count = codecEncode(*st, body, n, payload.ptr);
        defaultAllocator().free(st);
    }
    Array<u8> file;
    file.resize(kHeaderBytes + payload.count + kRecordOverhead + kFooterBytes);
    headerBuild(keys, kKindIndex, file.ptr);
    const u32 recTotal = recordSeal(keys, kNonceIndex, kRecIndex, nullptr, payload.ptr, payload.count,
                                    file.ptr + kHeaderBytes);
    u8* f = file.ptr + kHeaderBytes + recTotal;
    storeU64LE(f, kHeaderBytes);
    memCopy(f + 8, kFooterMagic, 4);
    storeU32LE(f + 12, 0);
    secureZero(&keys, sizeof keys);
    return writeFileAtomic(path, file.ptr, file.count, err);
}

bool indexFileRead(const MasterKey& k, const char* path, Array<u8>& body, String& err) {
    Container c;
    if (!containerOpen(k, path, c, err)) return false;
    if (c.kind != kKindIndex) return errSet(err, path, ": not an index file (it is a backup; pass an index made by create --index-out or backu index)");
    return containerReadMeta(c, c.lastOffset, c.lastLen, kRecIndex, kNonceIndex, body, err);
}

} // namespace bk
