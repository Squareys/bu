// bytes.hpp — little-endian and LEB128 byte encoding: ByteWriter and ByteReader.
//
// Every on-disk structure in bu (header, trailer, manifest, index) is built
// with these two and nothing else, so the format has exactly one notion of
// "a u64 on disk" and docs/format.md can define it once. Integers are unsigned
// LEB128 varints (7 bits per byte, little-endian groups) — the same shape as
// protobuf — because nearly every field is small (a mode, a length, a delta)
// and a fixed 8 bytes per field would make the manifest of a 100k-file tree
// several times larger before compression even sees it. Signed values go
// through zigzag so a small negative stays small.
//
// ByteReader never reads past its end and never traps: every getter sets a
// sticky `failed` flag on underrun or an over-long varint and returns zero, and
// the caller checks once at the end. That is what lets the decoders be written
// straight-line while still treating every byte of a decrypted record as
// untrusted input (an authenticated record is only as well-formed as the code
// that wrote it).
#pragma once

#include "array.hpp"
#include "string_view.hpp"

namespace bk {

inline void storeU32LE(u8* p, u32 v) { for (int i = 0; i < 4; ++i) p[i] = u8(v >> (8 * i)); }
inline void storeU64LE(u8* p, u64 v) { for (int i = 0; i < 8; ++i) p[i] = u8(v >> (8 * i)); }
inline u32 loadU32LE(const u8* p) { u32 v = 0; for (int i = 3; i >= 0; --i) v = (v << 8) | p[i]; return v; }
inline u64 loadU64LE(const u8* p) { u64 v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v; }
inline u16 loadU16BE(const u8* p) { return u16((u16(p[0]) << 8) | p[1]); }

inline u64 zigzagEncode(i64 v) { return (u64(v) << 1) ^ u64(v >> 63); }
inline i64 zigzagDecode(u64 v) { return i64(v >> 1) ^ -i64(v & 1); }

struct ByteWriter {
    Array<u8> buf;

    void bytes(const void* p, usize n) { buf.appendRange(static_cast<const u8*>(p), u32(n)); }
    void byte(u8 b) { buf.push(b); }
    void varint(u64 v) {
        u8 tmp[10]; u32 n = 0;
        while (v >= 0x80) { tmp[n++] = u8(v | 0x80); v >>= 7; }
        tmp[n++] = u8(v);
        bytes(tmp, n);
    }
    void svarint(i64 v) { varint(zigzagEncode(v)); }
    void str(StringView s) { varint(s.count); bytes(s.ptr, s.count); }
};

struct ByteReader {
    const u8* p = nullptr;
    const u8* end = nullptr;
    bool failed = false;

    ByteReader() = default;
    ByteReader(const u8* data, usize n) : p(data), end(data + n) {}

    usize remaining() const { return usize(end - p); }
    bool done() const { return p == end; }

    u8 byte() {
        if (p >= end) { failed = true; return 0; }
        return *p++;
    }
    // Pointer to the next n bytes (and skip them), or null with `failed` set.
    const u8* take(usize n) {
        if (n > remaining()) { failed = true; p = end; return nullptr; }
        const u8* r = p; p += n; return r;
    }
    bool bytes(void* out, usize n) {
        const u8* s = take(n);
        if (!s) { memSet(out, 0, n); return false; }
        memCopy(out, s, n); return true;
    }
    u64 varint() {
        u64 v = 0;
        for (u32 shift = 0; shift < 64; shift += 7) {
            if (p >= end) break;
            const u8 b = *p++;
            // The 10th byte may only carry the top bit of a u64; anything more
            // is an over-long encoding, refused rather than silently truncated.
            if (shift == 63 && b > 1) break;
            v |= u64(b & 0x7F) << shift;
            if (!(b & 0x80)) return v;
        }
        failed = true;
        return 0;
    }
    i64 svarint() { return zigzagDecode(varint()); }
    // A varint that must also fit `limit` (counts that size an allocation).
    u64 varintMax(u64 limit) {
        const u64 v = varint();
        if (v > limit) { failed = true; return 0; }
        return v;
    }
    StringView str(u32 maxLen) {
        const u64 n = varintMax(maxLen);
        const u8* s = take(n);
        return s ? StringView(reinterpret_cast<const char*>(s), u32(n)) : StringView();
    }
};

} // namespace bk
