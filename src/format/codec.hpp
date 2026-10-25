// codec.hpp — the plaintext payload of a record: optional LZ4 around a body.
//
// Every record (chunk, manifest, trailer, index) encrypts the same shape:
//
//   u8 codec            0 = stored, 1 = LZ4 block
//   u32 LE rawLength    only when codec == 1
//   body
//
// "Store when compression doesn't help" is decided per payload: LZ4 runs, and
// if its output plus the 4-byte length is not strictly smaller than the input,
// the input is stored as is. Already-compressed data (JPEG, zstd, encrypted
// files) therefore costs one LZ4 attempt and one byte, never growth. LZ4 is
// the speed choice (docs/design.md §Compression): at ~700 MB/s per core it
// is not the bottleneck behind disk I/O, where zstd would be.
//
// The one TU allowed to include lz4.h is codec.cpp.
#pragma once

#include "core/types.hpp"
#include "core/string.hpp"

namespace bk {

constexpr u8 kCodecStored = 0;
constexpr u8 kCodecLz4 = 1;

// Worst-case encoded size for a raw payload of n bytes.
u32 codecBound(u32 n);

// Per-thread LZ4 compression state (LZ4's hash table, ~16 KB). Opaque.
struct CodecState {
    alignas(8) u8 opaque[16416];
};

// Encode raw[0..n) into out (codecBound(n) bytes); returns the encoded size.
// `compress` false forces stored (the manifest of an empty tree, tests).
u32 codecEncode(CodecState& st, const u8* raw, u32 n, u8* out, bool compress = true);

// Raw length an encoded payload claims (stored: n-1); false if malformed or
// above maxRaw. Lets the caller size the output before decoding.
[[nodiscard]] bool codecRawLength(const u8* enc, u32 n, u32 maxRaw, u32& rawLen);

// Decode into out (which holds rawLen bytes from codecRawLength); false if the
// LZ4 stream is malformed or does not produce exactly rawLen bytes.
[[nodiscard]] bool codecDecode(const u8* enc, u32 n, u8* out, u32 rawLen);

} // namespace bk
