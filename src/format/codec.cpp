// codec.cpp — LZ4 framing for record payloads; the one TU that includes lz4.h.

#include "format/codec.hpp"
#include "core/bytes.hpp"

extern "C" {
#include "lz4.h"
}

namespace bk {

static_assert(sizeof(CodecState) >= sizeof(LZ4_stream_t), "CodecState must hold an LZ4_stream_t");

u32 codecBound(u32 n) {
    const u32 lz = u32(LZ4_compressBound(int(n)));
    return 5 + (lz > n ? lz : n);
}

BK_HOT u32 codecEncode(CodecState& st, const u8* raw, u32 n, u8* out, bool compress) {
    if (compress && n >= 64) {
        // extState: LZ4 initialises the state we own, so no malloc per call
        // and no 16 KB stack frame per worker. Output capped at n-5 bytes so a
        // payload that does not shrink fails fast instead of being finished.
        const int c = LZ4_compress_fast_extState(st.opaque, reinterpret_cast<const char*>(raw),
                                                 reinterpret_cast<char*>(out + 5), int(n), int(n) - 5, 1);
        if (c > 0 && u32(c) + 5 < n + 1) {
            out[0] = kCodecLz4;
            storeU32LE(out + 1, n);
            return u32(c) + 5;
        }
    }
    out[0] = kCodecStored;
    memCopy(out + 1, raw, n);
    return n + 1;
}

bool codecRawLength(const u8* enc, u32 n, u32 maxRaw, u32& rawLen) {
    if (n < 1) return false;
    if (enc[0] == kCodecStored) { rawLen = n - 1; return rawLen <= maxRaw; }
    if (enc[0] != kCodecLz4 || n < 5) return false;
    rawLen = loadU32LE(enc + 1);
    return rawLen <= maxRaw;
}

BK_HOT bool codecDecode(const u8* enc, u32 n, u8* out, u32 rawLen) {
    if (enc[0] == kCodecStored) {
        if (n - 1 != rawLen) return false;
        memCopy(out, enc + 1, rawLen);
        return true;
    }
    // LZ4_decompress_safe never writes past rawLen and never reads past n-5,
    // whatever the input: the bounds-checked decoder, as untrusted input needs
    // (an authenticated payload is still only as well-formed as its writer).
    const int d = LZ4_decompress_safe(reinterpret_cast<const char*>(enc + 5), reinterpret_cast<char*>(out),
                                      int(n - 5), int(rawLen));
    return d >= 0 && u32(d) == rawLen;
}

} // namespace bk
