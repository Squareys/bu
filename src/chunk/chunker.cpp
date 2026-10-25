// chunker.cpp — FastCDC cut finding and SQLite detection; see chunker.hpp.

#include "chunk/chunker.hpp"

namespace bk {

namespace {

// The gear table: 256 pseudo-random 64-bit values, generated at compile time
// with SplitMix64 from a fixed seed. Fixed forever — changing a single value
// moves every cut point and makes the next backup re-store everything — so
// the seed is part of the format, and test_chunker pins two entries.
struct GearTable { u64 v[256]; };
constexpr GearTable makeGear() {
    GearTable t{};
    u64 s = 0x6261636b75636463ull;   // "backucdc"
    for (int i = 0; i < 256; ++i) {
        s += 0x9e3779b97f4a7c15ull;
        u64 z = s;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
        t.v[i] = z ^ (z >> 31);
    }
    return t;
}
constexpr GearTable kGear = makeGear();

// A mask of `bits` one-bits spread evenly over the top 32 bit positions. With
// the left-shifting gear hash, bit k depends on the last k+1 bytes, so using
// high bits gives every tested bit a window of 32-64 bytes — enough context
// that cut points are content-defined rather than byte-defined.
constexpr u64 spreadMask(int bits) {
    u64 m = 0;
    for (int i = 0; i < bits; ++i) m |= u64(1) << (63 - (i * 32) / bits);
    return m;
}
constexpr u64 kMaskHard = spreadMask(15);   // before the average: P(cut) = 2^-15
constexpr u64 kMaskEasy = spreadMask(13);   // after it: 2^-13
static_assert(__builtin_popcountll(kMaskHard) == 15 && __builtin_popcountll(kMaskEasy) == 13, "masks");

} // namespace

u32 cdcNextCut(const u8* p, u32 n) {
    if (n <= kCdcMin) return n;     // only legal at eof: the tail is one chunk
    const u32 limit = n < kCdcMax ? n : kCdcMax;
    const u32 normal = limit < kCdcAvg ? limit : kCdcAvg;
    u64 h = 0;
    u32 i = kCdcMin;
    // FastCDC skips the first kCdcMin bytes: no cut can fall there, so
    // hashing them would only be work. The hash therefore starts empty at
    // kCdcMin, which is fine — the mask only looks at high bits, which fill
    // within ~32 bytes.
    for (; i < normal; ++i) {
        h = (h << 1) + kGear.v[p[i]];
        if (!(h & kMaskHard)) return i + 1;
    }
    for (; i < limit; ++i) {
        h = (h << 1) + kGear.v[p[i]];
        if (!(h & kMaskEasy)) return i + 1;
    }
    return limit;
}

u32 sqliteChunkSize(const u8* head, u32 n) {
    static const u8 kMagic[16] = {'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3',0};
    if (n < 100 || __builtin_memcmp(head, kMagic, 16) != 0) return 0;
    u32 page = (u32(head[16]) << 8) | head[17];
    if (page == 1) page = 65536;
    if (page < 512 || page > 65536 || (page & (page - 1))) return 0;
    return page >= 4096 ? page : 4096;
}

} // namespace bk
