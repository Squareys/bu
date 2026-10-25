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

// The reference definition. The hash at byte i is the gear hash of bytes
// [i-63, i]; it is primed over the 63 bytes before kCdcMin, so the first
// tested position already sees a full window. (Without the priming the cut
// points would depend on the chunk start and phase 1 could not run ahead.)
BK_HOT u32 cdcNextCut(const u8* p, u32 n) {
    if (n <= kCdcMin) return n;     // only legal at eof: the tail is one chunk
    const u32 limit = n < kCdcMax ? n : kCdcMax;
    const u32 normal = limit < kCdcAvg ? limit : kCdcAvg;
    u64 h = 0;
    for (u32 i = kCdcMin - 63; i < kCdcMin; ++i) h = (h << 1) + kGear.v[p[i]];
    u32 i = kCdcMin;
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

namespace {

// Positions i in [0, n) of p, hash primed over p[-warm, 0), recorded as base + i.
inline void scanImpl(const u8* p, u32 warm, u32 n, u32 base, CdcHits& out) {
    u64 h = 0;
    for (const u8* q = p - warm; q < p; ++q) h = (h << 1) + kGear.v[*q];
    // Easy hits are ~1 in 8 KiB and hard ones ~1 in 32 KiB, and the 9 mask
    // bits they share pass ~1 in 512, so the branch is almost never taken and
    // the loop is one load, one shift-add and one test per byte.
    constexpr u64 kEither = kMaskHard & kMaskEasy;
    for (u32 i = 0; i < n; ++i) {
        h = (h << 1) + kGear.v[p[i]];
        if (__builtin_expect(!(h & kEither), 0)) {
            if (!(h & kMaskHard)) out.hard.push(base + i);
            if (!(h & kMaskEasy)) out.easy.push(base + i);
        }
    }
}

} // namespace

BK_HOT void cdcScan(const u8* p, u32 from, u32 to, CdcHits& out) {
    scanImpl(p + from, from >= 63 ? 63 : from, to - from, from, out);
}

BK_HOT void cdcScanWarm(const u8* p, u32 warm, u32 n, CdcHits& out) {
    scanImpl(p, warm > 63 ? 63 : warm, n, 0, out);
}

BK_HOT u32 cdcSelect(const CdcHits& hits, u32 n, bool last, Array<Cut>& cuts) {
    u32 start = 0, ih = 0, ie = 0;
    for (;;) {
        const u32 rem = n - start;
        if (rem == 0 || (!last && rem < kCdcMax)) break;
        u32 len;
        if (rem <= kCdcMin) {
            len = rem;
        } else {
            const u32 limit = start + (rem < kCdcMax ? rem : kCdcMax);
            const u32 normal = limit < start + kCdcAvg ? limit : start + kCdcAvg;
            // Both lists ascend and chunk starts only move forward, so each
            // index only ever advances: the whole selection is linear.
            while (ih < hits.hard.count && hits.hard[ih] < start + kCdcMin) ++ih;
            while (ie < hits.easy.count && hits.easy[ie] < normal) ++ie;
            if (ih < hits.hard.count && hits.hard[ih] < normal) len = hits.hard[ih] + 1 - start;
            else if (ie < hits.easy.count && hits.easy[ie] < limit) len = hits.easy[ie] + 1 - start;
            else len = limit - start;
        }
        cuts.push(Cut{start, len});
        start += len;
    }
    return start;
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
