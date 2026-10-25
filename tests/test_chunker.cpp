// test_chunker.cpp — the chunk boundary rules backups depend on.
//
// The property that matters is not the exact cut positions but that they are
// CONTENT-DEFINED: inserting bytes near the start of a file must leave the
// chunks after the edit unchanged, or every increment re-stores the whole
// file. The gear table is pinned too, because changing it silently moves
// every cut point for every existing user.

#include "chunk/chunker.hpp"
#include "core/array.hpp"
#include "test.hpp"

using namespace bk;

namespace {

void randomFill(Array<u8>& a, u32 n, u64 seed) {
    a.resize(n);
    u64 x = seed;
    for (u32 i = 0; i < n; ++i) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; a[i] = u8(x >> 24); }
}

void cutAll(const u8* p, u32 n, Array<u32>& lens) {
    u32 pos = 0;
    while (pos < n) { const u32 c = cdcNextCut(p + pos, n - pos); lens.push(c); pos += c; }
}

} // namespace

BK_TEST(cdc_sizes_stay_within_bounds_and_average_near_target) {
    Array<u8> data;
    randomFill(data, 32u << 20, 1);
    Array<u32> lens;
    cutAll(data.ptr, data.count, lens);
    u64 total = 0;
    bool bounds = true;
    for (u32 i = 0; i < lens.count; ++i) {
        total += lens[i];
        if (lens[i] > kCdcMax || (i + 1 < lens.count && lens[i] < kCdcMin)) bounds = false;
    }
    BK_CHECK(bounds);
    BK_CHECK_EQ(total, u64(data.count));
    const u64 avg = total / lens.count;
    printf("    cdc: %u chunks, average %llu bytes\n", lens.count, (unsigned long long)avg);
    BK_CHECK(avg > 12000 && avg < 24000);
}

BK_TEST(cdc_resynchronises_after_an_insertion_at_the_start) {
    Array<u8> a, b;
    randomFill(a, 4u << 20, 7);
    b.resize(a.count + 3);
    b[0] = 'x'; b[1] = 'y'; b[2] = 'z';
    memCopy(b.ptr + 3, a.ptr, a.count);
    Array<u32> la, lb;
    cutAll(a.ptr, a.count, la);
    cutAll(b.ptr, b.count, lb);
    // Compare chunk ends measured from the END of the data: after the first
    // couple of chunks every boundary must coincide.
    u32 same = 0;
    u32 ia = la.count, ib = lb.count;
    while (ia > 0 && ib > 0 && la[ia - 1] == lb[ib - 1]) { --ia; --ib; ++same; }
    BK_CHECK(same + 2 >= la.count);
}

BK_TEST(cdc_tail_shorter_than_min_is_one_chunk) {
    Array<u8> a;
    randomFill(a, 1000, 3);
    BK_CHECK_EQ(cdcNextCut(a.ptr, 1000), 1000u);
}

BK_TEST(sqlite_header_detection) {
    u8 h[100] = {};
    memCopy(h, "SQLite format 3", 16);   // includes the NUL
    h[16] = 0x10; h[17] = 0x00;          // 4096
    BK_CHECK_EQ(sqliteChunkSize(h, 100), 4096u);
    h[16] = 0x00; h[17] = 0x01;          // 1 means 65536
    BK_CHECK_EQ(sqliteChunkSize(h, 100), 65536u);
    h[16] = 0x02; h[17] = 0x00;          // 512 -> grouped to 4096
    BK_CHECK_EQ(sqliteChunkSize(h, 100), 4096u);
    h[16] = 0x10; h[17] = 0x01;          // not a power of two
    BK_CHECK_EQ(sqliteChunkSize(h, 100), 0u);
    h[16] = 0x10; h[17] = 0x00;
    BK_CHECK_EQ(sqliteChunkSize(h, 99), 0u);   // shorter than a header
    h[0] = 's';
    BK_CHECK_EQ(sqliteChunkSize(h, 100), 0u);
}

BK_TEST(cdc_two_phase_scan_matches_the_reference_definition) {
    // The pipeline cuts with cdcScan (in parallel segments) + cdcSelect; the
    // definition is cdcNextCut. Any disagreement would make cut points depend
    // on thread count or block boundaries, so check both shapes: one window,
    // and the same data fed as windows with a carried tail, scanned in
    // arbitrary segments.
    Array<u8> data;
    randomFill(data, 3u << 20, 11);
    Array<u32> ref;
    cutAll(data.ptr, data.count, ref);

    CdcHits whole;
    cdcScan(data.ptr, 0, data.count, whole);
    Array<Cut> cuts;
    BK_CHECK_EQ(cdcSelect(whole, data.count, true, cuts), data.count);
    BK_REQUIRE(cuts.count == ref.count);
    bool same = true;
    for (u32 i = 0; i < ref.count; ++i) same = same && cuts[i].len == ref[i];
    BK_CHECK(same);

    // Windowed: 300 KiB of new data per round, tail carried, 3 uneven segments.
    Array<u32> got;
    u32 consumed = 0;
    while (consumed < data.count) {
        const u32 avail = min<u32>(data.count - consumed, 300u << 10);
        const bool last = consumed + avail == data.count;
        // The window is whatever is pending: from `consumed` to the end of this round.
        const u32 roundEnd = consumed + avail;
        u32 winStart = consumed;
        (void)winStart;
        CdcHits parts[3];
        const u32 n = roundEnd - consumed;
        const u32 a = n / 5, b = n / 2;
        cdcScan(data.ptr + consumed, 0, a, parts[0]);
        cdcScan(data.ptr + consumed, a, b, parts[1]);
        cdcScan(data.ptr + consumed, b, n, parts[2]);
        CdcHits all;
        for (CdcHits& h : parts) { all.hard.appendRange(h.hard.ptr, h.hard.count); all.easy.appendRange(h.easy.ptr, h.easy.count); }
        Array<Cut> c;
        const u32 used = cdcSelect(all, n, last, c);
        for (const Cut& x : c) got.push(x.len);
        if (used == 0 && !last) {
            // Not enough for a maximal chunk yet: widen the next round.
            const u32 more = min<u32>(data.count - roundEnd, 300u << 10);
            CdcHits w;
            cdcScan(data.ptr + consumed, 0, n + more, w);
            Array<Cut> c2;
            const u32 used2 = cdcSelect(w, n + more, consumed + n + more == data.count, c2);
            for (const Cut& x : c2) got.push(x.len);
            consumed += used2;
            continue;
        }
        consumed += used;
    }
    BK_REQUIRE(got.count == ref.count);
    same = true;
    for (u32 i = 0; i < ref.count; ++i) same = same && got[i] == ref[i];
    BK_CHECK(same);
}
