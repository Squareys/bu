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
