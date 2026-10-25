// chunker.hpp — where chunks end: FastCDC for general files, exact page
// boundaries for SQLite databases.
//
// CONTENT-DEFINED CHUNKING (FastCDC, Xia et al. 2016/2020). A 64-bit "gear"
// rolling hash (h = (h << 1) + G[byte]) runs over the data and a chunk ends
// where selected hash bits are all zero. Because the hash only depends on the
// last ~64 bytes, a cut point is a property of the content around it, not of
// its offset: insert a byte at the start of a 1 GB file and every chunk after
// the first re-synchronises at the same content, so only the chunk around the
// edit is new. Fixed-size chunking would shift and re-store all of it.
// Parameters: min 4 KiB, average ~16 KiB, max 64 KiB, with FastCDC's
// "normalised chunking" — a harder mask (15 bits) before the average and an
// easier one (13 bits) after it — which pulls sizes toward the average.
// docs/design.md §Chunking has the measured size distribution.
//
// SQLITE. SQLite updates pages in place; a database is an array of fixed-size
// pages and an UPDATE rewrites exactly the pages it touches. CDC would work
// but would cut across page boundaries, so one changed page would usually
// dirty two chunks. Chunking at the page size makes the increment exactly the
// changed pages. A file is treated as SQLite when its first 16 bytes are
// "SQLite format 3\0" and the big-endian page size at offset 16 is a power of
// two in 512..32768 (or 1, which means 65536). Pages under 4 KiB are grouped
// to 4 KiB chunks: below that the ~60 bytes of per-chunk overhead (record,
// table entry, manifest reference) stop being small next to the payload.
#pragma once

#include "core/types.hpp"

namespace bk {

constexpr u32 kCdcMin = 4u << 10;
constexpr u32 kCdcAvg = 16u << 10;
constexpr u32 kCdcMax = 64u << 10;

// Length of the next chunk in p[0..n). Call it with n >= kCdcMax unless this is the
// end of the file, in which case n may be anything > 0; the result is at most
// min(n, kCdcMax). Pure function of the bytes: the same data cuts the same way.
u32 cdcNextCut(const u8* p, u32 n);

// Fixed chunk size for a SQLite database whose first `n` bytes are `head`, or
// 0 if this is not a SQLite database (then use CDC).
u32 sqliteChunkSize(const u8* head, u32 n);

} // namespace bk
