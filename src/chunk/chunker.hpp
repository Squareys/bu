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
// Parameters: min 4 KiB, average ~20 KiB, max 64 KiB, with FastCDC's
// "normalised chunking" — a harder mask (15 bits) before 16 KiB and an easier
// one (13 bits) after it — which pulls sizes toward the average.
//
// TWO PHASES, SO THE SCAN CAN RUN IN PARALLEL. The hash tested at byte i is
// the gear hash of the 64 bytes ending at i (older bytes have shifted out of
// the 64-bit state), and no position closer than kCdcMin to a chunk start is
// ever tested. So whether byte i is a candidate does not depend on where the
// current chunk started, and a window can be scanned for candidates in
// independent segments (phase 1, cdcScan, on several threads), after which
// picking the cuts is a cheap serial walk over a sparse candidate list
// (phase 2, cdcSelect). cdcNextCut is the straightforward one-pass
// definition; tests/test_chunker.cpp proves the two agree.
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

#include "core/array.hpp"


namespace bk {

constexpr u32 kCdcMin = 4u << 10;
constexpr u32 kCdcAvg = 16u << 10;   // where the mask switches from hard to easy
constexpr u32 kCdcMax = 64u << 10;

// Length of the next chunk in p[0..n). Call it with n >= kCdcMax unless this is the
// end of the file, in which case n may be anything > 0; the result is at most
// min(n, kCdcMax). Pure function of the bytes: the same data cuts the same way.
u32 cdcNextCut(const u8* p, u32 n);

// Candidate positions in a window, ascending: bytes whose 64-byte gear hash
// passes the hard (resp. easy) mask. Positions are window offsets.
struct CdcHits {
    Array<u32> hard;
    Array<u32> easy;
};

// Phase 1: append the candidates among positions [from, to) of window p.
// Thread-safe for disjoint ranges into separate CdcHits.
void cdcScan(const u8* p, u32 from, u32 to, CdcHits& out);
// Phase 1 over p[0..n) where the `warm` (<= 63) bytes before p are the data
// that precedes it in the file: positions are recorded relative to p. This is
// how a reader scans a block it has read together with its 63-byte prefix.
void cdcScanWarm(const u8* p, u32 warm, u32 n, CdcHits& out);

struct Cut { u32 off, len; };

// Phase 2: cut window p[0..n) using its candidates (all positions scanned).
// Stops when the rest is shorter than kCdcMax and `last` is false (that tail
// carries over to the next window); returns the bytes consumed.
u32 cdcSelect(const CdcHits& hits, u32 n, bool last, Array<Cut>& cuts);

// Fixed chunk size for a SQLite database whose first `n` bytes are `head`, or
// 0 if this is not a SQLite database (then use CDC).
u32 sqliteChunkSize(const u8* head, u32 n);

} // namespace bk
