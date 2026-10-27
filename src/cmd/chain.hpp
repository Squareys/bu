// chain.hpp — the segments of one chain, read together: restore, check,
// merge, index, list and create (for its base) all start here.
//
// A chain is the CHAIN arguments in order: chain files, or one file per
// segment, or `-`. Nothing in a segment refers to another by FILE NAME OR
// OFFSET: a delta manifest names its parent by snapshot ID, and a chunk is
// found by its ID in whichever segment holds it. That is what keeps chains
// valid after a merge (the merged file has a new name and salt, and
// increments made before or after it still resolve), and what lets a chain
// be several files or one.
//
// TWO WAYS TO READ, chosen by the descriptor, never by a flag:
//
//   seek     a regular file (a path, or `-` when stdin is one). Each source is
//            walked back from its end, trailer by trailer, to offset 0; only
//            the trailers, headers, tables and the manifests needed are read,
//            through a window of kWindow bytes so that small segments cost no
//            extra round trip on a network mount. Chunk data is read later in
//            spans (chainReadSpan).
//   stream   a pipe on stdin, the only argument. The records are read once,
//            in order: chunk records go to a sink in batches as they arrive,
//            manifests and tables are kept. Nothing is buffered on disk.
//
// AN INCOMPLETE TAIL. A create killed mid-append (SIGKILL, power loss) leaves
// a partial segment at the end of a chain file. A seek reader that finds no
// valid trailer at the end scans back for the last one that starts a valid
// walk to offset 0, and ignores what follows (Source::tail); the next create
// cuts it off. A stream reader reports a stream that ends inside a segment.
//
// "The latest snapshot" is the one with the highest generation (from the
// trailers, so no manifest is decrypted to find it); on a tie the later
// segment wins, and list says which it picked.
#pragma once

#include "core/hash_index.hpp"
#include "format/segment.hpp"
#include "format/snapshot.hpp"

namespace bk {

// One CHAIN argument.
struct Source {
    String path;               // as named; "-" is stdin
    int fd = -1;
    bool own = false;          // we opened it (stdin is not ours to close)
    bool seekable = false;
    u64 size = 0;              // seek: the end of the last complete segment
    u64 tail = 0;              // seek: bytes after it (an incomplete segment)
    bool writerActive = false; // another bu held the chain's lock when we looked

    Source() = default;
    Source(Source&& o);
    Source(const Source&) = delete;
    ~Source();
};

struct ChunkLoc {
    ChunkId id;
    u64 offset = 0;     // seek: of the record's length prefix, in its source
    u64 nonce = 0;
    u32 recLen = 0;     // L
    u32 rawLen = 0;     // decoded chunk size
};

struct Seg {
    u32 source = 0;
    u64 start = 0;                  // offset of its header in the source
    u8 header[kHeaderBytes];
    SegKeys keys;
    Trailer t;
    Array<ChunkLoc> chunks;         // from the table
    bool tableLoaded = false;
    Array<u8> manifest;             // the decrypted manifest body
    bool manifestLoaded = false;
    Snapshot head;                  // header fields (snapshotPeek)
    Snapshot snap;                  // fully decoded, once resolved
    bool resolved = false;
    bool resolving = false;         // cycle guard

    Seg() = default;
    Seg(Seg&&) = default;
    Seg& operator=(Seg&&) = default;
};

// A stream reader's buffer (stdin as a pipe).
struct StreamIn {
    Array<u8> buf;
    u32 head = 0, tail = 0;    // unread bytes are buf[head..tail)
    u64 pos = 0;               // stream offset of buf[head]
    bool eof = false;
};

struct Chain {
    const MasterKey* key = nullptr;
    Array<Source> sources;
    Array<Seg> segs;           // sources in argument order, each front to back
    bool plain = false;        // unencrypted (the first header says so)
    u16 firstKind = 0;         // the first header's kind (an index file: list)
    bool stream = false;       // one source, read as a stream
    StreamIn in;
    u64 streamTail = 0;        // stream: bytes of an incomplete last segment
    // Chunk ID -> (segment << 32 | chunk): the first segment listing an ID wins.
    HashIndex idIndex;
    Array<u64> idWhere;
};

// Open the CHAIN arguments (paths, or "-" for stdin) and read the first
// header, which says whether the chain is encrypted (c.plain). A pipe must be
// the only argument and is read as a stream; a regular file is read by
// seeking. `err` names the argument.
[[nodiscard]] bool chainArgsOpen(const Array<const char*>& args, Chain& c, String& err);
// The same for a descriptor create already holds (the chain it appends to).
[[nodiscard]] bool chainFdOpen(int fd, const char* name, Chain& c, String& err);

// Seek mode, with c.key set: walk every source back from its end, checking
// every header (the key, and that no segment's mode differs from the first)
// and trailer, past an incomplete tail. Tables and manifests are not read.
[[nodiscard]] bool chainWalk(Chain& c, String& err);
// Seek mode, for create appending to the chain in source 0: the segments
// from the end back to the last self-contained manifest in the last
// segment's ancestry, and no further (a long chain costs create a few reads,
// not one per segment). An incomplete tail is found as chainWalk finds it.
// Front-to-back order; the last segment's snapshot is the base.
[[nodiscard]] bool chainWalkTail(Chain& c, String& err);
// Seek mode: read every segment's table and index the chunk IDs.
[[nodiscard]] bool chainLoadTables(Chain& c, String& err);

// Stream mode, with c.key set: read the whole stream. Chunk records are
// handed to the sink in batches (`body` points into the stream buffer and is
// valid during the call); manifests and tables are kept, and each table is
// checked against the records that came before it. False from the sink stops
// the stream with its error. An incomplete last segment is left out and its
// size put in c.streamTail; the caller decides what that means.
struct StreamChunk {
    u32 seg, index;            // segment, and the record's index in it
    u64 nonce;
    const u8* body;
    u32 bodyLen;
};
struct StreamSink {
    bool (*fn)(void* ctx, Chain& c, const StreamChunk* recs, u32 n, String& err) = nullptr;
    void* ctx = nullptr;
};
[[nodiscard]] bool chainStream(Chain& c, StreamSink* sink, String& err);
// Stream mode, after chainStream: index the chunk IDs from the tables.
void chainIndexChunks(Chain& c);

// The segment holding the latest snapshot.
u32 chainLatest(const Chain& c);
// Load (seek mode) and peek segment i's manifest.
[[nodiscard]] bool chainHead(Chain& c, u32 i, String& err);
// Fully decode segment i's snapshot, resolving parents among the segments.
[[nodiscard]] bool chainResolve(Chain& c, u32 i, String& err);
// Where a chunk is; false if no segment has it.
bool chainFind(const Chain& c, const ChunkId& id, u32& seg, u32& chunk);
// Every distinct ref of `s` that no segment holds (for messages).
u32 chainCountMissing(const Chain& c, const Snapshot& s);
// "path" or "path at offset N" for messages about segment i.
void chainSegName(const Chain& c, u32 i, String& out);
// The notes a reader prints about incomplete tails (once per source).
void chainReportTails(const Chain& c);

// The checkpoint counters of segment i's snapshot (see IndexData): the
// manifest bytes written as deltas since the last self-contained manifest in
// its ancestry, and that manifest's bytes. Resolves as needed.
[[nodiscard]] bool chainCheckpoint(Chain& c, u32 i, u64& deltaBytes, u64& fullBytes, String& err);

// ---- reading chunk records (seek mode) ----------------------------------------

// Read the records of chunks [first, first + count) of segment `s` —
// consecutive in the file by construction — with one pread into `span`.
// Restore, check and merge read a chain this way, in spans of about
// kSpanBytes: one ~20 KiB pread per record from many threads at scattered
// offsets left them at half the speed of a sequential read of the same file.
constexpr u32 kSpanBytes = 256u << 10;
// The span size for `total` bytes of records read by `threads` threads:
// kSpanBytes, or less when that would leave threads idle (small chains).
inline u64 chainSpanTarget(u64 total, u32 threads) {
    return min<u64>(kSpanBytes, max<u64>(u64(64) << 10, total / (u64(threads) * 4)));
}
// The bytes chainReadSpan reads for chunks [first, first + count).
u64 chainSpanBytes(const Seg& s, u32 first, u32 count);
[[nodiscard]] bool chainReadSpan(const Chain& c, u32 seg, u32 first, u32 count, Array<u8>& span, String& err);
// Ask the kernel to start reading a span now (POSIX_FADV_WILLNEED). A task
// prefetches the span `chainPrefetchTasks` tasks ahead of its own, so about
// kPrefetchBytes of reads stay queued whatever the thread count: on one
// disk shared with the restore's writes, that queue depth is what keeps the
// reads going.
void chainPrefetchSpan(const Chain& c, u32 seg, u32 first, u32 count);
constexpr u64 kPrefetchBytes = u64(16) << 20;
inline u32 chainPrefetchTasks(u64 spanTarget, u32 threads) {
    return max<u32>(threads, u32(kPrefetchBytes / spanTarget));
}
// Authenticate chunk `index` of segment `seg` from its record `rec` (length
// prefix first, as read by chainReadSpan), leaving the still-encoded payload
// in `payload` and the decoded, verified bytes in `out` (rawLen bytes).
// `checkHead`: also open the record header and compare it with the table
// (check does; restore and merge skip it, the table being authenticated).
[[nodiscard]] bool chainOpenChunk(const Chain& c, u32 seg, u32 index, const u8* rec, bool checkHead,
                                  Array<u8>& payload, u8* out, String& err);

// ---- index files --------------------------------------------------------------

[[nodiscard]] bool indexFileWrite(const MasterKey& k, const char* path, const IndexData& d, String& err);
// Read an index file: its mode must match `k` (refused by name otherwise).
[[nodiscard]] bool indexFileRead(const MasterKey& k, const char* path, IndexData& d, String& err);
// The first header of a file, to learn whether it is encrypted before
// unlocking a key (an index given to create or restore).
[[nodiscard]] bool fileHeaderPeek(const char* path, u16& kind, bool& plain, String& err);

} // namespace bk
