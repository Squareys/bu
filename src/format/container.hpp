// container.hpp — the bu file format: header, sealed records, footer.
//
// One container shape serves both kinds of file bu writes — a backup and an
// index — so there is one parser to harden and one place docs/format.md
// describes. Layout (all integers little-endian):
//
//   header   64 bytes, plaintext
//            magic "BUBAK\r\n\x1a" | u16 version | u16 kind | u32 reserved
//            | salt[32] | check[16] = keyed-BLAKE3(checkKey, header[0..48))
//   records  repeated: u32 length | AES-256-GCM ciphertext | 16-byte tag
//   footer   16 bytes: u64 trailer offset | "BKFT" | u32 reserved (0)
//
// A backup's records are its new chunks (in stream order), then the manifest,
// then the trailer (the per-file chunk table). An index file has exactly one
// record, the index. The footer points at the last record so a reader that can
// seek finds the table without scanning; a writer streaming to a pipe can
// still produce it because it counts bytes as it goes.
//
// KEYS AND NONCES (docs/design.md §Nonces). The master key never encrypts
// anything. Each container draws a fresh random 32-byte salt and derives its
// own AES key and header-check key from master||salt with BLAKE3 derive_key,
// so two containers never share an AES key and nonce reuse across files is
// impossible by construction. Within a container the nonce is a 64-bit counter
// (little-endian, then four zero bytes): chunk records use their stream
// sequence number (< 2^63), metadata records use fixed values with the top bit
// set. Every record's associated data is its type byte plus its chunk ID (zero
// for metadata), so a record cannot be replayed as a different type or under a
// different ID even inside one file.
#pragma once

#include "core/array.hpp"
#include "core/string.hpp"
#include "crypto/crypto.hpp"
#include "io/io.hpp"

namespace bk {

constexpr u32 kHeaderBytes = 64;
constexpr u32 kFooterBytes = 16;
constexpr u32 kRecordOverhead = 4 + kTagBytes;   // length prefix + tag
constexpr u16 kFormatVersion = 1;

constexpr u16 kKindBackup = 1;
constexpr u16 kKindIndex = 2;

constexpr u8 kRecChunk = 1;
constexpr u8 kRecManifest = 2;
constexpr u8 kRecTrailer = 3;
constexpr u8 kRecIndex = 4;

// Largest raw chunk any chunker emits (CDC max, or one 64 KiB SQLite page).
constexpr u32 kMaxChunk = 64u << 10;
// Largest metadata record (manifest, trailer, index) a reader will allocate
// for. The trailer is the one that grows: ~22 bytes per new chunk, so 3 GiB
// bounds one backup file at ~140 million new chunks, ~2.8 TB of unique data
// at the average chunk size (docs/design.md §12).
constexpr u32 kMaxMetaRecord = 3u << 30;

constexpr u64 kNonceMetaBase = u64(1) << 63;
constexpr u64 kNonceManifest = kNonceMetaBase + 0;
constexpr u64 kNonceTrailer = kNonceMetaBase + 1;
constexpr u64 kNonceIndex = kNonceMetaBase + 2;

// The master key K and what every backup derives from it. K comes out of a
// key file's slot (format/keyfile.hpp); nothing here knows about passphrases.
// Wiped when it goes out of scope, whichever way a command exits.
struct MasterKey {
    Key master;
    Key idKey;        // derived: keyed-BLAKE3 key for chunk IDs
    ~MasterKey() { secureZero(this, sizeof *this); }
};

// Set out.master = master and derive idKey.
void masterKeyInit(const Key& master, MasterKey& out);

// The chunk ID: keyed BLAKE3 of the raw chunk, truncated to 128 bits.
void chunkIdOf(const MasterKey& k, const u8* data, usize n, ChunkId& out);

struct ContainerKeys {
    u8 salt[kSaltBytes];
    AeadKey aead;
    Key check;
};

void containerKeysDerive(const MasterKey& k, const u8 salt[kSaltBytes], ContainerKeys& out);

void headerBuild(const ContainerKeys& keys, u16 kind, u8 out[kHeaderBytes]);

// Seal an encoded payload (format/codec.hpp) as a record into out, which must
// hold n + kRecordOverhead bytes. `id` is null for metadata records. Returns
// the record's total size. Thread-safe (keys are read-only).
u32 recordSeal(const ContainerKeys& keys, u64 nonce, u8 type, const ChunkId* id,
               const u8* payload, u32 n, u8* out);

// Open a record body (ciphertext + tag, `len` bytes, i.e. without the length
// prefix) into payload (len - kTagBytes bytes). False on authentication failure.
[[nodiscard]] bool recordOpen(const ContainerKeys& keys, u64 nonce, u8 type, const ChunkId* id,
                              const u8* body, u32 len, u8* payload);

// ---- reading -------------------------------------------------------------

struct ChunkLoc {
    ChunkId id;
    u64 offset = 0;     // of the record's length prefix
    u64 nonce = 0;
    u32 recLen = 0;     // ciphertext + tag
    u32 rawLen = 0;     // decoded chunk size
};

struct Container {
    String path;
    int fd = -1;
    u64 fileSize = 0;
    u16 kind = 0;
    ContainerKeys keys;
    // Backup only: the chunk table from the trailer, and where the manifest is.
    Array<ChunkLoc> chunks;
    u64 manifestOffset = 0;
    u32 manifestLen = 0;
    // The last record (trailer of a backup, the index of an index file).
    u64 lastOffset = 0;
    u32 lastLen = 0;

    Container() = default;
    Container(const Container&) = delete;
    Container& operator=(const Container&) = delete;
    // Moves hand the descriptor over (Array<Container> grows by moving).
    Container(Container&& o);
    Container& operator=(Container&& o) = delete;
    ~Container();
};

// Open, check header (wrong key is reported as such), footer and — for a
// backup — decrypt and parse the trailer. `err` names the file.
[[nodiscard]] bool containerOpen(const MasterKey& k, const char* path, Container& c, String& err);

// Read, authenticate and decode a metadata record into `body`.
[[nodiscard]] bool containerReadMeta(const Container& c, u64 offset, u32 len, u8 type, u64 nonce,
                                     Array<u8>& body, String& err);

// Read one chunk record, authenticate it, decode it into `out` (resized to
// rawLen) and verify that its keyed hash is the ID it was filed under.
// Thread-safe: pread only. `scratch` is caller-owned to avoid per-call mallocs.
[[nodiscard]] bool containerReadChunk(const MasterKey& k, const Container& c, const ChunkLoc& loc,
                                      Array<u8>& scratch, Array<u8>& out, String& err);
// Read and authenticate one chunk record, leaving the still-encoded payload
// in `payload` (merge re-seals it without recompressing) and the decoded
// bytes in `raw`; verifies the ID like containerReadChunk.
[[nodiscard]] bool containerReadChunkPayload(const MasterKey& k, const Container& c, const ChunkLoc& loc,
                                             Array<u8>& scratch, Array<u8>& payload, Array<u8>& raw,
                                             String& err);

// Read the records of chunks [first, first + count) of a backup — consecutive
// in the file by construction — with one pread into `span` (resized). Restore
// and check read the backup this way, in spans of about kSpanBytes: one
// ~20 KiB pread per record from many threads at scattered offsets left them
// at half the speed of a sequential read of the same file.
constexpr u32 kSpanBytes = 256u << 10;
// The span size for `total` bytes of records read by `threads` threads:
// kSpanBytes, or less when that would leave threads idle (small backups).
inline u64 containerSpanTarget(u64 total, u32 threads) {
    return min<u64>(kSpanBytes, max<u64>(u64(64) << 10, total / (u64(threads) * 4)));
}
[[nodiscard]] bool containerReadSpan(const Container& c, u32 first, u32 count, Array<u8>& span, String& err);
// Ask the kernel to start reading a span now (POSIX_FADV_WILLNEED). A task
// prefetches the span `containerPrefetchTasks` tasks ahead of its own, so
// about kPrefetchBytes of reads stay queued whatever the thread count: on one
// disk shared with the restore's writes, that queue depth is what keeps the
// reads going.
void containerPrefetchSpan(const Container& c, u32 first, u32 count);
constexpr u64 kPrefetchBytes = u64(16) << 20;
inline u32 containerPrefetchTasks(u64 spanTarget, u32 threads) {
    return max<u32>(threads, u32(kPrefetchBytes / spanTarget));
}
// The bytes containerReadSpan reads for chunks [first, first + count).
u64 containerSpanBytes(const Container& c, u32 first, u32 count);
// Authenticate, decode and verify chunk `loc` from its record `rec` (length
// prefix first, as read by containerReadSpan at rec - span = loc.offset -
// chunks[first].offset). The decoded bytes go to `out`, which must hold
// loc.rawLen bytes; `payload` is caller-owned scratch.
[[nodiscard]] bool containerOpenChunk(const MasterKey& k, const Container& c, const ChunkLoc& loc, const u8* rec,
                                      Array<u8>& payload, u8* out, String& err);

// ---- writing a backup -----------------------------------------------------

struct TrailerEntry {
    ChunkId id;
    u64 nonce;
    u32 recLen;
    u32 rawLen;
};

// The keys are wiped on destruction, as Container's are.
struct ContainerWriter {
    OutStream* out = nullptr;
    ContainerKeys keys;
    Array<TrailerEntry> chunks;

    ContainerWriter() = default;
    ContainerWriter(const ContainerWriter&) = delete;
    ContainerWriter& operator=(const ContainerWriter&) = delete;
    ~ContainerWriter() { secureZero(&keys, sizeof keys); }
};

// Fresh salt + keys; writes the header.
[[nodiscard]] bool writerBegin(ContainerWriter& w, OutStream& out, const MasterKey& k, String& err);
// Record a chunk in the trailer whose sealed record the caller has written
// to the stream itself (create's writer gathers records with writeVec).
void writerNoteChunk(ContainerWriter& w, const ChunkId& id, u64 nonce, u32 rawLen, u32 recTotal);
// Append a sealed chunk record (as produced by recordSeal).
void writerAddChunk(ContainerWriter& w, const ChunkId& id, u64 nonce, u32 rawLen, const u8* rec, u32 recTotal);
// Seal and write the manifest body, the trailer and the footer; flush.
[[nodiscard]] bool writerFinish(ContainerWriter& w, const u8* manifest, u32 n, String& err);

// ---- index files ------------------------------------------------------------

[[nodiscard]] bool indexFileWrite(const MasterKey& k, const char* path, const u8* body, u32 n, String& err);
[[nodiscard]] bool indexFileRead(const MasterKey& k, const char* path, Array<u8>& body, String& err);

} // namespace bk
