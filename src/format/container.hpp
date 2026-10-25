// container.hpp — the backu file format: header, sealed records, footer.
//
// One container shape serves both kinds of file backu writes — a backup and an
// index — so there is one parser to harden and one place docs/format.md
// describes. Layout (all integers little-endian):
//
//   header   64 bytes, plaintext
//            magic "BACKU\r\n\x1a" | u16 version | u16 kind | u32 reserved
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
// Largest metadata record (manifest, trailer, index) a reader will allocate for.
constexpr u32 kMaxMetaRecord = 1u << 30;

constexpr u64 kNonceMetaBase = u64(1) << 63;
constexpr u64 kNonceManifest = kNonceMetaBase + 0;
constexpr u64 kNonceTrailer = kNonceMetaBase + 1;
constexpr u64 kNonceIndex = kNonceMetaBase + 2;

struct MasterKey {
    Key master;
    Key idKey;        // derived: keyed-BLAKE3 key for chunk IDs
};

// Parse a key file ("backu-key-1 <64 hex digits>\n"); derives idKey.
[[nodiscard]] bool keyLoad(const char* path, MasterKey& out, String& err);
// A fresh key file's text.
[[nodiscard]] bool keyGenerate(String& out, String& err);

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

// ---- writing a backup -----------------------------------------------------

struct TrailerEntry {
    ChunkId id;
    u64 nonce;
    u32 recLen;
    u32 rawLen;
};

struct ContainerWriter {
    OutStream* out = nullptr;
    ContainerKeys keys;
    Array<TrailerEntry> chunks;
};

// Fresh salt + keys; writes the header.
[[nodiscard]] bool writerBegin(ContainerWriter& w, OutStream& out, const MasterKey& k, String& err);
// Append a sealed chunk record (as produced by recordSeal).
void writerAddChunk(ContainerWriter& w, const ChunkId& id, u64 nonce, u32 rawLen, const u8* rec, u32 recTotal);
// Seal and write the manifest body, the trailer and the footer; flush.
[[nodiscard]] bool writerFinish(ContainerWriter& w, const u8* manifest, u32 n, String& err);

// ---- index files ------------------------------------------------------------

[[nodiscard]] bool indexFileWrite(const MasterKey& k, const char* path, const u8* body, u32 n, String& err);
[[nodiscard]] bool indexFileRead(const MasterKey& k, const char* path, Array<u8>& body, String& err);

} // namespace bk
