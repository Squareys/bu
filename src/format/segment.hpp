// segment.hpp — the bu file format: segments, sealed records, the trailer.
//
// A CHAIN is a file of segments laid end to end: a full backup and the
// increments appended after it. Each segment is self-contained and every
// offset in it is relative to its own first byte, so `cat a.bu b.bu > c.bu`
// of segments written separately is a valid chain, and a reader finds them by
// walking back from the end of the file, trailer by trailer. One shape also
// serves the index file (kind 2), so there is one parser to harden and one
// place docs/format.md describes. Layout (all integers little-endian):
//
//   header   64 bytes: magic "BUBAK\r\n\x1a" | u16 version | u16 kind
//            | u16 flags (bit 0: unencrypted) | u16 0 | salt[32] | check[16]
//   records  repeated: u32 L | record header (25 bytes) | body (L - 25 bytes)
//            record header = sealed { u8 type | u64 body nonce }, nonce
//            kNonceHeadBase + the record's ordinal in the segment; body =
//            sealed payload (format/codec.hpp) under the body nonce
//   trailer  64 bytes: u64 segment length | u64 manifest offset | u64 table
//            offset | u32 manifest L | u32 table L | u64 generation
//            | check[16] | magic "BUEND\r\n\x1a"
//
// A segment's records are its new chunks (in stream order), the manifest (its
// snapshot) and the table (ID, length, nonce and size of every chunk record).
// An index file has one record, the index, and no table.
//
// WHY A RECORD HEADER. A chunk's body nonce is its stream sequence number,
// fixed by the chunker before any worker runs (determinism, unique by
// construction); the writer later drops duplicates, so the stored records
// carry gappy, increasing sequence numbers. A reader that seeks gets them
// from the table at the segment's end; a reader streaming from a pipe meets
// the records first. The record header tells it each body's type and nonce,
// sealed under a nonce the reader can count (the ordinal) — so the gaps,
// which say where unchanged data sits between changed chunks, stay hidden.
//
// KEYS AND NONCES (docs/design.md §3). The master key never encrypts
// anything. Each segment draws a fresh random 32-byte salt and derives its
// own AES key and check key from master||salt with BLAKE3 derive_key, so two
// segments never share an AES key. Under one key three nonce spaces never
// meet: chunk bodies use their sequence number (< 2^63), metadata bodies
// fixed values from 2^63, record headers 2^63 + 2^62 + ordinal. A body's
// associated data is its type byte; a chunk's content is bound to its ID by
// the reader re-hashing it, which a reader streaming the records needs anyway
// (it learns the ID from the content).
//
// UNENCRYPTED SEGMENTS (--no-key, header flag bit 0) keep the same layout
// with the AEAD replaced by checksums: a payload is stored in the clear and
// its 16 tag bytes are an unkeyed BLAKE3 of nonce, type and payload — or, for
// a chunk, the chunk ID itself (unkeyed BLAKE3 of the content), which the
// reader re-hashes. That detects damage, not tampering: anyone can recompute
// a checksum.
#pragma once

#include "core/array.hpp"
#include "core/string.hpp"
#include "crypto/crypto.hpp"
#include "io/io.hpp"

namespace bk {

constexpr u32 kHeaderBytes = 64;
constexpr u32 kTrailerBytes = 64;
constexpr u32 kRecHeadPlain = 9;                           // u8 type | u64 body nonce
constexpr u32 kRecHeadBytes = kRecHeadPlain + kTagBytes;   // sealed
constexpr u32 kRecPrefix = 4 + kRecHeadBytes;              // length + record header
constexpr u32 kRecordOverhead = kRecPrefix + kTagBytes;    // prefix + the body's tag
constexpr u16 kFormatVersion = 2;

constexpr u16 kKindSegment = 1;
constexpr u16 kKindIndex = 2;
constexpr u16 kFlagPlain = 1;     // header flags bit 0: unencrypted (--no-key)

constexpr u8 kRecChunk = 1;
constexpr u8 kRecManifest = 2;
constexpr u8 kRecTable = 3;
constexpr u8 kRecIndex = 4;

// Largest raw chunk any chunker emits (CDC max, or one 64 KiB SQLite page).
constexpr u32 kMaxChunk = 64u << 10;
// Largest L a reader accepts for a chunk record (payload header, LZ4 slack).
constexpr u32 kMaxChunkRecord = kRecHeadBytes + kMaxChunk + 64 + kTagBytes;
// Largest metadata record (manifest, table, index) a reader will allocate
// for. The table is the one that grows: ~22 bytes per new chunk, so 3 GiB
// bounds one segment at ~140 million new chunks, ~2.8 TB of unique data at
// the average chunk size (docs/design.md §12).
constexpr u32 kMaxMetaRecord = 3u << 30;

constexpr u64 kNonceMetaBase = u64(1) << 63;
constexpr u64 kNonceManifest = kNonceMetaBase + 0;
constexpr u64 kNonceTable = kNonceMetaBase + 1;
constexpr u64 kNonceIndex = kNonceMetaBase + 2;
constexpr u64 kNonceHeadBase = kNonceMetaBase + (u64(1) << 62);

// The master key K and what every segment derives from it, or, for an
// unencrypted chain, no key at all (`plain`). K comes out of a key file's
// slot (format/keyfile.hpp); nothing here knows about passphrases. Wiped when
// it goes out of scope, whichever way a command exits.
struct MasterKey {
    Key master;
    Key idKey;        // derived: keyed-BLAKE3 key for chunk IDs
    bool plain = false;
    ~MasterKey() { secureZero(this, sizeof *this); }
};

// Set out.master = master and derive idKey.
void masterKeyInit(const Key& master, MasterKey& out);
// No key: chunk IDs are unkeyed BLAKE3 and nothing is encrypted.
void masterKeyPlain(MasterKey& out);

// The chunk ID: keyed BLAKE3 of the raw chunk (unkeyed without a key),
// truncated to 128 bits.
void chunkIdOf(const MasterKey& k, const u8* data, usize n, ChunkId& out);

// One segment's keys. Wiped on destruction (copies included).
struct SegKeys {
    u8 salt[kSaltBytes];
    AeadKey aead;
    Key check;
    bool plain = false;
    ~SegKeys() { secureZero(this, sizeof *this); }
};

void segKeysDerive(const MasterKey& k, const u8 salt[kSaltBytes], SegKeys& out);

void headerBuild(const SegKeys& keys, u16 kind, u8 out[kHeaderBytes]);
// The key-independent part of a header: magic, version, kind, flags. `why`
// says what is wrong (no file name).
[[nodiscard]] bool headerParse(const u8 h[kHeaderBytes], u16& kind, bool& plain, String& why);
// The check value under the segment's keys: false means the wrong key, or a
// damaged header.
[[nodiscard]] bool headerVerify(const SegKeys& keys, const u8 h[kHeaderBytes]);

// Seal a payload (format/codec.hpp) as a record body into out, which must
// hold n + kTagBytes bytes; returns that size. `id` is the chunk ID for a
// chunk body (an unencrypted one carries it as its tag), null otherwise.
// Thread-safe (keys are read-only).
u32 bodySeal(const SegKeys& keys, u64 nonce, u8 type, const ChunkId* id, const u8* payload, u32 n, u8* out);
// Open a body of `len` bytes into payload (len - kTagBytes bytes). False on
// authentication (or checksum) failure. An unencrypted chunk body is not
// checked here: its tag is its claimed ID (bodyTagId), which the caller
// compares with the hash of the decoded content.
[[nodiscard]] bool bodyOpen(const SegKeys& keys, u64 nonce, u8 type, const u8* body, u32 len, u8* payload);
inline void bodyTagId(const u8* body, u32 len, ChunkId& out) { memCopy(out.b, body + len - kTagBytes, kIdBytes); }

// The record prefix: u32 L (= kRecHeadBytes + bodyLen) and the sealed record
// header. `ordinal` counts the segment's records from 0.
void recPrefixSeal(const SegKeys& keys, u64 ordinal, u8 type, u64 bodyNonce, u32 bodyLen, u8 out[kRecPrefix]);
// False when the header does not open under this ordinal (or L is too small
// to hold a header and a tag).
[[nodiscard]] bool recPrefixOpen(const SegKeys& keys, u64 ordinal, const u8 in[kRecPrefix], u8& type, u64& bodyNonce,
                                 u32& bodyLen);

// The trailer's fields. Offsets are relative to the segment's first byte;
// lengths are record L values (a record occupies 4 + L bytes).
struct Trailer {
    u64 segLen = 0;
    u64 manOff = 0, tabOff = 0;
    u32 manLen = 0, tabLen = 0;     // tabLen 0: no table (an index file)
    u64 gen = 0;                    // the snapshot's generation
};

void trailerBuild(const SegKeys& keys, const u8 header[kHeaderBytes], const Trailer& t, u8 out[kTrailerBytes]);
// Magic and layout of the 64 bytes alone (no key): a candidate end of a
// segment. `why` names the problem.
[[nodiscard]] bool trailerParse(const u8 in[kTrailerBytes], Trailer& t, String& why);
// The check value, under the keys of the header the trailer points back to.
[[nodiscard]] bool trailerVerify(const SegKeys& keys, const u8 header[kHeaderBytes], const u8 in[kTrailerBytes]);
// The trailer's last 8 bytes; a reader scanning for the end of the last
// complete segment looks for them.
extern const u8 kTrailerMagic[8];

// Decode an opened chunk payload into out (rawLen bytes) and check that its
// hash is `id`. `why` says what is wrong.
[[nodiscard]] bool chunkDecode(const MasterKey& k, const u8* payload, u32 n, u32 rawLen, const ChunkId& id, u8* out,
                               String& why);

// ---- writing a segment ------------------------------------------------------

struct TableEntry {
    ChunkId id;
    u64 nonce;
    u32 recLen;     // L
    u32 rawLen;
};

// Writes one segment to an OutStream (a chain file opened O_APPEND, or a
// pipe): offsets are counted from the stream position at writerBegin.
struct SegWriter {
    OutStream* out = nullptr;
    SegKeys keys;
    u8 header[kHeaderBytes];
    u16 kind = kKindSegment;
    u64 base = 0;            // out->written at the header
    u64 ordinal = 0;         // records written so far
    Array<TableEntry> chunks;
};

// Fresh salt + keys; writes the header of a segment (kind 1) or index (2).
[[nodiscard]] bool writerBegin(SegWriter& w, OutStream& out, const MasterKey& k, u16 kind, String& err);
// A chunk record laid out in `rec`: kRecPrefix bytes for the prefix, then the
// body as bodySeal left it (bodyLen bytes). Fills the prefix and notes the
// chunk in the table; the caller writes the record (create gathers them with
// writeVec). Returns the record's size.
u32 writerChunk(SegWriter& w, const ChunkId& id, u64 nonce, u32 rawLen, u8* rec, u32 bodyLen);
// Seal and write the manifest (or, for an index, the index body), the table
// (segments only) and the trailer; flush. `gen` goes into the trailer.
[[nodiscard]] bool writerFinish(SegWriter& w, const u8* manifest, u32 n, u64 gen, String& err);

} // namespace bk
