// snapshot.hpp — the file tree of one backup (the manifest) and its encoding.
//
// A Snapshot is data-oriented: one Array<Entry>, one byte store for all
// names, one Array<ChunkId> holding every file's chunk list back to back
// and, parallel to it, each chunk's size.
// Entries are in walk order — depth-first, children sorted by name — so a
// directory always precedes what it contains (restore creates in one pass)
// and consecutive paths share long prefixes (the encoding exploits that).
//
// DELTA MANIFESTS (docs/design.md §Manifests). An increment's manifest is
// encoded against its parent snapshot: entries are always listed in full (a
// deleted file is simply absent), but a file's chunk list is a short program
// over the parent's list for the same path — COPY n, SEEK ±n, NEW n ids. A
// 1 GB SQLite database with 2% of its pages changed therefore costs ~2% of its
// chunk IDs in the increment, not all 262144 of them; an unchanged file costs
// its metadata and one COPY. Decoding needs the parent snapshot, which is
// found by its 16-byte snapshot ID among the segments given — and merge
// keeps a snapshot's ID, so increments made after a merge still find theirs.
//
// The files-cache fields (dev, ino, ctime) live in every manifest, not only
// in the index, so `bu index` can rebuild a complete files cache from the
// backups alone. They are encrypted like everything else.
#pragma once

#include "core/array.hpp"
#include "core/bytes.hpp"
#include "core/hash_index.hpp"
#include "core/string.hpp"
#include "crypto/crypto.hpp"

namespace bk {

constexpr u8 kEntryFile = 1;
constexpr u8 kEntryDir = 2;
constexpr u8 kEntrySymlink = 3;

constexpr u32 kSnapshotIdBytes = 16;

struct Entry {
    u32 pathOff = 0, pathLen = 0;       // into Snapshot::names
    u32 targetOff = 0, targetLen = 0;   // symlink target, into names
    u8 type = 0;
    u32 mode = 0;                       // permission bits only (07777)
    u32 uid = 0, gid = 0;
    i64 mtimeNs = 0;
    i64 ctimeNs = 0;
    u64 size = 0;
    u64 dev = 0, ino = 0;
    u32 firstRef = 0, refCount = 0;     // into Snapshot::refs
};

struct Snapshot {
    u8 id[kSnapshotIdBytes] = {};
    u8 parent[kSnapshotIdBytes] = {};
    bool hasParent = false;
    bool delta = false;        // encoded against the parent (needs it to decode)
    u64 gen = 0;               // 1 for a full backup, parent's + 1 for an increment
    i64 createdNs = 0;         // wall clock when create started (files-cache race guard)
    String names;
    Array<Entry> entries;
    Array<ChunkId> refs;
    Array<u32> sizes;          // per ref: the chunk's size
    HashIndex pathIndex;       // built by snapshotIndexPaths

    Snapshot() = default;
    Snapshot(Snapshot&&) = default;
    Snapshot& operator=(Snapshot&&) = default;
};

inline StringView entryPath(const Snapshot& s, const Entry& e) {
    return StringView(s.names.ptr + e.pathOff, e.pathLen);
}
inline StringView entryTarget(const Snapshot& s, const Entry& e) {
    return StringView(s.names.ptr + e.targetOff, e.targetLen);
}

// Append a name to the byte store; returns its offset.
u32 snapshotAddName(Snapshot& s, StringView name);

void snapshotIndexPaths(Snapshot& s);
// Entry index for `path`, or kInvalidIndex. Needs snapshotIndexPaths.
u32 snapshotFind(const Snapshot& s, StringView path);

// Encode. With `parent` non-null the result is a delta manifest against it
// (s.parent must be parent->id and s.hasParent true); otherwise
// self-contained, which a snapshot with a parent may also be (a checkpoint:
// readers resolving a chain stop there, docs/design.md §5).
void snapshotEncode(const Snapshot& s, const Snapshot* parent, ByteWriter& out);

// Just the header fields, without decoding entries (to find parents first).
[[nodiscard]] bool snapshotPeek(const u8* p, usize n, Snapshot& headerOut);

// Decode. `parent` must be the snapshot whose ID the header names when the
// manifest is a delta (head.delta), and is ignored otherwise. Every path is validated
// (relative, no empty, "." or ".." components) — restore relies on it.
[[nodiscard]] bool snapshotDecode(const u8* p, usize n, const Snapshot* parent, Snapshot& out, String& err);

// A safe relative path: non-empty, no leading '/', no empty, "." or ".." component.
bool pathIsSafe(StringView p);

// ---- the index file body -----------------------------------------------------
//
// An index is the latest snapshot, self-contained: it is the files cache and
// the dedupe set at once (the chunks the next increment may reference are
// exactly the chunks this snapshot references). Only writing a new segment
// somewhere the chain cannot be read back from — a pipe, or a separate file
// per increment — needs one; appending to a chain file reads the same from
// the chain's tail. Two counters carry the checkpoint rule across runs: the
// manifest bytes written as deltas since the chain's last self-contained
// manifest, and that manifest's size.

struct IndexData {
    Snapshot snap;
    Array<ChunkId> distinct;      // distinct refs, first-appearance order
    u64 deltaBytes = 0;           // delta manifest bytes since the last self-contained one
    u64 fullBytes = 0;            // the last self-contained manifest's bytes
};

// Fill `distinct` from snap.refs (first-appearance order).
void indexCollectDistinct(IndexData& d);
void indexEncode(const IndexData& d, ByteWriter& out);
[[nodiscard]] bool indexDecode(const u8* p, usize n, IndexData& d, String& err);

} // namespace bk
