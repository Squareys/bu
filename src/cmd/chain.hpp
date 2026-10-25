// chain.hpp — a set of backup files read together: restore, check, merge,
// index and list all start here.
//
// A "chain" is just the files the user named, in any order. Nothing in a
// backup refers to another backup by FILE NAME: a delta manifest names its
// parent by snapshot ID, and a chunk is found by its ID in whichever given
// file holds it. That is the property that makes merges safe — merge(full,
// inc1) produces a file with a new name and salt, and inc2 (made before or
// after) still resolves, because inc1's snapshot ID and every chunk inc2
// needs are in the merged file.
//
// "The latest snapshot" is the one with the highest generation; on a tie (two
// increments made from the same index) the one named later on the command
// line wins, and list says which it picked.
#pragma once

#include "core/hash_index.hpp"
#include "format/container.hpp"
#include "format/snapshot.hpp"

namespace bk {

struct ChainSnap {
    Array<u8> manifest;     // decrypted manifest body
    Snapshot head;          // header fields (from snapshotPeek)
    Snapshot snap;          // fully decoded, once resolved
    bool resolved = false;
    bool resolving = false; // cycle guard

    ChainSnap() = default;
    ChainSnap(ChainSnap&&) = default;
};

struct Chain {
    Array<Container> files;
    Array<ChainSnap> snaps;          // one per file, same order
    // Chunk ID -> (file << 32 | chunk index): the first file listing an ID wins.
    HashIndex idIndex;
    Array<u64> idWhere;
};

// Open every file (backups only), read and decrypt each manifest, index all
// chunk IDs. `err` names the first file that failed.
[[nodiscard]] bool chainOpen(const MasterKey& k, const Array<const char*>& paths, Chain& c, String& err);

// File index of the latest snapshot.
u32 chainLatest(const Chain& c);

// Fully decode file i's snapshot, resolving parents among the chain's files.
[[nodiscard]] bool chainResolve(Chain& c, u32 i, String& err);

// Where a chunk is; false if no given file has it.
bool chainFind(const Chain& c, const ChunkId& id, u32& file, u32& chunk);

// Every distinct ref of `s` that no file in the chain holds (for messages).
u32 chainCountMissing(const Chain& c, const Snapshot& s);

} // namespace bk
