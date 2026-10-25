// merge.cpp — `backu merge`: roll a chain forward into one self-contained file.
//
// SEMANTICS (docs/design.md §Merge). The output holds exactly ONE snapshot —
// the chain's latest — fully expanded (no parent), and exactly the chunks that
// snapshot references, nothing else. So merge(full, inc1) is "a full backup of
// the state at inc1", and full + inc1 can be deleted afterwards. Older
// snapshots are deliberately not kept: keeping history is what keeping the
// old files is for, and a one-snapshot file keeps merge, restore and the
// format simple.
//
// WHY LATER INCREMENTS KEEP WORKING. The merged snapshot keeps its snapshot ID
// and generation, and an increment made from inc1's index names inc1's
// snapshot ID as its parent and only references chunks that inc1's snapshot
// references (the index's dedupe set IS that snapshot's chunk set) or that it
// stores itself. Both are in the merged file. Nothing anywhere refers to a
// file name or a salt, so the renamed, re-salted merged file is a drop-in.
//
// The chain must reach back to a full backup — the output is self-contained,
// so every referenced chunk has to be somewhere in the input. Chunks are
// authenticated and re-hashed on the way through (merge doubles as a check of
// everything it keeps) and re-sealed under the new file's key without being
// recompressed.

#include "cmd/args.hpp"
#include "cmd/chain.hpp"
#include "cmd/commands.hpp"
#include "core/thread.hpp"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

namespace bk {

namespace {

struct MergeItem {
    u32 file, chunk;
    u32 recLen;           // sealed size in `rec`
};

struct MergeBatch {
    const MasterKey* key = nullptr;
    const Chain* chain = nullptr;
    const ContainerKeys* out = nullptr;
    Array<MergeItem> items;
    Array<Array<u8>> recs;      // per item slot in the batch
    u64 nonceBase = 0;
    Array<Array<u8>> scratch, payload, raw;   // per worker
    Mutex mu;
    String firstErr;
    bool failed = false;
};

void mergeTask(void* ctx, u32 i, u32 worker) {
    MergeBatch& b = *static_cast<MergeBatch*>(ctx);
    if (__atomic_load_n(&b.failed, __ATOMIC_RELAXED)) return;
    MergeItem& it = b.items[i];
    const Container& c = b.chain->files[it.file];
    const ChunkLoc& loc = c.chunks[it.chunk];
    String err;
    if (!containerReadChunkPayload(*b.key, c, loc, b.scratch[worker], b.payload[worker], b.raw[worker], err)) {
        Lock l(b.mu);
        if (!b.failed) { b.firstErr = move(err); __atomic_store_n(&b.failed, true, __ATOMIC_RELAXED); }
        return;
    }
    Array<u8>& rec = b.recs[i];
    rec.resize(b.payload[worker].count + kRecordOverhead);
    it.recLen = recordSeal(*b.out, b.nonceBase + i, kRecChunk, &loc.id, b.payload[worker].ptr,
                           b.payload[worker].count, rec.ptr);
}

} // namespace

int cmdMerge(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("merge", argc, argv, first, kArgKey | kArgJobs | kArgVerbose, a)) return kExitUsage;
    if (a.positional.count == 0) { fprintf(stderr, "backu merge: name the backup files to merge (oldest first is customary)\n"); return kExitUsage; }
    if (isatty(1)) { fprintf(stderr, "backu merge: refusing to write a backup to a terminal; redirect stdout\n"); return kExitUsage; }
    signal(SIGPIPE, SIG_IGN);

    String err;
    if (!cryptoCpuCheck(err)) { report(err); return kExitRuntime; }
    MasterKey key;
    if (!keyLoad(a.key, key, err)) { report(err); return kExitRuntime; }
    Chain chain;
    if (!chainOpen(key, a.positional, chain, err)) { report(err); return kExitRuntime; }
    const u32 latest = chainLatest(chain);
    if (!chainResolve(chain, latest, err)) { report(err); return kExitRuntime; }
    Snapshot& snap = chain.snaps[latest].snap;

    // Distinct refs in first-appearance order: the merged file's record order
    // follows the tree, so a restore reads it front to back.
    IndexData d;
    d.snap = move(snap);
    indexCollectDistinct(d);
    Array<MergeItem> all;
    all.resize(d.distinct.count);
    u32 missing = 0;
    for (u32 i = 0; i < d.distinct.count; ++i)
        if (!chainFind(chain, d.distinct[i], all[i].file, all[i].chunk)) ++missing;
    if (missing) {
        fprintf(stderr, "backu: %u chunks of the latest snapshot are in none of the given files; "
                        "merge needs the chain back to a full backup\n", missing);
        return kExitRuntime;
    }

    OutStream out;
    out.init(1);
    ContainerWriter cw;
    if (!writerBegin(cw, out, key, err)) { report(err); return kExitRuntime; }

    ThreadPool pool;
    pool.init(argsJobs(a));
    MergeBatch b;
    b.key = &key; b.chain = &chain; b.out = &cw.keys;
    b.mu.init();
    b.scratch.resize(pool.threads); b.payload.resize(pool.threads); b.raw.resize(pool.threads);
    const u32 batchSize = min<u32>(1024, pool.threads * 64);
    b.recs.resize(batchSize);
    bool ok = true;
    for (u32 start = 0; start < all.count && ok; start += batchSize) {
        const u32 n = min(batchSize, all.count - start);
        b.items.clear();
        b.items.appendRange(all.ptr + start, n);
        b.nonceBase = start;
        pool.run(n, mergeTask, &b);
        if (b.failed) { report(b.firstErr.view()); ok = false; break; }
        for (u32 i = 0; i < n; ++i) {
            const ChunkLoc& loc = chain.files[b.items[i].file].chunks[b.items[i].chunk];
            writerAddChunk(cw, loc.id, start + i, loc.rawLen, b.recs[i].ptr, b.items[i].recLen);
        }
        if (out.failed) ok = false;
    }
    pool.shutdown();
    b.mu.destroy();
    if (!ok) {
        if (out.failed) fprintf(stderr, "backu: writing the merged backup failed: %s\n", strerror(out.savedErrno));
        fprintf(stderr, "backu: merge FAILED; discard the partial output\n");
        return kExitRuntime;
    }

    d.snap.hasParent = false;
    ByteWriter manifest;
    snapshotEncode(d.snap, nullptr, manifest);
    if (!writerFinish(cw, manifest.buf.ptr, manifest.buf.count, err)) { report(err); return kExitRuntime; }
    if (a.verbose)
        fprintf(stderr, "backu: merged %u files into one: snapshot generation %llu, %u chunks, %llu bytes\n",
                chain.files.count, (unsigned long long)d.snap.gen, all.count, (unsigned long long)out.written);
    return kExitOk;
}

} // namespace bk
