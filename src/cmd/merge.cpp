// merge.cpp — `bu merge`: collapse a chain into one full segment.
//
// SEMANTICS (docs/design.md §7). The output is a chain of ONE segment holding
// the chain's latest snapshot, fully expanded (self-contained), and exactly
// the chunks that snapshot references, nothing else. So merging a chain is
// "a full backup of the state at its latest increment", made without reading
// the source data again. Older snapshots are deliberately not kept: keeping
// history is what keeping the old chain is for, and one snapshot per segment
// keeps the format and every command simple.
//
// WHY LATER INCREMENTS KEEP WORKING. The merged snapshot keeps its snapshot ID
// and generation, and an increment made from it (appended to the merged
// chain, or from an index of the same snapshot) names that ID as its parent
// and only references chunks that snapshot references (the base's dedupe
// set IS that snapshot's chunk set) or that it stores itself. Both are in the
// merged segment. Nothing anywhere refers to a file name, offset or salt.
//
// IN PLACE. `-o CHAIN` naming an input replaces it (`bu merge -o c.bu c.bu`
// compacts a chain): the output goes to a temp file beside it and is renamed
// over it, with the input locked the whole time, so a create cannot append a
// segment the rename would then throw away (create checks, after locking,
// that its path still names the file it opened).
//
// READING. The chain is read by seeking (a pipe is refused: the latest
// snapshot, which says what to keep, is at the end), in spans of nearby
// records like restore's; chunks are authenticated and re-hashed on the way
// through (merge doubles as a check of everything it keeps) and re-sealed
// under the new segment's key without being recompressed. The mode is kept:
// an unencrypted chain merges to an unencrypted one.

#include "cmd/args.hpp"
#include "cmd/chain.hpp"
#include "cmd/commands.hpp"
#include "cmd/passphrase.hpp"
#include "core/thread.hpp"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bk {

namespace {

constexpr u64 kSpanGap = u64(64) << 10;

struct MergeItem {
    u32 seg, chunk;
    u32 bodyLen;          // sealed body in `rec`
};

// A run of items whose records lie close together in one segment.
struct MergeTask {
    u32 seg, first, count;      // records read
    u32 firstItem, items;
};

struct MergeBatch {
    const Chain* chain = nullptr;
    const SegKeys* out = nullptr;
    Array<MergeItem>* items = nullptr;
    Array<MergeTask> tasks;
    Array<Array<u8>> recs;      // per item of the batch: prefix space + body
    u32 itemBase = 0;           // index of the batch's first item (its nonce)
    u32 lookahead = 0;
    Array<Array<u8>> span, payload, raw;   // per worker
    Mutex mu;
    String firstErr;
    bool failed = false;
};

void mergeTask(void* ctx, u32 i, u32 worker) {
    MergeBatch& b = *static_cast<MergeBatch*>(ctx);
    if (__atomic_load_n(&b.failed, __ATOMIC_RELAXED)) return;
    const MergeTask& t = b.tasks[i];
    if (b.lookahead && i + b.lookahead < b.tasks.count) {
        const MergeTask& n = b.tasks[i + b.lookahead];
        chainPrefetchSpan(*b.chain, n.seg, n.first, n.count);
    }
    const Seg& s = b.chain->segs[t.seg];
    String err;
    Array<u8>& span = b.span[worker];
    bool ok = chainReadSpan(*b.chain, t.seg, t.first, t.count, span, err);
    const u64 base = ok ? s.chunks[t.first].offset : 0;
    b.raw[worker].resize(kMaxChunk);
    for (u32 k = 0; k < t.items && ok; ++k) {
        const u32 idx = t.firstItem + k;
        MergeItem& it = (*b.items)[idx];
        const ChunkLoc& loc = s.chunks[it.chunk];
        Array<u8>& payload = b.payload[worker];
        ok = chainOpenChunk(*b.chain, t.seg, it.chunk, span.ptr + (loc.offset - base), false, payload,
                            b.raw[worker].ptr, err);
        if (!ok) break;
        Array<u8>& rec = b.recs[idx - b.itemBase];
        rec.resize(kRecPrefix + payload.count + kTagBytes);
        it.bodyLen = bodySeal(*b.out, idx, kRecChunk, &loc.id, payload.ptr, payload.count, rec.ptr + kRecPrefix);
    }
    if (!ok) {
        Lock l(b.mu);
        if (!b.failed) { b.firstErr = move(err); __atomic_store_n(&b.failed, true, __ATOMIC_RELAXED); }
    }
}

} // namespace

int cmdMerge(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("merge", argc, argv, first, kArgKey | kArgOut | kArgJobs | kArgVerbose, a)) return kExitUsage;
    if (a.positional.count == 0) return usage("merge", "name the CHAIN to merge"_s);
    const bool toStdout = !a.out || StringView(a.out) == "-"_s;
    if (toStdout && isatty(1))
        return usage("merge", "refusing to write a chain to a terminal; give -o NEW or redirect stdout"_s);
    signal(SIGPIPE, SIG_IGN);

    String err;
    Chain chain;
    if (!chainArgsOpen(a.positional, chain, err)) { report(err); return kExitRuntime; }
    if (chain.stream) {
        fprintf(stderr, "bu merge: cannot merge a chain from a pipe (what to keep is only known at its end); "
                        "save it to a file first\n");
        return kExitUsage;
    }
    MasterKey key;
    if (const int rc = keyForChain(a, "merge", chain.plain, chain.sources[0].path.view(), key)) return rc;
    chain.key = &key;

    // -o naming an input: lock that input for the whole merge (in place).
    // -o naming anything else that exists: refused, never overwritten.
    if (!toStdout) {
        struct stat out;
        if (lstat(a.out, &out) == 0) {
            u32 input = kInvalidIndex;
            for (u32 i = 0; i < chain.sources.count; ++i) {
                struct stat in;
                if (fstat(chain.sources[i].fd, &in) == 0 && in.st_dev == out.st_dev && in.st_ino == out.st_ino) input = i;
            }
            if (input == kInvalidIndex) {
                fprintf(stderr, "bu merge: %s exists and is not one of the chains merged; merge does not overwrite it\n", a.out);
                return kExitUsage;
            }
            if (flock(chain.sources[input].fd, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK) {
                fprintf(stderr, "bu: %s is locked: another bu is writing it; try again when it is done\n", a.out);
                return kExitRuntime;
            }
        }
    }

    if (!chainWalk(chain, err)) { report(err); return kExitRuntime; }
    chainReportTails(chain);
    if (chain.segs.count == 0) { fprintf(stderr, "bu: no complete backup in the chain\n"); return kExitRuntime; }
    if (!chainLoadTables(chain, err)) { report(err); return kExitRuntime; }
    const u32 latest = chainLatest(chain);
    if (!chainResolve(chain, latest, err)) { report(err); return kExitRuntime; }
    Snapshot& snap = chain.segs[latest].snap;

    // Distinct refs in first-appearance order: the merged segment's record
    // order follows the tree, so a restore reads it front to back.
    IndexData d;
    d.snap = move(snap);
    indexCollectDistinct(d);
    Array<MergeItem> all;
    all.resize(d.distinct.count);
    u32 missing = 0;
    for (u32 i = 0; i < d.distinct.count; ++i)
        if (!chainFind(chain, d.distinct[i], all[i].seg, all[i].chunk)) ++missing;
    if (missing) {
        fprintf(stderr, "bu: %u chunks of the latest snapshot are in none of the given segments; "
                        "merge needs the chain back to a full backup\n", missing);
        return kExitRuntime;
    }

    String tmp;
    int outFd = 1;
    if (toStdout) {
        pipeGrow(1);
    } else {
        outFd = tempFileBeside(a.out, tmp, err);
        if (outFd < 0) { report(err); return kExitRuntime; }
    }
    auto failOut = [&](StringView what) {
        report(what);
        if (!toStdout) { close(outFd); unlink(tmp.c_str()); }
        fprintf(stderr, "bu: merge FAILED%s\n", toStdout ? "; discard the partial output" : "");
        return kExitRuntime;
    };
    OutStream out;
    out.init(outFd);
    SegWriter cw;
    if (!writerBegin(cw, out, key, kKindSegment, err)) return failOut(err.view());

    ThreadPool pool;
    pool.init(argsJobs(a));
    MergeBatch b;
    b.chain = &chain; b.out = &cw.keys; b.items = &all;
    b.mu.init();
    b.span.resize(pool.threads); b.payload.resize(pool.threads); b.raw.resize(pool.threads);
    u64 total = 0;
    for (const Source& s : chain.sources) total += s.size;
    const u64 target = chainSpanTarget(total, pool.threads);
    b.lookahead = chainPrefetchTasks(target, pool.threads);
    const u32 batchSize = min<u32>(2048, pool.threads * 128);
    b.recs.resize(batchSize);
    bool ok = true;
    for (u32 start = 0; start < all.count && ok; start += batchSize) {
        const u32 n = min(batchSize, all.count - start);
        b.itemBase = start;
        b.tasks.clear();
        for (u32 i = start; i < start + n; ++i) {
            const MergeItem& it = all[i];
            const Seg& s = chain.segs[it.seg];
            MergeTask* t = b.tasks.count ? &b.tasks[b.tasks.count - 1] : nullptr;
            bool join = t && t->seg == it.seg && it.chunk >= t->first + t->count;
            if (join) {
                const ChunkLoc& last = s.chunks[t->first + t->count - 1];
                join = s.chunks[it.chunk].offset - (last.offset + 4 + last.recLen) <= kSpanGap
                       && chainSpanBytes(s, t->first, it.chunk - t->first + 1) <= target;
            }
            if (!join) t = &b.tasks.push(MergeTask{it.seg, it.chunk, 1, i, 0});
            t->count = it.chunk - t->first + 1;
            ++t->items;
        }
        pool.run(b.tasks.count, mergeTask, &b);
        if (b.failed) { ok = false; break; }
        for (u32 i = 0; i < n; ++i) {
            const MergeItem& it = all[start + i];
            const ChunkLoc& loc = chain.segs[it.seg].chunks[it.chunk];
            const u32 size = writerChunk(cw, loc.id, start + i, loc.rawLen, b.recs[i].ptr, it.bodyLen);
            out.write(b.recs[i].ptr, size);
        }
        if (out.failed) ok = false;
    }
    pool.shutdown();
    b.mu.destroy();
    if (!ok) {
        if (out.failed) {
            String m("writing the merged chain failed: "_s);
            m.append(StringView(strerror(out.savedErrno)));
            return failOut(m.view());
        }
        return failOut(b.firstErr.view());
    }

    d.snap.delta = false;
    ByteWriter manifest;
    snapshotEncode(d.snap, nullptr, manifest);
    if (!writerFinish(cw, manifest.buf.ptr, manifest.buf.count, d.snap.gen, err)) return failOut(err.view());
    if (!toStdout) {
        if (fsync(outFd) != 0 || close(outFd) != 0) {
            String m(StringView(tmp.c_str()));
            m.append(": "_s);
            m.append(StringView(strerror(errno)));
            outFd = -1;
            unlink(tmp.c_str());
            report(m.view());
            return kExitRuntime;
        }
        if (!renameDurably(tmp.c_str(), a.out, err)) { report(err); return kExitRuntime; }
    }
    if (a.verbose)
        fprintf(stderr, "bu: merged %u segments into one: snapshot generation %llu, %u chunks, %llu bytes\n",
                chain.segs.count, (unsigned long long)d.snap.gen, all.count, (unsigned long long)out.written);
    return kExitOk;
}

} // namespace bk
