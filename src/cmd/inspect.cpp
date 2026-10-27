// inspect.cpp — the read-only subcommands: check, index, list.
//
// `check` is the one to run from cron. It proves, for the chain given, that
// every record authenticates under the key (or matches its checksum, for an
// unencrypted chain), that every chunk's content hashes to its ID, that every
// snapshot's parent is present and decodes, and that every chunk any snapshot
// references is in some segment — i.e. that a restore of each snapshot would
// succeed, without writing anything. All three commands read a chain from a
// pipe as well as from a file, and need nothing but the stream.

#include "cmd/args.hpp"
#include "cmd/chain.hpp"
#include "cmd/commands.hpp"
#include "cmd/passphrase.hpp"
#include "core/thread.hpp"
#include "format/codec.hpp"

#include <stdio.h>
#include <time.h>

namespace bk {

namespace {

// Open the chain for a reading command, unlock what it needs, and read its
// structure: in seek mode walk it (and load the tables when `tables`); in
// stream mode read it all, handing chunk records to `sink`. `pool`, if any,
// is started once the passphrase has been read: the prompt holds Ctrl-Z
// back on its own thread, and a second thread would take the signal.
// Returns the exit status on failure, kExitOk otherwise.
int openForReading(const Args& a, const char* cmd, Chain& c, MasterKey& key, bool tables, StreamSink* sink,
                   ThreadPool* pool = nullptr) {
    String err;
    if (!chainArgsOpen(a.positional, c, err)) { report(err); return kExitRuntime; }
    if (const int rc = keyForChain(a, cmd, c.plain, c.sources[0].path.view(), key)) return rc;
    c.key = &key;
    if (pool) pool->init(argsJobs(a));
    if (c.firstKind == kKindIndex && !c.stream) {
        fprintf(stderr, "bu: %s is an index file, not a chain\n", c.sources[0].path.c_str());
        return kExitRuntime;
    }
    if (c.stream) {
        if (!chainStream(c, sink, err)) { report(err); return kExitRuntime; }
    } else {
        if (!chainWalk(c, err)) { report(err); return kExitRuntime; }
        if (tables && !chainLoadTables(c, err)) { report(err); return kExitRuntime; }
    }
    return kExitOk;
}

// ---- check ------------------------------------------------------------------

// One task per span of consecutive records (about kSpanBytes, fewer when the
// chain is small, so every thread gets work): one pread, then each record's
// header and body are authenticated, decoded and hashed from memory.
struct CheckSpan {
    u32 seg, first, count;
};

struct CheckCtx {
    const Chain* chain = nullptr;
    ThreadPool* pool = nullptr;
    Array<CheckSpan> work;
    u32 lookahead = 0;
    Array<Array<u8>> span, payload, raw;   // per worker
    // Stream mode: what each record decoded to, compared with the tables
    // once they have arrived (they follow the records).
    struct Seen { u32 seg, index, rawLen; ChunkId id; };
    Array<Seen> seen;
    u32 seenBase = 0;
    const StreamChunk* recs = nullptr;
    Mutex mu;
    u32 bad = 0;                     // under mu
};

void checkReport(CheckCtx& c, StringView e, u32 n = 1) {
    Lock l(c.mu);
    if (c.bad < 20) report(e);
    else if (c.bad == 20) report("(further errors not shown)"_s);
    c.bad += n;
}

void checkTask(void* ctx, u32 i, u32 worker) {
    CheckCtx& c = *static_cast<CheckCtx*>(ctx);
    const CheckSpan& s = c.work[i];
    const Seg& seg = c.chain->segs[s.seg];
    if (i + c.lookahead < c.work.count) {
        const CheckSpan& n = c.work[i + c.lookahead];
        chainPrefetchSpan(*c.chain, n.seg, n.first, n.count);
    }
    String err;
    Array<u8>& span = c.span[worker];
    Array<u8>& raw = c.raw[worker];
    raw.resize(kMaxChunk);
    if (!chainReadSpan(*c.chain, s.seg, s.first, s.count, span, err)) { checkReport(c, err.view(), s.count); return; }
    const u64 base = seg.chunks[s.first].offset;
    for (u32 k = 0; k < s.count; ++k) {
        const ChunkLoc& loc = seg.chunks[s.first + k];
        if (!chainOpenChunk(*c.chain, s.seg, s.first + k, span.ptr + (loc.offset - base), true, c.payload[worker],
                            raw.ptr, err))
            checkReport(c, err.view());
    }
}

// Stream mode: open, decode and hash one record; note its ID and size.
void checkStreamTask(void* ctx, u32 i, u32 worker) {
    CheckCtx& c = *static_cast<CheckCtx*>(ctx);
    const StreamChunk& r = c.recs[i];
    const Seg& seg = c.chain->segs[r.seg];
    CheckCtx::Seen& out = c.seen[c.seenBase + i];
    out.seg = r.seg;
    out.index = r.index;
    out.rawLen = kInvalidIndex;
    Array<u8>& payload = c.payload[worker];
    Array<u8>& raw = c.raw[worker];
    raw.resize(kMaxChunk);
    payload.resize(r.bodyLen - kTagBytes);
    String why;
    u32 rawLen = 0;
    if (!bodyOpen(seg.keys, r.nonce, kRecChunk, r.body, r.bodyLen, payload.ptr)) {
        errSet(why, "authentication failed for a chunk record — the stream was modified or damaged");
    } else if (!codecRawLength(payload.ptr, payload.count, kMaxChunk, rawLen)) {
        errSet(why, "malformed chunk payload");
    } else if (seg.keys.plain) {
        bodyTagId(r.body, r.bodyLen, out.id);
        if (chunkDecode(*c.chain->key, payload.ptr, payload.count, rawLen, out.id, raw.ptr, why)) out.rawLen = rawLen;
    } else if (!codecDecode(payload.ptr, payload.count, raw.ptr, rawLen)) {
        errSet(why, "chunk does not decompress");
    } else {
        chunkIdOf(*c.chain->key, raw.ptr, rawLen, out.id);
        out.rawLen = rawLen;
    }
    if (out.rawLen == kInvalidIndex) {
        String e("stdin: segment at offset "_s);
        e.appendU64(seg.start);
        e.append(": "_s);
        e.append(why.view());
        checkReport(c, e.view());
    }
}

bool checkSink(void* ctx, Chain&, const StreamChunk* recs, u32 n, String&) {
    CheckCtx& c = *static_cast<CheckCtx*>(ctx);
    c.recs = recs;
    c.seenBase = c.seen.count;
    c.seen.resize(c.seen.count + n);
    c.pool->run(n, checkStreamTask, &c);
    return true;
}

void snapLabel(const Snapshot& s, char out[17]) {
    hexEncode(s.id, 8, out);
    out[16] = 0;
}

void fmtTime(i64 ns, char* buf, usize cap) {
    const time_t t = time_t(ns / 1000000000);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(buf, cap, "%Y-%m-%d %H:%M:%S", &tmv);
}

void modeString(const Entry& e, char out[11]) {
    out[0] = e.type == kEntryDir ? 'd' : (e.type == kEntrySymlink ? 'l' : '-');
    const char* rwx = "rwxrwxrwx";
    for (int i = 0; i < 9; ++i) out[1 + i] = (e.mode & (0400u >> i)) ? rwx[i] : '-';
    if (e.mode & 04000) out[3] = (e.mode & 0100) ? 's' : 'S';
    if (e.mode & 02000) out[6] = (e.mode & 0010) ? 's' : 'S';
    if (e.mode & 01000) out[9] = (e.mode & 0001) ? 't' : 'T';
    out[10] = 0;
}

// A path or link target from a backup, printed so that it cannot drive the
// terminal: a name may hold any byte but '/' and NUL, and ESC sequences in
// one could rewrite the screen or, on some terminals, the clipboard or the
// title. Control bytes and DEL become \n, \t, \r or \xHH, and a backslash
// becomes \\ so the output stays unambiguous. Bytes from 0x80 up pass
// through: UTF-8 names stay readable.
void printEscaped(StringView p) {
    for (u32 i = 0; i < p.count; ++i) {
        const u8 c = u8(p[i]);
        if (c == '\\') fputs("\\\\", stdout);
        else if (c == '\n') fputs("\\n", stdout);
        else if (c == '\t') fputs("\\t", stdout);
        else if (c == '\r') fputs("\\r", stdout);
        else if (c < 0x20 || c == 0x7f) printf("\\x%02x", c);
        else putchar(c);
    }
}

void printEntries(const Snapshot& s) {
    for (const Entry& e : s.entries) {
        char mode[11], when[32];
        modeString(e, mode);
        fmtTime(e.mtimeNs, when, sizeof when);
        const StringView p = entryPath(s, e);
        printf("%s %5u %5u %12llu %s ", mode, e.uid, e.gid, (unsigned long long)e.size, when);
        printEscaped(p);
        if (e.type == kEntrySymlink) {
            fputs(" -> ", stdout);
            printEscaped(entryTarget(s, e));
        }
        printf("\n");
    }
}

} // namespace

int cmdCheck(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("check", argc, argv, first, kArgKey | kArgJobs | kArgVerbose, a)) return kExitUsage;
    if (a.positional.count == 0) return usage("check", "name the CHAIN to check"_s);
    ThreadPool pool;
    CheckCtx c;
    c.pool = &pool;
    c.mu.init();
    const u32 threads = argsJobs(a);
    c.span.resize(threads);
    c.payload.resize(threads);
    c.raw.resize(threads);
    StreamSink sink;
    sink.fn = checkSink;
    sink.ctx = &c;
    Chain chain;
    MasterKey key;
    c.chain = &chain;
    if (const int rc = openForReading(a, "check", chain, key, true, &sink, &pool)) {
        pool.shutdown();
        if (rc == kExitRuntime) fprintf(stderr, "bu: check FAILED\n");
        return rc;
    }

    u32 problems = 0;
    // An incomplete tail is a problem, unless a create is appending it now.
    chainReportTails(chain);
    for (const Source& s : chain.sources) if (s.tail && !s.writerActive) ++problems;
    if (chain.streamTail) ++problems;
    if (chain.segs.count == 0) { report("no complete backup in the chain"_s); ++problems; }

    String err;
    for (u32 i = 0; i < chain.segs.count; ++i) {
        if (!chainResolve(chain, i, err)) { report(err); ++problems; continue; }
        const u32 missing = chainCountMissing(chain, chain.segs[i].snap);
        if (missing) {
            String n;
            chainSegName(chain, i, n);
            fprintf(stderr, "bu: %s: snapshot references %u chunks that are in none of the segments\n", n.c_str(), missing);
            ++problems;
        }
    }

    u32 records = 0;
    for (const Seg& s : chain.segs) records += s.chunks.count;
    if (chain.stream) {
        // Every record that came by must be the chunk its table lists.
        for (const CheckCtx::Seen& s : c.seen) {
            if (s.rawLen == kInvalidIndex || s.seg >= chain.segs.count) continue;   // reported, or an incomplete tail
            const ChunkLoc& l = chain.segs[s.seg].chunks[s.index];
            if (!idEqual(l.id, s.id) || l.rawLen != s.rawLen) {
                String e("stdin: segment at offset "_s);
                e.appendU64(chain.segs[s.seg].start);
                e.append(": a chunk record does not match the chunk table (damaged)"_s);
                checkReport(c, e.view());
            }
        }
    } else {
        u64 total = 0;
        for (const Source& s : chain.sources) total += s.size;
        const u64 target = chainSpanTarget(total, pool.threads);
        for (u32 si = 0; si < chain.segs.count; ++si) {
            const Seg& s = chain.segs[si];
            u32 ch = 0;
            while (ch < s.chunks.count) {
                u32 n = 1;
                while (ch + n < s.chunks.count && chainSpanBytes(s, ch, n + 1) <= target) ++n;
                c.work.push(CheckSpan{si, ch, n});
                ch += n;
            }
        }
        c.lookahead = chainPrefetchTasks(target, pool.threads);
        pool.run(c.work.count, checkTask, &c);
    }
    pool.shutdown();
    c.mu.destroy();
    problems += c.bad;

    if (problems) {
        fprintf(stderr, "bu: check FAILED: %u problem%s in %u segment%s\n", problems, problems == 1 ? "" : "s",
                chain.segs.count, chain.segs.count == 1 ? "" : "s");
        return kExitRuntime;
    }
    if (a.verbose)
        fprintf(stderr, "bu: check ok: %u segments, %u chunk records verified, latest snapshot generation %llu\n",
                chain.segs.count, records, (unsigned long long)chain.segs[chainLatest(chain)].t.gen);
    return kExitOk;
}

int cmdIndex(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("index", argc, argv, first, kArgKey | kArgOut, a)) return kExitUsage;
    if (!a.out) return usage("index", "-o INDEX is required"_s);
    if (a.positional.count == 0) return usage("index", "name the CHAIN to index"_s);
    Chain chain;
    MasterKey key;
    if (const int rc = openForReading(a, "index", chain, key, true, nullptr)) return rc;
    chainReportTails(chain);
    String err;
    if (chain.segs.count == 0) { report("no complete backup in the chain"_s); return kExitRuntime; }
    const u32 latest = chainLatest(chain);
    IndexData d;
    if (!chainResolve(chain, latest, err) || !chainCheckpoint(chain, latest, d.deltaBytes, d.fullBytes, err)) {
        report(err);
        return kExitRuntime;
    }
    d.snap = move(chain.segs[latest].snap);
    if (chainCountMissing(chain, d.snap)) {
        fprintf(stderr, "bu: the latest snapshot references chunks in none of the segments; "
                        "an index from it would make the next increment reference missing data\n");
        return kExitRuntime;
    }
    if (!indexFileWrite(key, a.out, d, err)) { report(err); return kExitRuntime; }
    return kExitOk;
}

int cmdList(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("list", argc, argv, first, kArgKey, a)) return kExitUsage;
    if (a.positional.count == 0) return usage("list", "name a CHAIN (or one index file)"_s);
    String err;

    // An index file on its own: show its snapshot.
    if (a.positional.count == 1 && !(StringView(a.positional[0]) == "-"_s)) {
        u16 kind = 0;
        bool plain = false;
        if (fileHeaderPeek(a.positional[0], kind, plain, err) && kind == kKindIndex) {
            MasterKey key;
            if (const int rc = keyForChain(a, "list", plain, StringView(a.positional[0]), key)) return rc;
            IndexData d;
            if (!indexFileRead(key, a.positional[0], d, err)) { report(err); return kExitRuntime; }
            char label[17], when[32];
            snapLabel(d.snap, label);
            fmtTime(d.snap.createdNs, when, sizeof when);
            printf("# index: snapshot %s, generation %llu, created %s, %u entries, %u distinct chunks\n", label,
                   (unsigned long long)d.snap.gen, when, d.snap.entries.count, d.distinct.count);
            printEntries(d.snap);
            return kExitOk;
        }
        err.clear();
    }

    Chain chain;
    MasterKey key;
    if (const int rc = openForReading(a, "list", chain, key, true, nullptr)) return rc;
    chainReportTails(chain);
    if (chain.segs.count == 0) { report("no complete backup in the chain"_s); return kExitRuntime; }
    const u32 latest = chainLatest(chain);
    for (u32 i = 0; i < chain.segs.count; ++i) {
        if (!chainHead(chain, i, err)) { report(err); return kExitRuntime; }
        const Seg& s = chain.segs[i];
        const Snapshot& h = s.head;
        char label[17], parent[17], when[32], salt[17];
        snapLabel(h, label);
        if (h.hasParent) { hexEncode(h.parent, 8, parent); parent[16] = 0; } else memCopy(parent, "(none)", 7);
        hexEncode(s.keys.salt, 8, salt);
        salt[16] = 0;
        fmtTime(h.createdNs, when, sizeof when);
        // A digest of the chunk table (IDs, record and raw lengths, in file
        // order): two backups of the same tree under the same key have the
        // same one whatever -j was, which is how the tests check that the
        // output does not depend on thread scheduling.
        ByteWriter t;
        for (const ChunkLoc& l : s.chunks) { t.bytes(l.id.b, kIdBytes); t.varint(l.recLen); t.varint(l.rawLen); t.varint(l.nonce); }
        u8 digest[32];
        blake3Hash(t.buf.ptr, t.buf.count, digest);
        char dhex[17];
        hexEncode(digest, 8, dhex);
        dhex[16] = 0;
        String name;
        chainSegName(chain, i, name);
        printf("# %s: segment %s, snapshot %s, parent %s, generation %llu, %s, created %s, %u chunk records "
               "(table %s)%s\n",
               name.c_str(), salt, label, parent, (unsigned long long)h.gen, h.delta ? "delta" : "self-contained", when,
               s.chunks.count, dhex, i == latest ? "  <- latest" : "");
    }
    if (!chainResolve(chain, latest, err)) { report(err); return kExitRuntime; }
    printEntries(chain.segs[latest].snap);
    return kExitOk;
}

} // namespace bk
