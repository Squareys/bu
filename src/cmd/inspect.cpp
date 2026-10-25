// inspect.cpp — the read-only and small subcommands: check, index, list, keygen.
//
// `check` is the one to run from cron. It proves, for the files given, that
// every record authenticates under the key, that every chunk's content hashes
// to its ID, that every snapshot's parent is present and decodes, and that
// every chunk any snapshot references is in some given file — i.e. that a
// restore of each snapshot would succeed, without writing anything.

#include "cmd/args.hpp"
#include "cmd/chain.hpp"
#include "cmd/commands.hpp"
#include "core/thread.hpp"

#include <stdio.h>
#include <time.h>
#include <unistd.h>

namespace bk {

namespace {

// ---- check ------------------------------------------------------------------

struct CheckCtx {
    const MasterKey* key = nullptr;
    const Chain* chain = nullptr;
    Array<u64> work;                 // file << 32 | chunk
    Array<Array<u8>> scratch, raw;   // per worker
    Mutex mu;
    u32 bad = 0;                     // under mu
};

void checkTask(void* ctx, u32 i, u32 worker) {
    CheckCtx& c = *static_cast<CheckCtx*>(ctx);
    const u32 f = u32(c.work[i] >> 32), ch = u32(c.work[i]);
    const Container& file = c.chain->files[f];
    String err;
    if (containerReadChunk(*c.key, file, file.chunks[ch], c.scratch[worker], c.raw[worker], err)) return;
    Lock l(c.mu);
    if (c.bad < 20) report(err.view());
    else if (c.bad == 20) report("(further errors not shown)"_s);
    ++c.bad;
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

void printEntries(const Snapshot& s) {
    for (const Entry& e : s.entries) {
        char mode[11], when[32];
        modeString(e, mode);
        fmtTime(e.mtimeNs, when, sizeof when);
        const StringView p = entryPath(s, e);
        printf("%s %5u %5u %12llu %s %.*s", mode, e.uid, e.gid, (unsigned long long)e.size, when, int(p.count), p.ptr);
        if (e.type == kEntrySymlink) {
            const StringView t = entryTarget(s, e);
            printf(" -> %.*s", int(t.count), t.ptr);
        }
        printf("\n");
    }
}

bool loadKey(const Args& a, MasterKey& key) {
    String err;
    if (!cryptoCpuCheck(err) || !keyLoad(a.key, key, err)) { report(err); return false; }
    return true;
}

} // namespace

int cmdCheck(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("check", argc, argv, first, kArgKey | kArgJobs | kArgVerbose, a)) return kExitUsage;
    if (a.positional.count == 0) { fprintf(stderr, "backu check: name the backup files to check\n"); return kExitUsage; }
    MasterKey key;
    if (!loadKey(a, key)) return kExitRuntime;
    String err;
    Chain chain;
    if (!chainOpen(key, a.positional, chain, err)) { report(err); fprintf(stderr, "backu: check FAILED\n"); return kExitRuntime; }

    u32 problems = 0;
    for (u32 i = 0; i < chain.snaps.count; ++i) {
        if (!chainResolve(chain, i, err)) { report(err); ++problems; continue; }
        const u32 missing = chainCountMissing(chain, chain.snaps[i].snap);
        if (missing) {
            fprintf(stderr, "backu: %s: snapshot references %u chunks that are in none of the given files\n",
                    chain.files[i].path.c_str(), missing);
            ++problems;
        }
    }

    CheckCtx c;
    c.key = &key; c.chain = &chain;
    c.mu.init();
    for (u32 f = 0; f < chain.files.count; ++f)
        for (u32 ch = 0; ch < chain.files[f].chunks.count; ++ch) c.work.push((u64(f) << 32) | ch);
    ThreadPool pool;
    pool.init(argsJobs(a));
    c.scratch.resize(pool.threads);
    c.raw.resize(pool.threads);
    pool.run(c.work.count, checkTask, &c);
    pool.shutdown();
    c.mu.destroy();
    problems += c.bad;

    if (problems) {
        fprintf(stderr, "backu: check FAILED: %u problem%s in %u file%s\n", problems, problems == 1 ? "" : "s",
                chain.files.count, chain.files.count == 1 ? "" : "s");
        return kExitRuntime;
    }
    if (a.verbose)
        fprintf(stderr, "backu: check ok: %u files, %u chunk records verified, latest snapshot generation %llu\n",
                chain.files.count, c.work.count, (unsigned long long)chain.snaps[chainLatest(chain)].head.gen);
    return kExitOk;
}

int cmdIndex(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("index", argc, argv, first, kArgKey | kArgOut, a)) return kExitUsage;
    if (!a.out) { fprintf(stderr, "backu index: -o INDEX is required\n"); return kExitUsage; }
    if (a.positional.count == 0) { fprintf(stderr, "backu index: name the backup files of the chain\n"); return kExitUsage; }
    MasterKey key;
    if (!loadKey(a, key)) return kExitRuntime;
    String err;
    Chain chain;
    if (!chainOpen(key, a.positional, chain, err)) { report(err); return kExitRuntime; }
    const u32 latest = chainLatest(chain);
    if (!chainResolve(chain, latest, err)) { report(err); return kExitRuntime; }

    IndexData d;
    d.snap = move(chain.snaps[latest].snap);
    d.snap.hasParent = false;
    indexCollectDistinct(d);
    // Location: the file each chunk was found in (first given file holding it).
    Array<u32> slotOf;
    slotOf.resize(chain.files.count);
    for (u32 i = 0; i < slotOf.count; ++i) slotOf[i] = kInvalidIndex;
    d.location.resize(d.distinct.count);
    for (u32 i = 0; i < d.distinct.count; ++i) {
        u32 f, ch;
        if (!chainFind(chain, d.distinct[i], f, ch)) {
            fprintf(stderr, "backu: the latest snapshot references chunks in none of the given files; "
                            "an index from it would make the next increment reference missing data\n");
            return kExitRuntime;
        }
        if (slotOf[f] == kInvalidIndex) {
            slotOf[f] = d.backups.count;
            ChunkId& b = d.backups.addDefault();
            memCopy(b.b, chain.files[f].keys.salt, kIdBytes);
        }
        d.location[i] = slotOf[f];
    }
    ByteWriter w;
    indexEncode(d, w);
    if (!indexFileWrite(key, a.out, w.buf.ptr, w.buf.count, err)) { report(err); return kExitRuntime; }
    return kExitOk;
}

int cmdList(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("list", argc, argv, first, kArgKey, a)) return kExitUsage;
    if (a.positional.count == 0) { fprintf(stderr, "backu list: name backup files (or one index file)\n"); return kExitUsage; }
    MasterKey key;
    if (!loadKey(a, key)) return kExitRuntime;
    String err;

    // An index file on its own: show its snapshot and where its chunks live.
    if (a.positional.count == 1) {
        Container probe;
        if (containerOpen(key, a.positional[0], probe, err) && probe.kind == kKindIndex) {
            Array<u8> body;
            IndexData d;
            if (!indexFileRead(key, a.positional[0], body, err) || !indexDecode(body.ptr, body.count, d, err)) {
                report(err); return kExitRuntime;
            }
            char label[17], when[32];
            snapLabel(d.snap, label);
            fmtTime(d.snap.createdNs, when, sizeof when);
            printf("# index: snapshot %s, generation %llu, created %s, %u entries, %u distinct chunks\n", label,
                   (unsigned long long)d.snap.gen, when, d.snap.entries.count, d.distinct.count);
            Array<u32> perBackup;
            perBackup.resize(d.backups.count);
            for (u32 i = 0; i < perBackup.count; ++i) perBackup[i] = 0;
            for (u32 l : d.location) ++perBackup[l];
            for (u32 i = 0; i < d.backups.count; ++i) {
                char hex[33];
                hexEncode(d.backups[i].b, 16, hex);
                hex[32] = 0;
                printf("# chunks written to backup %.16s: %u\n", hex, perBackup[i]);
            }
            printEntries(d.snap);
            return kExitOk;
        }
        err.clear();
    }

    Chain chain;
    if (!chainOpen(key, a.positional, chain, err)) { report(err); return kExitRuntime; }
    const u32 latest = chainLatest(chain);
    for (u32 i = 0; i < chain.files.count; ++i) {
        const Snapshot& h = chain.snaps[i].head;
        char label[17], parent[17], when[32], salt[17];
        snapLabel(h, label);
        if (h.hasParent) { hexEncode(h.parent, 8, parent); parent[16] = 0; } else memCopy(parent, "(full)", 7);
        hexEncode(chain.files[i].keys.salt, 8, salt);
        salt[16] = 0;
        fmtTime(h.createdNs, when, sizeof when);
        // A digest of the chunk table (IDs, record and raw lengths, nonces, in
        // file order): two backups of the same tree under the same key have
        // the same one whatever -j was, which is how the tests check that the
        // output does not depend on thread scheduling.
        ByteWriter t;
        for (const ChunkLoc& l : chain.files[i].chunks) {
            t.bytes(l.id.b, kIdBytes); t.varint(l.recLen); t.varint(l.rawLen); t.varint(l.nonce);
        }
        u8 digest[32];
        blake3Hash(t.buf.ptr, t.buf.count, digest);
        char dhex[17];
        hexEncode(digest, 8, dhex);
        dhex[16] = 0;
        printf("# %s: backup %s, snapshot %s, parent %s, generation %llu, created %s, %u chunk records (table %s)%s\n",
               chain.files[i].path.c_str(), salt, label, parent, (unsigned long long)h.gen, when,
               chain.files[i].chunks.count, dhex, i == latest ? "  <- latest" : "");
    }
    if (!chainResolve(chain, latest, err)) { report(err); return kExitRuntime; }
    printEntries(chain.snaps[latest].snap);
    return kExitOk;
}

int cmdKeygen(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("keygen", argc, argv, first, 0, a)) return kExitUsage;
    if (a.positional.count) { fprintf(stderr, "backu keygen: takes no arguments (the key goes to stdout)\n"); return kExitUsage; }
    String key, err;
    if (!keyGenerate(key, err)) { report(err); return kExitRuntime; }
    const bool ok = writeAll(1, key.ptr, key.count);
    secureZero(key.ptr, key.count);
    if (!ok) { report("writing the key failed"_s); return kExitRuntime; }
    if (isatty(1))
        fprintf(stderr, "backu: that key is the only way to read your backups; store it somewhere other than them\n");
    return kExitOk;
}

} // namespace bk
