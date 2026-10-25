// create.cpp — `backu create`: walk, read, chunk, dedupe, compress, encrypt,
// stream to stdout; then write the new index.
//
// THE PIPELINE. After a metadata-only walk, the file data flows through four
// stages connected by bounded rings, so memory is capped no matter how big
// the tree is:
//
//   reader (1 thread)   large sequential read()s (kReadBlock) into a ring of
//                       kBlocks reused buffers; posix_fadvise SEQUENTIAL before
//                       and DONTNEED after each file; O_NOATIME when allowed;
//                       openat relative to a cached directory fd.
//   chunker (1 thread)  copies each block behind the unconsumed tail of the
//                       previous one and cuts chunks (FastCDC or SQLite pages)
//                       into job slots, numbering them 0, 1, 2, ...
//   workers (-j N)      per job: keyed-BLAKE3 ID, dedupe lookup, LZ4, AES-GCM.
//   writer (main)       takes jobs strictly in sequence order and writes them.
//
// DETERMINISM. A chunk's sequence number is its nonce, assigned by the
// chunker before any worker sees it, so the bytes a worker produces do not
// depend on which worker ran or when. Dedupe inside one backup is decided by
// the in-order writer: the first occurrence (lowest sequence) of an ID is
// stored, later ones are dropped. A worker may skip the compress+encrypt work
// for an ID the writer has ALREADY committed — that can only be a lower
// sequence number, so the outcome is the same either way. The output is
// therefore a function of the input tree, the key and the salt; thread count
// and scheduling only change how fast it appears.
//
// THE FILES CACHE. With --base, a regular file whose (dev, ino, size,
// mtime_ns, ctime_ns) all equal the base snapshot's entry for the same path
// is not opened at all: its chunk list is copied from the base. ctime is
// compared too because it cannot be set from user space — `touch -d` can put
// mtime back, but the ctime moves. The base snapshot's chunks are all in the
// chain by construction (see chain.hpp and docs/design.md §Merge), so this
// stays valid across merges. One guard against the classic race (a file
// modified within the same timestamp tick right after it was read): a cache
// entry is only trusted when its ctime is at least a second older than the
// moment the base backup started. Such files are simply read once more.

#include "chunk/chunker.hpp"
#include "cmd/args.hpp"
#include "cmd/commands.hpp"
#include "core/sort.hpp"
#include "core/thread.hpp"
#include "format/codec.hpp"
#include "format/container.hpp"
#include "format/snapshot.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bk {

namespace {

constexpr u32 kReadBlock = 4u << 20;   // one read() per 4 MiB: syscall cost vanishes, readahead stays fed
constexpr u32 kBlocks = 4;             // reader may run 3 blocks ahead of the chunker
constexpr i64 kRaceGuardNs = 1000000000;

// ---- the walk ---------------------------------------------------------------

struct ReadItem {
    u32 entry;          // index into the walk's entries
    u32 fsOff, fsLen;   // filesystem path, into Walk::fsPaths
};

struct Walk {
    Snapshot snap;               // entries + names; refs filled later
    Array<u32> cacheFrom;        // per entry: base entry to reuse, or kInvalidIndex
    Array<u32> readItem;         // per entry: ReadItem index, or kInvalidIndex
    Array<ReadItem> reads;
    String fsPaths;
    HashIndex seen;              // stored paths already added (overlapping roots)
    const IndexData* base = nullptr;
    bool useCache = false;
    u32 warnings = 0;
    u64 bytesToRead = 0;
    u64 bytesCached = 0;
};

void warn(Walk& w, StringView path, StringView what) {
    fprintf(stderr, "backu: warning: %.*s: %.*s\n", int(path.count), path.ptr, int(what.count), what.ptr);
    ++w.warnings;
}

i64 tsNs(const struct timespec& t) { return i64(t.tv_sec) * 1000000000 + t.tv_nsec; }

void addEntry(Walk& w, int dirfd, const char* name, StringView stored, StringView fsPath, const struct stat& st);

void walkDir(Walk& w, int fd, StringView stored, StringView fsPath) {
    // fdopendir takes ownership of the fd it is given; hand it a dup so the
    // caller's fd stays ours to use for fstatat/openat below.
    const int dfd = dup(fd);
    DIR* d = dfd >= 0 ? fdopendir(dfd) : nullptr;
    if (!d) { if (dfd >= 0) close(dfd); warn(w, fsPath, StringView(strerror(errno))); return; }
    String names;
    Array<u32> offs;
    errno = 0;
    while (struct dirent* de = readdir(d)) {     // glibc: getdents64 under the hood, 32 KiB at a time
        const StringView n(static_cast<const char*>(de->d_name));
        if (n == "."_s || n == ".."_s) continue;
        offs.push(names.count);
        names.append(n);
        names.append('\0');
    }
    if (errno) warn(w, fsPath, StringView(strerror(errno)));
    closedir(d);
    const char* base = names.c_str();
    sortRange(offs.ptr, offs.count, [base](u32 a, u32 b) { return strcmp(base + a, base + b) < 0; });

    String childStored, childFs;
    for (u32 o : offs) {
        const char* n = names.c_str() + o;
        childStored.assign(stored);
        if (!stored.empty()) childStored.append('/');
        childStored.append(StringView(n));
        childFs.assign(fsPath);
        if (!fsPath.endsWith("/"_s)) childFs.append('/');
        childFs.append(StringView(n));
        struct stat st;
        if (fstatat(fd, n, &st, AT_SYMLINK_NOFOLLOW) != 0) { warn(w, childFs, StringView(strerror(errno))); continue; }
        addEntry(w, fd, n, childStored, childFs, st);
    }
}

void addEntry(Walk& w, int dirfd, const char* name, StringView stored, StringView fsPath, const struct stat& st) {
    u8 type;
    if (S_ISREG(st.st_mode)) type = kEntryFile;
    else if (S_ISDIR(st.st_mode)) type = kEntryDir;
    else if (S_ISLNK(st.st_mode)) type = kEntrySymlink;
    else { warn(w, fsPath, "skipping special file (device, fifo or socket)"_s); return; }

    if (!stored.empty()) {
        const u64 h = fnv1a(stored);
        u32 slot = kInvalidIndex, v;
        while ((v = w.seen.next(h, slot)) != kInvalidIndex)
            if (entryPath(w.snap, w.snap.entries[v]) == stored) { warn(w, fsPath, "named twice; backed up once"_s); return; }
    }

    Entry e;
    e.type = type;
    e.mode = st.st_mode & 07777;
    e.uid = st.st_uid; e.gid = st.st_gid;
    e.mtimeNs = tsNs(st.st_mtim);
    e.ctimeNs = tsNs(st.st_ctim);
    e.dev = u64(st.st_dev); e.ino = u64(st.st_ino);
    e.size = type == kEntryFile ? u64(st.st_size) : 0;

    if (type == kEntrySymlink) {
        char buf[4097];
        const ssize_t n = readlinkat(dirfd, name, buf, sizeof buf);
        if (n < 0 || n >= ssize_t(sizeof buf)) { warn(w, fsPath, "cannot read symlink"_s); return; }
        e.targetLen = u32(n);
        e.targetOff = snapshotAddName(w.snap, StringView(buf, u32(n)));
    }

    // A root of "/" or "." has no name of its own: its children become the
    // top-level entries and the root itself is not recorded.
    const bool recordIt = !stored.empty();
    u32 idx = kInvalidIndex;
    if (recordIt) {
        e.pathLen = stored.count;
        e.pathOff = snapshotAddName(w.snap, stored);
        idx = w.snap.entries.count;
        w.snap.entries.push(e);
        w.seen.insert(fnv1a(stored), idx);
        w.cacheFrom.push(kInvalidIndex);
        w.readItem.push(kInvalidIndex);
    }

    if (type == kEntryFile && recordIt) {
        u32 bi = kInvalidIndex;
        if (w.useCache) {
            bi = snapshotFind(w.base->snap, stored);
            if (bi != kInvalidIndex) {
                const Entry& b = w.base->snap.entries[bi];
                const bool same = b.type == kEntryFile && b.dev == e.dev && b.ino == e.ino && b.size == e.size
                               && b.mtimeNs == e.mtimeNs && b.ctimeNs == e.ctimeNs
                               && b.ctimeNs < w.base->snap.createdNs - kRaceGuardNs;
                if (!same) bi = kInvalidIndex;
            }
        }
        if (bi != kInvalidIndex) {
            w.cacheFrom[idx] = bi;
            w.bytesCached += e.size;
        } else {
            ReadItem r;
            r.entry = idx;
            r.fsOff = w.fsPaths.count;
            r.fsLen = fsPath.count;
            w.fsPaths.append(fsPath);
            w.readItem[idx] = w.reads.count;
            w.reads.push(r);
            w.bytesToRead += e.size;
        }
    } else if (type == kEntryDir) {
        const int fd = openat(dirfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) { warn(w, fsPath, StringView(strerror(errno))); return; }
        walkDir(w, fd, stored, fsPath);
        close(fd);
    }
}

// Turn a command-line PATH into its stored name: leading "/" and "./" go,
// trailing "/" goes; ".." is refused (the stored tree must stay inside the
// restore directory, and "../x" has no sane name inside it).
bool storedName(StringView p, String& out) {
    while (p.startsWith("/"_s) || p.startsWith("./"_s)) p = p.from(p[0] == '/' ? 1 : 2);
    while (p.endsWith("/"_s)) p.count--;
    if (p == "."_s) p.count = 0;
    out.assign(p);
    return p.empty() || pathIsSafe(p);
}

// ---- the pipeline -----------------------------------------------------------

constexpr u8 kBlockFirst = 1, kBlockLast = 2, kBlockError = 4;

struct BlockMeta { u32 item; u32 len; u8 flags; };

struct Job {
    u8* raw = nullptr;     // kMaxChunk
    u8* rec = nullptr;     // sealed record
    u64 seq = 0;
    u32 item = 0;
    u32 rawLen = 0;
    u32 recLen = 0;        // 0: duplicate, nothing to write
    ChunkId id;
    u8 state = 0;          // 0 free, 1 queued, 2 done
};

constexpr u8 kJobFree = 0, kJobQueued = 1, kJobDone = 2;

struct Pipe {
    const Walk* walk = nullptr;
    const MasterKey* key = nullptr;
    const ContainerKeys* ckeys = nullptr;

    Mutex mu;
    Cond readerCv, chunkerCv, workerCv, writerCv;
    bool abort = false;

    // reader -> chunker
    u8* bufs[kBlocks] = {};
    BlockMeta meta[kBlocks];
    u32 blockHead = 0, blockTail = 0;
    bool readerDone = false;

    // chunker -> workers -> writer
    Job* jobs = nullptr;
    u32 slots = 0;
    u64 filled = 0, taken = 0, written = 0;
    bool chunkerDone = false;

    // dedupe: base set is read-only; the committed set is written by the
    // writer and read by workers, both under mu.
    const HashIndex* baseIdx = nullptr;
    const Array<ChunkId>* baseIds = nullptr;
    HashIndex committed;
    Array<ChunkId> committedIds;

    // per read item, written by the chunker, read after join
    Array<u64> itemBytes;
    Array<u8> itemFailed;
    u32 readWarnings = 0;    // under mu
};

bool setContains(const HashIndex& idx, const Array<ChunkId>& ids, const ChunkId& id) {
    u32 slot = kInvalidIndex, v;
    while ((v = idx.next(idHash(id), slot)) != kInvalidIndex)
        if (idEqual(ids[v], id)) return true;
    return false;
}

void readWarn(Pipe& p, StringView path, StringView what) {
    Lock l(p.mu);
    fprintf(stderr, "backu: warning: %.*s: %.*s\n", int(path.count), path.ptr, int(what.count), what.ptr);
    ++p.readWarnings;
}

// Reserve the next block buffer; null on abort.
u8* acquireBlock(Pipe& p, u32& slot) {
    Lock l(p.mu);
    while (p.blockHead - p.blockTail == kBlocks && !p.abort) p.readerCv.wait(p.mu);
    if (p.abort) return nullptr;
    slot = p.blockHead % kBlocks;
    return p.bufs[slot];
}

void publishBlock(Pipe& p, u32 item, u32 len, u8 flags) {
    Lock l(p.mu);
    BlockMeta& m = p.meta[p.blockHead % kBlocks];
    m.item = item; m.len = len; m.flags = flags;
    ++p.blockHead;
    p.chunkerCv.broadcast();
}

void* readerMain(void* arg) {
    Pipe& p = *static_cast<Pipe*>(arg);
    const Walk& w = *p.walk;
    String dirPath;
    int dirFd = -1;
    bool noatime = true;
    for (u32 it = 0; it < w.reads.count; ++it) {
        const ReadItem& r = w.reads[it];
        const StringView fs(w.fsPaths.ptr + r.fsOff, r.fsLen);
        // openat relative to a cached directory fd: consecutive files share a
        // directory (the walk is depth-first), so the kernel resolves the
        // directory path once per directory instead of once per file.
        const u32 slash = fs.findLast('/');
        const StringView dir = slash == kInvalidIndex ? "."_s : (slash == 0 ? "/"_s : fs.first(slash));
        const String name(fs.from(slash == kInvalidIndex ? 0 : slash + 1));
        if (dirFd < 0 || !(dirPath.view() == dir)) {
            if (dirFd >= 0) close(dirFd);
            dirPath.assign(dir);
            dirFd = open(dirPath.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
        }
        int fd = -1;
        if (dirFd >= 0) {
            // O_NOATIME: reading for a backup must not dirty every inode's
            // atime. Only the owner (or CAP_FOWNER) may ask; on EPERM drop it
            // for the rest of the run rather than paying a failed open per file.
            const int base = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
            fd = openat(dirFd, name.c_str(), base | (noatime ? O_NOATIME : 0));
            if (fd < 0 && errno == EPERM && noatime) { noatime = false; fd = openat(dirFd, name.c_str(), base); }
        }
        struct stat st;
        if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            readWarn(p, fs, fd < 0 ? StringView(strerror(errno)) : "no longer a regular file; skipped"_s);
            if (fd >= 0) close(fd);
            u32 slot;
            if (!acquireBlock(p, slot)) break;
            publishBlock(p, it, 0, kBlockFirst | kBlockLast | kBlockError);
            continue;
        }
        posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
        u8 flags = kBlockFirst;
        for (;;) {
            u32 slot;
            u8* buf = acquireBlock(p, slot);
            if (!buf) break;
            const i64 n = readFull(fd, buf, kReadBlock);
            if (n < 0) {
                readWarn(p, fs, StringView(strerror(errno)));
                publishBlock(p, it, 0, flags | kBlockLast | kBlockError);
                break;
            }
            const bool last = u64(n) < kReadBlock;
            publishBlock(p, it, u32(n), flags | (last ? kBlockLast : 0));
            flags = 0;
            if (last) break;
        }
        // Done with this file: tell the kernel its pages need not stay cached,
        // so backing up 10 GB does not evict the working set of everything
        // else on the machine.
        posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
        close(fd);
        Lock l(p.mu);
        if (p.abort) break;
    }
    if (dirFd >= 0) close(dirFd);
    Lock l(p.mu);
    p.readerDone = true;
    p.chunkerCv.broadcast();
    return nullptr;
}

// Hand one chunk to the workers; false on abort.
bool emitJob(Pipe& p, u32 item, const u8* data, u32 n) {
    Job* j;
    {
        Lock l(p.mu);
        while (p.filled - p.written >= p.slots && !p.abort) p.chunkerCv.wait(p.mu);
        if (p.abort) return false;
        j = &p.jobs[p.filled % p.slots];
    }
    memCopy(j->raw, data, n);    // the slot is free and only the chunker fills free slots
    Lock l(p.mu);
    j->seq = p.filled;
    j->item = item;
    j->rawLen = n;
    j->state = kJobQueued;
    ++p.filled;
    p.workerCv.signal();
    return true;
}

void* chunkerMain(void* arg) {
    Pipe& p = *static_cast<Pipe*>(arg);
    Array<u8> win;
    win.resize(kReadBlock + kMaxChunk);
    u32 winLen = 0;
    u32 fixed = 0;
    bool ok = true;
    while (ok) {
        BlockMeta m;
        u8* buf;
        {
            Lock l(p.mu);
            while (p.blockTail == p.blockHead && !p.readerDone && !p.abort) p.chunkerCv.wait(p.mu);
            if (p.abort || p.blockTail == p.blockHead) break;
            m = p.meta[p.blockTail % kBlocks];
            buf = p.bufs[p.blockTail % kBlocks];
        }
        if (m.flags & kBlockFirst) {
            winLen = 0;
            fixed = sqliteChunkSize(buf, m.len);
            p.itemBytes[m.item] = 0;
        }
        if (m.flags & kBlockError) {
            p.itemFailed[m.item] = 1;
            winLen = 0;
        } else {
            memCopy(win.ptr + winLen, buf, m.len);
            winLen += m.len;
            p.itemBytes[m.item] += m.len;
        }
        {
            Lock l(p.mu);
            ++p.blockTail;
            p.readerCv.signal();
        }
        if (m.flags & kBlockError) continue;
        const bool last = m.flags & kBlockLast;
        const u32 need = fixed ? fixed : kCdcMax;
        u32 pos = 0;
        while (ok) {
            const u32 rem = winLen - pos;
            if (rem == 0 || (!last && rem < need)) break;
            const u32 cut = fixed ? min(fixed, rem) : cdcNextCut(win.ptr + pos, rem);
            ok = emitJob(p, m.item, win.ptr + pos, cut);
            pos += cut;
        }
        memMove(win.ptr, win.ptr + pos, winLen - pos);
        winLen -= pos;
    }
    Lock l(p.mu);
    p.chunkerDone = true;
    p.workerCv.broadcast();
    p.writerCv.broadcast();
    return nullptr;
}

void* workerMain(void* arg) {
    Pipe& p = *static_cast<Pipe*>(arg);
    CodecState* st = static_cast<CodecState*>(defaultAllocator().alloc(sizeof(CodecState)));
    Array<u8> payload;
    payload.resize(codecBound(kMaxChunk));
    p.mu.lock();
    for (;;) {
        while (p.taken == p.filled && !p.chunkerDone && !p.abort) p.workerCv.wait(p.mu);
        if (p.abort || p.taken == p.filled) break;
        Job& j = p.jobs[p.taken % p.slots];
        ++p.taken;
        p.mu.unlock();

        chunkIdOf(*p.key, j.raw, j.rawLen, j.id);
        bool dup = setContains(*p.baseIdx, *p.baseIds, j.id);
        if (!dup) {
            p.mu.lock();
            dup = setContains(p.committed, p.committedIds, j.id);
            p.mu.unlock();
        }
        u32 recLen = 0;
        if (!dup) {
            const u32 n = codecEncode(*st, j.raw, j.rawLen, payload.ptr);
            recLen = recordSeal(*p.ckeys, j.seq, kRecChunk, &j.id, payload.ptr, n, j.rec);
        }

        p.mu.lock();
        j.recLen = recLen;
        j.state = kJobDone;
        if (j.seq == p.written) p.writerCv.signal();
    }
    p.mu.unlock();
    defaultAllocator().free(st);
    return nullptr;
}

struct Stats {
    u64 chunks = 0, newChunks = 0, rawRead = 0;
};

// The writer: in sequence order, store first occurrences, record every ref.
void writerLoop(Pipe& p, ContainerWriter& cw, Array<ChunkId>& refs, Array<u32>& itemFirst,
                Array<u32>& itemCount, Stats& stats) {
    p.mu.lock();
    for (;;) {
        while (!p.abort && (p.written < p.filled ? p.jobs[p.written % p.slots].state != kJobDone : !p.chunkerDone))
            p.writerCv.wait(p.mu);
        if (p.abort || (p.written == p.filled && p.chunkerDone)) break;
        Job& j = p.jobs[p.written % p.slots];
        // Only this thread inserts into `committed`, so reading it without
        // the lock here is safe; workers read it under the lock.
        const bool store = j.recLen && !setContains(p.committed, p.committedIds, j.id);
        if (store) {
            p.committed.insert(idHash(j.id), p.committedIds.count);
            p.committedIds.push(j.id);
        }
        p.mu.unlock();

        if (store) {
            writerAddChunk(cw, j.id, j.seq, j.rawLen, j.rec, j.recLen);
            ++stats.newChunks;
        }
        ++stats.chunks;
        stats.rawRead += j.rawLen;
        if (itemCount[j.item] == 0) itemFirst[j.item] = refs.count;
        ++itemCount[j.item];
        refs.push(j.id);
        const bool failed = cw.out->failed;

        p.mu.lock();
        j.state = kJobFree;
        ++p.written;
        p.chunkerCv.signal();
        if (failed) { p.abort = true; p.readerCv.broadcast(); p.chunkerCv.broadcast(); p.workerCv.broadcast(); }
    }
    p.mu.unlock();
}

void fmtBytes(u64 n, char* buf, usize cap) {
    if (n >= (u64(1) << 30)) snprintf(buf, cap, "%.2f GiB", double(n) / double(u64(1) << 30));
    else if (n >= (u64(1) << 20)) snprintf(buf, cap, "%.2f MiB", double(n) / double(u64(1) << 20));
    else if (n >= 1024) snprintf(buf, cap, "%.1f KiB", double(n) / 1024.0);
    else snprintf(buf, cap, "%llu B", (unsigned long long)n);
}

} // namespace

int cmdCreate(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("create", argc, argv, first, kArgKey | kArgBase | kArgIndexOut | kArgJobs | kArgNoCache | kArgVerbose, a))
        return kExitUsage;
    if (!a.indexOut) {
        fprintf(stderr, "backu create: --index-out INDEX is required (the next increment is made from it; "
                        "it may be the same file as --base)\n");
        return kExitUsage;
    }
    if (a.positional.count == 0) { fprintf(stderr, "backu create: name at least one PATH to back up\n"); return kExitUsage; }
    if (isatty(1)) {
        fprintf(stderr, "backu create: refusing to write a backup to a terminal; redirect stdout to a file or a pipe\n");
        return kExitUsage;
    }
    // A pipe reader that goes away (aws s3 cp failing) must become a write
    // error we report — and a run that does NOT write the index — not a
    // silent death by SIGPIPE.
    signal(SIGPIPE, SIG_IGN);

    String err;
    if (!cryptoCpuCheck(err)) { report(err); return kExitRuntime; }
    MasterKey key;
    if (!keyLoad(a.key, key, err)) { report(err); return kExitRuntime; }

    const i64 startNs = nowNs();
    IndexData base;
    const bool haveBase = a.base != nullptr;
    if (haveBase) {
        Array<u8> body;
        if (!indexFileRead(key, a.base, body, err) || !indexDecode(body.ptr, body.count, base, err)) {
            report(err); return kExitRuntime;
        }
        snapshotIndexPaths(base.snap);
    }
    HashIndex baseIdx;
    baseIdx.init(base.distinct.count);
    for (u32 i = 0; i < base.distinct.count; ++i) baseIdx.insert(idHash(base.distinct[i]), i);

    // ---- walk
    Walk w;
    w.base = &base;
    w.useCache = haveBase && !a.noCache;
    for (const char* rootArg : a.positional) {
        String stored;
        if (!storedName(StringView(rootArg), stored)) {
            fprintf(stderr, "backu create: '%s' contains a '..' component; cd to its parent and name it from there\n", rootArg);
            return kExitUsage;
        }
        struct stat st;
        if (fstatat(AT_FDCWD, rootArg, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            fprintf(stderr, "backu create: %s: %s\n", rootArg, strerror(errno));
            return kExitRuntime;
        }
        // For a root, "dirfd + name" is the cwd plus the path as given.
        addEntry(w, AT_FDCWD, rootArg, stored.view(), StringView(rootArg), st);
    }

    // ---- pipeline
    const u32 workers = argsJobs(a);
    Pipe p;
    p.walk = &w;
    p.key = &key;
    p.mu.init(); p.readerCv.init(); p.chunkerCv.init(); p.workerCv.init(); p.writerCv.init();
    p.baseIdx = &baseIdx;
    p.baseIds = &base.distinct;
    p.committed.init(1024);
    p.itemBytes.resize(w.reads.count);
    p.itemFailed.resize(w.reads.count);
    for (u32 i = 0; i < w.reads.count; ++i) { p.itemBytes[i] = 0; p.itemFailed[i] = 0; }
    Array<u8> blockMem;
    blockMem.resize(kReadBlock * kBlocks);
    for (u32 i = 0; i < kBlocks; ++i) p.bufs[i] = blockMem.ptr + usize(i) * kReadBlock;
    // Slots bound the work in flight: enough that every worker has a job and
    // the writer a backlog while one worker is slow, few enough that memory
    // stays at ~130 KiB per slot (raw + sealed buffers).
    p.slots = workers * 4 + 8;
    const u32 recCap = codecBound(kMaxChunk) + kRecordOverhead;
    Array<u8> jobMem;
    jobMem.resize(p.slots * (kMaxChunk + recCap));
    Array<Job> jobs;
    jobs.resize(p.slots);
    for (u32 i = 0; i < p.slots; ++i) {
        jobs[i].raw = jobMem.ptr + usize(i) * (kMaxChunk + recCap);
        jobs[i].rec = jobs[i].raw + kMaxChunk;
    }
    p.jobs = jobs.ptr;

    OutStream out;
    out.init(1);
    ContainerWriter cw;
    if (!writerBegin(cw, out, key, err)) { report(err); return kExitRuntime; }
    p.ckeys = &cw.keys;

    Array<ChunkId> newRefs;
    Array<u32> itemFirst, itemCount;
    itemFirst.resize(w.reads.count);
    itemCount.resize(w.reads.count);
    for (u32 i = 0; i < w.reads.count; ++i) { itemFirst[i] = 0; itemCount[i] = 0; }
    Stats stats;

    Thread reader, chunker;
    Array<Thread> pool;
    pool.resize(workers);
    u32 started = 0;
    if (!reader.start(readerMain, &p) || !chunker.start(chunkerMain, &p)) {
        report("cannot start threads"_s); return kExitRuntime;
    }
    for (u32 i = 0; i < workers; ++i) {
        if (!pool[started].start(workerMain, &p)) break;
        ++started;
    }
    if (started == 0) { report("cannot start worker threads"_s); return kExitRuntime; }
    writerLoop(p, cw, newRefs, itemFirst, itemCount, stats);
    reader.join();
    chunker.join();
    for (u32 i = 0; i < started; ++i) pool[i].join();

    if (out.failed) {
        fprintf(stderr, "backu: writing the backup to stdout failed: %s (index not written)\n", strerror(out.savedErrno));
        return kExitRuntime;
    }

    // ---- assemble the snapshot in entry order
    Snapshot& s = w.snap;
    Snapshot fin;
    fin.names = move(s.names);
    fin.entries.reserve(s.entries.count);
    fin.refs.reserve(newRefs.count);
    for (u32 i = 0; i < s.entries.count; ++i) {
        Entry e = s.entries[i];
        if (e.type == kEntryFile) {
            e.firstRef = fin.refs.count;
            if (w.cacheFrom[i] != kInvalidIndex) {
                const Entry& b = base.snap.entries[w.cacheFrom[i]];
                fin.refs.appendRange(base.snap.refs.ptr + b.firstRef, b.refCount);
                e.refCount = b.refCount;
            } else {
                const u32 it = w.readItem[i];
                if (p.itemFailed[it]) continue;     // unreadable: left out (warned)
                fin.refs.appendRange(newRefs.ptr + itemFirst[it], itemCount[it]);
                e.refCount = itemCount[it];
                if (p.itemBytes[it] != e.size) {
                    const StringView path = entryPath(fin, e);
                    fprintf(stderr, "backu: warning: %.*s: changed size while being read; stored what was read\n",
                            int(path.count), path.ptr);
                    ++w.warnings;
                    e.size = p.itemBytes[it];
                }
            }
        }
        fin.entries.push(e);
    }
    if (!randomBytes(fin.id, kSnapshotIdBytes, err)) { report(err); return kExitRuntime; }
    fin.gen = haveBase ? base.snap.gen + 1 : 1;
    fin.createdNs = startNs;
    if (haveBase) {
        fin.hasParent = true;
        memCopy(fin.parent, base.snap.id, kSnapshotIdBytes);
    }

    ByteWriter manifest;
    snapshotEncode(fin, haveBase ? &base.snap : nullptr, manifest);
    if (!writerFinish(cw, manifest.buf.ptr, manifest.buf.count, err)) { report(err); return kExitRuntime; }

    // ---- the new index: this snapshot, self-contained, plus locations
    IndexData idx;
    idx.snap = move(fin);
    idx.snap.hasParent = false;
    indexCollectDistinct(idx);
    ChunkId self;
    memCopy(self.b, cw.keys.salt, kIdBytes);
    Array<u32> remap;                    // base backup slot -> new slot
    remap.resize(base.backups.count);
    for (u32 i = 0; i < remap.count; ++i) remap[i] = kInvalidIndex;
    idx.backups.push(self);
    idx.location.resize(idx.distinct.count);
    for (u32 i = 0; i < idx.distinct.count; ++i) {
        const ChunkId& id = idx.distinct[i];
        u32 loc = 0;
        if (!setContains(p.committed, p.committedIds, id)) {
            u32 slot = kInvalidIndex, v;
            while ((v = baseIdx.next(idHash(id), slot)) != kInvalidIndex)
                if (idEqual(base.distinct[v], id)) break;
            if (v != kInvalidIndex && base.location.count) {
                const u32 old = base.location[v];
                if (remap[old] == kInvalidIndex) { remap[old] = idx.backups.count; idx.backups.push(base.backups[old]); }
                loc = remap[old];
            }
        }
        idx.location[i] = loc;
    }
    ByteWriter ib;
    indexEncode(idx, ib);
    if (!indexFileWrite(key, a.indexOut, ib.buf.ptr, ib.buf.count, err)) { report(err); return kExitRuntime; }

    if (a.verbose) {
        u32 cachedFiles = 0;
        for (u32 c : w.cacheFrom) if (c != kInvalidIndex) ++cachedFiles;
        char b1[32], b2[32], b3[32];
        fmtBytes(stats.rawRead, b1, sizeof b1);
        fmtBytes(w.bytesCached, b2, sizeof b2);
        fmtBytes(out.written, b3, sizeof b3);
        const double secs = double(nowNs() - startNs) / 1e9;
        fprintf(stderr,
                "backu: %u entries, %u files read (%s), %u from files cache (%s)\n"
                "backu: %llu chunks, %llu new; wrote %s in %.2f s (%.0f MiB/s read) with %u workers\n",
                idx.snap.entries.count, w.reads.count, b1, cachedFiles, b2,
                (unsigned long long)stats.chunks, (unsigned long long)stats.newChunks, b3, secs,
                secs > 0 ? double(stats.rawRead) / secs / double(1 << 20) : 0.0, started);
    }
    return (w.warnings || p.readWarnings) ? kExitRuntime : kExitOk;
}

} // namespace bk
