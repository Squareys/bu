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
//   chunker (1 thread)  moves the previous block's short tail in front of the
//                       new block and cuts chunks (FastCDC or SQLite pages),
//                       numbering them 0, 1, 2, ...; jobs point INTO the block.
//   workers (-j N)      per job: keyed-BLAKE3 ID, dedupe lookup, LZ4, AES-GCM,
//                       reading the chunk where the reader put it.
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

constexpr u32 kReadBlock = 1u << 20;   // one read() per MiB: syscall cost vanishes, and a block stays cache-resident until workers are done with it
constexpr u32 kBlocks = 12;            // 12 MiB in flight: readers run ahead while workers still read older blocks
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
    bool skipOut = false;        // stdout is a regular file at (skipDev, skipIno)
    u64 skipDev = 0, skipIno = 0;
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
    if (w.skipOut && u64(st.st_dev) == w.skipDev && u64(st.st_ino) == w.skipIno) return;   // our own output

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

// A read buffer: kMaxChunk bytes of headroom, then kReadBlock bytes of data.
// The chunker moves the unconsumed tail of the previous block (always shorter
// than one maximal chunk) into the headroom right before this block's data,
// so every chunk lies contiguous inside exactly one buffer and workers hash
// and compress straight out of it: the pipeline copies no file data.
constexpr u8 kBlockFree = 0, kBlockReading = 1, kBlockReady = 2, kBlockChunking = 3, kBlockDraining = 4;

struct Block {
    u8* mem = nullptr;     // kMaxChunk headroom + kReadBlock data
    u32 item = 0;
    u32 len = 0;           // data bytes after the headroom
    u8 flags = 0;
    u8 state = kBlockFree; // under mu
    u32 refs = 0;          // jobs still reading from this block, under mu
    CdcHits hits;          // CDC candidates in [0, len), block-relative (phase 1)
    u8* data() const { return mem + kMaxChunk; }
};

struct Job {
    const u8* raw = nullptr;   // inside blocks[block]
    u8* rec = nullptr;         // sealed record (slot-owned buffer)
    u64 seq = 0;
    u32 block = 0;
    u32 item = 0;
    u32 rawLen = 0;
    u32 recLen = 0;            // 0: duplicate, nothing to write
    ChunkId id;
    u8 state = 0;
};

constexpr u8 kJobFree = 0, kJobQueued = 1, kJobDone = 2;

struct Pipe {
    const Walk* walk = nullptr;
    const MasterKey* key = nullptr;
    const ContainerKeys* ckeys = nullptr;

    Mutex mu;
    Cond readerCv, chunkerCv, workerCv, writerCv;
    bool abort = false;

    // readers -> chunker. Readers claim (file, offset) ranges in order, each
    // with the next ring slot, and fill them concurrently; the chunker takes
    // slots strictly in ring order, so file order is preserved.
    Block blocks[kBlocks];
    u32 blockHead = 0, blockTail = 0;
    u32 claimItem = 0;         // next read item to claim from
    u64 claimOffset = 0;       // next offset in it
    u32 readersRunning = 0;

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

    // per read item
    Array<u64> itemBytes;      // chunker only, read after join
    Array<u8> itemFailed;      // under mu
    Array<u8> itemShrunk;      // under mu
    u32 readWarnings = 0;      // under mu
};

bool setContains(const HashIndex& idx, const Array<ChunkId>& ids, const ChunkId& id) {
    u32 slot = kInvalidIndex, v;
    while ((v = idx.next(idHash(id), slot)) != kInvalidIndex)
        if (idEqual(ids[v], id)) return true;
    return false;
}

void readWarnLocked(Pipe& p, StringView path, StringView what) {
    fprintf(stderr, "backu: warning: %.*s: %.*s\n", int(path.count), path.ptr, int(what.count), what.ptr);
    ++p.readWarnings;
}

// Chunker or last worker lets go of a block: free once nobody reads it.
// Called with mu held.
void releaseBlockLocked(Pipe& p, Block& b) {
    if (b.refs == 0) { b.state = kBlockFree; p.readerCv.broadcast(); }
    else b.state = kBlockDraining;
}

// One reader's open file, kept across consecutive claims of the same item.
struct ReaderFd {
    u32 item = kInvalidIndex;
    int fd = -1;
    String dirPath;
    int dirFd = -1;
    bool noatime = true;

    ~ReaderFd() { closeFile(); if (dirFd >= 0) close(dirFd); }
    void closeFile() { if (fd >= 0) close(fd); fd = -1; item = kInvalidIndex; }
};

// Open read item `it` (relative to a cached directory fd). -1 with errno set.
// `sizeNow` is its size at open (only set when it was opened by this call).
int openItem(ReaderFd& r, const Walk& w, u32 it, u64& sizeNow) {
    if (r.item == it) return r.fd;
    r.closeFile();
    const ReadItem& ri = w.reads[it];
    const StringView fs(w.fsPaths.ptr + ri.fsOff, ri.fsLen);
    const u32 slash = fs.findLast('/');
    const StringView dir = slash == kInvalidIndex ? "."_s : (slash == 0 ? "/"_s : fs.first(slash));
    const String name(fs.from(slash == kInvalidIndex ? 0 : slash + 1));
    // Consecutive files share a directory (the walk is depth-first), so the
    // kernel resolves the directory path once per directory, not per file.
    if (r.dirFd < 0 || !(r.dirPath.view() == dir)) {
        if (r.dirFd >= 0) close(r.dirFd);
        r.dirPath.assign(dir);
        r.dirFd = open(r.dirPath.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (r.dirFd < 0) return -1;
    }
    // O_NOATIME: reading for a backup must not dirty every inode's atime.
    // Only the owner (or CAP_FOWNER) may ask; after one EPERM, stop asking.
    const int base = O_RDONLY | O_NOFOLLOW | O_CLOEXEC;
    int fd = openat(r.dirFd, name.c_str(), base | (r.noatime ? O_NOATIME : 0));
    if (fd < 0 && errno == EPERM && r.noatime) { r.noatime = false; fd = openat(r.dirFd, name.c_str(), base); }
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); errno = EINVAL; return -1; }
    sizeNow = u64(st.st_size);
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    r.fd = fd;
    r.item = it;
    return fd;
}

// The readers. Each claims the next kReadBlock range of the walk's file list
// (sizes as the walk saw them — the backup is of the tree as walked) together
// with the next ring slot, preads it — plus the 63 bytes before it, which the
// CDC hash needs to warm up — runs CDC phase 1 over it while it is hot in
// cache, and marks it ready. Several readers means several reads in flight
// (NVMe wants queue depth; many small files want their open/stat latencies
// overlapped) and a CDC scan that keeps up with any number of workers.
void* readerMain(void* arg) {
    Pipe& p = *static_cast<Pipe*>(arg);
    threadSetName("backu-reader");
    const Walk& w = *p.walk;
    ReaderFd rf;
    for (;;) {
        u32 bi, item;
        u64 off;
        u32 len;
        u8 flags;
        {
            Lock l(p.mu);
            for (;;) {
                if (p.abort || p.claimItem >= w.reads.count) { bi = kInvalidIndex; break; }
                bi = p.blockHead % kBlocks;
                if (p.blocks[bi].state == kBlockFree) break;
                p.readerCv.wait(p.mu);
            }
            if (bi == kInvalidIndex) break;
            item = p.claimItem;
            const u64 size = w.snap.entries[w.reads[item].entry].size;
            off = p.claimOffset;
            len = u32(min<u64>(kReadBlock, size - off));
            flags = u8((off == 0 ? kBlockFirst : 0) | (off + len >= size ? kBlockLast : 0));
            if (flags & kBlockLast) { ++p.claimItem; p.claimOffset = 0; }
            else p.claimOffset = off + len;
            Block& b = p.blocks[bi];
            b.state = kBlockReading;
            b.item = item;
            ++p.blockHead;
        }
        Block& b = p.blocks[bi];
        b.hits.hard.clear();
        b.hits.easy.clear();
        u32 got = 0;
        bool failed = false, shrunk = false;
        int err = 0;
        if (len) {
            const u64 planned = w.snap.entries[w.reads[item].entry].size;
            u64 sizeNow = planned;
            const int fd = openItem(rf, w, item, sizeNow);
            // Grown or shrunk since the walk: the backup keeps the walked size
            // (or what is left), and says so, as Borg's "file changed" does.
            if (fd >= 0 && sizeNow != planned) shrunk = true;
            if (fd < 0) { failed = true; err = errno; }
            else {
                // Read the warm-up bytes with the block: one syscall, and the
                // scan then needs nothing from the previous block's buffer.
                const u32 warm = u32(min<u64>(off, 63));
                const i64 n = preadUpTo(fd, b.data() - warm, len + warm, off - warm);
                if (n < 0) { failed = true; err = errno; }
                else {
                    got = n > i64(warm) ? u32(n) - warm : 0;
                    if (got < len) shrunk = true;       // truncated under us
                    if (got) cdcScanWarm(b.data(), warm, got, b.hits);
                    // Read and done with: drop it from the page cache, so a
                    // 10 GB backup does not evict everybody else's working set.
                    posix_fadvise(fd, off_t(off), off_t(len), POSIX_FADV_DONTNEED);
                }
            }
        }
        if (flags & kBlockLast) rf.closeFile();
        Lock l(p.mu);
        if (failed || shrunk) {
            const ReadItem& ri = w.reads[item];
            const StringView fs(w.fsPaths.ptr + ri.fsOff, ri.fsLen);
            if (failed && !p.itemFailed[item]) readWarnLocked(p, fs, StringView(strerror(err)));
            if (shrunk && !failed && !p.itemShrunk[item])
                readWarnLocked(p, fs, "changed size while being backed up; stored the size seen by the walk (or what was left)"_s);
            if (failed) p.itemFailed[item] = 1;
            if (shrunk) p.itemShrunk[item] = 1;
        }
        b.len = got;
        b.flags = u8(flags | (failed ? kBlockError : 0));
        b.state = kBlockReady;
        p.chunkerCv.broadcast();
    }
    Lock l(p.mu);
    --p.readersRunning;
    p.chunkerCv.broadcast();
    return nullptr;
}

// Queue the cuts of one window for the workers, as many per lock round as
// there are free slots; false on abort.
bool emitJobs(Pipe& p, u32 blockIdx, u32 item, const u8* base, const Array<Cut>& cuts) {
    Block& b = p.blocks[blockIdx];
    u32 k = 0;
    while (k < cuts.count) {
        Lock l(p.mu);
        // Hysteresis: once the ring is full, wait until a quarter of it has
        // drained, then queue a whole batch under one lock. Refilling slot by
        // slot cost a futex wake-up per chunk on both sides.
        if (p.filled - p.written >= p.slots)
            while (p.filled - p.written > p.slots - p.slots / 4 && !p.abort) p.chunkerCv.wait(p.mu);
        if (p.abort) return false;
        const u32 n = min<u32>(u32(p.slots - (p.filled - p.written)), cuts.count - k);
        for (u32 i = 0; i < n; ++i, ++k) {
            Job& j = p.jobs[p.filled % p.slots];
            j.seq = p.filled;
            j.raw = base + cuts[k].off;
            j.rawLen = cuts[k].len;
            j.block = blockIdx;
            j.item = item;
            j.state = kJobQueued;
            ++p.filled;
        }
        b.refs += n;
        p.workerCv.broadcast();
    }
    return true;
}

void* chunkerMain(void* arg) {
    Pipe& p = *static_cast<Pipe*>(arg);
    threadSetName("backu-chunker");
    Array<Cut> cuts;
    cuts.reserve(kReadBlock / kCdcMin + 2);
    CdcHits hits;
    u32 fixed = 0;
    // The block still holding an unconsumed tail, and that tail.
    u32 prev = kInvalidIndex;
    u32 tailOff = 0, tailLen = 0;
    bool ok = true;
    while (ok) {
        u32 bi;
        bool dropped;
        {
            Lock l(p.mu);
            for (;;) {
                bi = p.blockTail % kBlocks;
                if (p.abort || p.blocks[bi].state == kBlockReady) break;
                if (p.readersRunning == 0 && p.blockTail == p.blockHead) break;
                p.chunkerCv.wait(p.mu);
            }
            if (p.abort || p.blocks[bi].state != kBlockReady) break;
            p.blocks[bi].state = kBlockChunking;
            ++p.blockTail;
            dropped = p.itemFailed[p.blocks[bi].item];
        }
        Block& b = p.blocks[bi];
        if (b.flags & kBlockFirst) {
            tailLen = 0;     // a new file never continues the previous one's tail
            fixed = sqliteChunkSize(b.data(), b.len);
            p.itemBytes[b.item] = 0;
        }
        // Move the previous block's tail into this block's headroom, then let
        // the previous block go (its queued jobs keep it alive until done).
        // The tail's CDC candidates are found by rescanning it (< 64 KiB):
        // the tail starts a chunk, so its first 63 bytes are never tested and
        // need no warm-up, and rescanning is right even when the tail itself
        // began in the previous block's headroom (a file that shrank mid-read
        // can leave a short, non-final block).
        u8* const win = b.data() - tailLen;
        hits.hard.clear();
        hits.easy.clear();
        if (tailLen && !dropped) {
            memCopy(win, p.blocks[prev].mem + tailOff, tailLen);
            if (!fixed) cdcScan(win, 0, tailLen, hits);
        }
        if (prev != kInvalidIndex) {
            Lock l(p.mu);
            releaseBlockLocked(p, p.blocks[prev]);
            prev = kInvalidIndex;
        }
        if (dropped) {
            // Unreadable (now or in an earlier block): this item is left out
            // of the snapshot; its remaining blocks are discarded.
            tailLen = 0;
            Lock l(p.mu);
            releaseBlockLocked(p, b);
            continue;
        }
        p.itemBytes[b.item] += b.len;
        const u32 winLen = tailLen + b.len;
        const bool last = b.flags & kBlockLast;
        cuts.clear();
        u32 pos = 0;
        if (fixed) {
            for (;;) {
                const u32 rem = winLen - pos;
                if (rem == 0 || (!last && rem < fixed)) break;
                const u32 cut = min(fixed, rem);
                cuts.push(Cut{pos, cut});
                pos += cut;
            }
        } else {
            for (u32 h : b.hits.hard) hits.hard.push(h + tailLen);
            for (u32 h : b.hits.easy) hits.easy.push(h + tailLen);
            pos = cdcSelect(hits, winLen, last, cuts);
        }
        ok = emitJobs(p, bi, b.item, win, cuts);
        tailLen = winLen - pos;
        if (tailLen) {
            prev = bi;
            tailOff = u32(win + pos - b.mem);
        } else {
            Lock l(p.mu);
            releaseBlockLocked(p, b);
        }
    }
    Lock l(p.mu);
    if (prev != kInvalidIndex) releaseBlockLocked(p, p.blocks[prev]);
    p.chunkerDone = true;
    p.workerCv.broadcast();
    p.writerCv.broadcast();
    return nullptr;
}

void* workerMain(void* arg) {
    Pipe& p = *static_cast<Pipe*>(arg);
    threadSetName("backu-worker");
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
        Block& b = p.blocks[j.block];
        if (--b.refs == 0 && b.state == kBlockDraining) { b.state = kBlockFree; p.readerCv.signal(); }
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
// The writer: in sequence order, store first occurrences, record every ref.
// It takes every finished job at the head of the ring in one lock round and
// writes their records with one writev, then frees the slots together.
void writerLoop(Pipe& p, ContainerWriter& cw, Array<ChunkId>& refs, Array<u32>& itemFirst,
                Array<u32>& itemCount, Stats& stats) {
    constexpr u32 kBatch = 64;
    IoSlice vec[kBatch];
    u8 store[kBatch];
    p.mu.lock();
    for (;;) {
        while (!p.abort && (p.written < p.filled ? p.jobs[p.written % p.slots].state != kJobDone : !p.chunkerDone))
            p.writerCv.wait(p.mu);
        if (p.abort || (p.written == p.filled && p.chunkerDone)) break;
        // Claim the run of finished jobs at the head. Only this thread
        // inserts into `committed`, and it does so here, under the lock that
        // workers read it under.
        u32 n = 0;
        while (n < kBatch && p.written + n < p.filled) {
            Job& j = p.jobs[(p.written + n) % p.slots];
            if (j.state != kJobDone) break;
            store[n] = j.recLen && !setContains(p.committed, p.committedIds, j.id);
            if (store[n]) {
                p.committed.insert(idHash(j.id), p.committedIds.count);
                p.committedIds.push(j.id);
            }
            ++n;
        }
        p.mu.unlock();

        u32 nv = 0;
        for (u32 k = 0; k < n; ++k) {
            const Job& j = p.jobs[(p.written + k) % p.slots];
            if (store[k]) {
                vec[nv++] = IoSlice{j.rec, j.recLen};
                writerNoteChunk(cw, j.id, j.seq, j.rawLen, j.recLen);
                ++stats.newChunks;
            }
            ++stats.chunks;
            stats.rawRead += j.rawLen;
            if (itemCount[j.item] == 0) itemFirst[j.item] = refs.count;
            ++itemCount[j.item];
            refs.push(j.id);
        }
        cw.out->writeVec(vec, nv);
        const bool failed = cw.out->failed;

        p.mu.lock();
        const u64 before = p.filled - p.written;
        for (u32 k = 0; k < n; ++k) p.jobs[(p.written + k) % p.slots].state = kJobFree;
        p.written += n;
        // See emitJobs: wake the chunker when the ring drains past the mark.
        const u64 mark = p.slots - p.slots / 4;
        if (before > mark && p.filled - p.written <= mark) p.chunkerCv.signal();
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
    // Fail before reading a byte if the index cannot be written: discovering
    // it after streaming a 100 GB backup would leave a backup with no index.
    {
        String probe(StringView(a.indexOut));
        probe.append(".probe.");
        probe.appendU64(u64(getpid()));
        const int fd = open(probe.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) { fprintf(stderr, "backu: cannot write the index next to %s: %s\n", a.indexOut, strerror(errno)); return kExitRuntime; }
        close(fd);
        unlink(probe.c_str());
    }

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
    // `backu create . > ./today.bk` must not back up its own output while
    // writing it: remember stdout's inode if it is a regular file.
    {
        struct stat out;
        if (fstat(1, &out) == 0 && S_ISREG(out.st_mode)) { w.skipDev = u64(out.st_dev); w.skipIno = u64(out.st_ino); w.skipOut = true; }
    }
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
    p.itemShrunk.resize(w.reads.count);
    for (u32 i = 0; i < w.reads.count; ++i) { p.itemBytes[i] = 0; p.itemFailed[i] = 0; p.itemShrunk[i] = 0; }
    Array<u8> blockMem;
    blockMem.resize((kMaxChunk + kReadBlock) * kBlocks);
    for (u32 i = 0; i < kBlocks; ++i) p.blocks[i].mem = blockMem.ptr + usize(i) * (kMaxChunk + kReadBlock);
    // Slots bound the work in flight: enough that every worker has a job and
    // the writer a backlog while one worker is slow, few enough that memory
    // stays at ~65 KiB per slot (one sealed-record buffer; raw data stays in
    // the read blocks).
    p.slots = workers * 4 + 8;
    // Readers: enough to keep a few reads in flight and the CDC scan (about a
    // fifth of the per-byte work) ahead of the workers.
    const u32 readers = min<u32>(4, max<u32>(1, (workers + 1) / 2));
    const u32 recCap = codecBound(kMaxChunk) + kRecordOverhead;
    Array<u8> jobMem;
    jobMem.resize(p.slots * recCap);
    Array<Job> jobs;
    jobs.resize(p.slots);
    for (u32 i = 0; i < p.slots; ++i) jobs[i].rec = jobMem.ptr + usize(i) * recCap;
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

    Thread chunker;
    Array<Thread> readerThreads, pool;
    readerThreads.resize(readers);
    pool.resize(workers);
    u32 started = 0, readersStarted = 0;
    for (u32 i = 0; i < readers; ++i) {
        { Lock l(p.mu); ++p.readersRunning; }    // before start: a fast reader may finish at once
        if (!readerThreads[readersStarted].start(readerMain, &p)) { Lock l(p.mu); --p.readersRunning; break; }
        ++readersStarted;
    }
    if (readersStarted == 0 || !chunker.start(chunkerMain, &p)) {
        report("cannot start threads"_s); return kExitRuntime;
    }
    for (u32 i = 0; i < workers; ++i) {
        if (!pool[started].start(workerMain, &p)) break;
        ++started;
    }
    if (started == 0) { report("cannot start worker threads"_s); return kExitRuntime; }
    writerLoop(p, cw, newRefs, itemFirst, itemCount, stats);
    for (u32 i = 0; i < readersStarted; ++i) readerThreads[i].join();
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
                e.size = p.itemBytes[it];           // differs only if it shrank (warned by the reader)
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
