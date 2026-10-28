// create.cpp — `bu create`: walk, read, chunk, dedupe, compress, encrypt,
// append one segment to a chain (or stream it to a pipe).
//
// WHERE IT GOES. CHAIN is a chain file: create locks it, reads its latest
// snapshot from the tail (the base: dedupe set, delta base and files cache in
// one), appends a segment with O_APPEND and fsyncs. Any failure — a write
// error, SIGINT, SIGTERM, SIGHUP — truncates the file back to where the
// segment began, so a chain never holds half a segment that bu wrote and
// gave up on; only SIGKILL or a crash can leave one, and readers skip it
// (chain.hpp). CHAIN `-` on a pipe streams the segment instead, with the
// base from an index file (--base) and the next one written by --index-out:
// the pipe cannot be read back.
//
// THE PIPELINE. After a metadata-only walk, the file data flows through four
// stages connected by bounded rings, so memory is capped no matter how big
// the tree is:
//
//   readers (up to 8)   1 MiB preads (kReadBlock) into a ring of kBlocks
//                       reused buffers, CDC phase 1 on each; posix_fadvise
//                       SEQUENTIAL before and DONTNEED after each range;
//                       O_NOATIME when allowed; openat relative to a cached
//                       directory fd.
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
// THE FILES CACHE. With a base, a regular file whose (dev, ino, size,
// mtime_ns, ctime_ns) all equal the base snapshot's entry for the same path
// is not opened at all: its chunk list is copied from the base. ctime is
// compared too because it cannot be set from user space — `touch -d` can put
// mtime back, but the ctime moves. The base snapshot's chunks are all in the
// chain by construction (see chain.hpp and docs/design.md §Merge), so this
// stays valid across merges. One guard against the classic race (a file
// modified within the same timestamp tick right after it was read): a cache
// entry is only trusted when its ctime is at least a second older than the
// moment the base backup started. Such files are simply read once more.
//
// WHAT IS WALKED. Each PATH is stored as given, less a leading "/" or "./";
// -C DIR makes create fchdir into DIR for the walk and the reads (tar's -C),
// so `-C /srv/data .` stores app.db instead of srv/data/app.db. Everything
// else named on the command line (CHAIN, --base, --index-out, the key and
// passphrase files) is opened before the fchdir or after the fchdir back, so
// it stays relative to where bu was started. --exclude patterns
// (cmd/exclude.hpp) are tested before an entry is even stat'ed, and an
// excluded directory is not opened. -x keeps the walk on each PATH's
// filesystem: a mount point is stored as an empty directory (so a restore
// recreates the place to mount on) and not descended into, as rsync -x does.

#include "chunk/chunker.hpp"
#include "cmd/args.hpp"
#include "cmd/chain.hpp"
#include "cmd/commands.hpp"
#include "cmd/exclude.hpp"
#include "cmd/passphrase.hpp"
#include "core/sort.hpp"
#include "core/thread.hpp"
#include "format/codec.hpp"
#include "format/snapshot.hpp"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bk {

namespace {

constexpr u32 kReadBlock = 1u << 20;   // one read() per MiB: syscall cost vanishes, and a block stays cache-resident until workers are done with it
constexpr u32 kBlocks = 16;            // 16 MiB in flight: readers run ahead while workers still read older blocks
constexpr u32 kMaxReaders = 8;
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
    const Excludes* excludes = nullptr;   // null: none given
    bool oneFs = false;          // -x: stay on rootDev
    u64 rootDev = 0;             // st_dev of the PATH being walked
    bool useCache = false;
    bool skipOut = false;        // stdout is a regular file at (skipDev, skipIno)
    u64 skipDev = 0, skipIno = 0;
    u32 warnings = 0;
    u64 bytesToRead = 0;
    u64 bytesCached = 0;
};

void warn(Walk& w, StringView path, StringView what) {
    fprintf(stderr, "bu: warning: %.*s: %.*s\n", int(path.count), path.ptr, int(what.count), what.ptr);
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
        if (w.excludes && excludeMatch(*w.excludes, childStored.c_str(), childStored.count)) continue;
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
    // -x: a file bind-mounted from elsewhere is on another filesystem too.
    if (w.oneFs && type != kEntryDir && u64(st.st_dev) != w.rootDev) return;
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
        if (w.oneFs && u64(st.st_dev) != w.rootDev) return;     // a mount point: stored, not entered
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
    u8* rec = nullptr;         // the record: kRecPrefix bytes, then the sealed body (slot-owned)
    u64 seq = 0;
    u32 block = 0;
    u32 item = 0;
    u32 rawLen = 0;
    u32 recLen = 0;            // body length; 0: duplicate, nothing to write
    ChunkId id;
    u8 state = 0;
};

constexpr u8 kJobFree = 0, kJobQueued = 1, kJobDone = 2;

struct Pipe {
    const Walk* walk = nullptr;
    const MasterKey* key = nullptr;
    const SegKeys* ckeys = nullptr;

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
    fprintf(stderr, "bu: warning: %.*s: %.*s\n", int(path.count), path.ptr, int(what.count), what.ptr);
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
    threadSetName("bu-reader");
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
            if (flags & kBlockLast) {
                ++p.claimItem;
                p.claimOffset = 0;
                // Nothing left to claim: readers waiting for a free slot must
                // wake up to see that and exit. The chunker finishes only
                // when every reader has (readersRunning == 0), so a reader
                // left asleep here hung the whole backup.
                if (p.claimItem >= w.reads.count) p.readerCv.broadcast();
            } else {
                p.claimOffset = off + len;
            }
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
    threadSetName("bu-chunker");
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
    threadSetName("bu-worker");
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
            recLen = bodySeal(*p.ckeys, j.seq, kRecChunk, &j.id, payload.ptr, n, j.rec + kRecPrefix);
        }

        p.mu.lock();
        j.recLen = recLen;
        j.state = kJobDone;
        Block& b = p.blocks[j.block];
        // Broadcast, not signal: a woken reader that finds the slot it waits
        // for still busy goes back to sleep and the wake-up is lost.
        if (--b.refs == 0 && b.state == kBlockDraining) { b.state = kBlockFree; p.readerCv.broadcast(); }
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
// It takes every finished job at the head of the ring in one lock round,
// seals each stored record's header (its ordinal is known only here) and
// writes the records with one writev, then frees the slots together.
void writerLoop(Pipe& p, SegWriter& cw, Array<ChunkId>& refs, Array<u32>& sizes, Array<u32>& itemFirst,
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
                vec[nv++] = IoSlice{j.rec, writerChunk(cw, j.id, j.seq, j.rawLen, j.rec, j.recLen)};
                ++stats.newChunks;
            }
            ++stats.chunks;
            stats.rawRead += j.rawLen;
            if (itemCount[j.item] == 0) itemFirst[j.item] = refs.count;
            ++itemCount[j.item];
            refs.push(j.id);
            sizes.push(j.rawLen);
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



// ---- where the segment goes -------------------------------------------------

// The signal handler's view of an append in progress: SIGINT, SIGTERM or
// SIGHUP truncates the chain back to where the segment began and then dies
// of the signal as it would have. Only the main thread writes the chain and
// only it takes these signals (the worker threads block them), so no write
// of ours can land after the truncate.
volatile sig_atomic_t gTruncFd = -1;
off_t gTruncTo = 0;

void onFatalSignal(int sig) {
    if (gTruncFd >= 0) (void)ftruncate(gTruncFd, gTruncTo);
    signal(sig, SIG_DFL);
    raise(sig);
}

constexpr int kFatalSignals[] = {SIGINT, SIGTERM, SIGHUP};

// A descriptor closed on every return path.
struct FdGuard {
    int fd = -1;
    ~FdGuard() { if (fd >= 0) close(fd); }
};

// The chain being appended to, or the pipe being streamed to.
struct Target {
    const char* name = nullptr;   // for messages
    int fd = -1;                  // written to
    int readFd = -1;              // read from (seek mode; the same fd, or a reopen of stdout)
    bool own = false, ownRead = false;
    bool seek = false;            // a regular file: lock, base from its tail, truncate on failure
    u64 size = 0;                 // seek: where the new segment begins

    ~Target() {
        if (ownRead && readFd >= 0) close(readFd);
        if (own && fd >= 0) close(fd);
    }
};

// Lock the chain (exclusively, without waiting: a second create on the same
// chain is a mistake to report, not to queue). A filesystem without locks
// gets a warning: then nothing stops two writers.
bool lockChain(Target& t) {
    if (flock(t.fd, LOCK_EX | LOCK_NB) == 0) return true;
    if (errno == EWOULDBLOCK) {
        fprintf(stderr, "bu: %s is locked: another bu is writing it (create or merge); try again when it is done\n", t.name);
        return false;
    }
    fprintf(stderr, "bu: warning: %s: cannot lock (%s); make sure no other bu writes this chain at the same time\n",
            t.name, strerror(errno));
    return true;
}

// Open CHAIN for appending, locked. A merge that replaced the file (rename)
// while we waited for nothing in particular leaves our descriptor on the old
// inode: compare with the path after locking and start over if it moved.
int openTarget(const char* chainArg, Target& t) {
    t.name = chainArg;
    if (StringView(chainArg) == "-"_s) {
        t.name = "stdout";
        if (isatty(1)) {
            fprintf(stderr, "bu create: refusing to write a backup to a terminal; name a CHAIN file or redirect stdout\n");
            return kExitUsage;
        }
        struct stat st;
        if (fstat(1, &st) != 0) { fprintf(stderr, "bu: stdout: %s\n", strerror(errno)); return kExitRuntime; }
        t.fd = 1;
        if (!S_ISREG(st.st_mode)) { pipeGrow(1); return kExitOk; }
        t.seek = true;
        if (!lockChain(t)) return kExitRuntime;
        // `>> chain` opens stdout write-only: read the chain through a second
        // descriptor. Writes go to the end (O_APPEND, or a seek for `1<>`).
        const int mode = fcntl(1, F_GETFL);
        if ((mode & O_ACCMODE) == O_WRONLY) {
            t.readFd = open("/proc/self/fd/1", O_RDONLY | O_CLOEXEC);
            if (t.readFd < 0) { fprintf(stderr, "bu: cannot read the chain on stdout back: %s\n", strerror(errno)); return kExitRuntime; }
            t.ownRead = true;
        } else {
            t.readFd = 1;
        }
        if (!(mode & O_APPEND) && lseek(1, 0, SEEK_END) < 0) { fprintf(stderr, "bu: stdout: %s\n", strerror(errno)); return kExitRuntime; }
        t.size = u64(st.st_size);
        return kExitOk;
    }
    for (int attempt = 0; attempt < 8; ++attempt) {
        t.fd = open(chainArg, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (t.fd < 0) { fprintf(stderr, "bu: %s: %s\n", chainArg, strerror(errno)); return kExitRuntime; }
        t.own = true;
        struct stat st, now;
        if (fstat(t.fd, &st) != 0 || !S_ISREG(st.st_mode)) {
            fprintf(stderr, "bu create: %s is not a regular file (to write to a pipe, name CHAIN as -)\n", chainArg);
            return kExitUsage;
        }
        if (!lockChain(t)) return kExitRuntime;
        if (stat(chainArg, &now) == 0 && now.st_dev == st.st_dev && now.st_ino == st.st_ino) {
            fstat(t.fd, &st);
            t.seek = true;
            t.readFd = t.fd;
            t.size = u64(st.st_size);
            return kExitOk;
        }
        close(t.fd);
        t.fd = -1;
        t.own = false;
    }
    fprintf(stderr, "bu: %s keeps being replaced while create opens it\n", chainArg);
    return kExitRuntime;
}

} // namespace

int cmdCreate(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("create", argc, argv, first, kArgKey | kArgBase | kArgIndexOut | kArgJobs | kArgNoCache | kArgVerbose
                                                    | kArgDir | kArgExclude | kArgOneFs, a))
        return kExitUsage;
    if (!a.key && !a.noKey) return usage("create", "give --key KEYFILE (encrypted) or --no-key (unencrypted)"_s);
    if (a.positional.count < 2) return usage("create", "name the CHAIN and at least one PATH to back up"_s);
    const char* chainArg = a.positional[0];
    String err;
    Excludes excludes;
    for (const char* pat : a.excludes)
        if (!excludeAdd(excludes, StringView(pat), err)) return usage("create", err.view());
    // -C DIR: opened now, entered only for the walk and the reads. A DIR that
    // is not there fails here, before the chain file is created or a
    // passphrase asked for.
    FdGuard walkDirFd, startDirFd;
    if (a.dir) {
        walkDirFd.fd = open(a.dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (walkDirFd.fd < 0) { fprintf(stderr, "bu create: -C %s: %s\n", a.dir, strerror(errno)); return kExitRuntime; }
        startDirFd.fd = open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (startDirFd.fd < 0) { fprintf(stderr, "bu create: the current directory: %s\n", strerror(errno)); return kExitRuntime; }
    }
    // A pipe reader that goes away (aws s3 cp failing) must become a write
    // error we report — and a run that does NOT write the index — not a
    // silent death by SIGPIPE.
    signal(SIGPIPE, SIG_IGN);

    Target t;
    if (const int rc = openTarget(chainArg, t)) return rc;
    Chain chain;
    bool chainPlain = a.noKey;
    if (t.seek && t.size) {
        if (a.base) {
            fprintf(stderr, "bu create: %s already holds backups and is its own base; --base is for writing "
                            "a new segment to an empty file or a pipe\n", t.name);
            return kExitUsage;
        }
        if (!chainFdOpen(t.readFd, t.name, chain, err)) { report(err); return kExitRuntime; }
        if (chain.firstKind != kKindSegment) {
            fprintf(stderr, "bu: %s is an index file, not a chain\n", t.name);
            return kExitRuntime;
        }
        chainPlain = chain.plain;
    } else if (a.base) {
        u16 kind = 0;
        if (!fileHeaderPeek(a.base, kind, chainPlain, err)) { report(err); return kExitRuntime; }
    }
    if (chainPlain != a.noKey) {
        String m(StringView(t.size ? t.name : a.base));
        m.append(chainPlain ? " is not encrypted (made with --no-key); use --no-key, not --key"_s
                            : " is encrypted; use --key KEYFILE, not --no-key"_s);
        return usage("create", m.view());
    }

    MasterKey key;
    if (a.noKey) masterKeyPlain(key);
    else if (!unlockKeyForCommand(a, key)) return kExitRuntime;
    // Fail before reading a byte if the index cannot be written: discovering
    // it after streaming a 100 GB backup would leave a backup with no index.
    if (a.indexOut) {
        String probe(StringView(a.indexOut));
        probe.append(".probe.");
        probe.appendU64(u64(getpid()));
        const int fd = open(probe.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) { fprintf(stderr, "bu: cannot write the index next to %s: %s\n", a.indexOut, strerror(errno)); return kExitRuntime; }
        close(fd);
        unlink(probe.c_str());
    }

    const i64 startNs = nowNs();
    IndexData base;
    bool haveBase = false;
    if (t.seek && t.size) {
        chain.key = &key;
        if (!chainWalkTail(chain, err)) { report(err); return kExitRuntime; }
        const Source& src = chain.sources[0];
        if (src.tail) {
            // An interrupted create's partial segment: cut it off (we hold
            // the lock, so nobody is writing it).
            if (ftruncate(t.fd, off_t(src.size)) != 0) { fprintf(stderr, "bu: %s: %s\n", t.name, strerror(errno)); return kExitRuntime; }
            fprintf(stderr, "bu: %s: removed %llu bytes of an incomplete backup at the end (an interrupted create)\n",
                    t.name, (unsigned long long)src.tail);
            t.size = src.size;
        }
        if (chain.segs.count) {
            const u32 last = chain.segs.count - 1;
            if (!chainResolve(chain, last, err) || !chainCheckpoint(chain, last, base.deltaBytes, base.fullBytes, err)) {
                report(err); return kExitRuntime;
            }
            base.snap = move(chain.segs[last].snap);
            indexCollectDistinct(base);
            haveBase = true;
        }
    } else if (a.base) {
        if (!indexFileRead(key, a.base, base, err)) { report(err); return kExitRuntime; }
        haveBase = true;
    }
    if (haveBase) snapshotIndexPaths(base.snap);
    HashIndex baseIdx;
    baseIdx.init(base.distinct.count);
    for (u32 i = 0; i < base.distinct.count; ++i) baseIdx.insert(idHash(base.distinct[i]), i);

    // ---- walk
    Walk w;
    w.base = &base;
    w.useCache = haveBase && !a.noCache;
    w.excludes = excludes.offs.count ? &excludes : nullptr;
    w.oneFs = a.oneFs;
    if (a.dir && fchdir(walkDirFd.fd) != 0) { fprintf(stderr, "bu create: -C %s: %s\n", a.dir, strerror(errno)); return kExitRuntime; }
    // A chain inside the tree it backs up must not back itself up while
    // growing: remember its inode.
    {
        struct stat out;
        if (fstat(t.fd, &out) == 0 && S_ISREG(out.st_mode)) { w.skipDev = u64(out.st_dev); w.skipIno = u64(out.st_ino); w.skipOut = true; }
    }
    for (u32 pi = 1; pi < a.positional.count; ++pi) {
        const char* rootArg = a.positional[pi];
        String stored;
        if (!storedName(StringView(rootArg), stored)) {
            fprintf(stderr, "bu create: '%s' contains a '..' component; cd to its parent and name it from there\n", rootArg);
            return kExitUsage;
        }
        if (w.excludes && !stored.empty() && excludeMatch(*w.excludes, stored.c_str(), stored.count)) continue;
        struct stat st;
        if (fstatat(AT_FDCWD, rootArg, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            fprintf(stderr, "bu create: %s: %s\n", rootArg, strerror(errno));
            return kExitRuntime;
        }
        w.rootDev = u64(st.st_dev);
        // For a root, "dirfd + name" is the cwd plus the path as given.
        addEntry(w, AT_FDCWD, rootArg, stored.view(), StringView(rootArg), st);
    }

    // ---- pipeline
    // Threads. With -j N: N workers and (N + 1) / 2 readers, at most 8.
    // Without: 8 readers (half the CPUs below 16) and the CPUs less three
    // quarters of the readers as workers. Readers are busy on a fast source
    // (tmpfs, a warm cache) and asleep on a disk; a worker per CPU on top of
    // 8 readers oversubscribed a 20-CPU machine and cost 8% on tmpfs, while
    // 14 workers lost nothing on the NVMe (docs/benchmarks.md).
    const u32 cpus = cpuCount();
    const u32 readers = a.jobs ? min<u32>(kMaxReaders, max<u32>(1, (a.jobs + 1) / 2))
                               : min<u32>(kMaxReaders, max<u32>(1, cpus / 2));
    const u32 workers = a.jobs ? a.jobs : max<u32>(1, cpus - readers * 3 / 4);
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
    // Readers (computed above): enough to keep reads in flight and the CDC
    // scan (about a fifth of the per-byte work) ahead of the workers. A
    // reader spends part of its time scanning, not waiting on the disk, so it
    // takes more readers than the queue depth the disk wants: on an NVMe, 8
    // instead of 4 made a full backup of a tree of small files 1.3-1.5x
    // faster and of one big file 1.4x. More than 8 measured no better.
    const u32 recCap = kRecPrefix + codecBound(kMaxChunk) + kTagBytes;
    Array<u8> jobMem;
    jobMem.resize(p.slots * recCap);
    Array<Job> jobs;
    jobs.resize(p.slots);
    for (u32 i = 0; i < p.slots; ++i) jobs[i].rec = jobMem.ptr + usize(i) * recCap;
    p.jobs = jobs.ptr;

    OutStream out;
    out.init(t.fd);
    SegWriter cw;
    if (t.seek) {
        gTruncTo = off_t(t.size);
        gTruncFd = t.fd;
        for (int sig : kFatalSignals) signal(sig, onFatalSignal);
    }
    // Truncate the chain back and report; for every failure from here on.
    auto abandon = [&](StringView what) {
        if (t.seek) {
            gTruncFd = -1;
            if (ftruncate(t.fd, off_t(t.size)) != 0)
                fprintf(stderr, "bu: %s: could not remove the partial backup: %s\n", t.name, strerror(errno));
        }
        report(what);
        if (t.seek) fprintf(stderr, "bu: %s is unchanged\n", t.name);
        return kExitRuntime;
    };
    if (!writerBegin(cw, out, key, kKindSegment, err)) return abandon(err.view());
    p.ckeys = &cw.keys;

    Array<ChunkId> newRefs;
    Array<u32> newSizes;
    Array<u32> itemFirst, itemCount;
    itemFirst.resize(w.reads.count);
    itemCount.resize(w.reads.count);
    for (u32 i = 0; i < w.reads.count; ++i) { itemFirst[i] = 0; itemCount[i] = 0; }
    Stats stats;

    // The threads block the fatal signals (they inherit this mask), so the
    // handler always runs on this thread, never during another's write.
    sigset_t fatal, old;
    sigemptyset(&fatal);
    for (int sig : kFatalSignals) sigaddset(&fatal, sig);
    pthread_sigmask(SIG_BLOCK, &fatal, &old);
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
    const bool chunkerUp = readersStarted > 0 && chunker.start(chunkerMain, &p);
    if (chunkerUp)
        for (u32 i = 0; i < workers; ++i) {
            if (!pool[started].start(workerMain, &p)) break;
            ++started;
        }
    pthread_sigmask(SIG_SETMASK, &old, nullptr);
    if (!chunkerUp || started == 0) return abandon("cannot start threads"_s);
    writerLoop(p, cw, newRefs, newSizes, itemFirst, itemCount, stats);
    for (u32 i = 0; i < readersStarted; ++i) readerThreads[i].join();
    chunker.join();
    for (u32 i = 0; i < started; ++i) pool[i].join();
    // Back to where bu was started: --index-out is relative to it.
    if (a.dir && fchdir(startDirFd.fd) != 0) {
        String m("cannot return to the starting directory: "_s);
        m.append(StringView(strerror(errno)));
        return abandon(m.view());
    }

    if (out.failed) {
        String m("writing the backup to "_s);
        m.append(StringView(t.name));
        m.append(" failed: "_s);
        m.append(StringView(strerror(out.savedErrno)));
        return abandon(m.view());
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
                fin.sizes.appendRange(base.snap.sizes.ptr + b.firstRef, b.refCount);
                e.refCount = b.refCount;
            } else {
                const u32 it = w.readItem[i];
                if (p.itemFailed[it]) continue;     // unreadable: left out (warned)
                fin.refs.appendRange(newRefs.ptr + itemFirst[it], itemCount[it]);
                fin.sizes.appendRange(newSizes.ptr + itemFirst[it], itemCount[it]);
                e.refCount = itemCount[it];
                e.size = p.itemBytes[it];           // differs only if it shrank (warned by the reader)
            }
        }
        fin.entries.push(e);
    }
    if (!randomBytes(fin.id, kSnapshotIdBytes, err)) return abandon(err.view());
    fin.gen = haveBase ? base.snap.gen + 1 : 1;
    fin.createdNs = startNs;
    if (haveBase) {
        fin.hasParent = true;
        memCopy(fin.parent, base.snap.id, kSnapshotIdBytes);
    }

    // A delta manifest, unless the deltas since the last self-contained one
    // would then outweigh it: a reader resolving the snapshot reads at most
    // about twice a full manifest, however long the chain (design.md §5).
    ByteWriter manifest;
    bool delta = haveBase;
    if (haveBase) {
        snapshotEncode(fin, &base.snap, manifest);
        if (base.deltaBytes + manifest.buf.count > base.fullBytes) {
            manifest.buf.clear();
            delta = false;
        }
    }
    if (!delta) snapshotEncode(fin, nullptr, manifest);
    if (!writerFinish(cw, manifest.buf.ptr, manifest.buf.count, fin.gen, err)) return abandon(err.view());
    if (t.seek && fsync(t.fd) != 0) {
        String m(StringView(t.name));
        m.append(": fsync: "_s);
        m.append(StringView(strerror(errno)));
        return abandon(m.view());
    }
    gTruncFd = -1;     // the segment is complete: an interrupt now keeps it

    // ---- the index, when asked for: this snapshot, self-contained
    if (a.indexOut) {
        IndexData idx;
        idx.deltaBytes = delta ? base.deltaBytes + manifest.buf.count : 0;
        idx.fullBytes = delta ? base.fullBytes : manifest.buf.count;
        idx.snap = move(fin);
        if (!indexFileWrite(key, a.indexOut, idx, err)) {
            report(err);
            fprintf(stderr, "bu: the backup was written, the index was not\n");
            return kExitRuntime;
        }
    }

    if (a.verbose) {
        u32 cachedFiles = 0;
        for (u32 c : w.cacheFrom) if (c != kInvalidIndex) ++cachedFiles;
        char b1[32], b2[32], b3[32];
        fmtBytes(stats.rawRead, b1, sizeof b1);
        fmtBytes(w.bytesCached, b2, sizeof b2);
        fmtBytes(out.written, b3, sizeof b3);
        const double secs = double(nowNs() - startNs) / 1e9;
        fprintf(stderr,
                "bu: %u entries, %u files read (%s), %u from files cache (%s)\n"
                "bu: %llu chunks, %llu new; wrote %s in %.2f s (%.0f MiB/s read) with %u workers\n",
                w.snap.entries.count, w.reads.count, b1, cachedFiles, b2,
                (unsigned long long)stats.chunks, (unsigned long long)stats.newChunks, b3, secs,
                secs > 0 ? double(stats.rawRead) / secs / double(1 << 20) : 0.0, started);
    }
    return (w.warnings || p.readWarnings) ? kExitWarnings : kExitOk;
}

} // namespace bk
