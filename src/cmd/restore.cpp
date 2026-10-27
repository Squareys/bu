// restore.cpp — `bu restore`: recreate the latest snapshot of a chain, or the
// files and directories under the PATHs named after `--`.
//
// Every chunk is authenticated (its record's tag under its segment's key, or
// its checksum in an unencrypted chain) and then re-hashed (the content must
// hash to the ID it is filed under) before a byte of it reaches the output.
//
// SEEK MODE (a chain file). Missing chunks are counted BEFORE anything is
// written, so an incomplete chain fails up front instead of leaving half a
// tree. Files are grouped into batches (bounded by open descriptors and
// bytes). A batch's chunks are sorted by their place in the chain, and runs
// of nearby records of one segment form a task: one pread of the whole span
// (~256 KiB, gaps of up to kSpanGap of records nobody needs included, since
// a round trip on a network mount costs more than reading them), then per
// chunk decrypt, decompress, verify, and one pwrite per run of chunks that
// continue each other in one output file. A chunk used in several places is
// decoded once. Tasks run on the thread pool and prefetch (WILLNEED) the span
// a few MiB ahead, so the disk sees a deep queue of large reads; reading one
// ~20 KiB record per pread from many threads ran at half the disk's
// sequential speed. Two batches overlap: the main thread creates and sizes
// the next batch's files while a finisher thread runs the current one. Eight
// threads by default: more only add kernel time writing into the page cache
// (docs/benchmarks.md). A partial restore reads only its files' chunks.
//
// STREAM MODE (a pipe on stdin). The snapshot comes from --index, since the
// chain's own manifests arrive after the data. Every file is created and
// sized first, then the records are read once: each chunk record is opened,
// decoded and hashed on the pool, and the main thread writes the chunks the
// snapshot uses to every place they go (the snapshot knows each chunk's size,
// so every offset is known before the data arrives). Nothing is buffered on
// disk; missing chunks are only known at the end of the stream, and reported
// then.
//
// Output files are sized first (ftruncate), so an all-zero chunk is simply
// not written and stays a hole: a sparse SQLite file restores sparse.
//
// SAFETY OF THE OUTPUT TREE. Paths were validated at decode (relative, no
// "..", no empty components), and every path is resolved component by
// component with O_NOFOLLOW from the restore directory's fd, so a symlink in
// the restored tree — or one an attacker planted in the target directory —
// can never redirect a write outside it. Restored symlinks are created as
// links, never followed. A name that already exists in the target is
// unlinked and created anew (O_EXCL): opening it with O_TRUNC would write
// through a hard link planted there into a file outside the tree, and block
// forever on a planted FIFO. Stream mode opens files again to write them;
// it does so with O_NOFOLLOW and refuses a file whose device and inode are
// not the ones it created. Directory modes are set through a descriptor
// opened O_NOFOLLOW, never by name, so a directory swapped for a symlink
// between the check and the chmod cannot pass the chmod on to its target.
// The symlink branch needs no such care: unlinkat with no flags removes a
// link rather than following it, symlinkat fails on any name that reappears,
// and chown and utimens are called with AT_SYMLINK_NOFOLLOW.
//
// Set-uid and set-gid bits on regular files are restored only when running
// as root, as GNU tar does: for anyone else they would make a file from the
// backup run with the restoring user's identity, which is not something a
// restore should hand out. A directory's set-gid bit (group inheritance, no
// privilege) is kept.

#include "cmd/args.hpp"
#include "cmd/chain.hpp"
#include "cmd/commands.hpp"
#include "cmd/passphrase.hpp"
#include "core/sort.hpp"
#include "core/thread.hpp"
#include "format/codec.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bk {

namespace {

// A batch holds up to kBatchFiles open output files and kBatchBytes of data;
// two batches are open at once (see Restorer). Few, large batches: each one
// ends with a barrier where threads wait for the slowest span, and its files
// are what the spans of tiny files are made from (256 files of 8 KiB, the old
// limit, made one 2 MiB batch for twenty threads).
constexpr u32 kBatchFiles = 4096;
constexpr u64 kBatchBytes = u64(1024) << 20;
// Records nobody needs that a span may read through rather than split.
constexpr u64 kSpanGap = u64(64) << 10;

// Files per batch within the descriptor limit: raise the soft limit towards
// the hard one if needed (a soft limit of 1024 is common), and stay under
// whatever we get, with room for the chain files and directories.
u32 batchFileLimit() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) return 256;
    const rlim_t want = rlim_t(2 * kBatchFiles + 256);
    if (rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < want) {
        struct rlimit up = rl;
        up.rlim_cur = rl.rlim_max == RLIM_INFINITY ? want : min<rlim_t>(rl.rlim_max, want);
        if (setrlimit(RLIMIT_NOFILE, &up) == 0) rl = up;
    }
    if (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur >= want) return kBatchFiles;
    return rl.rlim_cur > 2 * 16 + 256 ? u32((rl.rlim_cur - 256) / 2) : 16;
}

// Resolves parent directories under the restore root, creating missing ones,
// never following a symlink. Caches the last directory, which is the common
// case: entries are depth-first, so siblings arrive together.
struct DirResolver {
    int root = -1;
    String cachedPath;
    int cachedFd = -1;

    ~DirResolver() { if (cachedFd >= 0) close(cachedFd); }

    // fd for directory `dir` (relative, "" = root); -1 with err on failure.
    int open(StringView dir, String& err) {
        if (dir.empty()) return root;
        if (cachedFd >= 0 && cachedPath.view() == dir) return cachedFd;
        int fd = dup(root);
        u32 start = 0;
        String comp;
        for (u32 i = 0; i <= dir.count && fd >= 0; ++i) {
            if (i < dir.count && dir[i] != '/') continue;
            comp.assign(dir.sub(start, i - start));
            start = i + 1;
            int next = openat(fd, comp.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next < 0 && errno == ENOENT) {
                // A parent outside the restored set (PATH...) or not yet made.
                if (mkdirat(fd, comp.c_str(), 0700) == 0 || errno == EEXIST)
                    next = openat(fd, comp.c_str(), O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            }
            if (next < 0) {
                errSet(err, dir, ": ", errno == ENOTDIR || errno == ELOOP
                           ? "a parent is a symlink or not a directory; refusing to write through it"
                           : strerror(errno));
                close(fd);
                return -1;
            }
            close(fd);
            fd = next;
        }
        if (cachedFd >= 0) close(cachedFd);
        cachedFd = fd;
        cachedPath.assign(dir);
        return fd;
    }
};

void splitPath(StringView p, StringView& dir, StringView& name) {
    const u32 s = p.findLast('/');
    if (s == kInvalidIndex) { dir = StringView(); name = p; }
    else { dir = p.first(s); name = p.from(s + 1); }
}

// One chunk of one output file.
struct Piece {
    u32 out;        // index into Batch::fds
    u32 seg;        // where the chunk is
    u32 chunk;
    u64 offset;     // in the output file
};

// A task: records [first, first + count) of one segment, read with one
// pread (chainReadSpan), and the pieces they restore, in chain order.
struct Task {
    u32 seg;
    u32 first, count;
    u32 firstPiece, pieceCount;
};

constexpr u32 kOutBuf = 1u << 20;         // decoded bytes gathered per pwrite
constexpr u32 kRestoreThreads = 8;

// Per worker scratch, shared by both batches (one runs at a time).
struct Scratch {
    Array<Array<u8>> span, payload, out;
};

struct Batch {
    const Chain* chain = nullptr;
    Scratch* scratch = nullptr;
    u32 lookahead = 0;
    u64 spanTarget = kSpanBytes;
    Array<int> fds;
    Array<u32> entries;
    Array<Piece> pieces;
    Array<Task> tasks;
    u64 bytes = 0;
    Mutex mu;
    String firstErr;     // under mu
    bool failed = false; // under mu (read racily as a hint to stop early)
};

// Sort the batch's pieces by their place in the chain and cut them into
// tasks: a piece joins the current task when its record is in the same
// segment, the gap before it is small and the span stays within the target.
void planTasks(Batch& b) {
    sortRange(b.pieces.ptr, b.pieces.count, [](const Piece& x, const Piece& y) {
        if (x.seg != y.seg) return x.seg < y.seg;
        if (x.chunk != y.chunk) return x.chunk < y.chunk;
        return x.out != y.out ? x.out < y.out : x.offset < y.offset;
    });
    b.tasks.clear();
    for (u32 i = 0; i < b.pieces.count; ++i) {
        const Piece& pc = b.pieces[i];
        const Seg& s = b.chain->segs[pc.seg];
        Task* t = b.tasks.count ? &b.tasks[b.tasks.count - 1] : nullptr;
        bool join = t && t->seg == pc.seg;
        if (join && pc.chunk >= t->first + t->count) {
            const ChunkLoc& last = s.chunks[t->first + t->count - 1];
            const u64 gap = s.chunks[pc.chunk].offset - (last.offset + 4 + last.recLen);
            join = gap <= kSpanGap && chainSpanBytes(s, t->first, pc.chunk - t->first + 1) <= b.spanTarget;
        }
        if (!join) t = &b.tasks.push(Task{pc.seg, pc.chunk, 1, i, 0});
        t->count = pc.chunk - t->first + 1;
        ++t->pieceCount;
    }
}

void runTask(void* ctx, u32 i, u32 worker) {
    Batch& b = *static_cast<Batch*>(ctx);
    if (__atomic_load_n(&b.failed, __ATOMIC_RELAXED)) return;
    const Task& t = b.tasks[i];
    const Seg& s = b.chain->segs[t.seg];
    if (b.lookahead && i + b.lookahead < b.tasks.count) {
        const Task& n = b.tasks[i + b.lookahead];
        chainPrefetchSpan(*b.chain, n.seg, n.first, n.count);
    }
    String err;
    Array<u8>& span = b.scratch->span[worker];
    Array<u8>& buf = b.scratch->out[worker];
    buf.resize(kOutBuf);
    bool ok = chainReadSpan(*b.chain, t.seg, t.first, t.count, span, err);
    // Decoded chunks that continue one another in the same output file are
    // gathered in `buf` and written with one pwrite: fewer, larger writes
    // into the page cache, less contention on the inode between threads.
    u32 pendOut = 0, pendLen = 0;
    u64 pendOff = 0;
    auto flush = [&]() {
        if (ok && pendLen && !pwriteAll(b.fds[pendOut], buf.ptr, pendLen, pendOff)) {
            ok = false;
            errSet(err, "writing restored data: ", strerror(errno));
        }
        pendLen = 0;
    };
    const u64 base = ok ? s.chunks[t.first].offset : 0;
    // The chunk decoded last: pieces are sorted, so every use of a chunk
    // follows its first and reuses those bytes (still in `buf` at lastAt,
    // whatever was flushed since) instead of decoding it again.
    u32 lastChunk = kInvalidIndex, lastAt = 0;
    bool lastZero = false;
    for (u32 k = 0; k < t.pieceCount && ok; ++k) {
        const Piece& pc = b.pieces[t.firstPiece + k];
        const ChunkLoc& loc = s.chunks[pc.chunk];
        if (pendLen && (pc.out != pendOut || pc.offset != pendOff + pendLen || pendLen + loc.rawLen > kOutBuf)) flush();
        if (!ok) break;
        u8* dst = buf.ptr + pendLen;
        if (pc.chunk == lastChunk) {
            if (lastZero) continue;
            memMove(dst, buf.ptr + lastAt, loc.rawLen);
        } else {
            if (!chainOpenChunk(*b.chain, t.seg, pc.chunk, span.ptr + (loc.offset - base), false,
                                b.scratch->payload[worker], dst, err)) {
                ok = false;
                break;
            }
            lastChunk = pc.chunk;
            // An all-zero chunk is not written: it stays a hole (the file was
            // sized with ftruncate), so a sparse file restores sparse.
            lastZero = loc.rawLen && dst[0] == 0 && memEqual(dst, dst + 1, loc.rawLen - 1);
            if (lastZero) { flush(); continue; }
        }
        lastAt = pendLen;
        if (!pendLen) { pendOut = pc.out; pendOff = pc.offset; }
        pendLen += loc.rawLen;
    }
    flush();
    if (!ok) {
        Lock l(b.mu);
        if (!b.failed) { b.firstErr = move(err); __atomic_store_n(&b.failed, true, __ATOMIC_RELAXED); }
    }
}

struct Restorer {
    Chain* chain = nullptr;
    const Snapshot* snap = nullptr;
    DirResolver dirs;
    ThreadPool pool;
    Scratch scratch;
    // Two batches: the main thread creates the files of one while the
    // finisher thread runs the other's tasks on the pool and then sets its
    // files' owner, mode and times. Creating files is a third of a restore's
    // wall time on ext4; done in turn with the data it left the pool idle.
    Batch batches[2];
    u32 filling = 0;          // the batch the main thread fills
    Thread finisher;
    bool finisherUp = false;
    Mutex mu;
    Cond cv;
    Batch* queued = nullptr;  // under mu: handed over, not yet taken
    bool busy = false;        // under mu: the finisher is inside a batch
    bool stop = false;        // under mu
    bool fatal = false;       // under mu: a batch failed
    u32 batchFiles = kBatchFiles;
    bool chown = false;
    bool stream = false;      // stream mode: files are created, not batched
    Array<u32> created;       // stream mode: entries of the files created
    Array<u64> createdDev, createdIno;
    u32 errors = 0;           // both threads: __atomic
    u64 files = 0, bytes = 0;
};

void entryError(Restorer& r, const Entry& e, StringView what) {
    const StringView p = entryPath(*r.snap, e);
    fprintf(stderr, "bu: %.*s: %.*s\n", int(p.count), p.ptr, int(what.count), what.ptr);
    __atomic_add_fetch(&r.errors, 1, __ATOMIC_RELAXED);
}

// The mode a regular file is given: set-uid/set-gid only for root (above).
u32 fileMode(const Restorer& r, const Entry& e) { return r.chown ? e.mode : e.mode & ~u32(06000); }

// chmod a directory entry that was a directory a moment ago, through an fd
// opened O_NOFOLLOW | O_DIRECTORY (a symlink or anything else put there since
// is refused, never followed). A directory we may not read cannot be opened
// that way; for it, fchmodat with AT_SYMLINK_NOFOLLOW (glibc >= 2.32 does it
// through an O_PATH descriptor, so it is not a second lookup by name either).
bool chmodDirAt(int pfd, const char* name, u32 mode) {
    const int fd = openat(pfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno == EACCES && fchmodat(pfd, name, mode_t(mode), AT_SYMLINK_NOFOLLOW) == 0;
    const bool ok = fchmod(fd, mode_t(mode)) == 0;
    close(fd);
    return ok;
}

void timesOf(const Entry& e, struct timespec ts[2]) {
    ts[0].tv_sec = e.mtimeNs / 1000000000; ts[0].tv_nsec = e.mtimeNs % 1000000000;
    if (ts[0].tv_nsec < 0) { ts[0].tv_nsec += 1000000000; ts[0].tv_sec -= 1; }
    ts[1] = ts[0];
}

// Owner, mode, mtime of a restored file, then close it.
bool finishFile(Restorer& r, const Entry& e, int fd) {
    struct timespec ts[2];
    timesOf(e, ts);
    // Owner before mode: chown clears set-uid/set-gid bits, so the mode
    // must be applied after it to survive.
    if (r.chown && fchown(fd, e.uid, e.gid) != 0) entryError(r, e, StringView(strerror(errno)));
    if (fchmod(fd, mode_t(fileMode(r, e))) != 0) entryError(r, e, StringView(strerror(errno)));
    if (futimens(fd, ts) != 0) entryError(r, e, StringView(strerror(errno)));
    if (close(fd) != 0) { entryError(r, e, StringView(strerror(errno))); return false; }
    return true;
}

// Run the batch's tasks, then finish each file: owner, mode, mtime, close.
bool flushBatch(Restorer& r, Batch& b) {
    planTasks(b);
    r.pool.run(b.tasks.count, runTask, &b);
    bool ok = !b.failed;
    if (!ok) { report(b.firstErr.view()); __atomic_add_fetch(&r.errors, 1, __ATOMIC_RELAXED); }
    for (u32 i = 0; i < b.fds.count; ++i)
        if (!finishFile(r, r.snap->entries[b.entries[i]], b.fds[i])) ok = false;
    b.fds.clear(); b.entries.clear(); b.pieces.clear(); b.tasks.clear(); b.bytes = 0;
    return ok;
}

void* finisherMain(void* arg) {
    Restorer& r = *static_cast<Restorer*>(arg);
    threadSetName("bu-finisher");
    r.mu.lock();
    for (;;) {
        while (!r.queued && !r.stop) r.cv.wait(r.mu);
        if (!r.queued) break;
        Batch& b = *r.queued;
        r.queued = nullptr;
        r.busy = true;
        r.mu.unlock();
        const bool ok = flushBatch(r, b);
        r.mu.lock();
        if (!ok) r.fatal = true;
        r.busy = false;
        r.cv.broadcast();
    }
    r.mu.unlock();
    return nullptr;
}

// Hand the batch being filled to the finisher once it is done with the
// previous one, and go on filling the other. False once any batch failed.
bool submitBatch(Restorer& r) {
    Batch& b = r.batches[r.filling];
    if (!r.finisherUp) return flushBatch(r, b);
    Lock l(r.mu);
    while (r.queued || r.busy) r.cv.wait(r.mu);
    if (r.fatal) return false;
    if (b.fds.count == 0) return true;
    r.queued = &b;
    r.cv.broadcast();
    r.filling ^= 1;
    return true;
}

// Wait for the finisher to drain and stop it; false if any batch failed.
bool finishBatches(Restorer& r) {
    if (!r.finisherUp) return true;
    {
        Lock l(r.mu);
        while (r.queued || r.busy) r.cv.wait(r.mu);
        r.stop = true;
        r.cv.broadcast();
    }
    r.finisher.join();
    r.finisherUp = false;
    return !r.fatal;
}

// Create (replace) a regular file and size it; -1 after reporting.
int createFile(Restorer& r, const Entry& e, int pfd, const char* name) {
    // Replace, never open, what is there (see the top of the file). EISDIR
    // leaves the directory alone; the O_EXCL create then reports EEXIST.
    if (unlinkat(pfd, name, 0) != 0 && errno != ENOENT && errno != EISDIR) {
        entryError(r, e, StringView(strerror(errno)));
        return -1;
    }
    const int fd = openat(pfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { entryError(r, e, StringView(strerror(errno))); return -1; }
    if (ftruncate(fd, off_t(e.size)) != 0) { entryError(r, e, StringView(strerror(errno))); close(fd); return -1; }
    return fd;
}

bool restoreFile(Restorer& r, u32 ei, int pfd, const char* name) {
    const Entry& e = r.snap->entries[ei];
    const int fd = createFile(r, e, pfd, name);
    if (fd < 0) return true;
    ++r.files; r.bytes += e.size;
    if (r.stream) {
        // Written later, as the stream brings the chunks; remember which
        // inode we made, so a file swapped in meanwhile is refused.
        struct stat st;
        if (fstat(fd, &st) != 0) { entryError(r, e, StringView(strerror(errno))); close(fd); return true; }
        r.created.push(ei);
        r.createdDev.push(u64(st.st_dev));
        r.createdIno.push(u64(st.st_ino));
        close(fd);
        return true;
    }
    Batch& b = r.batches[r.filling];
    const u32 slot = b.fds.count;
    b.fds.push(fd);
    b.entries.push(ei);
    u64 off = 0;
    for (u32 k = 0; k < e.refCount; ++k) {
        u32 sg = 0, ch = 0;
        chainFind(*r.chain, r.snap->refs[e.firstRef + k], sg, ch);   // presence checked up front
        if (r.chain->segs[sg].chunks[ch].rawLen != r.snap->sizes[e.firstRef + k]) {
            entryError(r, e, "a chunk's size differs between the manifest and the chunk table (damaged)"_s);
            return false;
        }
        b.pieces.push(Piece{slot, sg, ch, off});
        off += r.snap->sizes[e.firstRef + k];
    }
    b.bytes += e.size;
    if (b.fds.count >= r.batchFiles || b.bytes >= kBatchBytes) return submitBatch(r);
    return true;
}

// ---- stream mode ----------------------------------------------------------------

// Where the chunks of the snapshot go: per distinct ID, its size and the
// (file, offset) places it is written to.
struct StreamPlace {
    u32 file;       // index into Restorer::created
    u64 offset;
};

struct StreamRestore {
    Restorer* r = nullptr;
    const MasterKey* key = nullptr;
    Array<ChunkId> distinct;
    HashIndex idx;
    Array<u32> size;            // per distinct
    Array<u32> firstPlace;      // per distinct + 1: CSR into places
    Array<StreamPlace> places;
    Array<u8> done;             // per distinct, main thread only
    u32 remaining = 0;
    // One batch of records, decoded on the pool.
    struct Slot {
        Array<u8> payload, raw;
        ChunkId id;
        u32 rawLen = 0;
        u32 want = kInvalidIndex;   // distinct index, or kInvalidIndex
        bool zero = false;
    };
    Array<Slot> slots;
    const StreamChunk* recs = nullptr;
    const Chain* chain = nullptr;
    Mutex mu;
    String firstErr;            // under mu
    bool failed = false;
    // Open output files: a small cache (entries in walk order make most
    // writes hit the file written last).
    static constexpr u32 kOpen = 64;
    u32 openFile[kOpen];
    int openFd[kOpen];
    u32 nextEvict = 0;
};

u32 findDistinct(const StreamRestore& st, const ChunkId& id) {
    u32 slot = kInvalidIndex, v;
    while ((v = st.idx.next(idHash(id), slot)) != kInvalidIndex)
        if (idEqual(st.distinct[v], id)) return v;
    return kInvalidIndex;
}

void decodeTask(void* ctx, u32 i, u32) {
    StreamRestore& st = *static_cast<StreamRestore*>(ctx);
    const StreamChunk& rec = st.recs[i];
    StreamRestore::Slot& slot = st.slots[i];
    slot.want = kInvalidIndex;
    const Seg& s = st.chain->segs[rec.seg];
    String why;
    bool ok = true;
    if (s.keys.plain) {
        // The tag is the claimed ID: skip a chunk nobody wants undecoded.
        bodyTagId(rec.body, rec.bodyLen, slot.id);
        const u32 d = findDistinct(st, slot.id);
        if (d == kInvalidIndex || st.done[d]) return;
    }
    slot.payload.resize(rec.bodyLen - kTagBytes);
    if (!bodyOpen(s.keys, rec.nonce, kRecChunk, rec.body, rec.bodyLen, slot.payload.ptr)) {
        ok = errSet(why, "authentication failed for a chunk record — the stream was modified or damaged");
    } else if (!codecRawLength(slot.payload.ptr, slot.payload.count, kMaxChunk, slot.rawLen)) {
        ok = errSet(why, "malformed chunk payload");
    } else {
        slot.raw.resize(kMaxChunk);
        if (!s.keys.plain) {
            if (!codecDecode(slot.payload.ptr, slot.payload.count, slot.raw.ptr, slot.rawLen))
                ok = errSet(why, "chunk does not decompress");
            else chunkIdOf(*st.key, slot.raw.ptr, slot.rawLen, slot.id);
        } else {
            ok = chunkDecode(*st.key, slot.payload.ptr, slot.payload.count, slot.rawLen, slot.id, slot.raw.ptr, why);
        }
    }
    if (!ok) {
        Lock l(st.mu);
        if (!st.failed) {
            String n;
            n.append("stdin: segment at offset "_s);
            n.appendU64(st.chain->segs[rec.seg].start);
            n.append(": "_s);
            n.append(why.view());
            st.firstErr = move(n);
            st.failed = true;
        }
        return;
    }
    const u32 d = findDistinct(st, slot.id);
    if (d == kInvalidIndex || st.done[d]) return;
    slot.want = d;
    slot.zero = slot.rawLen && slot.raw.ptr[0] == 0 && memEqual(slot.raw.ptr, slot.raw.ptr + 1, slot.rawLen - 1);
}

// The descriptor of created file `f`, opened again (O_NOFOLLOW, and only if
// it is still the inode we created).
int streamFd(StreamRestore& st, u32 f, String& err) {
    for (u32 k = 0; k < StreamRestore::kOpen; ++k) if (st.openFile[k] == f) return st.openFd[k];
    Restorer& r = *st.r;
    const Entry& e = r.snap->entries[r.created[f]];
    StringView parent, base;
    splitPath(entryPath(*r.snap, e), parent, base);
    const int pfd = r.dirs.open(parent, err);
    if (pfd < 0) return -1;
    const String name(base);
    const int fd = openat(pfd, name.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat s;
    if (fd < 0 || fstat(fd, &s) != 0 || u64(s.st_dev) != r.createdDev[f] || u64(s.st_ino) != r.createdIno[f]) {
        if (fd >= 0) close(fd);
        errSet(err, entryPath(*r.snap, e), ": replaced while being restored; not writing through it");
        return -1;
    }
    const u32 k = st.nextEvict;
    st.nextEvict = (k + 1) % StreamRestore::kOpen;
    if (st.openFile[k] != kInvalidIndex) close(st.openFd[k]);
    st.openFile[k] = f;
    st.openFd[k] = fd;
    return fd;
}

bool streamSink(void* ctx, Chain& c, const StreamChunk* recs, u32 n, String& err) {
    StreamRestore& st = *static_cast<StreamRestore*>(ctx);
    if (st.slots.count < n) st.slots.resize(n);
    st.recs = recs;
    st.chain = &c;
    st.r->pool.run(n, decodeTask, &st);
    if (st.failed) { err = move(st.firstErr); return false; }
    for (u32 i = 0; i < n; ++i) {
        const StreamRestore::Slot& slot = st.slots[i];
        const u32 d = slot.want;
        if (d == kInvalidIndex || st.done[d]) continue;
        if (slot.rawLen != st.size[d]) {
            return errSet(err, "stdin: a chunk's size differs from the index's (the index does not belong to this chain?)");
        }
        st.done[d] = 1;
        --st.remaining;
        if (slot.zero) continue;
        for (u32 p = st.firstPlace[d]; p < st.firstPlace[d + 1]; ++p) {
            const int fd = streamFd(st, st.places[p].file, err);
            if (fd < 0) return false;
            if (!pwriteAll(fd, slot.raw.ptr, slot.rawLen, st.places[p].offset))
                return errSet(err, "writing restored data: ", strerror(errno));
        }
    }
    return true;
}

// Plan where every chunk goes, read the stream, then finish the files.
bool streamRestore(Restorer& r, Chain& c, const MasterKey& key, String& err) {
    StreamRestore st;
    st.r = &r;
    st.key = &key;
    st.mu.init();
    for (u32 k = 0; k < StreamRestore::kOpen; ++k) st.openFile[k] = kInvalidIndex;
    const Snapshot& snap = *r.snap;
    // Distinct IDs of the created files, with their places (CSR).
    Array<u32> count;
    st.idx.init(1024);
    for (u32 f = 0; f < r.created.count; ++f) {
        const Entry& e = snap.entries[r.created[f]];
        for (u32 k = 0; k < e.refCount; ++k) {
            const ChunkId& id = snap.refs[e.firstRef + k];
            u32 d = findDistinct(st, id);
            if (d == kInvalidIndex) {
                d = st.distinct.count;
                st.idx.insert(idHash(id), d);
                st.distinct.push(id);
                st.size.push(snap.sizes[e.firstRef + k]);
                count.push(0);
            } else if (st.size[d] != snap.sizes[e.firstRef + k]) {
                return errSet(err, "the index gives one chunk two sizes (damaged)");
            }
            ++count[d];
        }
    }
    st.firstPlace.resize(st.distinct.count + 1);
    u32 sum = 0;
    for (u32 d = 0; d < st.distinct.count; ++d) { st.firstPlace[d] = sum; sum += count[d]; count[d] = 0; }
    st.firstPlace[st.distinct.count] = sum;
    st.places.resize(sum);
    for (u32 f = 0; f < r.created.count; ++f) {
        const Entry& e = snap.entries[r.created[f]];
        u64 off = 0;
        for (u32 k = 0; k < e.refCount; ++k) {
            const u32 d = findDistinct(st, snap.refs[e.firstRef + k]);
            st.places[st.firstPlace[d] + count[d]++] = StreamPlace{f, off};
            off += snap.sizes[e.firstRef + k];
        }
    }
    st.done.resize(st.distinct.count);
    for (u32 d = 0; d < st.distinct.count; ++d) st.done[d] = 0;
    st.remaining = st.distinct.count;

    StreamSink sink;
    sink.fn = streamSink;
    sink.ctx = &st;
    const bool ok = chainStream(c, &sink, err);
    auto closeAll = [&]() {
        for (u32 k = 0; k < StreamRestore::kOpen; ++k)
            if (st.openFile[k] != kInvalidIndex) { close(st.openFd[k]); st.openFile[k] = kInvalidIndex; }
    };
    closeAll();
    st.mu.destroy();
    if (!ok) return false;
    if (st.remaining) {
        String n;
        n.appendU64(st.remaining);
        return errSet(err, "stdin: ", n.view(), " chunks of the snapshot were not in the stream; the chain is incomplete "
                      "(stream every segment from the full backup on)");
    }
    // Is the index's snapshot one of the chain's?
    u32 found = kInvalidIndex;
    for (u32 i = 0; i < c.segs.count; ++i) if (memEqual(c.segs[i].head.id, snap.id, kSnapshotIdBytes)) found = i;
    if (found == kInvalidIndex)
        return errSet(err, "the index's snapshot is in none of the stream's segments (an index of another chain?)");
    if (found != chainLatest(c))
        fprintf(stderr, "bu: note: restored generation %llu from the index; the stream's latest is generation %llu\n",
                (unsigned long long)snap.gen, (unsigned long long)c.segs[chainLatest(c)].t.gen);
    // Owner, mode and times, now that the data is written.
    for (u32 f = 0; f < r.created.count; ++f) {
        const int fd = streamFd(st, f, err);
        if (fd < 0) { report(err); __atomic_add_fetch(&r.errors, 1, __ATOMIC_RELAXED); continue; }
        for (u32 k = 0; k < StreamRestore::kOpen; ++k)
            if (st.openFile[k] == f) st.openFile[k] = kInvalidIndex;
        finishFile(r, snap.entries[r.created[f]], fd);
    }
    closeAll();
    return true;
}

// Is `path` the PATH `p`, or inside it?
bool under(StringView path, StringView p) {
    return path == p || (path.startsWith(p) && path.count > p.count && path[p.count] == '/');
}

// Is `path` selected by the PATHs (all of them when none were named)?
bool selected(StringView path, const Array<StringView>& only) {
    if (!only.count) return true;
    for (const StringView& p : only) if (under(path, p)) return true;
    return false;
}

} // namespace

int cmdRestore(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("restore", argc, argv, first, kArgKey | kArgDir | kArgIndex | kArgJobs | kArgVerbose, a))
        return kExitUsage;
    const u32 nChains = a.dashDash == kInvalidIndex ? a.positional.count : a.dashDash;
    if (nChains == 0) return usage("restore", "name the CHAIN to restore from (PATHs to restore go after --)"_s);
    Array<const char*> chains;
    chains.appendRange(a.positional.ptr, nChains);
    Array<StringView> only;
    for (u32 i = nChains; i < a.positional.count; ++i) {
        StringView p(a.positional[i]);
        while (p.endsWith("/"_s)) p.count--;
        while (p.startsWith("/"_s) || p.startsWith("./"_s)) p = p.from(p[0] == '/' ? 1 : 2);
        if (!pathIsSafe(p)) {
            fprintf(stderr, "bu restore: PATH must name a relative path inside the backup, not '%s'\n", a.positional[i]);
            return kExitUsage;
        }
        only.push(p);
    }

    String err;
    Chain chain;
    if (!chainArgsOpen(chains, chain, err)) { report(err); return kExitRuntime; }
    if (chain.stream && !a.index)
        return usage("restore", "a chain read from a pipe needs --index INDEX: the snapshot to restore must be "
                                "known before the data streams past"_s);
    if (!chain.stream && a.index) return usage("restore", "--index is for a chain read from a pipe"_s);
    MasterKey key;
    if (const int rc = keyForChain(a, "restore", chain.plain, chain.sources[0].path.view(), key)) return rc;
    chain.key = &key;

    IndexData idx;
    const Snapshot* snapPtr = nullptr;
    if (chain.stream) {
        if (!indexFileRead(key, a.index, idx, err)) { report(err); return kExitRuntime; }
        snapPtr = &idx.snap;
    } else {
        if (!chainWalk(chain, err)) { report(err); return kExitRuntime; }
        chainReportTails(chain);
        if (chain.segs.count == 0) { fprintf(stderr, "bu: no complete backup in the chain\n"); return kExitRuntime; }
        if (!chainLoadTables(chain, err)) { report(err); return kExitRuntime; }
        const u32 latest = chainLatest(chain);
        if (!chainResolve(chain, latest, err)) { report(err); return kExitRuntime; }
        snapPtr = &chain.segs[latest].snap;
        // Only the chunks of the selected files must be present.
        u32 missing = 0, sg, ch;
        for (const Entry& e : snapPtr->entries) {
            if (e.type != kEntryFile || !selected(entryPath(*snapPtr, e), only)) continue;
            for (u32 k = 0; k < e.refCount; ++k)
                if (!chainFind(chain, snapPtr->refs[e.firstRef + k], sg, ch)) ++missing;
        }
        if (missing) {
            fprintf(stderr, "bu: %u chunk references point to chunks in none of the given segments; "
                            "the chain is incomplete (give every segment from the full backup on)\n", missing);
            return kExitRuntime;
        }
    }
    const Snapshot& snap = *snapPtr;
    for (const StringView& p : only) {
        bool any = false;
        for (const Entry& e : snap.entries) if (under(entryPath(snap, e), p)) { any = true; break; }
        if (!any) { fprintf(stderr, "bu: %.*s: not in the backup\n", int(p.count), p.ptr); return kExitRuntime; }
    }

    const char* dir = a.dir ? a.dir : ".";
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) { fprintf(stderr, "bu: %s: %s\n", dir, strerror(errno)); return kExitRuntime; }
    Restorer r;
    r.chain = &chain; r.snap = &snap;
    r.stream = chain.stream;
    r.dirs.root = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (r.dirs.root < 0) { fprintf(stderr, "bu: %s: %s\n", dir, strerror(errno)); return kExitRuntime; }
    r.chown = geteuid() == 0;
    // Eight threads unless -j says otherwise: reading wants queue depth, which
    // the prefetch below provides without threads, and more threads writing
    // into the page cache only cost kernel CPU (docs/benchmarks.md, gap 4).
    r.pool.init(a.jobs ? a.jobs : min<u32>(cpuCount(), kRestoreThreads));
    r.scratch.span.resize(r.pool.threads);
    r.scratch.payload.resize(r.pool.threads);
    r.scratch.out.resize(r.pool.threads);
    u64 total = 0;
    for (const Source& s : chain.sources) total += s.size;
    for (Batch& b : r.batches) {
        b.chain = &chain; b.scratch = &r.scratch;
        b.mu.init();
        b.spanTarget = chainSpanTarget(total, r.pool.threads);
        b.lookahead = chainPrefetchTasks(b.spanTarget, r.pool.threads);
    }
    r.batchFiles = batchFileLimit();
    r.mu.init(); r.cv.init();
    // Without the thread (resource limit) batches run in turn on this one.
    if (!r.stream) r.finisherUp = r.finisher.start(finisherMain, &r);

    Array<u32> dirsDone;
    bool fatal = false;
    String name;
    for (u32 i = 0; i < snap.entries.count && !fatal; ++i) {
        const Entry& e = snap.entries[i];
        const StringView path = entryPath(snap, e);
        if (!selected(path, only)) continue;
        StringView parent, base;
        splitPath(path, parent, base);
        const int pfd = r.dirs.open(parent, err);
        if (pfd < 0) { report(err); __atomic_add_fetch(&r.errors, 1, __ATOMIC_RELAXED); continue; }
        name.assign(base);
        if (e.type == kEntryDir) {
            if (mkdirat(pfd, name.c_str(), 0700) != 0 && errno != EEXIST) { entryError(r, e, StringView(strerror(errno))); continue; }
            struct stat st;
            if (fstatat(pfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode)) {
                entryError(r, e, "exists and is not a directory"_s); continue;
            }
            // Directories get their final mode/mtime at the very end: writing
            // into one bumps its mtime, and a read-only mode would block us.
            if (!chmodDirAt(pfd, name.c_str(), 0700 | (e.mode & 0777))) {
                entryError(r, e, "replaced while being restored, or its mode cannot be set"_s); continue;
            }
            dirsDone.push(i);
        } else if (e.type == kEntrySymlink) {
            unlinkat(pfd, name.c_str(), 0);
            const String target(entryTarget(snap, e));
            if (symlinkat(target.c_str(), pfd, name.c_str()) != 0) { entryError(r, e, StringView(strerror(errno))); continue; }
            if (r.chown) fchownat(pfd, name.c_str(), e.uid, e.gid, AT_SYMLINK_NOFOLLOW);
            struct timespec ts[2];
            timesOf(e, ts);
            utimensat(pfd, name.c_str(), ts, AT_SYMLINK_NOFOLLOW);
        } else {
            if (!restoreFile(r, i, pfd, name.c_str())) fatal = true;
        }
    }
    if (r.stream) {
        if (!fatal && !streamRestore(r, chain, key, err)) { report(err); fatal = true; }
        chainReportTails(chain);
    } else {
        if (!fatal && !submitBatch(r)) fatal = true;
        if (!finishBatches(r)) fatal = true;
        for (int fd : r.batches[r.filling].fds) close(fd);   // left over by a failure
    }

    for (u32 k = dirsDone.count; k > 0; --k) {
        const Entry& e = snap.entries[dirsDone[k - 1]];
        StringView parent, base;
        splitPath(entryPath(snap, e), parent, base);
        const int pfd = r.dirs.open(parent, err);
        if (pfd < 0) continue;
        name.assign(base);
        if (r.chown) fchownat(pfd, name.c_str(), e.uid, e.gid, AT_SYMLINK_NOFOLLOW);
        if (!chmodDirAt(pfd, name.c_str(), e.mode)) entryError(r, e, "cannot set the directory's mode"_s);
        struct timespec ts[2];
        timesOf(e, ts);
        utimensat(pfd, name.c_str(), ts, AT_SYMLINK_NOFOLLOW);
    }
    r.pool.shutdown();
    for (Batch& b : r.batches) b.mu.destroy();
    r.cv.destroy(); r.mu.destroy();
    close(r.dirs.root);
    if (a.verbose)
        fprintf(stderr, "bu: restored %llu files (%llu bytes) from snapshot generation %llu\n",
                (unsigned long long)r.files, (unsigned long long)r.bytes, (unsigned long long)snap.gen);
    if (fatal || r.errors) {
        fprintf(stderr, "bu: restore FAILED (%u error%s); the restored tree is incomplete\n", r.errors + (fatal && !r.errors),
                r.errors == 1 ? "" : "s");
        return kExitRuntime;
    }
    return kExitOk;
}

} // namespace bk
