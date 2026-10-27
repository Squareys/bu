// restore.cpp — `bu restore`: recreate the latest snapshot of a chain.
//
// Every chunk is authenticated (GCM tag under its file's key, with its ID in
// the associated data) and then re-hashed (keyed BLAKE3 must equal the ID it
// was filed under) before a byte of it reaches the output. Missing chunks are
// counted BEFORE anything is written, so an incomplete chain fails up front
// instead of leaving half a tree.
//
// PARALLELISM. Files are grouped into batches (bounded by open descriptors
// and bytes); within a batch every chunk is an independent task — pread,
// decrypt, verify, decompress, pwrite at its offset — run on the thread pool.
// Output files are opened and sized first (ftruncate), so an all-zero chunk is
// simply not written and stays a hole: a sparse SQLite file restores sparse.
//
// SAFETY OF THE OUTPUT TREE. Paths were validated at decode (relative, no
// "..", no empty components), and every path is resolved component by
// component with O_NOFOLLOW from the restore directory's fd, so a symlink in
// the restored tree — or one an attacker planted in the target directory —
// can never redirect a write outside it. Restored symlinks are created as
// links, never followed. A name that already exists in the target is
// unlinked and created anew (O_EXCL): opening it with O_TRUNC would write
// through a hard link planted there into a file outside the tree, and block
// forever on a planted FIFO. Directory modes are set through a descriptor
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
#include "core/thread.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bk {

namespace {

constexpr u32 kBatchFiles = 256;
constexpr u64 kBatchBytes = u64(256) << 20;

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
                // A parent outside the restored set (--path) or not yet made.
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

struct Task {
    u32 out;        // index into Batch::fds
    u32 file;       // chain file
    u32 chunk;      // chunk index in that file
    u64 offset;     // in the output file
};

struct Batch {
    const MasterKey* key = nullptr;
    const Chain* chain = nullptr;
    Array<int> fds;
    Array<u32> entries;
    Array<Task> tasks;
    u64 bytes = 0;
    // per worker scratch
    Array<Array<u8>> scratch, raw;
    Mutex mu;
    String firstErr;     // under mu
    bool failed = false; // under mu (read racily as a hint to stop early)
};

void runTask(void* ctx, u32 i, u32 worker) {
    Batch& b = *static_cast<Batch*>(ctx);
    if (__atomic_load_n(&b.failed, __ATOMIC_RELAXED)) return;
    const Task& t = b.tasks[i];
    const Container& c = b.chain->files[t.file];
    String err;
    Array<u8>& raw = b.raw[worker];
    bool ok = containerReadChunk(*b.key, c, c.chunks[t.chunk], b.scratch[worker], raw, err);
    if (ok && raw.count) {
        const bool zero = raw[0] == 0 && memEqual(raw.ptr, raw.ptr + 1, raw.count - 1);
        if (!zero && !pwriteAll(b.fds[t.out], raw.ptr, raw.count, t.offset)) {
            ok = false;
            errSet(err, "writing restored data: ", strerror(errno));
        }
    }
    if (!ok) {
        Lock l(b.mu);
        if (!b.failed) { b.firstErr = move(err); __atomic_store_n(&b.failed, true, __ATOMIC_RELAXED); }
    }
}

struct Restorer {
    const MasterKey* key = nullptr;
    Chain* chain = nullptr;
    const Snapshot* snap = nullptr;
    DirResolver dirs;
    ThreadPool pool;
    Batch batch;
    bool chown = false;
    u32 errors = 0;
    u64 files = 0, bytes = 0;
};

void entryError(Restorer& r, const Entry& e, StringView what) {
    const StringView p = entryPath(*r.snap, e);
    fprintf(stderr, "bu: %.*s: %.*s\n", int(p.count), p.ptr, int(what.count), what.ptr);
    ++r.errors;
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

// Run the batch's tasks, then finish each file: owner, mode, mtime, close.
bool flushBatch(Restorer& r) {
    Batch& b = r.batch;
    r.pool.run(b.tasks.count, runTask, &b);
    bool ok = !b.failed;
    if (!ok) { report(b.firstErr.view()); ++r.errors; }
    for (u32 i = 0; i < b.fds.count; ++i) {
        const Entry& e = r.snap->entries[b.entries[i]];
        const int fd = b.fds[i];
        struct timespec ts[2];
        timesOf(e, ts);
        // Owner before mode: chown clears set-uid/set-gid bits, so the mode
        // must be applied after it to survive.
        if (r.chown && fchown(fd, e.uid, e.gid) != 0) entryError(r, e, StringView(strerror(errno)));
        if (fchmod(fd, mode_t(fileMode(r, e))) != 0) entryError(r, e, StringView(strerror(errno)));
        if (futimens(fd, ts) != 0) entryError(r, e, StringView(strerror(errno)));
        if (close(fd) != 0) { entryError(r, e, StringView(strerror(errno))); ok = false; }
    }
    b.fds.clear(); b.entries.clear(); b.tasks.clear(); b.bytes = 0;
    return ok;
}

bool restoreFile(Restorer& r, u32 ei, int pfd, const char* name) {
    const Entry& e = r.snap->entries[ei];
    // Replace, never open, what is there (see the top of the file). EISDIR
    // leaves the directory alone; the O_EXCL create then reports EEXIST.
    if (unlinkat(pfd, name, 0) != 0 && errno != ENOENT && errno != EISDIR) {
        entryError(r, e, StringView(strerror(errno)));
        return true;
    }
    const int fd = openat(pfd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) { entryError(r, e, StringView(strerror(errno))); return true; }
    if (ftruncate(fd, off_t(e.size)) != 0) { entryError(r, e, StringView(strerror(errno))); close(fd); return true; }
    Batch& b = r.batch;
    const u32 slot = b.fds.count;
    b.fds.push(fd);
    b.entries.push(ei);
    u64 off = 0;
    for (u32 k = 0; k < e.refCount; ++k) {
        u32 f = 0, ch = 0;
        chainFind(*r.chain, r.snap->refs[e.firstRef + k], f, ch);   // presence checked up front
        b.tasks.push(Task{slot, f, ch, off});
        off += r.chain->files[f].chunks[ch].rawLen;
    }
    if (off != e.size) entryError(r, e, "chunk sizes do not add up to the recorded file size (damaged manifest?)"_s);
    b.bytes += e.size;
    ++r.files; r.bytes += e.size;
    if (b.fds.count >= kBatchFiles || b.bytes >= kBatchBytes) return flushBatch(r);
    return true;
}

} // namespace

int cmdRestore(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("restore", argc, argv, first, kArgKey | kArgDir | kArgPath | kArgJobs | kArgVerbose, a))
        return kExitUsage;
    if (a.positional.count == 0) { fprintf(stderr, "bu restore: name the backup files of the chain\n"); return kExitUsage; }
    StringView prefix = a.path ? StringView(a.path) : StringView();
    while (prefix.endsWith("/"_s)) prefix.count--;
    while (prefix.startsWith("/"_s)) prefix = prefix.from(1);
    if (a.path && !pathIsSafe(prefix)) {
        fprintf(stderr, "bu restore: --path must name a relative path inside the backup, not '%s'\n", a.path);
        return kExitUsage;
    }

    String err;
    MasterKey key;
    if (!unlockKeyForCommand(a, key)) return kExitRuntime;
    Chain chain;
    if (!chainOpen(key, a.positional, chain, err)) { report(err); return kExitRuntime; }
    const u32 latest = chainLatest(chain);
    if (!chainResolve(chain, latest, err)) { report(err); return kExitRuntime; }
    const Snapshot& snap = chain.snaps[latest].snap;
    const u32 missing = chainCountMissing(chain, snap);
    if (missing) {
        fprintf(stderr, "bu: %u chunk references point to chunks in none of the given files; "
                        "the chain is incomplete (give every file from the full backup on)\n", missing);
        return kExitRuntime;
    }

    const char* dir = a.dir ? a.dir : ".";
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) { fprintf(stderr, "bu: %s: %s\n", dir, strerror(errno)); return kExitRuntime; }
    Restorer r;
    r.key = &key; r.chain = &chain; r.snap = &snap;
    r.dirs.root = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (r.dirs.root < 0) { fprintf(stderr, "bu: %s: %s\n", dir, strerror(errno)); return kExitRuntime; }
    r.chown = geteuid() == 0;
    r.pool.init(argsJobs(a));
    r.batch.key = &key; r.batch.chain = &chain;
    r.batch.mu.init();
    r.batch.scratch.resize(r.pool.threads);
    r.batch.raw.resize(r.pool.threads);

    Array<u32> dirsDone;
    bool fatal = false;
    String name;
    for (u32 i = 0; i < snap.entries.count && !fatal; ++i) {
        const Entry& e = snap.entries[i];
        const StringView path = entryPath(snap, e);
        if (a.path && !(path == prefix || (path.startsWith(prefix) && path[prefix.count] == '/'))) continue;
        StringView parent, base;
        splitPath(path, parent, base);
        const int pfd = r.dirs.open(parent, err);
        if (pfd < 0) { report(err); ++r.errors; continue; }
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
    if (!fatal && !flushBatch(r)) fatal = true;

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
    r.batch.mu.destroy();
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
