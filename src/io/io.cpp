// io.cpp — see io.hpp.

#include "io/io.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>  // rename
#include <string.h>
#include <sys/random.h>  // getrandom
#include <sys/stat.h>
#include <sys/uio.h>   // writev
#include <time.h>
#include <unistd.h>

namespace bk {

// Declared in core/string.hpp; lives here, in a cold (-Oz) TU, because
// nothing on a hot path builds error messages.
bool errSetParts(String& e, const StringView* parts, u32 n) {
    // Built aside: a part may be a view of `e` itself (a message wrapped
    // with the file name: `errSet(err, path, ": ", err.view())`).
    String out;
    for (u32 i = 0; i < n; ++i) out.append(parts[i]);
    e = move(out);
    return false;
}

i64 readFull(int fd, void* buf, usize n) {
    u8* p = static_cast<u8*>(buf);
    usize got = 0;
    while (got < n) {
        const ssize_t r = ::read(fd, p + got, n - got);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) break;
        got += usize(r);
    }
    return i64(got);
}

i64 preadUpTo(int fd, void* buf, usize n, u64 off) {
    u8* p = static_cast<u8*>(buf);
    usize got = 0;
    while (got < n) {
        const ssize_t r = ::pread(fd, p + got, n - got, off_t(off + got));
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) break;
        got += usize(r);
    }
    return i64(got);
}

bool preadFull(int fd, void* buf, usize n, u64 off, String& err) {
    u8* p = static_cast<u8*>(buf);
    usize got = 0;
    while (got < n) {
        const ssize_t r = ::pread(fd, p + got, n - got, off_t(off + got));
        if (r < 0) { if (errno == EINTR) continue; return errSet(err, "read: ", strerror(errno)); }
        if (r == 0) return errSet(err, "unexpected end of file (truncated backup?)");
        got += usize(r);
    }
    return true;
}

bool writeAll(int fd, const void* buf, usize n) {
    const u8* p = static_cast<const u8*>(buf);
    while (n) {
        const ssize_t w = ::write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w; n -= usize(w);
    }
    return true;
}

bool pwriteAll(int fd, const void* buf, usize n, u64 off) {
    const u8* p = static_cast<const u8*>(buf);
    while (n) {
        const ssize_t w = ::pwrite(fd, p, n, off_t(off));
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w; n -= usize(w); off += u64(w);
    }
    return true;
}

void OutStream::write(const void* p, usize n) {
    written += n;
    if (failed) return;
    const u8* s = static_cast<const u8*>(p);
    if (toMemory) { buf.appendRange(s, u32(n)); return; }
    // A write at least a block long bypasses the buffer: copying a 4 MB
    // record into the buffer only to write it out again is a wasted memcpy.
    if (buf.count + n > kOutBlock) {
        if (!flush()) return;
        if (n >= kOutBlock) {
            if (!writeAll(fd, s, n)) { failed = true; savedErrno = errno; }
            return;
        }
    }
    buf.appendRange(s, u32(n));
}

static_assert(sizeof(IoSlice) == sizeof(struct iovec), "IoSlice mirrors iovec");

void OutStream::writeVec(const IoSlice* v, u32 n) {
    usize total = 0;
    for (u32 i = 0; i < n; ++i) total += v[i].len;
    if (toMemory) { for (u32 i = 0; i < n; ++i) write(v[i].ptr, v[i].len); return; }
    written += total;
    if (failed || total == 0) return;
    if (!flush()) return;
    // writev may stop anywhere, including inside a slice; advance through
    // the slices by what was accepted and retry the rest.
    struct iovec iov[64];
    u32 i = 0;
    usize skip = 0;
    while (i < n) {
        u32 k = 0;
        for (u32 q = i; q < n && k < 64; ++q, ++k) {
            iov[k].iov_base = const_cast<u8*>(static_cast<const u8*>(v[q].ptr)) + (q == i ? skip : 0);
            iov[k].iov_len = v[q].len - (q == i ? skip : 0);
        }
        ssize_t w = ::writev(fd, iov, int(k));
        if (w < 0) {
            if (errno == EINTR) continue;
            failed = true; savedErrno = errno; return;
        }
        while (w > 0 && i < n) {
            const usize left = v[i].len - skip;
            if (usize(w) >= left) { w -= ssize_t(left); ++i; skip = 0; }
            else { skip += usize(w); w = 0; }
        }
        while (i < n && v[i].len == 0) ++i;
    }
}

bool OutStream::flush() {
    if (failed) return false;
    if (toMemory) return true;
    if (buf.count && !writeAll(fd, buf.ptr, buf.count)) { failed = true; savedErrno = errno; return false; }
    buf.count = 0;
    return true;
}

bool readWholeFile(const char* path, u64 maxBytes, Array<u8>& out, String& err) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errSet(err, path, ": ", strerror(errno));
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { ::close(fd); return errSet(err, path, ": not a regular file"); }
    if (u64(st.st_size) > maxBytes) { ::close(fd); return errSet(err, path, ": file too large"); }
    out.resize(u32(st.st_size));
    const i64 r = readFull(fd, out.ptr, out.count);
    const int e = errno;
    ::close(fd);
    if (r < 0) return errSet(err, path, ": ", strerror(e));
    out.count = u32(r);
    return true;
}

int tempFileBeside(const char* path, String& tmp, String& err) {
    // The temp name is the target's plus 16 random hex digits, created with
    // O_EXCL | O_NOFOLLOW: anyone who can write in the directory could plant
    // a symlink or a file of their own at a predictable name (the pid), and
    // an O_TRUNC open would follow the link — clobbering its target, as root
    // anything — or write our data into their file with their mode. Here an
    // existing name is never opened, only skipped. O_TMPFILE + linkat was
    // the alternative; it still needs a named temp to rename over the
    // target (linkat will not replace), so it only adds a second code path.
    for (u32 attempt = 0; attempt < 8; ++attempt) {
        u8 rnd[8];
        if (getrandom(rnd, sizeof rnd, 0) != ssize_t(sizeof rnd)) { errSet(err, "getrandom: ", strerror(errno)); return -1; }
        static const char kDigits[] = "0123456789abcdef";
        char hex[16];
        for (u32 i = 0; i < 8; ++i) { hex[2 * i] = kDigits[rnd[i] >> 4]; hex[2 * i + 1] = kDigits[rnd[i] & 15]; }
        tmp.assign(StringView(path));
        tmp.append(".tmp."_s);
        tmp.append(StringView(hex, 16));
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0) return fd;
        if (errno != EEXIST) { errSet(err, tmp.c_str(), ": ", strerror(errno)); return -1; }
    }
    errSet(err, path, ": cannot create a temporary file beside it");
    return -1;
}

bool renameDurably(const char* tmp, const char* path, String& err) {
    if (::rename(tmp, path) != 0) {
        const int re = errno;
        ::unlink(tmp);
        return errSet(err, path, ": ", strerror(re));
    }
    // The rename is durable only once the directory is: without this fsync a
    // crash can bring back the old file (for a key file, a removed slot).
    const StringView p(path);
    const u32 slash = p.findLast('/');
    String dir(slash == kInvalidIndex ? "."_s : (slash == 0 ? "/"_s : p.first(slash)));
    const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0) return errSet(err, dir.c_str(), ": ", strerror(errno));
    const bool synced = fsync(dfd) == 0;
    const int de = errno;
    ::close(dfd);
    if (!synced) return errSet(err, dir.c_str(), ": ", strerror(de));
    return true;
}

bool writeFileAtomic(const char* path, const void* data, usize n, String& err) {
    String tmp;
    const int fd = tempFileBeside(path, tmp, err);
    if (fd < 0) return false;
    bool ok = writeAll(fd, data, n) && fsync(fd) == 0;
    const int e = errno;
    if (::close(fd) != 0) ok = false;
    if (!ok) { ::unlink(tmp.c_str()); return errSet(err, tmp.c_str(), ": ", strerror(e)); }
    return renameDurably(tmp.c_str(), path, err);
}

void pipeGrow(int fd) {
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISFIFO(st.st_mode)) (void)fcntl(fd, F_SETPIPE_SZ, 1 << 20);
}

i64 nowNs() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return i64(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}

} // namespace bk
