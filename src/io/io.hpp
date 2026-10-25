// io.hpp — the Unix I/O primitives every command shares.
//
// Plain read/write/pread/pwrite on file descriptors with the two loops every
// caller would otherwise get wrong: EINTR retry and short transfers. No stdio
// FILE* for data (stdio is for messages only), no mmap — a file truncated
// while mapped turns the next load into SIGBUS, and a backup tool reads files
// other programs are writing.
//
// OutStream is the buffered sink for a container being streamed to stdout: a
// pipe to `aws s3 cp -` or a file, it does not care. It writes in large
// blocks (kOutBlock) because a pipe reader wakes per write, and it counts every
// byte so the writer knows each record's offset without seeking — stdout may
// not be seekable.
#pragma once

#include "core/array.hpp"
#include "core/string.hpp"

namespace bk {

constexpr u32 kOutBlock = 4u << 20;

// Full read; returns bytes read (< n only at EOF) or -1 with errno set.
i64 readFull(int fd, void* buf, usize n);
// Positional read of up to n bytes, looping over short reads; returns the
// bytes read (< n only at end of file) or -1 with errno set.
i64 preadUpTo(int fd, void* buf, usize n, u64 off);
// Full positional read; false on error or short read (with `err` filled).
[[nodiscard]] bool preadFull(int fd, void* buf, usize n, u64 off, String& err);
// Write all n bytes; false with errno set.
[[nodiscard]] bool writeAll(int fd, const void* buf, usize n);
[[nodiscard]] bool pwriteAll(int fd, const void* buf, usize n, u64 off);

// Layout-compatible with struct iovec (io.cpp static_asserts it), so callers
// need not include <sys/uio.h>.
struct IoSlice {
    const void* ptr;
    usize len;
};

struct OutStream {
    int fd = -1;
    Array<u8> buf;
    u64 written = 0;     // bytes accepted so far (buffered + flushed)
    bool failed = false;
    int savedErrno = 0;

    void init(int outFd) { fd = outFd; buf.reserve(kOutBlock); buf.count = 0; }
    void write(const void* p, usize n);
    // Gather-write straight from the callers' buffers (writev): records go
    // from the workers' slots to the fd with no copy into `buf`.
    void writeVec(const IoSlice* v, u32 n);
    // Flush the buffer; false if any write so far failed (errno in savedErrno).
    [[nodiscard]] bool flush();
};

// Whole small file into `out` (key files, index files); bounded by maxBytes.
[[nodiscard]] bool readWholeFile(const char* path, u64 maxBytes, Array<u8>& out, String& err);
// Write `data` to `path` atomically: a temp file beside it, fsync, rename.
// A crash leaves either the old file or the new one, never half of either —
// this is how the index is replaced, and a torn index would silently make the
// next increment store everything again (or worse, think it needn't).
[[nodiscard]] bool writeFileAtomic(const char* path, const void* data, usize n, String& err);

// Wall clock in nanoseconds since the epoch.
i64 nowNs();

} // namespace bk
