// chain.cpp — see chain.hpp.

#include "cmd/chain.hpp"
#include "core/bytes.hpp"
#include "format/codec.hpp"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bk {

namespace {

// Metadata reads go through a window of this many bytes ending at the read:
// walking back, the window that holds a trailer usually holds the table, the
// manifest and the header of a small segment too, and the trailer of the one
// before. On a network mount each pread is a round trip.
constexpr u32 kWindow = 256u << 10;
// The stream buffer. A chunk record (at most kMaxChunkRecord) always fits.
constexpr u32 kStreamBuf = 8u << 20;

bool failAt(String& err, StringView path, u64 offset, StringView what) {
    String off;
    off.appendU64(offset);
    return errSet(err, path, ": at offset ", off.view(), ": ", what);
}

struct Window {
    int fd = -1;
    u64 off = 0;
    Array<u8> buf;
};

// The bytes [off, off + n) of the source, through the window.
const u8* windowGet(Window& w, u64 off, u32 n, String& err) {
    if (off >= w.off && off + n <= w.off + w.buf.count) return w.buf.ptr + (off - w.off);
    const u64 end = off + n;
    const u64 want = max<u64>(n, kWindow);
    const u64 begin = end > want ? end - want : 0;
    w.buf.resize(u32(end - begin));
    w.off = begin;
    if (!preadFull(w.fd, w.buf.ptr, w.buf.count, begin, err)) { w.buf.count = 0; return nullptr; }
    return w.buf.ptr + (off - begin);
}

// Read metadata record bytes [off, off + 4 + len): small ones through the
// window, large ones straight into `out`.
bool readRecordBytes(Window& w, u64 off, u32 len, Array<u8>& out, String& err) {
    const u64 total = 4 + u64(len);
    out.resize(u32(total));
    if (total <= kWindow) {
        const u8* p = windowGet(w, off, u32(total), err);
        if (!p) return false;
        memCopy(out.ptr, p, total);
        return true;
    }
    return preadFull(w.fd, out.ptr, usize(total), off, err);
}

// Open a metadata record's body (its nonce and type are fixed) and decode
// the payload into `out`.
bool openMetaBody(const SegKeys& keys, u8 type, u64 nonce, const u8* body, u32 bodyLen, Array<u8>& out, String& why) {
    Array<u8> payload;
    payload.resize(bodyLen - kTagBytes);
    if (!bodyOpen(keys, nonce, type, body, bodyLen, payload.ptr))
        return errSet(why, "authentication failed for a metadata record — the file was modified or damaged");
    u32 raw = 0;
    if (!codecRawLength(payload.ptr, payload.count, kMaxMetaRecord, raw)) return errSet(why, "malformed metadata payload");
    out.resize(raw);
    if (!codecDecode(payload.ptr, payload.count, out.ptr, raw)) return errSet(why, "metadata payload does not decompress");
    return true;
}

// Check a record's header: the type and body nonce it says, under ordinal.
bool checkHead(const SegKeys& keys, u64 ordinal, const u8* rec, u8 type, u64 nonce, String& why) {
    u8 gotType = 0;
    u64 gotNonce = 0;
    u32 bodyLen = 0;
    if (recPrefixOpen(keys, ordinal, rec, gotType, gotNonce, bodyLen) && gotType == type && gotNonce == nonce
        && kRecHeadBytes + bodyLen == loadU32LE(rec))
        return true;
    return errSet(why, "record header authentication failed — the file was modified or damaged");
}

// Parse a table body into s.chunks (offsets from `recBase`, the absolute
// offset of the first chunk record). `limit` caps the count before the
// allocation (the bytes the records could occupy).
bool parseTable(Seg& s, const u8* p, u32 n, u64 recBase, u64 limit, String& why) {
    ByteReader r(p, n);
    if (r.varint() != 2) return errSet(why, "unsupported chunk table version");
    const u64 count = r.varintMax(limit / (4 + kRecHeadBytes + kTagBytes));
    s.chunks.resize(u32(count));
    u64 off = recBase, nonce = 0;
    for (u32 i = 0; i < count && !r.failed; ++i) {
        ChunkLoc& l = s.chunks[i];
        r.bytes(l.id.b, kIdBytes);
        l.recLen = u32(r.varintMax(kMaxChunkRecord));
        nonce += r.varint();
        l.nonce = nonce;
        l.rawLen = u32(r.varintMax(kMaxChunk));
        l.offset = off;
        off += 4 + u64(l.recLen);
        // Strictly increasing and below the metadata range: the writer never
        // reuses a nonce, so a table that claims otherwise is damaged.
        if (l.recLen < kRecHeadBytes + kTagBytes || (i > 0 && l.nonce <= s.chunks[i - 1].nonce)
            || l.nonce >= kNonceMetaBase)
            r.failed = true;
    }
    if (r.failed || !r.done()) return errSet(why, "malformed chunk table");
    if (off != recBase + limit) return errSet(why, "chunk table does not add up to the segment layout (damaged)");
    s.tableLoaded = true;
    return true;
}

// The segment ending at `end`: trailer, header, keys, both checks. False
// with `why` when there is none (or it does not verify). `hard` is set when
// a trailer points back at a real bu header and something after that fails
// (another key, the other mode, a bad check): a segment end that is wrong,
// not an incomplete tail.
bool segAt(const Chain& c, Window& w, u64 end, Seg& s, String& why, bool* hard = nullptr) {
    if (end < kHeaderBytes + kTrailerBytes) return errSet(why, "too short to hold a segment");
    const u8* tp = windowGet(w, end - kTrailerBytes, kTrailerBytes, why);
    if (!tp) return false;
    u8 tr[kTrailerBytes];
    memCopy(tr, tp, kTrailerBytes);
    if (!trailerParse(tr, s.t, why)) return false;
    if (s.t.segLen > end) return errSet(why, "segment trailer claims more bytes than precede it (damaged)");
    s.start = end - s.t.segLen;
    const u8* hp = windowGet(w, s.start, kHeaderBytes, why);
    if (!hp) return false;
    memCopy(s.header, hp, kHeaderBytes);
    u16 kind = 0;
    bool plain = false;
    if (!headerParse(s.header, kind, plain, why)) return false;
    if (hard) *hard = true;
    if (kind != kKindSegment) return errSet(why, "an index file inside a chain (damaged)");
    if (plain != c.plain)
        return errSet(why, c.plain ? "an encrypted segment in an unencrypted chain; a chain is one or the other"
                                   : "an unencrypted segment in an encrypted chain; a chain is one or the other");
    segKeysDerive(*c.key, s.header + 16, s.keys);
    if (!headerVerify(s.keys, s.header)) return errSet(why, plain ? "header damaged" : "wrong key (or the header is damaged)");
    if (!trailerVerify(s.keys, s.header, tr)) return errSet(why, "segment trailer authentication failed (damaged)");
    if (s.t.tabLen == 0) return errSet(why, "segment without a chunk table (damaged)");
    return true;
}

// Walk back from `end` to offset 0, appending segments last-first.
bool walkFrom(const Chain& c, Window& w, u32 si, u64 end, Array<Seg>& rev, String& err) {
    const StringView path = c.sources[si].path.view();
    while (end > 0) {
        Seg& s = rev.addDefault();
        s.source = si;
        String why;
        if (!segAt(c, w, end, s, why)) {
            failAt(err, path, end, why.view());
            return false;
        }
        end = s.start;
    }
    return true;
}

// The end of the last complete segment, when the file's own end is not one:
// scan back for trailer magic and take the first position that walks back
// to offset 0. Encrypted, a trailer that authenticates is a real segment
// end, so a walk that breaks after it is damage, not a tail. Unencrypted,
// stored chunk data may contain trailer bytes (a backup of a chain), so a
// candidate that does not walk is only skipped.
bool recoverEnd(const Chain& c, Window& w, u32 si, Array<Seg>& rev, u64& end, String& err) {
    const Source& src = c.sources[si];
    Array<u8> block;
    constexpr u32 kBlock = 1u << 20;
    u64 hi = src.size;
    while (hi > kHeaderBytes + kTrailerBytes - 1) {
        const u64 lo = hi > kBlock ? hi - kBlock : 0;
        block.resize(u32(hi - lo));
        if (!preadFull(src.fd, block.ptr, block.count, lo, err)) return false;
        for (u32 i = block.count; i >= 8; --i) {
            if (!memEqual(block.ptr + i - 8, kTrailerMagic, 8)) continue;
            const u64 p = lo + i;
            Seg probe;
            String why;
            if (!segAt(c, w, p, probe, why)) continue;
            rev.clear();
            if (walkFrom(c, w, si, p, rev, err)) { end = p; return true; }
            if (!c.plain) return false;
            rev.clear();
            err.clear();
        }
        if (lo == 0) break;
        hi = lo + 7;      // a magic straddling the block boundary is found in the next block
    }
    end = 0;              // no complete segment at all: an interrupted first backup
    rev.clear();
    return true;
}

bool openSource(Chain& c, Source& s, String& err) {
    struct stat st;
    if (fstat(s.fd, &st) != 0) return errSet(err, s.path.view(), ": ", strerror(errno));
    s.seekable = S_ISREG(st.st_mode);
    if (s.seekable) {
        s.size = u64(st.st_size);
        // A shared lock that cannot be had means a create is appending right
        // now: an incomplete tail is then expected, not a fault. Released at
        // once, so a long restore never makes a create wait or fail.
        if (flock(s.fd, LOCK_SH | LOCK_NB) != 0) s.writerActive = errno == EWOULDBLOCK;
        else flock(s.fd, LOCK_UN);
    } else if (S_ISDIR(st.st_mode)) {
        return errSet(err, s.path.view(), ": is a directory");
    }
    return true;
}

bool streamFill(Chain& c, int fd, u32 n, String& err);

} // namespace

Source::Source(Source&& o)
    : path(move(o.path)), fd(o.fd), own(o.own), seekable(o.seekable), size(o.size), tail(o.tail),
      writerActive(o.writerActive) {
    o.fd = -1;
    o.own = false;
}

Source::~Source() {
    if (own && fd >= 0) ::close(fd);
}

namespace {

bool firstHeader(Chain& c, String& err) {
    Source& s = c.sources[0];
    u8 h[kHeaderBytes];
    if (s.seekable) {
        if (s.size == 0) return errSet(err, s.path.view(), ": is empty (no backup in it yet)");
        if (s.size < kHeaderBytes) return errSet(err, s.path.view(), ": too short to be a bu file");
        if (!preadFull(s.fd, h, kHeaderBytes, 0, err)) return errSet(err, s.path.view(), ": ", err.view());
    } else {
        if (!streamFill(c, s.fd, kHeaderBytes, err)) {
            if (err.empty()) errSet(err, "stdin: ", c.in.tail ? "too short to be a bu file" : "is empty (no backup on it)");
            return false;
        }
        memCopy(h, c.in.buf.ptr + c.in.head, kHeaderBytes);
    }
    String why;
    bool plain = false;
    if (!headerParse(h, c.firstKind, plain, why)) return errSet(err, s.path.view(), ": ", why.view());
    c.plain = plain;
    return true;
}

} // namespace

bool chainArgsOpen(const Array<const char*>& args, Chain& c, String& err) {
    c.sources.reserve(args.count);
    u32 stdinUses = 0;
    for (const char* a : args) {
        Source& s = c.sources.addDefault();
        s.path.assign(StringView(a) == "-"_s ? "stdin"_s : StringView(a));
        if (StringView(a) == "-"_s) {
            if (++stdinUses > 1) return errSet(err, "'-' (stdin) named twice");
            s.fd = 0;
        } else {
            s.fd = ::open(a, O_RDONLY | O_CLOEXEC);
            if (s.fd < 0) return errSet(err, a, ": ", strerror(errno));
            s.own = true;
        }
        if (!openSource(c, s, err)) return false;
        if (!s.seekable) {
            if (args.count != 1)
                return errSet(err, a, ": a pipe must be the only CHAIN argument (it is read as one stream)");
            c.stream = true;
            pipeGrow(s.fd);
            c.in.buf.resize(kStreamBuf);
        }
    }
    return firstHeader(c, err);
}

bool chainFdOpen(int fd, const char* name, Chain& c, String& err) {
    Source& s = c.sources.addDefault();
    s.path.assign(StringView(name));
    s.fd = fd;
    if (!openSource(c, s, err)) return false;
    return firstHeader(c, err);
}

bool chainWalk(Chain& c, String& err) {
    for (u32 si = 0; si < c.sources.count; ++si) {
        Source& src = c.sources[si];
        Window w;
        w.fd = src.fd;
        // The first header decides: a wrong key or a foreign file is said
        // as such here, not as a missing trailer after a scan.
        u8 h[kHeaderBytes];
        if (src.size < kHeaderBytes) return errSet(err, src.path.view(), ": too short to be a bu file");
        if (!preadFull(src.fd, h, kHeaderBytes, 0, err)) return errSet(err, src.path.view(), ": ", err.view());
        {
            String why;
            u16 kind = 0;
            bool plain = false;
            if (!headerParse(h, kind, plain, why)) return errSet(err, src.path.view(), ": ", why.view());
            if (kind == kKindIndex)
                return errSet(err, src.path.view(), ": is an index file, not a chain (index files go to "
                                                    "create --base and restore --index)");
            if (plain != c.plain)
                return errSet(err, src.path.view(), plain ? ": is unencrypted and the chain before it is not; "
                                                            "a chain is one or the other"
                                                          : ": is encrypted and the chain before it is not; "
                                                            "a chain is one or the other");
            SegKeys k;
            segKeysDerive(*c.key, h + 16, k);
            if (!headerVerify(k, h))
                return errSet(err, src.path.view(), plain ? ": header damaged" : ": wrong key (or the header is damaged)");
        }
        Array<Seg> rev;
        Seg last;
        last.source = si;
        String why;
        u64 end = src.size;
        bool hard = false;
        if (segAt(c, w, end, last, why, &hard)) {
            if (!walkFrom(c, w, si, end, rev, err)) return false;
        } else if (hard) {
            return failAt(err, src.path.view(), end, why.view());
        } else {
            if (!recoverEnd(c, w, si, rev, end, err)) return false;
            src.tail = src.size - end;
            src.size = end;
        }
        for (u32 k = rev.count; k > 0; --k) c.segs.push(move(rev[k - 1]));
    }
    return true;
}

bool chainWalkTail(Chain& c, String& err) {
    Source& src = c.sources[0];
    Window w;
    w.fd = src.fd;
    Seg last;
    String why;
    bool hard = false;
    if (!segAt(c, w, src.size, last, why, &hard)) {
        if (hard) return failAt(err, src.path.view(), src.size, why.view());
        // Not a complete segment at the end: find the last one with a full
        // walk (the rare path, after an interrupted create).
        Array<Seg> rev;
        u64 end = 0;
        if (!recoverEnd(c, w, 0, rev, end, err)) return false;
        src.tail = src.size - end;
        src.size = end;
        for (u32 k = rev.count; k > 0; --k) c.segs.push(move(rev[k - 1]));
        return true;
    }
    // Walk back while the snapshot still needs an ancestor: the last
    // segment's, then its parent's, until a self-contained manifest.
    u64 end = src.size;
    bool wantAny = true;
    u8 want[kSnapshotIdBytes];
    while (end > 0) {
        Seg& s = c.segs.addDefault();
        if (!segAt(c, w, end, s, why)) return failAt(err, src.path.view(), end, why.view());
        end = s.start;
        if (!chainHead(c, c.segs.count - 1, err)) return false;
        const Seg& h = c.segs[c.segs.count - 1];
        if (!wantAny && !memEqual(h.head.id, want, kSnapshotIdBytes)) continue;
        if (!h.head.delta) break;
        memCopy(want, h.head.parent, kSnapshotIdBytes);
        wantAny = false;
    }
    for (u32 i = 0, j = c.segs.count; i + 1 < j; ++i, --j) swap(c.segs[i], c.segs[j - 1]);
    return true;
}

void chainReportTails(const Chain& c) {
    for (const Source& s : c.sources) {
        if (!s.tail) continue;
        fprintf(stderr, "bu: %s: ignoring the last %llu bytes, %s\n", s.path.c_str(), (unsigned long long)s.tail,
                s.writerActive ? "a backup being appended right now"
                               : "an incomplete backup (an interrupted create; the next create removes it)");
    }
    if (c.streamTail)
        fprintf(stderr, "bu: stdin: the stream ends inside a segment; ignoring its last %llu bytes "
                        "(a truncated copy, or an interrupted create)\n", (unsigned long long)c.streamTail);
}

bool chainLoadTables(Chain& c, String& err) {
    for (u32 i = 0; i < c.segs.count; ++i) {
        Seg& s = c.segs[i];
        const Source& src = c.sources[s.source];
        Window w;
        w.fd = src.fd;
        Array<u8> rec, body;
        const u64 off = s.start + s.t.tabOff;
        String why;
        if (!readRecordBytes(w, off, s.t.tabLen, rec, err)) return failAt(err, src.path.view(), off, err.view());
        if (loadU32LE(rec.ptr) != s.t.tabLen) return failAt(err, src.path.view(), off, "record length does not match the trailer (damaged)");
        // The record header's ordinal is the number of chunk records + 1,
        // which only the table says: open the body first (its nonce and
        // type are fixed), parse, then check the header.
        if (!openMetaBody(s.keys, kRecTable, kNonceTable, rec.ptr + kRecPrefix, s.t.tabLen - kRecHeadBytes, body, why)
            || !parseTable(s, body.ptr, body.count, s.start + kHeaderBytes, s.t.manOff - kHeaderBytes, why)
            || !checkHead(s.keys, u64(s.chunks.count) + 1, rec.ptr, kRecTable, kNonceTable, why))
            return failAt(err, src.path.view(), off, why.view());
    }
    chainIndexChunks(c);
    return true;
}

void chainIndexChunks(Chain& c) {
    u32 total = 0;
    for (const Seg& s : c.segs) total += s.chunks.count;
    c.idIndex.init(total);
    c.idWhere.clear();
    c.idWhere.reserve(total);
    for (u32 si = 0; si < c.segs.count; ++si) {
        const Seg& s = c.segs[si];
        for (u32 ci = 0; ci < s.chunks.count; ++ci) {
            u32 a, b;
            if (chainFind(c, s.chunks[ci].id, a, b)) continue;
            c.idIndex.insert(idHash(s.chunks[ci].id), c.idWhere.count);
            c.idWhere.push((u64(si) << 32) | ci);
        }
    }
}

void chainSegName(const Chain& c, u32 i, String& out) {
    const Seg& s = c.segs[i];
    out.assign(c.sources[s.source].path.view());
    bool alone = true;
    for (u32 j = 0; j < c.segs.count; ++j) if (j != i && c.segs[j].source == s.source) alone = false;
    if (alone) return;
    out.append(" at offset "_s);
    out.appendU64(s.start);
}

bool chainHead(Chain& c, u32 i, String& err) {
    Seg& s = c.segs[i];
    if (!s.manifestLoaded) {
        if (c.stream) return errSet(err, "internal: manifest not read from the stream");
        const Source& src = c.sources[s.source];
        Window w;
        w.fd = src.fd;
        Array<u8> rec;
        const u64 off = s.start + s.t.manOff;
        if (!readRecordBytes(w, off, s.t.manLen, rec, err)) return failAt(err, src.path.view(), off, err.view());
        if (loadU32LE(rec.ptr) != s.t.manLen) return failAt(err, src.path.view(), off, "record length does not match the trailer (damaged)");
        // The manifest's record header is checked when the table is loaded
        // (its ordinal is the chunk count); create reads no tables and opens
        // the body alone, whose offset and length the trailer authenticated.
        String why;
        if ((s.tableLoaded && !checkHead(s.keys, s.chunks.count, rec.ptr, kRecManifest, kNonceManifest, why))
            || !openMetaBody(s.keys, kRecManifest, kNonceManifest, rec.ptr + kRecPrefix, s.t.manLen - kRecHeadBytes,
                             s.manifest, why))
            return failAt(err, src.path.view(), off, why.view());
        s.manifestLoaded = true;
    }
    if (!snapshotPeek(s.manifest.ptr, s.manifest.count, s.head)) {
        String n;
        chainSegName(c, i, n);
        return errSet(err, n.view(), ": malformed manifest");
    }
    if (s.head.gen != s.t.gen) {
        String n;
        chainSegName(c, i, n);
        return errSet(err, n.view(), ": the manifest's generation differs from the trailer's (damaged)");
    }
    return true;
}

u32 chainLatest(const Chain& c) {
    u32 best = 0;
    for (u32 i = 1; i < c.segs.count; ++i)
        if (c.segs[i].t.gen >= c.segs[best].t.gen) best = i;
    return best;
}

bool chainResolve(Chain& c, u32 i, String& err) {
    if (!chainHead(c, i, err)) return false;
    Seg& s = c.segs[i];
    if (s.resolved) return true;
    String name;
    chainSegName(c, i, name);
    if (s.resolving) return errSet(err, name.view(), ": snapshot parents form a cycle (damaged chain)");
    const Snapshot* parent = nullptr;
    if (s.head.delta) {
        // The parent is almost always the segment just before; look there
        // first, then further back, then after (segments given out of order).
        u32 pi = kInvalidIndex;
        for (u32 k = 1; k <= c.segs.count && pi == kInvalidIndex; ++k) {
            const u32 j = k <= i ? i - k : k;
            if (j == i || j >= c.segs.count) continue;
            if (!chainHead(c, j, err)) return false;
            if (memEqual(c.segs[j].head.id, s.head.parent, kSnapshotIdBytes)) pi = j;
        }
        if (pi == kInvalidIndex) {
            char hex[2 * kSnapshotIdBytes];
            hexEncode(s.head.parent, 8, hex);
            return errSet(err, name.view(), ": is an increment whose parent snapshot ", StringView(hex, 16),
                          " is in none of the given segments (give the whole chain: the full backup or merged "
                          "file, then every increment since)");
        }
        s.resolving = true;
        const bool ok = chainResolve(c, pi, err);
        c.segs[i].resolving = false;
        if (!ok) return false;
        parent = &c.segs[pi].snap;
    }
    Seg& me = c.segs[i];
    if (!snapshotDecode(me.manifest.ptr, me.manifest.count, parent, me.snap, err)) {
        String e(name.view());
        e.append(": ");
        e.append(err.view());
        err = move(e);
        return false;
    }
    snapshotIndexPaths(me.snap);
    me.resolved = true;
    return true;
}

bool chainCheckpoint(Chain& c, u32 i, u64& deltaBytes, u64& fullBytes, String& err) {
    deltaBytes = 0;
    fullBytes = 0;
    if (!chainResolve(c, i, err)) return false;
    // Follow the parents back to the self-contained manifest, summing deltas.
    u32 cur = i;
    for (u32 guard = 0; guard <= c.segs.count; ++guard) {
        const Seg& s = c.segs[cur];
        if (!s.head.delta) { fullBytes = s.manifest.count; return true; }
        deltaBytes += s.manifest.count;
        u32 next = kInvalidIndex;
        for (u32 j = 0; j < c.segs.count; ++j)
            if (c.segs[j].resolved && memEqual(c.segs[j].head.id, s.head.parent, kSnapshotIdBytes)) next = j;
        if (next == kInvalidIndex) break;
        cur = next;
    }
    return errSet(err, "internal: parent chain not resolved");
}

bool chainFind(const Chain& c, const ChunkId& id, u32& seg, u32& chunk) {
    u32 slot = kInvalidIndex, v;
    while ((v = c.idIndex.next(idHash(id), slot)) != kInvalidIndex) {
        const u64 w = c.idWhere[v];
        const u32 f = u32(w >> 32), ch = u32(w);
        if (idEqual(c.segs[f].chunks[ch].id, id)) { seg = f; chunk = ch; return true; }
    }
    return false;
}

u32 chainCountMissing(const Chain& c, const Snapshot& s) {
    u32 missing = 0, f, ch;
    for (const ChunkId& id : s.refs) if (!chainFind(c, id, f, ch)) ++missing;
    return missing;
}

// ---- spans ----------------------------------------------------------------------

u64 chainSpanBytes(const Seg& s, u32 first, u32 count) {
    const ChunkLoc& last = s.chunks[first + count - 1];
    return last.offset + 4 + u64(last.recLen) - s.chunks[first].offset;
}

void chainPrefetchSpan(const Chain& c, u32 seg, u32 first, u32 count) {
    const Seg& s = c.segs[seg];
    posix_fadvise(c.sources[s.source].fd, off_t(s.chunks[first].offset), off_t(chainSpanBytes(s, first, count)),
                  POSIX_FADV_WILLNEED);
}

bool chainReadSpan(const Chain& c, u32 seg, u32 first, u32 count, Array<u8>& span, String& err) {
    const Seg& s = c.segs[seg];
    const Source& src = c.sources[s.source];
    const u64 off = s.chunks[first].offset;
    const u64 n = chainSpanBytes(s, first, count);
    if (off + n > src.size || n > (u64(1) << 31)) return failAt(err, src.path.view(), off, "record outside the file (truncated or damaged)");
    span.resize(u32(n));
    if (!preadFull(src.fd, span.ptr, usize(n), off, err)) return failAt(err, src.path.view(), off, err.view());
    return true;
}

bool chainOpenChunk(const Chain& c, u32 seg, u32 index, const u8* rec, bool checkHead, Array<u8>& payload, u8* out,
                    String& err) {
    const Seg& s = c.segs[seg];
    const ChunkLoc& loc = s.chunks[index];
    const StringView path = c.sources[s.source].path.view();
    if (loadU32LE(rec) != loc.recLen) return failAt(err, path, loc.offset, "record length does not match the chunk table (damaged)");
    if (checkHead) {
        u8 type = 0;
        u64 nonce = 0;
        u32 bodyLen = 0;
        if (!recPrefixOpen(s.keys, index, rec, type, nonce, bodyLen) || type != kRecChunk || nonce != loc.nonce)
            return failAt(err, path, loc.offset, "record header authentication failed — the file was modified or damaged");
    }
    const u32 bodyLen = loc.recLen - kRecHeadBytes;
    const u8* body = rec + kRecPrefix;
    if (s.keys.plain) {
        ChunkId tagId;
        bodyTagId(body, bodyLen, tagId);
        if (!idEqual(tagId, loc.id)) return failAt(err, path, loc.offset, "chunk record does not match the chunk table (damaged)");
    }
    payload.resize(bodyLen - kTagBytes);
    if (!bodyOpen(s.keys, loc.nonce, kRecChunk, body, bodyLen, payload.ptr))
        return failAt(err, path, loc.offset, "authentication failed for a chunk record — the file was modified or damaged");
    String why;
    if (!chunkDecode(*c.key, payload.ptr, payload.count, loc.rawLen, loc.id, out, why))
        return failAt(err, path, loc.offset, why.view());
    return true;
}

// ---- stream mode ------------------------------------------------------------------

namespace {

// Make n unread bytes available. False at end of input with `err` empty, or
// on a read error. Moving the unread bytes to the front invalidates pointers
// into the buffer, so the caller flushes its batch first (`beforeMove`).
bool streamFill(Chain& c, int fd, u32 n, String& err) {
    StreamIn& in = c.in;
    while (in.tail - in.head < n) {
        if (in.eof) return false;
        if (in.buf.count - in.tail < n - (in.tail - in.head) || in.tail == in.buf.count) {
            // Compact.
            memMove(in.buf.ptr, in.buf.ptr + in.head, in.tail - in.head);
            in.tail -= in.head;
            in.head = 0;
        }
        const ssize_t r = ::read(fd, in.buf.ptr + in.tail, in.buf.count - in.tail);
        if (r < 0) {
            if (errno == EINTR) continue;
            return errSet(err, "reading stdin: ", strerror(errno));
        }
        if (r == 0) { in.eof = true; continue; }
        in.tail += u32(r);
    }
    return true;
}

void streamTake(StreamIn& in, u32 n) {
    in.head += n;
    in.pos += n;
}

struct Batch {
    Array<StreamChunk> recs;
};

bool flushBatch(Chain& c, StreamSink* sink, Batch& b, String& err) {
    if (b.recs.count && sink && sink->fn && !sink->fn(sink->ctx, c, b.recs.ptr, b.recs.count, err)) return false;
    b.recs.clear();
    return true;
}

// Like streamFill, but flushes the batch before the buffer has to move.
bool need(Chain& c, StreamSink* sink, Batch& b, u32 n, bool& eof, String& err) {
    eof = false;
    StreamIn& in = c.in;
    if (in.tail - in.head >= n) return true;
    if (in.buf.count - in.head < n || in.tail == in.buf.count) {
        if (!flushBatch(c, sink, b, err)) return false;
    }
    if (streamFill(c, c.sources[0].fd, n, err)) return true;
    if (!err.empty()) return false;
    eof = true;
    return true;
}

// Read `n` bytes of a metadata body that may be larger than the buffer.
bool streamReadInto(Chain& c, StreamSink* sink, Batch& b, u32 n, Array<u8>& out, bool& eof, String& err) {
    eof = false;
    out.resize(n);
    StreamIn& in = c.in;
    const u32 have = min<u32>(n, in.tail - in.head);
    memCopy(out.ptr, in.buf.ptr + in.head, have);
    streamTake(in, have);
    if (have == n) return true;
    if (!flushBatch(c, sink, b, err)) return false;
    in.head = in.tail = 0;
    const i64 r = readFull(c.sources[0].fd, out.ptr + have, n - have);
    if (r < 0) return errSet(err, "reading stdin: ", strerror(errno));
    in.pos += u64(r);
    if (u32(r) < n - have) { in.eof = true; eof = true; }
    return true;
}

bool streamFail(String& err, u64 pos, StringView what) { return failAt(err, "stdin"_s, pos, what); }

} // namespace

bool chainStream(Chain& c, StreamSink* sink, String& err) {
    StreamIn& in = c.in;
    Batch b;
    b.recs.reserve(4096);
    bool eof = false;
    for (;;) {
        const u64 segStart = in.pos;
        if (!need(c, sink, b, kHeaderBytes, eof, err)) return false;
        if (eof) {
            if (in.tail - in.head == 0) break;           // a clean end, between segments
            c.streamTail = in.tail - in.head;
            break;
        }
        Seg& s = c.segs.addDefault();
        const u32 si = c.segs.count - 1;
        s.start = segStart;
        memCopy(s.header, in.buf.ptr + in.head, kHeaderBytes);
        String why;
        u16 kind = 0;
        bool plain = false;
        if (!headerParse(s.header, kind, plain, why)) return streamFail(err, segStart, why.view());
        if (kind != kKindSegment)
            return streamFail(err, segStart, "an index file, not a chain (index files go to restore --index)");
        if (plain != c.plain) return streamFail(err, segStart, "a chain mixes encrypted and unencrypted segments");
        segKeysDerive(*c.key, s.header + 16, s.keys);
        if (!headerVerify(s.keys, s.header))
            return streamFail(err, segStart, plain ? "header damaged" : "wrong key (or the header is damaged)");
        streamTake(in, kHeaderBytes);

        u64 ordinal = 0;
        bool sawManifest = false, sawTable = false, incomplete = false;
        u64 manOff = 0, tabOff = 0;
        u32 manLen = 0, tabLen = 0;
        Array<ChunkLoc> seen;
        while (!sawTable) {
            const u64 recPos = in.pos;
            if (!need(c, sink, b, kRecPrefix, eof, err)) return false;
            if (eof) { incomplete = true; break; }
            const u8* pre = in.buf.ptr + in.head;
            u8 type = 0;
            u64 nonce = 0;
            u32 bodyLen = 0;
            if (!recPrefixOpen(s.keys, ordinal, pre, type, nonce, bodyLen))
                return streamFail(err, recPos, "record header authentication failed — the stream was modified or damaged");
            const u32 len = kRecHeadBytes + bodyLen;
            if (type == kRecChunk) {
                if (sawManifest || len > kMaxChunkRecord || nonce >= kNonceMetaBase
                    || (seen.count && nonce <= seen[seen.count - 1].nonce))
                    return streamFail(err, recPos, "chunk record out of place (damaged)");
                if (!need(c, sink, b, 4 + len, eof, err)) return false;
                if (eof) { incomplete = true; break; }
                StreamChunk& r = b.recs.addDefault();
                r.seg = si;
                r.index = seen.count;
                r.nonce = nonce;
                r.body = in.buf.ptr + in.head + kRecPrefix;
                r.bodyLen = bodyLen;
                ChunkLoc& l = seen.addDefault();
                l.offset = recPos - segStart;
                l.nonce = nonce;
                l.recLen = len;
                streamTake(in, 4 + len);
            } else if ((type == kRecManifest && !sawManifest && nonce == kNonceManifest)
                       || (type == kRecTable && sawManifest && nonce == kNonceTable)) {
                if (len > kMaxMetaRecord) return streamFail(err, recPos, "metadata record too large (damaged)");
                Array<u8> rec;
                rec.resize(kRecPrefix);
                memCopy(rec.ptr, pre, kRecPrefix);
                streamTake(in, kRecPrefix);
                Array<u8> body;
                if (!streamReadInto(c, sink, b, bodyLen, body, eof, err)) return false;
                if (eof) { incomplete = true; break; }
                Array<u8> decoded;
                if (!openMetaBody(s.keys, type, nonce, body.ptr, bodyLen, decoded, why))
                    return streamFail(err, recPos, why.view());
                if (type == kRecManifest) {
                    sawManifest = true;
                    manOff = recPos - segStart;
                    manLen = len;
                    s.manifest = move(decoded);
                    s.manifestLoaded = true;
                } else {
                    sawTable = true;
                    tabOff = recPos - segStart;
                    tabLen = len;
                    if (!parseTable(s, decoded.ptr, decoded.count, kHeaderBytes, manOff - kHeaderBytes, why))
                        return streamFail(err, recPos, why.view());
                }
            } else {
                return streamFail(err, recPos, "record out of place (damaged)");
            }
            ++ordinal;
        }
        if (!incomplete) {
            if (!need(c, sink, b, kTrailerBytes, eof, err)) return false;
            if (eof) incomplete = true;
        }
        if (incomplete) {
            // Drop the partial segment; its chunks may already have gone to
            // the sink, which is harmless (each was authenticated).
            if (!flushBatch(c, sink, b, err)) return false;
            c.streamTail = in.pos + (in.tail - in.head) - segStart;
            c.segs.pop();
            break;
        }
        const u8* tr = in.buf.ptr + in.head;
        if (!trailerParse(tr, s.t, why)) return streamFail(err, in.pos, why.view());
        if (!trailerVerify(s.keys, s.header, tr))
            return streamFail(err, in.pos, "segment trailer authentication failed (damaged)");
        if (s.t.segLen != in.pos + kTrailerBytes - segStart || s.t.manOff != manOff || s.t.manLen != manLen
            || s.t.tabOff != tabOff || s.t.tabLen != tabLen)
            return streamFail(err, in.pos, "segment trailer does not match the records before it (damaged)");
        // The table must describe exactly the records that came by.
        if (s.chunks.count != seen.count) return streamFail(err, segStart + tabOff, "chunk table does not match the records (damaged)");
        for (u32 k = 0; k < seen.count; ++k) {
            ChunkLoc& l = s.chunks[k];
            if (l.recLen != seen[k].recLen || l.nonce != seen[k].nonce || l.offset != seen[k].offset)
                return streamFail(err, segStart + tabOff, "chunk table does not match the records (damaged)");
        }
        streamTake(in, kTrailerBytes);
        if (!chainHead(c, si, err)) return false;
    }
    if (!flushBatch(c, sink, b, err)) return false;
    chainIndexChunks(c);
    return true;
}

// ---- index files --------------------------------------------------------------------

bool fileHeaderPeek(const char* path, u16& kind, bool& plain, String& err) {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errSet(err, path, ": ", strerror(errno));
    u8 h[kHeaderBytes];
    const i64 n = readFull(fd, h, kHeaderBytes);
    ::close(fd);
    if (n != i64(kHeaderBytes)) return errSet(err, path, ": too short to be a bu file");
    String why;
    if (!headerParse(h, kind, plain, why)) return errSet(err, path, ": ", why.view());
    return true;
}

bool indexFileWrite(const MasterKey& k, const char* path, const IndexData& d, String& err) {
    ByteWriter body;
    indexEncode(d, body);
    // Built whole in memory, then replaced atomically (writeFileAtomic): an
    // index is small next to the data it describes, and a torn one must never
    // be visible under the real name.
    OutStream out;
    out.toMemory = true;
    out.buf.reserve(body.buf.count + 1024);
    SegWriter w;
    if (!writerBegin(w, out, k, kKindIndex, err)) return false;
    if (!writerFinish(w, body.buf.ptr, body.buf.count, d.snap.gen, err)) return false;
    return writeFileAtomic(path, out.buf.ptr, out.buf.count, err);
}

bool indexFileRead(const MasterKey& k, const char* path, IndexData& d, String& err) {
    Array<u8> file;
    if (!readWholeFile(path, u64(kMaxMetaRecord) + 4096, file, err)) return false;
    if (file.count < kHeaderBytes + kTrailerBytes) return errSet(err, path, ": too short to be a bu file");
    String why;
    u16 kind = 0;
    bool plain = false;
    if (!headerParse(file.ptr, kind, plain, why)) return errSet(err, path, ": ", why.view());
    if (kind != kKindIndex) return errSet(err, path, ": is a chain, not an index file (give an index made by create --index-out or bu index)");
    if (plain != k.plain)
        return errSet(err, path, plain ? ": is an unencrypted index; the chain is encrypted"
                                       : ": is an encrypted index; the chain is unencrypted");
    SegKeys keys;
    segKeysDerive(k, file.ptr + 16, keys);
    if (!headerVerify(keys, file.ptr)) return errSet(err, path, plain ? ": header damaged" : ": wrong key (or the header is damaged)");
    Trailer t;
    const u8* tr = file.ptr + file.count - kTrailerBytes;
    if (!trailerParse(tr, t, why)) return errSet(err, path, ": ", why.view(), " (truncated?)");
    if (t.segLen != file.count || t.tabLen != 0 || t.manOff != kHeaderBytes)
        return errSet(err, path, ": not a valid index file layout (damaged)");
    if (!trailerVerify(keys, file.ptr, tr)) return errSet(err, path, ": trailer authentication failed (damaged)");
    if (loadU32LE(file.ptr + t.manOff) != t.manLen) return errSet(err, path, ": record length does not match (damaged)");
    Array<u8> body;
    if (!checkHead(keys, 0, file.ptr + t.manOff, kRecIndex, kNonceIndex, why)
        || !openMetaBody(keys, kRecIndex, kNonceIndex, file.ptr + t.manOff + kRecPrefix, t.manLen - kRecHeadBytes, body, why))
        return errSet(err, path, ": ", why.view());
    if (!indexDecode(body.ptr, body.count, d, err)) return errSet(err, path, ": ", err.view());
    if (d.snap.gen != t.gen) return errSet(err, path, ": generation does not match the trailer (damaged)");
    return true;
}

} // namespace bk
