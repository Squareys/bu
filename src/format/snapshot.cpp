// snapshot.cpp — manifest and index encoding; see snapshot.hpp.
//
// Wire format of a manifest (docs/format.md §Manifest has the same in prose):
//
//   varint version (1) | id[16] | u8 flags (bit 0: delta) | [parent[16]]
//   | varint gen | svarint createdNs | varint entryCount | varint refCount
//   then per entry:
//     varint sharedPrefix | varint suffixLen | suffix     path, prefix-coded
//     u8 type | varint mode | varint uid | varint gid
//     svarint mtimeNs | svarint ctimeNs | varint dev | varint ino
//     file:    varint size | u8 base | varint opCount | ops
//     symlink: varint targetLen | target
//   op: varint (n << 2 | kind); kind 0 COPY n, 1 SEEK zigzag(n), 2 NEW n + n ids
//
// `base` is 1 when the ops run against the parent snapshot's chunk list for
// the same path; 0 means there is no list to copy from and every op is NEW.

#include "format/snapshot.hpp"

namespace bk {

namespace {

constexpr u32 kMaxPath = 4096;
constexpr u8 kOpCopy = 0, kOpSeek = 1, kOpNew = 2;

void putOp(ByteWriter& w, u8 kind, u64 n) { w.varint((n << 2) | kind); }

// Encode `cur` as ops over `old`. Greedy and linear: at each position copy
// while the lists agree; on disagreement, if the new ID occurs somewhere in
// the old list jump there (SEEK) and resume copying, else emit a run of NEW.
// That captures in-place page rewrites (SQLite), insertions and deletions
// (CDC re-synchronising) and moved blocks, which is every pattern that occurs
// between two versions of one file, in O(n) with one hash table per file.
void encodeOps(Span<const ChunkId> cur, Span<const ChunkId> old, ByteWriter& w) {
    // Position lookup only pays off on longer lists; a short one is scanned.
    HashIndex pos;
    const bool useMap = old.count > 16;
    if (useMap) {
        pos.init(old.count);
        // Insert back to front so a lookup's FIRST candidate is the earliest
        // occurrence of a repeated ID (all-zero SQLite pages repeat a lot).
        for (u32 j = old.count; j > 0; --j) pos.insert(idHash(old[j - 1]), j - 1);
    }
    auto findOld = [&](const ChunkId& id) -> u32 {
        if (!useMap) {
            for (u32 j = 0; j < old.count; ++j) if (idEqual(old[j], id)) return j;
            return kInvalidIndex;
        }
        u32 slot = kInvalidIndex, v;
        u32 best = kInvalidIndex;
        while ((v = pos.next(idHash(id), slot)) != kInvalidIndex)
            if (idEqual(old[v], id) && v < best) best = v;
        return best;
    };

    // Ops are counted first into a scratch writer so the count can lead.
    ByteWriter ops;
    u32 opCount = 0;
    u32 i = 0, j = 0;
    while (i < cur.count) {
        if (j < old.count && idEqual(cur[i], old[j])) {
            u32 n = 0;
            while (i < cur.count && j < old.count && idEqual(cur[i], old[j])) { ++i; ++j; ++n; }
            putOp(ops, kOpCopy, n); ++opCount;
            continue;
        }
        const u32 p = findOld(cur[i]);
        if (p != kInvalidIndex) {
            putOp(ops, kOpSeek, zigzagEncode(i64(p) - i64(j))); ++opCount;
            j = p;
            continue;
        }
        const u32 start = i;
        while (i < cur.count && !(j < old.count && idEqual(cur[i], old[j])) && findOld(cur[i]) == kInvalidIndex) ++i;
        putOp(ops, kOpNew, i - start); ++opCount;
        for (u32 k = start; k < i; ++k) ops.bytes(cur[k].b, kIdBytes);
    }
    w.varint(opCount);
    w.bytes(ops.buf.ptr, ops.buf.count);
}

} // namespace

u32 snapshotAddName(Snapshot& s, StringView name) {
    const u32 off = s.names.count;
    s.names.append(name);
    return off;
}

void snapshotIndexPaths(Snapshot& s) {
    s.pathIndex.init(s.entries.count);
    for (u32 i = 0; i < s.entries.count; ++i) s.pathIndex.insert(fnv1a(entryPath(s, s.entries[i])), i);
}

u32 snapshotFind(const Snapshot& s, StringView path) {
    u32 slot = kInvalidIndex, v;
    const u64 h = fnv1a(path);
    while ((v = s.pathIndex.next(h, slot)) != kInvalidIndex)
        if (entryPath(s, s.entries[v]) == path) return v;
    return kInvalidIndex;
}

bool pathIsSafe(StringView p) {
    if (p.empty() || p.count > kMaxPath || p[0] == '/') return false;
    u32 start = 0;
    for (u32 i = 0; i <= p.count; ++i) {
        if (i == p.count || p[i] == '/') {
            const StringView c = p.sub(start, i - start);
            if (c.empty() || c == "."_s || c == ".."_s) return false;
            start = i + 1;
        } else if (p[i] == 0) {
            return false;
        }
    }
    return true;
}

void snapshotEncode(const Snapshot& s, const Snapshot* parent, ByteWriter& w) {
    w.buf.reserve(s.entries.count * 48 + s.names.count + 64);
    w.varint(1);
    w.bytes(s.id, kSnapshotIdBytes);
    w.byte(parent ? 1 : 0);
    if (parent) w.bytes(parent->id, kSnapshotIdBytes);
    w.varint(s.gen);
    w.svarint(s.createdNs);
    w.varint(s.entries.count);
    w.varint(s.refs.count);
    StringView prev;
    for (const Entry& e : s.entries) {
        const StringView path = entryPath(s, e);
        u32 shared = 0;
        while (shared < prev.count && shared < path.count && prev[shared] == path[shared]) ++shared;
        w.varint(shared);
        w.str(path.from(shared));
        prev = path;
        w.byte(e.type);
        w.varint(e.mode);
        w.varint(e.uid);
        w.varint(e.gid);
        w.svarint(e.mtimeNs);
        w.svarint(e.ctimeNs);
        w.varint(e.dev);
        w.varint(e.ino);
        if (e.type == kEntryFile) {
            w.varint(e.size);
            const Span<const ChunkId> cur(s.refs.ptr + e.firstRef, e.refCount);
            u32 pi = kInvalidIndex;
            if (parent) {
                pi = snapshotFind(*parent, path);
                if (pi != kInvalidIndex && parent->entries[pi].type != kEntryFile) pi = kInvalidIndex;
            }
            if (pi != kInvalidIndex) {
                const Entry& pe = parent->entries[pi];
                w.byte(1);
                encodeOps(cur, Span<const ChunkId>(parent->refs.ptr + pe.firstRef, pe.refCount), w);
            } else {
                w.byte(0);
                encodeOps(cur, Span<const ChunkId>(), w);
            }
        } else if (e.type == kEntrySymlink) {
            w.str(entryTarget(s, e));
        }
    }
}

namespace {

bool decodeHeader(ByteReader& r, Snapshot& out) {
    if (r.varint() != 1) return false;
    r.bytes(out.id, kSnapshotIdBytes);
    const u8 flags = r.byte();
    if (flags > 1) return false;
    out.hasParent = flags & 1;
    if (out.hasParent) r.bytes(out.parent, kSnapshotIdBytes);
    else memSet(out.parent, 0, kSnapshotIdBytes);
    out.gen = r.varint();
    out.createdNs = r.svarint();
    return !r.failed;
}

} // namespace

bool snapshotPeek(const u8* p, usize n, Snapshot& out) {
    ByteReader r(p, n);
    return decodeHeader(r, out);
}

bool snapshotDecode(const u8* p, usize n, const Snapshot* parent, Snapshot& out, String& err) {
    ByteReader r(p, n);
    if (!decodeHeader(r, out)) return errSet(err, "malformed manifest header");
    if (out.hasParent && (!parent || !memEqual(parent->id, out.parent, kSnapshotIdBytes)))
        return errSet(err, "delta manifest decoded without its parent snapshot");
    // Every entry takes at least 12 bytes, so the count is bounded by the
    // input. Refs are not (a COPY spells many from two bytes), so they get an
    // absolute cap — 2^28 refs is ~4 TB at the average chunk size — and the
    // reservation is clamped to what the bytes could plausibly hold.
    const u64 count = r.varintMax(n / 12);
    const u64 refTotal = r.varintMax(u64(1) << 28);
    if (r.failed) return errSet(err, "malformed manifest header");
    out.entries.reserve(u32(count));
    out.refs.reserve(u32(min<u64>(refTotal, n + (parent ? parent->refs.count : 0))));
    out.names.reserve(u32(n));
    String prev;
    for (u64 k = 0; k < count; ++k) {
        Entry e;
        const u64 shared = r.varintMax(prev.count);
        const StringView suffix = r.str(kMaxPath);
        if (r.failed || shared + suffix.count > kMaxPath) return errSet(err, "malformed manifest entry");
        prev.truncate(u32(shared));
        prev.append(suffix);
        if (!pathIsSafe(prev.view())) return errSet(err, "manifest contains an unsafe path");
        e.pathLen = prev.count;
        e.pathOff = snapshotAddName(out, prev.view());
        e.type = r.byte();
        e.mode = u32(r.varintMax(07777));
        e.uid = u32(r.varintMax(0xFFFFFFFFu));
        e.gid = u32(r.varintMax(0xFFFFFFFFu));
        e.mtimeNs = r.svarint();
        e.ctimeNs = r.svarint();
        e.dev = r.varint();
        e.ino = r.varint();
        if (e.type == kEntryFile) {
            e.size = r.varint();
            const u8 base = r.byte();
            const Entry* pe = nullptr;
            if (base == 1) {
                const u32 pi = parent ? snapshotFind(*parent, prev.view()) : kInvalidIndex;
                if (pi == kInvalidIndex || parent->entries[pi].type != kEntryFile)
                    return errSet(err, "delta manifest refers to a file its parent does not have");
                pe = &parent->entries[pi];
            } else if (base != 0) {
                return errSet(err, "malformed manifest entry");
            }
            const ChunkId* old = pe ? parent->refs.ptr + pe->firstRef : nullptr;
            const u32 oldCount = pe ? pe->refCount : 0;
            const u64 ops = r.varintMax(r.remaining());
            e.firstRef = out.refs.count;
            u64 j = 0;
            for (u64 o = 0; o < ops && !r.failed; ++o) {
                const u64 v = r.varint();
                const u8 kind = u8(v & 3);
                const u64 m = v >> 2;
                if (kind == kOpCopy) {
                    if (j + m > oldCount || out.refs.count + m > refTotal) return errSet(err, "manifest COPY out of range");
                    out.refs.appendRange(old + j, u32(m));
                    j += m;
                } else if (kind == kOpSeek) {
                    const i64 nj = i64(j) + zigzagDecode(m);
                    if (nj < 0 || u64(nj) > oldCount) return errSet(err, "manifest SEEK out of range");
                    j = u64(nj);
                } else if (kind == kOpNew) {
                    if (m > r.remaining() / kIdBytes || out.refs.count + m > refTotal) return errSet(err, "manifest NEW out of range");
                    for (u64 q = 0; q < m; ++q) r.bytes(out.refs.addDefault().b, kIdBytes);
                } else {
                    return errSet(err, "malformed manifest op");
                }
            }
            e.refCount = out.refs.count - e.firstRef;
        } else if (e.type == kEntrySymlink) {
            const StringView t = r.str(kMaxPath);
            e.targetLen = t.count;
            e.targetOff = snapshotAddName(out, t);
        } else if (e.type != kEntryDir) {
            return errSet(err, "unknown manifest entry type");
        }
        if (r.failed) return errSet(err, "truncated manifest");
        out.entries.push(e);
    }
    if (!r.done()) return errSet(err, "trailing bytes after the manifest");
    if (out.refs.count != refTotal) return errSet(err, "manifest chunk count mismatch");
    return true;
}

// ---- index ----------------------------------------------------------------

void indexCollectDistinct(IndexData& d) {
    HashIndex seen;
    seen.init(d.snap.refs.count);
    d.distinct.clear();
    for (const ChunkId& id : d.snap.refs) {
        u32 slot = kInvalidIndex, v;
        bool dup = false;
        while ((v = seen.next(idHash(id), slot)) != kInvalidIndex)
            if (idEqual(d.distinct[v], id)) { dup = true; break; }
        if (dup) continue;
        seen.insert(idHash(id), d.distinct.count);
        d.distinct.push(id);
    }
}

void indexEncode(const IndexData& d, ByteWriter& w) {
    ByteWriter snap;
    snapshotEncode(d.snap, nullptr, snap);
    w.varint(1);
    w.varint(snap.buf.count);
    w.bytes(snap.buf.ptr, snap.buf.count);
    w.varint(d.backups.count);
    for (const ChunkId& b : d.backups) w.bytes(b.b, kIdBytes);
    w.varint(d.location.count);
    for (u32 l : d.location) w.varint(l);
}

bool indexDecode(const u8* p, usize n, IndexData& d, String& err) {
    ByteReader r(p, n);
    if (r.varint() != 1) return errSet(err, "unsupported index version");
    const u64 snapLen = r.varintMax(r.remaining());
    const u8* snap = r.take(snapLen);
    if (!snap || !snapshotDecode(snap, snapLen, nullptr, d.snap, err)) {
        if (err.empty()) errSet(err, "malformed index");
        return false;
    }
    const u64 nb = r.varintMax(r.remaining() / kIdBytes);
    d.backups.resize(u32(nb));
    for (u32 i = 0; i < nb; ++i) r.bytes(d.backups[i].b, kIdBytes);
    const u64 nl = r.varintMax(r.remaining());
    d.location.resize(u32(nl));
    for (u32 i = 0; i < nl; ++i) d.location[i] = u32(r.varintMax(nb ? nb - 1 : 0));
    if (r.failed || !r.done()) return errSet(err, "malformed index");
    indexCollectDistinct(d);
    if (d.location.count != d.distinct.count) return errSet(err, "index location table does not match its snapshot");
    return true;
}

} // namespace bk
