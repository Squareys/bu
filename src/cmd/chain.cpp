// chain.cpp — see chain.hpp.

#include "cmd/chain.hpp"

namespace bk {

bool chainOpen(const MasterKey& k, const Array<const char*>& paths, Chain& c, String& err) {
    c.files.reserve(paths.count);
    c.snaps.reserve(paths.count);
    u32 totalChunks = 0;
    for (const char* p : paths) {
        Container& f = c.files.addDefault();
        if (!containerOpen(k, p, f, err)) return false;
        if (f.kind != kKindBackup)
            return errSet(err, p, ": is an index file, not a backup (index files go to create --base)");
        ChainSnap& s = c.snaps.addDefault();
        if (!containerReadMeta(f, f.manifestOffset, f.manifestLen, kRecManifest, kNonceManifest, s.manifest, err))
            return false;
        if (!snapshotPeek(s.manifest.ptr, s.manifest.count, s.head)) return errSet(err, p, ": malformed manifest");
        totalChunks += f.chunks.count;
    }
    c.idIndex.init(totalChunks);
    c.idWhere.reserve(totalChunks);
    for (u32 fi = 0; fi < c.files.count; ++fi) {
        const Container& f = c.files[fi];
        for (u32 ci = 0; ci < f.chunks.count; ++ci) {
            u32 a, b;
            if (chainFind(c, f.chunks[ci].id, a, b)) continue;
            c.idIndex.insert(idHash(f.chunks[ci].id), c.idWhere.count);
            c.idWhere.push((u64(fi) << 32) | ci);
        }
    }
    return true;
}

u32 chainLatest(const Chain& c) {
    u32 best = 0;
    for (u32 i = 1; i < c.snaps.count; ++i)
        if (c.snaps[i].head.gen >= c.snaps[best].head.gen) best = i;
    return best;
}

bool chainResolve(Chain& c, u32 i, String& err) {
    ChainSnap& s = c.snaps[i];
    if (s.resolved) return true;
    if (s.resolving) return errSet(err, c.files[i].path.view(), ": snapshot parents form a cycle (damaged chain)");
    const Snapshot* parent = nullptr;
    if (s.head.hasParent) {
        u32 pi = kInvalidIndex;
        for (u32 j = 0; j < c.snaps.count; ++j)
            if (j != i && memEqual(c.snaps[j].head.id, s.head.parent, kSnapshotIdBytes)) pi = j;
        if (pi == kInvalidIndex) {
            char hex[2 * kSnapshotIdBytes];
            hexEncode(s.head.parent, 8, hex);
            return errSet(err, c.files[i].path.view(), ": is an increment whose parent snapshot ",
                          StringView(hex, 16), " is in none of the given files (give the whole chain: "
                          "the full backup or merged file, then every increment in between)");
        }
        s.resolving = true;
        const bool ok = chainResolve(c, pi, err);
        s.resolving = false;
        if (!ok) return false;
        parent = &c.snaps[pi].snap;
    }
    if (!snapshotDecode(s.manifest.ptr, s.manifest.count, parent, s.snap, err)) {
        String e(c.files[i].path.view());
        e.append(": ");
        e.append(err.view());
        err = move(e);
        return false;
    }
    snapshotIndexPaths(s.snap);
    s.resolved = true;
    return true;
}

bool chainFind(const Chain& c, const ChunkId& id, u32& file, u32& chunk) {
    u32 slot = kInvalidIndex, v;
    while ((v = c.idIndex.next(idHash(id), slot)) != kInvalidIndex) {
        const u64 w = c.idWhere[v];
        const u32 f = u32(w >> 32), ch = u32(w);
        if (idEqual(c.files[f].chunks[ch].id, id)) { file = f; chunk = ch; return true; }
    }
    return false;
}

u32 chainCountMissing(const Chain& c, const Snapshot& s) {
    u32 missing = 0, f, ch;
    for (const ChunkId& id : s.refs) if (!chainFind(c, id, f, ch)) ++missing;
    return missing;
}

} // namespace bk
