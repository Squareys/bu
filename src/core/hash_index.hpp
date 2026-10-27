// hash_index.hpp — open-addressing multimap from a 64-bit hash to a u32 value.
//
// The one hash table in bu, used for "chunk ID -> where it is" and "path ->
// entry". It stores only the hash and an index; the caller keeps the real keys
// in its own data-oriented array and confirms a candidate by comparing them.
// That keeps the table at 12 bytes a slot and type-free (no templates over key
// types, no hash/equality functors), and it is exactly as correct as a full
// map: `find` walks every slot whose stored hash matches, so two keys that
// collide on 64 bits are both reachable.
//
// Linear probing, power-of-two capacity, max load 1/2, no deletion (nothing in
// bu ever removes a key; a command builds its tables and exits).
#pragma once

#include "array.hpp"
#include "string_view.hpp"

namespace bk {

struct HashIndex {
    Array<u64> hashes;
    Array<u32> values;   // kInvalidIndex marks an empty slot
    u32 used = 0;

    void init(u32 expected) {
        u32 cap = 16;
        while (cap < expected * 2 + 2) cap <<= 1;
        hashes.resize(cap);
        values.resize(cap);
        for (u32 i = 0; i < cap; ++i) values[i] = kInvalidIndex;
        used = 0;
    }

    void insert(u64 h, u32 value) {
        if (hashes.count == 0 || (used + 1) * 2 > hashes.count) grow();
        const u32 mask = hashes.count - 1;
        u32 i = u32(h) & mask;
        while (values[i] != kInvalidIndex) i = (i + 1) & mask;
        hashes[i] = h; values[i] = value; ++used;
    }

    // Iterate candidates: `u32 slot = kInvalidIndex; while ((v = next(h, slot)) != kInvalidIndex)`.
    // Returns the value of the next slot after `slot` whose hash equals h.
    u32 next(u64 h, u32& slot) const {
        if (hashes.count == 0) return kInvalidIndex;
        const u32 mask = hashes.count - 1;
        u32 i = slot == kInvalidIndex ? (u32(h) & mask) : ((slot + 1) & mask);
        while (values[i] != kInvalidIndex) {
            if (hashes[i] == h) { slot = i; return values[i]; }
            i = (i + 1) & mask;
        }
        return kInvalidIndex;
    }

    void grow() {
        Array<u64> oh = move(hashes);
        Array<u32> ov = move(values);
        init(oh.count ? oh.count : 8);
        for (u32 i = 0; i < oh.count; ++i)
            if (ov[i] != kInvalidIndex) insert(oh[i], ov[i]);
    }
};

// FNV-1a: the path hash (paths are not random, IDs are — see idHash).
inline u64 fnv1a(StringView s) {
    u64 h = 1469598103934665603ull;
    for (u32 i = 0; i < s.count; ++i) { h ^= u8(s.ptr[i]); h *= 1099511628211ull; }
    return h;
}

} // namespace bk
