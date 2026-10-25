// memory.cpp — the heap Allocator behind every Array and String.
#include "memory.hpp"

#include <stdlib.h> // malloc/free/realloc — C library, not STL containers.

namespace bk {

// Aligned allocation with one code path: over-allocate, then store the
// original base pointer in the word immediately preceding the aligned block so
// free() can recover it.
static void* heapAlloc(void*, usize size, usize align) {
    if (align < sizeof(void*)) align = sizeof(void*);
    const usize total = size + align + sizeof(void*);
    void* base = ::malloc(total);
    if (!base) return nullptr;
    const uptr raw = reinterpret_cast<uptr>(base) + sizeof(void*);
    const uptr aligned = (raw + (align - 1)) & ~static_cast<uptr>(align - 1);
    reinterpret_cast<void**>(aligned)[-1] = base;
    return reinterpret_cast<void*>(aligned);
}

static void heapFree(void*, void* ptr) {
    if (!ptr) return;
    ::free(reinterpret_cast<void**>(ptr)[-1]);
}

// In-place grow via libc realloc. Blocks are over-allocated with the malloc
// base stashed before the aligned pointer, so we realloc the BASE then
// re-establish alignment; if the new base lands at a different alignment
// offset we memmove the payload to the new aligned slot (rare).
static void* heapRealloc(void*, void* ptr, usize newSize, usize align) {
    if (!ptr) return heapAlloc(nullptr, newSize, align);
    if (align < sizeof(void*)) align = sizeof(void*);
    void* oldBase = reinterpret_cast<void**>(ptr)[-1];
    const usize oldOff = reinterpret_cast<uptr>(ptr) - reinterpret_cast<uptr>(oldBase);
    const usize total = newSize + align + sizeof(void*);
    void* base = ::realloc(oldBase, total);
    if (!base) return nullptr;
    const uptr raw = reinterpret_cast<uptr>(base) + sizeof(void*);
    const uptr aligned = (raw + (align - 1)) & ~static_cast<uptr>(align - 1);
    const usize newOff = aligned - reinterpret_cast<uptr>(base);
    if (newOff != oldOff)
        __builtin_memmove(reinterpret_cast<void*>(aligned),
                          reinterpret_cast<u8*>(base) + oldOff, newSize);
    reinterpret_cast<void**>(aligned)[-1] = base;
    return reinterpret_cast<void*>(aligned);
}

Allocator& defaultAllocator() {
    static Allocator a{heapAlloc, heapFree, heapRealloc, nullptr};
    return a;
}

} // namespace bk
