// memory.hpp — allocation primitives.
//
// We deliberately avoid the STL allocator model (too much template machinery,
// bad for compile times). An Allocator is a tiny vtable-free struct of three
// function pointers + an opaque context. Containers store an Allocator by
// value, so they can live on the global heap, in an arena, or in a scratch
// buffer with no type changes.
//
// No <new> needed by callers: construct/destruct helpers below wrap placement
// new behind a function so headers that only *use* containers never include it.
#pragma once

#include "types.hpp"

namespace bk {

// Raw, untyped memory ops. Backed by malloc/free in memory.cpp. Alignment is
// honoured (over-allocates + stores the base pointer just before the block).
struct Allocator {
    void* (*allocFn)(void* ctx, usize size, usize align) = nullptr;
    void  (*freeFn)(void* ctx, void* ptr) = nullptr;
    // In-place grow. May return a moved block (it copies for you) or the same
    // pointer. NULL means "this allocator can't realloc" (e.g. a bump arena) —
    // callers must fall back to alloc-new + copy + free. May itself return null
    // on OOM. Kept as a third fn pointer so the struct stays POD/vtable-free.
    void* (*reallocFn)(void* ctx, void* ptr, usize newSize, usize align) = nullptr;
    void* ctx = nullptr;

    void* alloc(usize size, usize align = 16) const { return allocFn(ctx, size, align); }
    void  free(void* ptr) const { if (ptr) freeFn(ctx, ptr); }
    void* realloc(void* p, usize newSize, usize align = 16) const {
        return reallocFn ? reallocFn(ctx, p, newSize, align) : nullptr;
    }
};

// The process-wide heap allocator (malloc/free). Always valid.
Allocator& defaultAllocator();

// Low-level byte helpers (compiler builtins — no <cstring>).
inline void memCopy(void* dst, const void* src, usize n) { __builtin_memcpy(dst, src, n); }
inline void memMove(void* dst, const void* src, usize n) { __builtin_memmove(dst, src, n); }
inline void memSet(void* dst, int v, usize n)            { __builtin_memset(dst, v, n); }
inline bool memEqual(const void* a, const void* b, usize n) { return __builtin_memcmp(a, b, n) == 0; }

} // namespace bk

// Placement new/delete are normally declared by <new>, but we use only the two
// non-allocating placement forms, so we DECLARE them ourselves — header-free.
// Must be at global scope. clang/gcc recognise this exact reserved signature and
// never emit an actual call for `new (p) T`, so no definition is needed to link.
// The guards defer to the real <new> in any TU that happens to include it
// (_NEW is libstdc++'s guard, _LIBCPP_NEW is libc++'s).
#if !defined(_NEW) && !defined(_LIBCPP_NEW)
void* operator new(bk::usize, void* p) noexcept;
void  operator delete(void*, void*) noexcept;
#endif

namespace bk {

template <typename T, typename... Args>
inline T* construct(T* p, Args&&... args) {
    return new (p) T(forward<Args>(args)...);
}

template <typename T>
inline void destruct(T* p) {
    p->~T();
}

template <typename T>
inline void destructRange(T* p, u32 count) {
    for (u32 i = 0; i < count; ++i) p[i].~T();
}

// True when T can be relocated with a raw memcpy (no move ctor side effects).
// Lets Array growth be a single memcpy instead of a per-element move loop.
template <typename T>
inline constexpr bool kTriviallyRelocatable = __is_trivially_copyable(T);

} // namespace bk
