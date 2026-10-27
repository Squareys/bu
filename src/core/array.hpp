// array.hpp — owning, growable array. Our std::vector replacement.
//
// Design choices for compile-time and runtime frugality:
//  * Stores an Allocator by value (default = global heap) so the same type can
//    build into an arena with no template churn.
//  * Growth uses realloc-in-place for trivially-relocatable T (everything in
//    our DOD arrays qualifies) and falls back to a move loop otherwise.
//  * Header-only but minimal: no <initializer_list>, no iterators beyond raw
//    pointers, no exceptions.
#pragma once

#include "memory.hpp"
#include "span.hpp"

namespace bk {

template <typename T>
struct Array {
    T* ptr = nullptr;
    u32 count = 0;
    u32 cap = 0;
    Allocator alloc = defaultAllocator();

    Array() = default;
    explicit Array(Allocator a) : alloc(a) {}

    Array(const Array&) = delete;            // owning: copies must be explicit
    Array& operator=(const Array&) = delete;

    Array(Array&& o) : ptr(o.ptr), count(o.count), cap(o.cap), alloc(o.alloc) {
        o.ptr = nullptr; o.count = 0; o.cap = 0;
    }
    Array& operator=(Array&& o) {
        if (this != &o) {
            free();
            ptr = o.ptr; count = o.count; cap = o.cap; alloc = o.alloc;
            o.ptr = nullptr; o.count = 0; o.cap = 0;
        }
        return *this;
    }

    ~Array() { free(); }

    void free() {
        if (ptr) {
            if (!kTriviallyRelocatable<T>) destructRange(ptr, count);
            alloc.free(ptr);
        }
        ptr = nullptr; count = 0; cap = 0;
    }

    u32 size() const { return count; }
    bool empty() const { return count == 0; }
    T* data() const { return ptr; }
    T& operator[](u32 i) const { return ptr[i]; }
    T& back() const { return ptr[count - 1]; }
    T* begin() const { return ptr; }
    T* end() const { return ptr + count; }

    Span<T> span() const { return Span<T>(ptr, count); }

    void reserve(u32 newCap) {
        if (newCap <= cap) return;
        u32 c = cap ? cap * 2 : 8;
        if (c < newCap) c = newCap;
        // Fast path: a trivially-relocatable T in an allocator that can realloc
        // (the default heap) grows in place instead of alloc-new + memcpy + free.
        if (ptr && kTriviallyRelocatable<T>) {
            if (void* rp = alloc.realloc(ptr, usize(c) * sizeof(T), alignof(T))) {
                ptr = static_cast<T*>(rp); cap = c; return;
            }
        }
        T* np = static_cast<T*>(alloc.alloc(usize(c) * sizeof(T), alignof(T)));
        if (ptr) {
            if (kTriviallyRelocatable<T>) {
                memCopy(np, ptr, usize(count) * sizeof(T));
            } else {
                for (u32 i = 0; i < count; ++i) { construct(np + i, move(ptr[i])); destruct(ptr + i); }
            }
            alloc.free(ptr);
        }
        ptr = np; cap = c;
    }

    void resize(u32 n) {
        reserve(n);
        if (n > count) for (u32 i = count; i < n; ++i) construct(ptr + i);
        else if (n < count && !kTriviallyRelocatable<T>) destructRange(ptr + n, count - n);
        count = n;
    }

    T& push(const T& v) {
        if (count == cap) reserve(count + 1);
        construct(ptr + count, v);
        return ptr[count++];
    }
    T& push(T&& v) {
        if (count == cap) reserve(count + 1);
        construct(ptr + count, move(v));
        return ptr[count++];
    }
    // Append uninitialized slot — caller fills it. Returns its index.
    u32 addUninit() {
        if (count == cap) reserve(count + 1);
        return count++;
    }
    T& addDefault() {
        if (count == cap) reserve(count + 1);
        construct(ptr + count);
        return ptr[count++];
    }

    void appendRange(const T* src, u32 n) {
        reserve(count + n);
        if (kTriviallyRelocatable<T>) memCopy(ptr + count, src, usize(n) * sizeof(T));
        else for (u32 i = 0; i < n; ++i) construct(ptr + count + i, src[i]);
        count += n;
    }

    void pop() { BK_ASSERT(count > 0); --count; if (!kTriviallyRelocatable<T>) destruct(ptr + count); }

    // Insert/erase by index. Shifts use move so move-only T works.
    void insert(u32 pos, const T& v) {
        if (pos > count) pos = count;
        reserve(count + 1);
        for (u32 i = count; i > pos; --i) ptr[i] = move(ptr[i - 1]);
        ptr[pos] = v; ++count;
    }
    // Insert a default-constructed slot at `pos` (move-shifting the tail right),
    // returned for the caller to fill. Works for move-only T where
    // insert(pos, const T&) cannot — there is no value to copy.
    T& insertDefault(u32 pos) {
        if (pos > count) pos = count;
        addDefault();                                  // grow by one at the end
        for (u32 i = count - 1; i > pos; --i) ptr[i] = move(ptr[i - 1]);
        return ptr[pos];                               // now a moved-from (default-ish) slot
    }
    void erase(u32 pos) {
        if (pos >= count) return;
        for (u32 i = pos; i + 1 < count; ++i) ptr[i] = move(ptr[i + 1]);
        --count;
    }
    void eraseRange(u32 a, u32 b) {
        if (b > count) b = count;
        if (a >= b) return;
        const u32 d = b - a;
        for (u32 i = a; i + d < count; ++i) ptr[i] = move(ptr[i + d]);
        count -= d;
    }

    // Keep capacity, drop elements.
    void clear() {
        if (!kTriviallyRelocatable<T>) destructRange(ptr, count);
        count = 0;
    }
};

} // namespace bk
