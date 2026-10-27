// string.hpp — owning, heap-backed byte string.
//
// Where ownership is genuinely needed: error messages (`String& err`), joined
// paths, and the byte builders the segment format serialises into. Always
// kept NUL-terminated so a path can go straight to open()/lstat() without a
// copy.
#pragma once

#include "string_view.hpp"

namespace bk {

struct String {
    char* ptr = nullptr;
    u32 count = 0;
    u32 cap = 0;
    Allocator alloc = defaultAllocator();

    String() = default;
    String(StringView s) { assign(s); }

    String(const String&) = delete;
    String& operator=(const String&) = delete;
    String(String&& o) : ptr(o.ptr), count(o.count), cap(o.cap), alloc(o.alloc) {
        o.ptr = nullptr; o.count = 0; o.cap = 0;
    }
    String& operator=(String&& o) {
        if (this != &o) { free(); ptr = o.ptr; count = o.count; cap = o.cap; alloc = o.alloc;
            o.ptr = nullptr; o.count = 0; o.cap = 0; }
        return *this;
    }
    ~String() { free(); }

    void free() { if (ptr) alloc.free(ptr); ptr = nullptr; count = 0; cap = 0; }

    u32 size() const { return count; }
    bool empty() const { return count == 0; }
    // Never null: an empty String still hands out a valid "" so C APIs are safe.
    const char* c_str() const { return ptr ? ptr : ""; }
    StringView view() const { return StringView(ptr ? ptr : "", count); }
    operator StringView() const { return view(); }
    void clear() { count = 0; if (ptr) ptr[0] = 0; }
    void truncate(u32 n) { if (n < count) { count = n; ptr[n] = 0; } }

    void reserve(u32 n) {
        if (n + 1 <= cap) return;
        u32 c = cap ? cap * 2 : 32;
        if (c < n + 1) c = n + 1;
        if (ptr) {
            if (void* rp = alloc.realloc(ptr, c, 1)) { ptr = static_cast<char*>(rp); cap = c; return; }
        }
        char* np = static_cast<char*>(alloc.alloc(c, 1));
        if (ptr) { memCopy(np, ptr, count); alloc.free(ptr); }
        ptr = np; cap = c;
    }
    void assign(StringView s) { count = 0; append(s); }
    void append(StringView s) {
        reserve(count + s.count);
        if (s.count) memCopy(ptr + count, s.ptr, s.count);
        count += s.count;
        ptr[count] = 0;
    }
    void append(char c) {
        reserve(count + 1);
        ptr[count++] = c;
        ptr[count] = 0;
    }
    void appendU64(u64 v) {
        char tmp[24]; u32 n = 0;
        do { tmp[n++] = char('0' + (v % 10)); v /= 10; } while (v);
        reserve(count + n);
        for (u32 k = 0; k < n; ++k) ptr[count + k] = tmp[n - 1 - k];
        count += n;
        ptr[count] = 0;
    }
};

// Build an error message from parts without stdio: `errSet(err, "open ", path, ": ", why)`.
// Parsers and library code never print; they fill `err` and the command
// prints it once. The template only gathers views; the appending is one
// out-of-line function, so the ~150 error sites cost a call each, not an
// inlined append loop each (that was ~1 KB in cryptoCpuCheck alone).
bool errSetParts(String& e, const StringView* parts, u32 n);
template <typename... Parts>
inline bool errSet(String& e, Parts... parts) {
    const StringView v[] = {StringView(parts)...};
    return errSetParts(e, v, u32(sizeof...(Parts)));
}

} // namespace bk
