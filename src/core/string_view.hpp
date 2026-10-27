// string_view.hpp — zero-copy, non-owning view over bytes.
//
// The universal string-passing type in bu: argv, paths, manifest names,
// error messages. It never allocates and is not guaranteed NUL-terminated, so
// the length always travels with the pointer. Deliberately minimal: no SIMD
// `find` and no UTF-8 helpers, because nothing in a backup tool scans
// text — path handling only ever compares and slices.
#pragma once

#include "memory.hpp"
#include "types.hpp"

namespace bk {

struct StringView {
    const char* ptr = nullptr;
    u32 count = 0;

    constexpr StringView() = default;
    constexpr StringView(const char* p, u32 n) : ptr(p), count(n) {}

    // From a string LITERAL: the compiler supplies the length from the array
    // bound, so a literal never pays a runtime strlen. consteval makes
    // `StringView(buf)` over a runtime char array a hard error, steering such
    // sites to the explicit (ptr, len) form.
    template <usize N>
    consteval StringView(const char (&s)[N]) : ptr(s), count(static_cast<u32>(N - 1)) {}

    // From a genuine runtime NUL-terminated C string (argv, d_name). Never null.
    constexpr StringView(const char* s) : ptr(s), count(0) {
        while (s[count]) ++count;
    }

    constexpr u32 size() const { return count; }
    constexpr bool empty() const { return count == 0; }
    constexpr char operator[](u32 i) const { return ptr[i]; }
    constexpr const char* data() const { return ptr; }
    constexpr const char* begin() const { return ptr; }
    constexpr const char* end() const { return ptr + count; }

    constexpr StringView sub(u32 start, u32 n) const { return StringView(ptr + start, n); }
    constexpr StringView from(u32 start) const {
        return start >= count ? StringView(ptr + count, 0) : StringView(ptr + start, count - start);
    }
    constexpr StringView first(u32 n) const { return StringView(ptr, n < count ? n : count); }

    constexpr bool startsWith(StringView p) const {
        return count >= p.count && StringView(ptr, p.count) == p;
    }
    constexpr bool endsWith(StringView p) const {
        return count >= p.count && StringView(ptr + count - p.count, p.count) == p;
    }

    // Size-first: a length mismatch returns before any byte is compared. No
    // operator!= on purpose — C++20 synthesises it, and declaring one would
    // suppress the reversed candidate `String == "x"_s` relies on.
    constexpr bool operator==(StringView o) const {
        return count == o.count && (count == 0 || __builtin_memcmp(ptr, o.ptr, count) == 0);
    }

    constexpr u32 find(char c, u32 start = 0) const {
        for (u32 i = start; i < count; ++i) if (ptr[i] == c) return i;
        return kInvalidIndex;
    }
    constexpr u32 findLast(char c) const {
        for (u32 i = count; i > 0; --i) if (ptr[i - 1] == c) return i - 1;
        return kInvalidIndex;
    }
};

constexpr StringView operator""_s(const char* s, usize n) {
    return StringView(s, static_cast<u32>(n));
}

static_assert(("abc"_s).size() == 3, "_s carries the literal length");
static_assert(!("abc"_s == "abcd"_s), "length mismatch short-circuits to false");
static_assert("dir/file"_s.startsWith("dir/"_s) && "a.bk"_s.endsWith(".bk"_s), "prefix/suffix");
static_assert(("a/b/c"_s).findLast('/') == 3 && ("abc"_s).find('z') == kInvalidIndex, "find");

// Parse a non-negative decimal integer; false on empty, overflow or a non-digit.
constexpr bool parseU64(StringView s, u64& out) {
    if (s.count == 0) return false;
    u64 v = 0;
    for (u32 i = 0; i < s.count; ++i) {
        const char c = s.ptr[i];
        if (c < '0' || c > '9') return false;
        if (v > (~u64(0) - u64(c - '0')) / 10) return false;
        v = v * 10 + u64(c - '0');
    }
    out = v;
    return true;
}
static_assert([]{ u64 v = 0; return parseU64("4096"_s, v) && v == 4096; }(), "parseU64");
static_assert([]{ u64 v = 0; return !parseU64("18446744073709551616"_s, v); }(), "overflow refused");
static_assert([]{ u64 v = 0; return !parseU64("12a"_s, v); }(), "non-digit refused");

} // namespace bk
