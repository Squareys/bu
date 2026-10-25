// span.hpp — non-owning view over a contiguous range of T.
//
// The read/pass-by-value workhorse: functions take Span<const T> instead of a
// (pointer, count) pair or an owning container reference. Zero allocation, zero
// ownership, trivially copyable.
#pragma once

#include "types.hpp"

namespace bk {

template <typename T>
struct Span {
    T* ptr = nullptr;
    u32 count = 0;

    constexpr Span() = default;
    constexpr Span(T* p, u32 n) : ptr(p), count(n) {}

    constexpr u32 size() const { return count; }
    constexpr bool empty() const { return count == 0; }
    constexpr T& operator[](u32 i) const { return ptr[i]; }
    constexpr T* data() const { return ptr; }

    constexpr T* begin() const { return ptr; }
    constexpr T* end() const { return ptr + count; }

    constexpr Span<T> sub(u32 start, u32 n) const { return Span<T>(ptr + start, n); }

    // Implicit T* -> const T* view conversion (Span<int> -> Span<const int>).
    constexpr operator Span<const T>() const { return Span<const T>(ptr, count); }
};

} // namespace bk
