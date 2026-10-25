// types.hpp — fundamental scalar typedefs and a few global helpers.
//
// Lowest-level header in the project; parsed by nearly every TU. It pulls in
// *nothing* — not even the "freestanding" <cstdint>/<cstddef>. The fixed-width
// and size types are available header-free as compiler builtin macros
// (__UINT32_TYPE__ etc.), which gcc and clang both provide on our single
// target (Linux x86-64). The static_asserts turn any wrong target into a loud
// compile error rather than silent UB.
//
// Keep this header tiny: every byte added here is paid for across the whole
// translation-unit graph.
#pragma once

namespace bk {

using u8  = __UINT8_TYPE__;
using u16 = __UINT16_TYPE__;
using u32 = __UINT32_TYPE__;
using u64 = __UINT64_TYPE__;
using i8  = __INT8_TYPE__;
using i16 = __INT16_TYPE__;
using i32 = __INT32_TYPE__;
using i64 = __INT64_TYPE__;
using f32 = float;
using f64 = double;
using usize = __SIZE_TYPE__;
using uptr  = __UINTPTR_TYPE__;

static_assert(sizeof(u8) == 1 && sizeof(u16) == 2 && sizeof(u32) == 4 && sizeof(u64) == 8,
              "unexpected fixed-width integer sizes — wrong compiler/target?");
static_assert(sizeof(usize) == 8 && sizeof(uptr) == 8,
              "backu targets 64-bit Linux x86-64 only");

// Sentinel for "no index" in the data-oriented arrays. We use index-based
// references everywhere instead of pointers (pointers are unstable across
// reallocation; indices survive growth and serialize cleanly).
constexpr u32 kInvalidIndex = 0xFFFFFFFFu;

// Branch hints — cheap and free of header cost.
#define BK_LIKELY(x)   (__builtin_expect(!!(x), 1))
#define BK_UNLIKELY(x) (__builtin_expect(!!(x), 0))

#if defined(NDEBUG)
#define BK_ASSERT(cond) ((void)0)
#else
// Minimal assert that does not drag in <cassert>. SIGILL under a debugger.
#define BK_ASSERT(cond) ((cond) ? (void)0 : __builtin_trap())
#endif

template <typename T> struct RemoveRef      { using Type = T; };
template <typename T> struct RemoveRef<T&>  { using Type = T; };
template <typename T> struct RemoveRef<T&&> { using Type = T; };

template <typename T>
constexpr typename RemoveRef<T>::Type&& move(T&& v) {
    return static_cast<typename RemoveRef<T>::Type&&>(v);
}

template <typename T>
constexpr T&& forward(typename RemoveRef<T>::Type& v) {
    return static_cast<T&&>(v);
}

template <typename T>
constexpr void swap(T& a, T& b) {
    T t = static_cast<T&&>(a);
    a = static_cast<T&&>(b);
    b = static_cast<T&&>(t);
}

template <typename T> constexpr T min(T a, T b) { return a < b ? a : b; }
template <typename T> constexpr T max(T a, T b) { return a > b ? a : b; }
template <typename T> constexpr T clamp(T v, T lo, T hi) { return v < lo ? lo : (v > hi ? hi : v); }

} // namespace bk
