// sort.hpp — an in-place sort for our arrays (no <algorithm>).
//
// Used where order is part of the output: directory entries are sorted by name
// so a backup's manifest does not depend on readdir order (which differs
// between filesystems and even between two runs on the same one after a
// rename), and so consecutive paths share prefixes for the manifest coding.
// Quicksort with median-of-three and an insertion-sort finish; recursion only
// on the smaller side, so stack depth is O(log n) whatever the input.
#pragma once

#include "types.hpp"

namespace bk {

template <typename T, typename Less>
void sortRange(T* a, u32 n, Less less) {
    while (n > 16) {
        // Median of three into a[0], a[mid], a[n-1]; mid is the LOWER middle,
        // which is what guarantees Hoare's split point j lands in [0, n-2]
        // so both sides are non-empty and the loop always shrinks.
        const u32 mid = (n - 1) / 2;
        if (less(a[mid], a[0])) swap(a[mid], a[0]);
        if (less(a[n - 1], a[0])) swap(a[n - 1], a[0]);
        if (less(a[n - 1], a[mid])) swap(a[n - 1], a[mid]);
        const T pivot = a[mid];
        i64 i = -1, j = i64(n);
        for (;;) {
            do { ++i; } while (less(a[i], pivot));
            do { --j; } while (less(pivot, a[j]));
            if (i >= j) break;
            swap(a[i], a[j]);
        }
        // [0, j] <= pivot <= [j+1, n)
        const u32 left = u32(j) + 1;
        if (left < n - left) { sortRange(a, left, less); a += left; n -= left; }
        else { sortRange(a + left, n - left, less); n = left; }
    }
    for (u32 i = 1; i < n; ++i) {
        T v = a[i];
        u32 j = i;
        while (j > 0 && less(v, a[j - 1])) { a[j] = a[j - 1]; --j; }
        a[j] = v;
    }
}

} // namespace bk
