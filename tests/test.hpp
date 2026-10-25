// test.hpp — the tiny no-STL unit test harness.
//
// Tests self-register at static-init time; test_main.cpp walks the list.
// A failure prints file:line and the expression, marks the test failed and
// keeps going, so one broken assertion does not hide the rest.
#pragma once

#include "core/string_view.hpp"

#include <stdio.h>

namespace bk {

struct TestCase {
    const char* name;   // never null: the stringised test name
    void (*fn)();
    TestCase* next;
};

TestCase*& testList();
bool& testFailedFlag();

struct TestRegistrar {
    TestCase tc;
    TestRegistrar(const char* name, void (*fn)()) {
        tc.name = name;
        tc.fn = fn;
        tc.next = testList();
        testList() = &tc;
    }
};

} // namespace bk

#define BK_TEST(name) \
    static void bk_test_##name(); \
    static bk::TestRegistrar bk_reg_##name(#name, &bk_test_##name); \
    static void bk_test_##name()

#define BK_CHECK(cond) \
    do { if (!(cond)) { \
        printf("    FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        bk::testFailedFlag() = true; \
    } } while (0)

// Like BK_CHECK, but a false condition ends the test: for preconditions whose
// failure would make the rest of the test read garbage.
#define BK_REQUIRE(cond) \
    do { if (!(cond)) { \
        printf("    FAIL %s:%d: %s (required — test aborted)\n", __FILE__, __LINE__, #cond); \
        bk::testFailedFlag() = true; \
        return; \
    } } while (0)

#define BK_CHECK_EQ(a, b) \
    do { auto ea_ = (a); auto eb_ = (b); \
        if (!(ea_ == eb_)) { \
            printf("    FAIL %s:%d: %s == %s (got %lld vs %lld)\n", __FILE__, __LINE__, #a, #b, \
                   (long long)ea_, (long long)eb_); \
            bk::testFailedFlag() = true; \
        } } while (0)

// Compare n bytes against a hex string literal; prints both on mismatch.
#define BK_CHECK_HEX(bytes, n, hexLiteral) \
    do { char got_[2 * 4096 + 1]; bk::testHex((bytes), (n), got_); \
        if (!(bk::StringView(got_, 2 * (n)) == bk::StringView(hexLiteral))) { \
            printf("    FAIL %s:%d: %s\n      got  %s\n      want %s\n", __FILE__, __LINE__, #bytes, \
                   got_, hexLiteral); \
            bk::testFailedFlag() = true; \
        } } while (0)

namespace bk {
inline void testHex(const u8* p, usize n, char* out) {
    static const char d[] = "0123456789abcdef";
    for (usize i = 0; i < n; ++i) { out[2*i] = d[p[i] >> 4]; out[2*i+1] = d[p[i] & 15]; }
    out[2 * n] = 0;
}
} // namespace bk
