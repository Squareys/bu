// test_main.cpp — runs every registered BK_TEST, optionally filtered by a
// substring of the test name: `bu_tests [FILTER]`. Exit 1 if any failed.

#include "test.hpp"

namespace bk {
TestCase*& testList() { static TestCase* head = nullptr; return head; }
bool& testFailedFlag() { static bool f = false; return f; }
} // namespace bk

int main(int argc, char** argv) {
    using namespace bk;
    const StringView filter = argc > 1 ? StringView(argv[1]) : StringView();
    // The list is built in reverse registration order; reverse it so tests
    // run in source order, which is the order a reader expects failures in.
    TestCase* rev = nullptr;
    for (TestCase* t = testList(); t;) { TestCase* n = t->next; t->next = rev; rev = t; t = n; }
    u32 run = 0, failed = 0;
    for (TestCase* t = rev; t; t = t->next) {
        const StringView name(t->name);
        bool match = filter.empty();
        for (u32 i = 0; !match && i + filter.count <= name.count; ++i)
            match = name.sub(i, filter.count) == filter;
        if (!match) continue;
        testFailedFlag() = false;
        t->fn();
        ++run;
        if (testFailedFlag()) { ++failed; printf("FAIL %s\n", t->name); }
    }
    printf("%u tests, %u failed\n", run, failed);
    return failed ? 1 : 0;
}
