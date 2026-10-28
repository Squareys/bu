// test_exclude.cpp — `create --exclude`: which patterns match the whole
// stored path and which the last name, how a pattern is normalised, and that
// a pattern with nothing left in it is refused rather than matching nothing
// (or everything).

#include "cmd/exclude.hpp"
#include "test.hpp"

using namespace bk;

namespace {

bool matches(const Excludes& x, const char* stored) {
    return excludeMatch(x, stored, StringView(stored).count);
}

} // namespace

BK_TEST(exclude_name_pattern_matches_last_name_at_any_depth) {
    Excludes x;
    String err;
    BK_REQUIRE(excludeAdd(x, "*.tmp"_s, err));
    BK_REQUIRE(excludeAdd(x, "cache"_s, err));
    BK_CHECK(matches(x, "a.tmp"));
    BK_CHECK(matches(x, "memory/deep/b.tmp"));
    BK_CHECK(matches(x, "cache"));
    BK_CHECK(matches(x, "srv/app/cache"));
    BK_CHECK(!matches(x, "cache.db"));
    BK_CHECK(!matches(x, "a.tmp.keep"));
    BK_CHECK(!matches(x, "tmp"));
}

BK_TEST(exclude_path_pattern_matches_whole_stored_path) {
    Excludes x;
    String err;
    BK_REQUIRE(excludeAdd(x, "memory/scratch"_s, err));
    BK_CHECK(matches(x, "memory/scratch"));
    BK_CHECK(!matches(x, "scratch"));
    BK_CHECK(!matches(x, "other/memory/scratch"));
    BK_CHECK(!matches(x, "memory/scratch2"));
    // * crosses / in a whole-path pattern (no FNM_PATHNAME), as in tar.
    Excludes y;
    BK_REQUIRE(excludeAdd(y, "logs/*.log"_s, err));
    BK_CHECK(matches(y, "logs/a.log"));
    BK_CHECK(matches(y, "logs/2026/a.log"));
    BK_CHECK(!matches(y, "a.log"));
}

BK_TEST(exclude_pattern_is_normalised_like_a_path) {
    Excludes x;
    String err;
    // Leading / and ./ go (stored paths have none), but still make the
    // pattern a whole-path one: /tmp is the top-level tmp, not every tmp.
    BK_REQUIRE(excludeAdd(x, "/tmp"_s, err));
    BK_REQUIRE(excludeAdd(x, "./build/"_s, err));
    BK_CHECK(matches(x, "tmp"));
    BK_CHECK(!matches(x, "a/tmp"));
    BK_CHECK(matches(x, "build"));
    BK_CHECK(!matches(x, "a/build"));
    // A trailing / alone does not anchor: node_modules/ is every node_modules.
    Excludes y;
    BK_REQUIRE(excludeAdd(y, "node_modules/"_s, err));
    BK_CHECK(matches(y, "web/node_modules"));
}

BK_TEST(exclude_refuses_patterns_with_nothing_left) {
    Excludes x;
    String err;
    BK_CHECK(!excludeAdd(x, "/"_s, err));
    BK_CHECK(!excludeAdd(x, "./"_s, err));
    BK_CHECK(!excludeAdd(x, "."_s, err));
    BK_CHECK(!err.empty());
    BK_CHECK_EQ(x.offs.count, 0u);
    BK_CHECK(!matches(x, "anything"));
}
