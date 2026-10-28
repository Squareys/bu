// exclude.hpp — `create --exclude PATTERN`: which stored paths the walk skips.
//
// The rule mirrors rsync and .gitignore, the tools people already write
// patterns for: a pattern with a `/` in it matches the whole stored path
// (anchored at the top of the backup), one without matches the last name at
// any depth. Patterns are glob(7) patterns matched with fnmatch(3) without
// FNM_PATHNAME, so in a whole-path pattern `*` matches across `/` (as in
// tar), and `cache/**` and `cache/*` both mean everything below cache.
//
// A pattern is normalised the way create normalises a PATH (storedName): a
// leading `/` or `./` and a trailing `/` go, since stored paths have none.
// The `/` test is made before that, on the pattern without its trailing
// slashes, so `/tmp` still means the top-level tmp, not every tmp.
//
// Rejected: regular expressions (slower, and nobody's muscle memory for
// paths), include patterns and pattern files (rsync's filter language is a
// language; bu backs up what you name and leaves out what you name).
#pragma once

#include "core/array.hpp"
#include "core/string.hpp"

namespace bk {

struct Excludes {
    String pats;          // the normalised patterns, each NUL-terminated
    Array<u32> offs;      // start of each pattern in pats
    Array<u8> whole;      // per pattern: 1 = whole stored path, 0 = last name
};

// Add one pattern. False (with `err`) when nothing is left of it after
// normalisation ("/", "./").
[[nodiscard]] bool excludeAdd(Excludes& x, StringView pattern, String& err);

// Does any pattern match `stored` (a stored path: relative, no leading or
// trailing `/`, never null, NUL-terminated at stored[len])?
bool excludeMatch(const Excludes& x, const char* stored, u32 len);

} // namespace bk
