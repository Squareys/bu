// exclude.cpp — see exclude.hpp.
//
// fnmatch is glibc's; the walk calls it once per pattern per directory entry,
// which is noise next to the fstatat each entry already costs (and an
// excluded entry is checked before that stat, so it costs less than before).

#include "cmd/exclude.hpp"

#include <fnmatch.h>

namespace bk {

bool excludeAdd(Excludes& x, StringView pattern, String& err) {
    StringView p = pattern;
    while (p.endsWith("/"_s)) p.count--;
    const bool whole = p.find('/') != kInvalidIndex;
    while (p.startsWith("/"_s) || p.startsWith("./"_s)) p = p.from(p[0] == '/' ? 1 : 2);
    if (p.empty() || p == "."_s)
        return errSet(err, "--exclude needs a pattern that names something below the top, not '"_s, pattern, "'"_s);
    x.offs.push(x.pats.count);
    x.pats.append(p);
    x.pats.append('\0');
    x.whole.push(whole ? 1 : 0);
    return true;
}

bool excludeMatch(const Excludes& x, const char* stored, u32 len) {
    const u32 slash = StringView(stored, len).findLast('/');
    const char* name = slash == kInvalidIndex ? stored : stored + slash + 1;
    for (u32 i = 0; i < x.offs.count; ++i)
        if (fnmatch(x.pats.c_str() + x.offs[i], x.whole[i] ? stored : name, 0) == 0) return true;
    return false;
}

} // namespace bk
