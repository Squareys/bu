// args.cpp — see args.hpp.

#include "cmd/args.hpp"
#include "core/thread.hpp"

#include <stdio.h>

namespace bk {

namespace {

struct Spec { StringView name; u32 flag; bool takesValue; };
const Spec kSpecs[] = {
    {"--key"_s, kArgKey, true},
    {"--base"_s, kArgBase, true},
    {"--index-out"_s, kArgIndexOut, true},
    {"-j"_s, kArgJobs, true},
    {"--no-files-cache"_s, kArgNoCache, false},
    {"-C"_s, kArgDir, true},
    {"--path"_s, kArgPath, true},
    {"-o"_s, kArgOut, true},
    {"-v"_s, kArgVerbose, false},
};

bool usageError(const char* cmd, StringView a, StringView b = ""_s, StringView c = ""_s) {
    fprintf(stderr, "bu %s: %.*s%.*s%.*s\n(run `bu help` for usage)\n", cmd, int(a.count), a.ptr,
            int(b.count), b.ptr, int(c.count), c.ptr);
    return false;
}

} // namespace

bool argsParse(const char* cmd, int argc, char** argv, int first, u32 allowed, Args& out) {
    u32 seen = 0;
    bool endOfOptions = false;
    for (int i = first; i < argc; ++i) {
        const StringView a(argv[i]);
        if (endOfOptions || a.empty() || a[0] != '-' || a == "-"_s) {
            out.positional.push(argv[i]);
            continue;
        }
        if (a == "--"_s) { endOfOptions = true; continue; }
        const Spec* spec = nullptr;
        for (const Spec& s : kSpecs) if (s.name == a) { spec = &s; break; }
        if (!spec || !(allowed & spec->flag)) return usageError(cmd, "unknown option '"_s, a, "'"_s);
        if (seen & spec->flag) return usageError(cmd, "option '"_s, a, "' given twice"_s);
        seen |= spec->flag;
        const char* value = nullptr;
        if (spec->takesValue) {
            if (i + 1 >= argc) return usageError(cmd, "option '"_s, a, "' needs a value"_s);
            value = argv[++i];
            if (StringView(value).empty()) return usageError(cmd, "option '"_s, a, "' has an empty value"_s);
        }
        switch (spec->flag) {
        case kArgKey: out.key = value; break;
        case kArgBase: out.base = value; break;
        case kArgIndexOut: out.indexOut = value; break;
        case kArgDir: out.dir = value; break;
        case kArgPath: out.path = value; break;
        case kArgOut: out.out = value; break;
        case kArgNoCache: out.noCache = true; break;
        case kArgVerbose: out.verbose = true; break;
        case kArgJobs: {
            u64 n = 0;
            if (!parseU64(StringView(value), n) || n < 1 || n > 1024)
                return usageError(cmd, "-j needs a whole number from 1 to 1024, not '"_s, StringView(value), "'"_s);
            out.jobs = u32(n);
            break;
        }
        default: break;
        }
    }
    if ((allowed & kArgKey) && !out.key) return usageError(cmd, "--key KEYFILE is required"_s);
    return true;
}

void report(StringView msg) {
    fprintf(stderr, "bu: %.*s\n", int(msg.count), msg.ptr);
}

u32 argsJobs(const Args& a) { return a.jobs ? a.jobs : cpuCount(); }

} // namespace bk
