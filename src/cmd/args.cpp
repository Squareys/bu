// args.cpp — see args.hpp.

#include "cmd/args.hpp"
#include "core/thread.hpp"
#include "format/keyfile.hpp"

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
    {"--index"_s, kArgIndex, true},
    {"--no-key"_s, kArgNoKey, false},
    {"-o"_s, kArgOut, true},
    {"-v"_s, kArgVerbose, false},
    {"--passphrase-file"_s, kArgPassFile, true},
    {"--passphrase-fd"_s, kArgPassFd, true},
    {"--new-passphrase-file"_s, kArgNewPassFile, true},
    {"--new-passphrase-fd"_s, kArgNewPassFd, true},
    {"--kdf-memory"_s, kArgKdfMemory, true},
    {"--kdf-time"_s, kArgKdfTime, true},
    {"--kdf-target-ms"_s, kArgKdfTargetMs, true},
    {"--slot"_s, kArgSlot, true},
};

// A whole number in [lo, hi], or a usage error naming the option and the range.
bool numberIn(const char* cmd, StringView opt, const char* value, u64 lo, u64 hi, u64& out);

bool usageError(const char* cmd, StringView a, StringView b = ""_s, StringView c = ""_s) {
    fprintf(stderr, "bu %s: %.*s%.*s%.*s\n(run `bu help` for usage)\n", cmd, int(a.count), a.ptr,
            int(b.count), b.ptr, int(c.count), c.ptr);
    return false;
}

bool numberIn(const char* cmd, StringView opt, const char* value, u64 lo, u64 hi, u64& out) {
    if (parseU64(StringView(value), out) && out >= lo && out <= hi) return true;
    fprintf(stderr, "bu %s: %.*s needs a whole number from %llu to %llu, not '%s'\n(run `bu help` for usage)\n",
            cmd, int(opt.count), opt.ptr, (unsigned long long)lo, (unsigned long long)hi, value);
    return false;
}

} // namespace

bool argsParse(const char* cmd, int argc, char** argv, int first, u32 allowed, Args& out) {
    u32 seen = 0;
    bool endOfOptions = false;
    if (allowed & kArgKey) allowed |= kArgPass | kArgNoKey;
    for (int i = first; i < argc; ++i) {
        const StringView a(argv[i]);
        if (endOfOptions || a.empty() || a[0] != '-' || a == "-"_s) {
            out.positional.push(argv[i]);
            continue;
        }
        if (a == "--"_s) { endOfOptions = true; out.dashDash = out.positional.count; continue; }
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
        case kArgIndex: out.index = value; break;
        case kArgNoKey: out.noKey = true; break;
        case kArgOut: out.out = value; break;
        case kArgNoCache: out.noCache = true; break;
        case kArgVerbose: out.verbose = true; break;
        case kArgPassFile: out.passFile = value; break;
        case kArgNewPassFile: out.newPassFile = value; break;
        case kArgPassFd:
        case kArgNewPassFd: {
            u64 n = 0;
            if (!numberIn(cmd, a, value, 0, 65535, n)) return false;
            (spec->flag == kArgPassFd ? out.passFd : out.newPassFd) = int(n);
            break;
        }
        case kArgKdfMemory: {
            u64 n = 0;
            if (!numberIn(cmd, a, value, kKdfMinMemMiB, kKdfMaxMemMiB, n)) return false;
            out.kdfMemMiB = u32(n);
            break;
        }
        case kArgKdfTime: {
            u64 n = 0;
            if (!numberIn(cmd, a, value, kKdfMinPasses, kKdfMaxPasses, n)) return false;
            out.kdfPasses = u32(n);
            break;
        }
        case kArgKdfTargetMs: {
            u64 n = 0;
            if (!numberIn(cmd, a, value, 100, 60000, n)) return false;
            out.kdfTargetMs = u32(n);
            break;
        }
        case kArgSlot: {
            u64 n = 0;
            if (!numberIn(cmd, a, value, 0, kKeySlots - 1, n)) return false;
            out.slot = u32(n);
            break;
        }
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
    if (out.key && out.noKey) return usageError(cmd, "give --key KEYFILE or --no-key, not both"_s);
    if (out.noKey && (seen & kArgPass)) return usageError(cmd, "--passphrase-file and --passphrase-fd go with --key"_s);
    if ((seen & kArgPassFile) && (seen & kArgPassFd))
        return usageError(cmd, "give --passphrase-file or --passphrase-fd, not both"_s);
    if ((seen & kArgNewPassFile) && (seen & kArgNewPassFd))
        return usageError(cmd, "give --new-passphrase-file or --new-passphrase-fd, not both"_s);
    if ((seen & kArgKdfTime) && (seen & kArgKdfTargetMs))
        return usageError(cmd, "give --kdf-time or --kdf-target-ms, not both"_s);
    return true;
}

int usage(const char* cmd, StringView msg) {
    usageError(cmd, msg);
    return kExitUsage;
}

void report(StringView msg) {
    fprintf(stderr, "bu: %.*s\n", int(msg.count), msg.ptr);
}

u32 argsJobs(const Args& a) { return a.jobs ? a.jobs : cpuCount(); }

} // namespace bk
