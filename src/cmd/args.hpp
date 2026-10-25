// args.hpp — command-line parsing shared by every subcommand.
//
// The rules (CLAUDE.md): an unknown flag, a repeated flag, a flag missing its
// value and an out-of-range number are each refused BY NAME with exit status
// 2; nothing is guessed, clamped or silently ignored. A backup tool that
// misreads `--bsae` as a path and makes a full backup instead of an increment
// is a tool that quietly costs somebody a day of upload.
#pragma once

#include "core/array.hpp"
#include "core/string.hpp"

namespace bk {

constexpr int kExitOk = 0;
constexpr int kExitRuntime = 1;
constexpr int kExitUsage = 2;

// Every option any subcommand takes. A subcommand declares which it accepts
// with a mask; one parser means one set of refusal messages.
enum ArgFlag : u32 {
    kArgKey = 1u << 0,          // --key FILE
    kArgBase = 1u << 1,         // --base INDEX
    kArgIndexOut = 1u << 2,     // --index-out INDEX
    kArgJobs = 1u << 3,         // -j N
    kArgNoCache = 1u << 4,      // --no-files-cache
    kArgDir = 1u << 5,          // -C DIR
    kArgPath = 1u << 6,         // --path PREFIX
    kArgOut = 1u << 7,          // -o FILE
    kArgVerbose = 1u << 8,      // -v
};

struct Args {
    const char* key = nullptr;       // each may be null when not given
    const char* base = nullptr;
    const char* indexOut = nullptr;
    const char* dir = nullptr;
    const char* path = nullptr;
    const char* out = nullptr;
    u32 jobs = 0;                    // 0 = online CPU count
    bool noCache = false;
    bool verbose = false;
    Array<const char*> positional;   // never null entries
};

// Parse argv[first..argc) for subcommand `cmd`, accepting the options in
// `allowed`. On a usage error prints "backu CMD: message" and returns false.
[[nodiscard]] bool argsParse(const char* cmd, int argc, char** argv, int first, u32 allowed, Args& out);

// Print "backu: message" (or "backu CMD: message") to stderr.
void report(StringView msg);

// Jobs to use: -j, or the online CPU count.
u32 argsJobs(const Args& a);

} // namespace bk
