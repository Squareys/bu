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
    kArgPassFile = 1u << 9,     // --passphrase-file FILE
    kArgPassFd = 1u << 10,      // --passphrase-fd N
    kArgNewPassFile = 1u << 11, // --new-passphrase-file FILE
    kArgNewPassFd = 1u << 12,   // --new-passphrase-fd N
    kArgKdfMemory = 1u << 13,   // --kdf-memory MIB
    kArgKdfTime = 1u << 14,     // --kdf-time PASSES
    kArgKdfTargetMs = 1u << 15, // --kdf-target-ms MS
    kArgSlot = 1u << 16,        // --slot N
};
// Every command that unlocks a key file takes both passphrase sources; with
// neither, it asks on the terminal.
constexpr u32 kArgPass = kArgPassFile | kArgPassFd;
constexpr u32 kArgNewPass = kArgNewPassFile | kArgNewPassFd;
constexpr u32 kArgKdf = kArgKdfMemory | kArgKdfTime | kArgKdfTargetMs;

struct Args {
    const char* key = nullptr;       // each may be null when not given
    const char* base = nullptr;
    const char* indexOut = nullptr;
    const char* dir = nullptr;
    const char* path = nullptr;
    const char* out = nullptr;
    const char* passFile = nullptr;
    const char* newPassFile = nullptr;
    int passFd = -1;                 // -1 when not given
    int newPassFd = -1;
    u32 kdfMemMiB = 0;               // 0 = not given (automatic)
    u32 kdfPasses = 0;               // 0 = not given (calibrated)
    u32 kdfTargetMs = 0;             // 0 = not given (the default target)
    u32 slot = kInvalidIndex;        // kInvalidIndex = not given
    u32 jobs = 0;                    // 0 = online CPU count
    bool noCache = false;
    bool verbose = false;
    Array<const char*> positional;   // never null entries
};

// Parse argv[first..argc) for subcommand `cmd`, accepting the options in
// `allowed` (kArgKey brings kArgPass with it). On a usage error prints "bu CMD: message" and returns false.
[[nodiscard]] bool argsParse(const char* cmd, int argc, char** argv, int first, u32 allowed, Args& out);

// Print "bu: message" (or "bu CMD: message") to stderr.
void report(StringView msg);

// Jobs to use: -j, or the online CPU count.
u32 argsJobs(const Args& a);

} // namespace bk
