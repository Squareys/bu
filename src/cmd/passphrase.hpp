// passphrase.hpp — where a passphrase comes from, and unlocking the key file
// for the commands that read or write backups.
//
// Three sources, in this order of precedence: --passphrase-file PATH (the
// first line, without its line ending), --passphrase-fd N (bytes up to the
// first newline or end of input), or the controlling terminal. The terminal
// is /dev/tty opened directly, with echo off: stdin and stdout carry backup
// data (`bu create ... > x.bk`, `... | bu ...`), so they can be neither the
// prompt nor the answer. Without a terminal and without a file or fd, the
// command fails and says which flags would have worked; it never falls back
// to reading stdin.
//
// Rejected: an environment variable (it leaks through /proc/PID/environ to
// the same user and into child processes and crash reports); a passphrase as
// a command-line argument (visible in `ps` to every user).
#pragma once

#include "cmd/args.hpp"
#include "format/container.hpp"
#include "format/keyfile.hpp"

namespace bk {

// Holds one passphrase; wiped on destruction.
struct Passphrase {
    char buf[kPassphraseMax + 2];
    u32 len = 0;
    StringView view() const { return StringView(buf, len); }
    ~Passphrase() { secureZero(buf, sizeof buf); }
};

// Read a passphrase from `file` (may be null), else from `fd` (-1: none),
// else from the terminal, showing `prompt`. `confirm`: on the terminal, ask
// twice and require the same answer (for a new passphrase). `hint` names the
// flags that would have supplied it, for the error when there is no
// terminal. Refuses an empty or over-long passphrase. Warns (warnIfShared)
// when `file` is accessible by other users.
[[nodiscard]] bool passphraseGet(const char* file, int fd, StringView prompt, StringView hint, bool confirm,
                                 Passphrase& out, String& err);

// "bu: warning: <what> <path> is accessible by other users" when `path` has
// any group or other permission bits. Key files and passphrase files.
void warnIfShared(const char* what, const char* path);
// One warning per slot keyFileUnlock skipped (bits of `kdfFailed`), naming
// the memory it asked for.
void warnKdfSkipped(const char* path, const KeyFile& f, u32 kdfFailed);

// For create, restore, merge, check, index and list: check the CPU, read
// a.key, get the passphrase (a.passFile, a.passFd or the terminal), unlock,
// derive. Reports the error itself; false means exit 1.
[[nodiscard]] bool unlockKeyForCommand(const Args& a, MasterKey& out);

} // namespace bk
