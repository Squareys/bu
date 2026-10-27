// main.cpp — `bu`: subcommand dispatch and the help text.
//
// bu is a Unix filter: `create` and `merge` write a backup to stdout and
// never open a network connection — where the bytes go (a file, `aws s3 cp -`,
// ssh, a tape) is the caller's pipe. Everything else reads backup files from
// disk, where it may seek. Exit status: 0 ok, 1 runtime failure (or warnings
// during create — see the help text), 2 usage error.

#include "cmd/args.hpp"
#include "cmd/commands.hpp"
#include "core/string_view.hpp"

#include <stdio.h>

using namespace bk;

namespace {

const char kHelp[] =
"bu " BU_VERSION " — backup utility: encrypted, deduplicating, incremental backups as a Unix filter\n"
"\n"
"  bu key init KEYFILE\n"
"      Make a new key file: a random master key, stored only wrapped under a\n"
"      passphrase (asked twice). Keep a copy of the file away from the\n"
"      backups: they need the file AND a passphrase.\n"
"  bu key add KEYFILE        add a passphrase (up to 8)\n"
"  bu key passwd KEYFILE     change the passphrase you unlock with\n"
"  bu key remove KEYFILE [--slot N]\n"
"                            remove the slot you unlock with, or slot N\n"
"  bu key info KEYFILE       list the slots and their KDF costs\n"
"      init, add and passwd take --kdf-memory MIB (8-4096), --kdf-time PASSES\n"
"      (1-100) or --kdf-target-ms MS (100-60000, default 2000: the passes are\n"
"      calibrated so one unlock takes about that long here).\n"
"\n"
"  bu create --key KEYFILE --index-out INDEX [--base INDEX] [-j N]\n"
"               [--no-files-cache] [-v] PATH... > BACKUP\n"
"      Stream a backup of PATH... to stdout. With --base, an increment: only\n"
"      chunks the base index does not list are stored, and files whose\n"
"      metadata is unchanged are not even read (--no-files-cache: read them).\n"
"      Writes the new INDEX (atomically, after the backup was fully written);\n"
"      --index-out may name the same file as --base.\n"
"\n"
"  bu restore --key KEYFILE [-C DIR] [--path PREFIX] [-j N] [-v] BACKUP...\n"
"      Restore the latest snapshot of the chain BACKUP... (the full backup or\n"
"      merged file and every increment since, in any order) into DIR\n"
"      (default: current directory), every chunk authenticated and verified.\n"
"\n"
"  bu merge --key KEYFILE [-j N] [-v] BACKUP... > MERGED\n"
"      One self-contained backup of the chain's latest snapshot holding only\n"
"      the chunks it references. merge(full, inc1) replaces both; later\n"
"      increments keep working with it.\n"
"\n"
"  bu check --key KEYFILE [-j N] [-v] BACKUP...\n"
"      Authenticate every record and verify every snapshot is complete.\n"
"\n"
"  bu index --key KEYFILE -o INDEX BACKUP...\n"
"      Rebuild a lost index (files cache included) from the chain.\n"
"\n"
"  bu list --key KEYFILE BACKUP... | INDEX\n"
"      Show the files, and the latest snapshot's tree.\n"
"\n"
"Every command that unlocks a key file (--key, and key add/passwd/remove)\n"
"asks for the passphrase on the terminal, or reads it from\n"
"--passphrase-file PATH (its first line) or --passphrase-fd N, for\n"
"unattended runs; key add and passwd read the new one from\n"
"--new-passphrase-file PATH or --new-passphrase-fd N (key init: from\n"
"--passphrase-file or --passphrase-fd).\n"
"\n"
"-j N sets the worker threads (default: online CPUs; restore: at most 8);\n"
"create adds up to four reader threads, a chunker and a writer. Exit status:\n"
"0 ok; 1 failure, or create finished with warnings (unreadable files were\n"
"left out; the backup and index are still valid); 2 usage error.\n"
"\n"
"Example (to S3, keeping the index only when the upload succeeded):\n"
"  set -o pipefail\n"
"  bu create --key k --passphrase-file ~/.bu-pass --base idx --index-out idx.new ~/data \\\n"
"      | aws s3 cp - s3://bucket/data-$(date +%F).bk && mv idx.new idx\n";

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { fputs(kHelp, stderr); return kExitUsage; }
    const StringView cmd(argv[1]);
    if (cmd == "create"_s) return cmdCreate(argc, argv, 2);
    if (cmd == "restore"_s) return cmdRestore(argc, argv, 2);
    if (cmd == "merge"_s) return cmdMerge(argc, argv, 2);
    if (cmd == "check"_s) return cmdCheck(argc, argv, 2);
    if (cmd == "index"_s) return cmdIndex(argc, argv, 2);
    if (cmd == "list"_s) return cmdList(argc, argv, 2);
    if (cmd == "key"_s) return cmdKey(argc, argv, 2);
    if (cmd == "help"_s || cmd == "--help"_s || cmd == "-h"_s) { fputs(kHelp, stdout); return kExitOk; }
    if (cmd == "version"_s || cmd == "--version"_s) { puts("bu " BU_VERSION); return kExitOk; }
    fprintf(stderr, "bu: unknown command '%s' (run `bu help`)\n", argv[1]);
    return kExitUsage;
}
