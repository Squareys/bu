// main.cpp — `backu`: subcommand dispatch and the help text.
//
// backu is a Unix filter: `create` and `merge` write a backup to stdout and
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
"backu " BACKU_VERSION " — deduplicated, compressed, encrypted incremental backups\n"
"\n"
"  backu keygen > KEYFILE\n"
"      Make a new random key. Keep it away from the backups: without it they\n"
"      cannot be read, by anybody.\n"
"\n"
"  backu create --key KEYFILE --index-out INDEX [--base INDEX] [-j N]\n"
"               [--no-files-cache] [-v] PATH... > BACKUP\n"
"      Stream a backup of PATH... to stdout. With --base, an increment: only\n"
"      chunks the base index does not list are stored, and files whose\n"
"      metadata is unchanged are not even read (--no-files-cache: read them).\n"
"      Writes the new INDEX (atomically, after the backup was fully written);\n"
"      --index-out may name the same file as --base.\n"
"\n"
"  backu restore --key KEYFILE [-C DIR] [--path PREFIX] [-j N] [-v] BACKUP...\n"
"      Restore the latest snapshot of the chain BACKUP... (the full backup or\n"
"      merged file and every increment since, in any order) into DIR\n"
"      (default: current directory), every chunk authenticated and verified.\n"
"\n"
"  backu merge --key KEYFILE [-j N] [-v] BACKUP... > MERGED\n"
"      One self-contained backup of the chain's latest snapshot holding only\n"
"      the chunks it references. merge(full, inc1) replaces both; later\n"
"      increments keep working with it.\n"
"\n"
"  backu check --key KEYFILE [-j N] [-v] BACKUP...\n"
"      Authenticate every record and verify every snapshot is complete.\n"
"\n"
"  backu index --key KEYFILE -o INDEX BACKUP...\n"
"      Rebuild a lost index (files cache included) from the chain.\n"
"\n"
"  backu list --key KEYFILE BACKUP... | INDEX\n"
"      Show the files, and the latest snapshot's tree.\n"
"\n"
"-j N defaults to the number of online CPUs. Exit status: 0 ok; 1 failure, or\n"
"create finished with warnings (unreadable files were left out; the backup\n"
"and index are still valid); 2 usage error.\n"
"\n"
"Example (to S3, keeping the index only when the upload succeeded):\n"
"  set -o pipefail\n"
"  backu create --key k --base idx --index-out idx.new ~/data \\\n"
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
    if (cmd == "keygen"_s) return cmdKeygen(argc, argv, 2);
    if (cmd == "help"_s || cmd == "--help"_s || cmd == "-h"_s) { fputs(kHelp, stdout); return kExitOk; }
    if (cmd == "version"_s || cmd == "--version"_s) { puts("backu " BACKU_VERSION); return kExitOk; }
    fprintf(stderr, "backu: unknown command '%s' (run `backu help`)\n", argv[1]);
    return kExitUsage;
}
