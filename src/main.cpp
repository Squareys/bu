// main.cpp — `bu`: subcommand dispatch and the help text.
//
// bu works on chain files through file descriptors and never opens a network
// connection: a chain lives on a local disk, a network mount (NFS, SMB,
// sshfs, rclone) or goes through a pipe (ssh, `aws s3 cp -`), and bu does
// not care which. Exit status: 0 ok, 1 runtime failure, 2 usage error, 3
// create finished with warnings (see the help text).

#include "cmd/args.hpp"
#include "cmd/commands.hpp"
#include "core/string_view.hpp"

#include <stdio.h>

using namespace bk;

namespace {

const char kHelp[] =
"bu " BU_VERSION " — backup utility: encrypted, deduplicating, incremental backups in one chain file\n"
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
"  bu create (--key KEYFILE | --no-key) [--base INDEX] [--index-out INDEX]\n"
"            [-C DIR] [--exclude PATTERN]... [-x] [-j N] [--no-files-cache] [-v]\n"
"            CHAIN PATH...\n"
"      Back up PATH... into CHAIN. A new or empty file gets a full backup; a\n"
"      chain gets an increment appended (its latest snapshot is the base:\n"
"      only new chunks are stored, and files whose metadata is unchanged are\n"
"      not even read; --no-files-cache: read them). CHAIN - writes to stdout;\n"
"      to a pipe, with the base from --base INDEX. --index-out writes the new\n"
"      snapshot's index (for the next --base). --no-key: unencrypted, with\n"
"      checksums against damage but no protection against tampering.\n"
"      Each PATH is stored as given, less a leading / or ./ (/srv/data is\n"
"      srv/data); -C DIR reads the PATHs from DIR, so -C /srv/data . stores\n"
"      app.db, not srv/data/app.db. CHAIN, --base, --index-out and the key\n"
"      stay relative to where bu was started. --exclude PATTERN (repeatable)\n"
"      leaves out what matches, and a directory's contents with it: a glob\n"
"      with a / matches the whole stored path, one without matches the last\n"
"      name at any depth. -x, --one-file-system: do not descend into a\n"
"      directory on another filesystem than its PATH (it is stored empty).\n"
"\n"
"  bu restore [--key KEYFILE] [--index INDEX] [-C DIR] [-j N] [-v] CHAIN... [-- PATH...]\n"
"      Restore the latest snapshot into DIR (default: the current directory),\n"
"      or only the PATHs given after --. Every chunk is authenticated and\n"
"      verified. A chain read from a pipe (CHAIN -) needs --index.\n"
"\n"
"  bu merge [--key KEYFILE] [-o OUT] [-j N] [-v] CHAIN...\n"
"      One full segment with the chain's latest snapshot and only the chunks\n"
"      it references, to OUT (default: stdout). -o naming the input compacts\n"
"      it in place; increments appended later keep working.\n"
"\n"
"  bu check [--key KEYFILE] [-j N] [-v] CHAIN...\n"
"      Authenticate every record and verify every snapshot is complete.\n"
"\n"
"  bu list [--key KEYFILE] CHAIN... | INDEX\n"
"      Show the segments, and the latest snapshot's tree.\n"
"\n"
"  bu index [--key KEYFILE] -o INDEX CHAIN...\n"
"      Write the index of the latest snapshot (for create --base, restore\n"
"      --index).\n"
"\n"
"CHAIN... is a chain file, or the segments of one as separate files, in\n"
"order; - is stdin (or stdout for create). A regular file is read by\n"
"seeking, a pipe as a stream. Reading commands learn from the chain whether\n"
"it is encrypted: --key is required for an encrypted chain and refused for\n"
"an unencrypted one (--no-key may be given to say so). Every command that\n"
"unlocks a key file asks for the passphrase on the terminal, or reads it\n"
"from --passphrase-file PATH (its first line) or --passphrase-fd N; key add\n"
"and passwd read the new one from --new-passphrase-file PATH or\n"
"--new-passphrase-fd N (key init: from --passphrase-file or --passphrase-fd).\n"
"\n"
"-j N sets the worker threads (default: online CPUs; restore: at most 8;\n"
"create: the CPUs less three quarters of its readers).\n"
"\n"
"Exit status: 0 ok; 1 failure; 2 usage error; 3 create finished with\n"
"warnings (unreadable files were left out, or a file changed size while it\n"
"was read): the backup is complete and valid, the warnings say what it lacks.\n"
"\n"
"Example (daily, from cron):\n"
"  bu create --key k --passphrase-file ~/.bu-pass -C ~/data /mnt/backup/data.bu .\n";

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
    if (cmd == "version"_s || cmd == "--version"_s) { puts("bu " BU_VERSION " (" BU_COMMIT ", " BU_BUILD_TYPE ")"); return kExitOk; }
    fprintf(stderr, "bu: unknown command '%s' (run `bu help`)\n", argv[1]);
    return kExitUsage;
}
