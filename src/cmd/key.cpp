// key.cpp — `bu key init|add|remove|passwd|info`: the key file's lifecycle.
//
// The master key is made once, by init, from getrandom, and never leaves the
// process unwrapped: there is no command that prints it and no flag that
// reads it. Everything else edits passphrase slots around the same key, so
// none of these commands touches a backup, and backups made before a
// passphrase change open with the new passphrase.
//
// Changes are written with keyFileReplace (temp file, fsync, rename), which
// refuses a key path that is a symlink or has other hard links: the rename
// would leave the real file, and with it a removed passphrase, in place.
// add, passwd and remove check that before asking for anything. There is no
// lock: two `bu key` commands run at once on one file both read the old
// slots and the second rename wins, dropping the first one's change. Key
// management is rare and interactive; a lock file would be a second thing
// to go stale. Every
// command that adds or rewrites a slot first unlocks the file with an
// existing passphrase, so knowing one passphrase is what it takes to manage
// the others, as with cryptsetup luksAddKey/luksKillSlot.

#include "cmd/args.hpp"
#include "cmd/commands.hpp"
#include "cmd/passphrase.hpp"
#include "format/keyfile.hpp"

#include <stdio.h>
#include <sys/stat.h>

namespace bk {

namespace {

const StringView kPassHint = "--passphrase-file PATH or --passphrase-fd N"_s;
const StringView kNewPassHint = "--new-passphrase-file PATH or --new-passphrase-fd N"_s;

bool onePath(const char* sub, const Args& a) {
    if (a.positional.count == 1) return true;
    fprintf(stderr, "bu key %s: name exactly one KEYFILE\n(run `bu help` for usage)\n", sub);
    return false;
}

String promptFor(StringView what, const char* path) {
    String p(what);
    p.append(StringView(path));
    p.append(": "_s);
    return p;
}

// KDF parameters from the flags: both given, used as given; otherwise the
// passes are calibrated to the target time (memory as given, or automatic).
bool kdfFromArgs(const Args& a, KdfParams& out) {
    String err;
    if (a.kdfPasses) {
        out.passes = a.kdfPasses;
        out.memKiB = (a.kdfMemMiB ? a.kdfMemMiB : kdfAutoMemMiB()) << 10;
        return true;
    }
    if (!kdfCalibrate(a.kdfTargetMs ? a.kdfTargetMs : kKdfDefaultTargetMs, a.kdfMemMiB, out, err)) {
        report(err);
        return false;
    }
    return true;
}

void describeKdf(const KdfParams& k, char* buf, usize cap) {
    snprintf(buf, cap, "argon2id, %u MiB, %u pass%s%s", k.memKiB >> 10, k.passes, k.passes == 1 ? "" : "es",
             kdfParamsWeak(k) ? " (weak)" : "");
}

// Said when a slot is written with parameters below RFC 9106's: a warning,
// since the user chose them (or this host is too slow for more).
void warnIfWeak(const char* path, u32 slot, const KdfParams& k) {
    if (kdfParamsWeak(k))
        fprintf(stderr, "bu: warning: %s: slot %u is below 64 MiB / 3 passes; offline guessing is cheaper than "
                        "RFC 9106 recommends (raise --kdf-memory or --kdf-time)\n", path, slot);
}

// Refused before any passphrase is asked for (keyFileCheckReplaceable).
bool replaceable(const char* path) {
    String err;
    if (keyFileCheckReplaceable(path, err)) return true;
    report(err);
    return false;
}

// Read the file and unlock it with an existing passphrase.
bool openAndUnlock(const Args& a, const char* path, KeyFile& f, Key& master, u32& slot) {
    String err;
    if (!cryptoCpuCheck(err) || !keyFileRead(path, f, err)) { report(err); return false; }
    warnIfShared("key file", path);
    Passphrase pass;
    if (!passphraseGet(a.passFile, a.passFd, promptFor("Passphrase for "_s, path), kPassHint, false, pass, err)) {
        report(err);
        return false;
    }
    u32 kdfFailed = 0;
    const bool ok = keyFileUnlock(f, pass.view(), master, slot, kdfFailed, err);
    warnKdfSkipped(path, f, kdfFailed);
    if (!ok) {
        String msg;
        errSet(msg, path, ": ", err.view());
        report(msg);
        return false;
    }
    return true;
}

// A new passphrase (asked twice on a terminal) into `slot`, then the file
// replaced on disk.
bool writeSlot(const Args& a, const char* path, KeyFile& f, u32 slot, const Key& master, const char* file,
               int fd, StringView hint) {
    String err;
    Passphrase pass;
    if (!passphraseGet(file, fd, promptFor("New passphrase for "_s, path), hint, true, pass, err)) {
        report(err);
        return false;
    }
    KdfParams kdf;
    if (!kdfFromArgs(a, kdf)) return false;
    if (!keyFileSetSlot(f, slot, master, pass.view(), kdf, err) || !keyFileReplace(path, f, err)) {
        report(err);
        return false;
    }
    char desc[96];
    describeKdf(kdf, desc, sizeof desc);
    fprintf(stderr, "bu: %s: slot %u set (%s)\n", path, slot, desc);
    warnIfWeak(path, slot, kdf);
    return true;
}

int keyInit(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("key init", argc, argv, first, kArgPass | kArgKdf, a)) return kExitUsage;
    if (!onePath("init", a)) return kExitUsage;
    const char* path = a.positional[0];
    String err;
    if (!cryptoCpuCheck(err)) { report(err); return kExitRuntime; }
    // Refuse before asking for anything: the file may be somebody's only key.
    struct stat st;
    if (lstat(path, &st) == 0) {
        fprintf(stderr, "bu: %s: already exists; bu never overwrites a key file\n", path);
        return kExitRuntime;
    }
    Passphrase pass;
    if (!passphraseGet(a.passFile, a.passFd, promptFor("New passphrase for "_s, path), kPassHint, true, pass, err)) {
        report(err);
        return kExitRuntime;
    }
    KdfParams kdf;
    if (!kdfFromArgs(a, kdf)) return kExitRuntime;
    Key master;
    KeyFile f;
    const bool ok = randomBytes(master.b, kKeyBytes, err) && keyFileCreate(master, pass.view(), kdf, f, err) &&
                    keyFileWriteNew(path, f, err);
    secureZero(master.b, kKeyBytes);
    if (!ok) { report(err); return kExitRuntime; }
    char desc[96];
    describeKdf(kdf, desc, sizeof desc);
    fprintf(stderr,
            "bu: %s: new key, slot 0 (%s)\n"
            "bu: the backups need this file AND a passphrase; keep a copy of the file away from the backups\n",
            path, desc);
    warnIfWeak(path, 0, kdf);
    return kExitOk;
}

int keyAdd(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("key add", argc, argv, first, kArgPass | kArgNewPass | kArgKdf, a)) return kExitUsage;
    if (!onePath("add", a)) return kExitUsage;
    const char* path = a.positional[0];
    if (!replaceable(path)) return kExitRuntime;
    String err;
    KeyFile f;
    if (!keyFileRead(path, f, err)) { report(err); return kExitRuntime; }
    u32 freeSlot = kInvalidIndex;
    for (u32 i = 0; i < kKeySlots && freeSlot == kInvalidIndex; ++i) {
        KeySlotInfo info;
        keyFileSlot(f, i, info);
        if (info.state == kSlotEmpty) freeSlot = i;
    }
    if (freeSlot == kInvalidIndex) {
        fprintf(stderr, "bu: %s: all %u key slots are in use (remove one first)\n", path, kKeySlots);
        return kExitRuntime;
    }
    Key master;
    u32 slot = 0;
    if (!openAndUnlock(a, path, f, master, slot)) return kExitRuntime;
    const bool ok = writeSlot(a, path, f, freeSlot, master, a.newPassFile, a.newPassFd, kNewPassHint);
    secureZero(master.b, kKeyBytes);
    return ok ? kExitOk : kExitRuntime;
}

int keyPasswd(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("key passwd", argc, argv, first, kArgPass | kArgNewPass | kArgKdf, a)) return kExitUsage;
    if (!onePath("passwd", a)) return kExitUsage;
    const char* path = a.positional[0];
    if (!replaceable(path)) return kExitRuntime;
    KeyFile f;
    Key master;
    u32 slot = 0;
    if (!openAndUnlock(a, path, f, master, slot)) return kExitRuntime;
    const bool ok = writeSlot(a, path, f, slot, master, a.newPassFile, a.newPassFd, kNewPassHint);
    secureZero(master.b, kKeyBytes);
    return ok ? kExitOk : kExitRuntime;
}

int keyRemove(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("key remove", argc, argv, first, kArgPass | kArgSlot, a)) return kExitUsage;
    if (!onePath("remove", a)) return kExitUsage;
    const char* path = a.positional[0];
    if (!replaceable(path)) return kExitRuntime;
    KeyFile f;
    Key master;
    u32 opened = 0;
    if (!openAndUnlock(a, path, f, master, opened)) return kExitRuntime;
    secureZero(master.b, kKeyBytes);
    const u32 target = a.slot != kInvalidIndex ? a.slot : opened;
    String err;
    if (!keyFileRemoveSlot(f, target, err)) {
        fprintf(stderr, "bu: %s: slot %u: %s\n", path, target, err.c_str());
        return kExitRuntime;
    }
    if (!keyFileReplace(path, f, err)) { report(err); return kExitRuntime; }
    fprintf(stderr, "bu: %s: slot %u removed (copies of this file made earlier still have it)\n", path, target);
    return kExitOk;
}

int keyInfo(int argc, char** argv, int first) {
    Args a;
    if (!argsParse("key info", argc, argv, first, 0, a)) return kExitUsage;
    if (!onePath("info", a)) return kExitUsage;
    const char* path = a.positional[0];
    String err;
    KeyFile f;
    if (!keyFileRead(path, f, err)) { report(err); return kExitRuntime; }
    warnIfShared("key file", path);
    char id[33];
    hexEncode(keyFileId(f), 16, id);
    id[32] = 0;
    printf("%s: bu key file, format %u, key ID %s\n", path, kKeyFileVersion, id);
    u32 damaged = 0;
    for (u32 i = 0; i < kKeySlots; ++i) {
        KeySlotInfo s;
        keyFileSlot(f, i, s);
        if (s.state == kSlotEmpty) { printf("slot %u: empty\n", i); continue; }
        if (s.state == kSlotDamaged) { printf("slot %u: DAMAGED (%s)\n", i, s.why); ++damaged; continue; }
        char desc[96];
        describeKdf(s.kdf, desc, sizeof desc);
        printf("slot %u: passphrase, %s\n", i, desc);
    }
    return damaged ? kExitRuntime : kExitOk;
}

} // namespace

int cmdKey(int argc, char** argv, int first) {
    const StringView sub = first < argc ? StringView(argv[first]) : ""_s;
    if (sub == "init"_s) return keyInit(argc, argv, first + 1);
    if (sub == "add"_s) return keyAdd(argc, argv, first + 1);
    if (sub == "remove"_s) return keyRemove(argc, argv, first + 1);
    if (sub == "passwd"_s) return keyPasswd(argc, argv, first + 1);
    if (sub == "info"_s) return keyInfo(argc, argv, first + 1);
    if (sub.empty()) fprintf(stderr, "bu key: name a subcommand: init, add, remove, passwd or info\n");
    else fprintf(stderr, "bu key: unknown subcommand '%s' (init, add, remove, passwd or info)\n", argv[first]);
    return kExitUsage;
}

} // namespace bk
