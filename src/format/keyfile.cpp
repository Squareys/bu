// keyfile.cpp — see keyfile.hpp for the layout and why it is shaped so.
//
// Every secret that passes through here (passphrase-derived KEK, its AES
// schedule, the unwrapped key) lives in a local that is wiped before the
// function returns, on every path.

#include "format/keyfile.hpp"
#include "core/bytes.hpp"
#include "io/io.hpp"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace bk {

namespace {

// Same trick as the container magic: CR LF ^Z make a newline-converting copy
// fail at the magic instead of somewhere in a slot.
constexpr u8 kMagic[8] = {'B', 'U', 'K', 'E', 'Y', '\r', '\n', 0x1a};
constexpr StringView kOldPrefix = "bu-key-1 "_s;
// BLAKE3 derive_key context for the key ID (hardcoded, globally unique; a
// format constant like the container contexts).
constexpr StringView kCtxKeyId = "bu 2026-10-27 key file key id v2"_s;

constexpr u32 kIdBytesKF = 16;
constexpr u32 kCheckBytes = 16;
constexpr u32 kHeaderAuthBytes = 32;     // header bytes the AAD and checksum cover
constexpr u32 kSlotParamBytes = 48;      // state .. reserved, before the wrapped key
constexpr u32 kSlotSealedBytes = kKeyBytes + kTagBytes;
constexpr u32 kSlotCheckOffset = kSlotParamBytes + kSlotSealedBytes;
static_assert(kSlotCheckOffset + kCheckBytes == kKeySlotBytes, "slot layout");
static_assert(kHeaderAuthBytes + kCheckBytes == kKeyHeaderBytes, "header layout");
static_assert(kKeyFileBytes == 944, "docs/format.md gives the key file size");

// Slot field offsets.
constexpr u32 kOffState = 0, kOffKdf = 1, kOffLanes = 2, kOffPasses = 4, kOffMem = 8, kOffSalt = 16,
              kOffNonce = 32;

u8* slotPtr(KeyFile& f, u32 i) { return f.bytes + kKeyHeaderBytes + i * kKeySlotBytes; }
const u8* slotPtr(const KeyFile& f, u32 i) { return f.bytes + kKeyHeaderBytes + i * kKeySlotBytes; }

void checksum(const u8* p, usize n, u8 out[kCheckBytes]) {
    u8 h[32];
    blake3Hash(p, n, h);
    memCopy(out, h, kCheckBytes);
}

bool checksumOk(const u8* p, usize n) {
    u8 c[kCheckBytes];
    checksum(p, n, c);
    return memEqual(c, p + n, kCheckBytes);
}

void keyIdOf(const Key& master, u8 out[kIdBytesKF]) {
    Key id;
    blake3DeriveKey(kCtxKeyId, master.b, kKeyBytes, id);
    memCopy(out, id.b, kIdBytesKF);
}

// header[0..32) ‖ slot index ‖ slot[0..48): everything a slot's meaning
// depends on except the sealed key itself.
constexpr u32 kAadBytes = kHeaderAuthBytes + 1 + kSlotParamBytes;
void slotAad(const KeyFile& f, u32 i, u8 out[kAadBytes]) {
    memCopy(out, f.bytes, kHeaderAuthBytes);
    out[kHeaderAuthBytes] = u8(i);
    memCopy(out + kHeaderAuthBytes + 1, slotPtr(f, i), kSlotParamBytes);
}

bool paramsValid(const KdfParams& k) {
    return k.passes >= kKdfMinPasses && k.passes <= kKdfMaxPasses && k.memKiB >= (kKdfMinMemMiB << 10) &&
           k.memKiB <= (kKdfMaxMemMiB << 10);
}

bool zeroBytes(const u8* p, usize n) {
    u8 acc = 0;
    for (usize i = 0; i < n; ++i) acc |= p[i];
    return acc == 0;
}

// Argon2id(pass, salt) -> AES key schedule. The raw KEK is wiped here; the
// schedule is the caller's to wipe.
bool slotKek(StringView pass, const u8* salt, const KdfParams& kdf, AeadKey& st, String& err) {
    Key kek;
    if (!kdfArgon2id(pass.ptr, pass.count, salt, kdf.passes, kdf.memKiB, kek.b, kKeyBytes, err)) return false;
    aeadInit(st, kek);
    secureZero(kek.b, kKeyBytes);
    return true;
}

} // namespace

bool keyFileParse(const u8* data, usize n, KeyFile& out, String& err) {
    if (n >= kOldPrefix.count && memEqual(data, kOldPrefix.ptr, kOldPrefix.count))
        return errSet(err, "a bu-key-1 plaintext key, the format before passphrase slots; this bu reads only "
                           "key files made by `bu key init` (key file format 2)");
    if (n < sizeof kMagic || !memEqual(data, kMagic, sizeof kMagic)) return errSet(err, "not a bu key file");
    if (n >= 10 && loadU16LE(data + 8) != kKeyFileVersion) return errSet(err, "unsupported key file version");
    if (n != kKeyFileBytes) return errSet(err, "damaged key file (wrong size)");
    if (!checksumOk(data, kHeaderAuthBytes) || loadU16LE(data + 10) != kKeySlots || loadU32LE(data + 12) != 0)
        return errSet(err, "damaged key file (header checksum mismatch)");
    memCopy(out.bytes, data, kKeyFileBytes);
    return true;
}

const u8* keyFileId(const KeyFile& f) { return f.bytes + 16; }

void keyFileSlot(const KeyFile& f, u32 i, KeySlotInfo& out) {
    out = KeySlotInfo();
    const u8* s = slotPtr(f, i);
    if (!checksumOk(s, kSlotCheckOffset)) { out.state = kSlotDamaged; out.why = "checksum mismatch"; return; }
    if (s[kOffState] == 0) {
        if (!zeroBytes(s, kSlotCheckOffset)) { out.state = kSlotDamaged; out.why = "empty slot with data"; }
        return;
    }
    if (s[kOffState] != 1) { out.state = kSlotDamaged; out.why = "unknown slot state"; return; }
    if (s[kOffKdf] != kKdfArgon2id || loadU16LE(s + kOffLanes) != 1) {
        out.state = kSlotDamaged; out.why = "unknown KDF"; return;
    }
    out.kdf.passes = loadU32LE(s + kOffPasses);
    out.kdf.memKiB = loadU32LE(s + kOffMem);
    if (!paramsValid(out.kdf) || loadU32LE(s + 12) != 0 || loadU32LE(s + 44) != 0) {
        out.state = kSlotDamaged; out.why = "KDF parameters out of range"; return;
    }
    out.state = kSlotActive;
}

bool keyFileSetSlot(KeyFile& f, u32 i, const Key& master, StringView pass, const KdfParams& kdf, String& err) {
    if (i >= kKeySlots || !paramsValid(kdf)) return errSet(err, "invalid key slot or KDF parameters");
    if (pass.count == 0 || pass.count > kPassphraseMax) return errSet(err, "invalid passphrase length");
    u8 s[kKeySlotBytes];
    memSet(s, 0, sizeof s);
    s[kOffState] = 1;
    s[kOffKdf] = kKdfArgon2id;
    storeU16LE(s + kOffLanes, 1);
    storeU32LE(s + kOffPasses, kdf.passes);
    storeU32LE(s + kOffMem, kdf.memKiB);
    if (!randomBytes(s + kOffSalt, kKdfSaltBytes, err) || !randomBytes(s + kOffNonce, kNonceBytes, err)) return false;
    AeadKey st;
    if (!slotKek(pass, s + kOffSalt, kdf, st, err)) return false;
    // The AAD reads the slot's parameter bytes from the file image, so put
    // them in place first; the slot is complete only after the seal.
    memCopy(slotPtr(f, i), s, kSlotParamBytes);
    u8 aad[kAadBytes];
    slotAad(f, i, aad);
    aeadSeal(st, s + kOffNonce, aad, sizeof aad, master.b, kKeyBytes, s + kSlotParamBytes);
    secureZero(&st, sizeof st);
    checksum(s, kSlotCheckOffset, s + kSlotCheckOffset);
    memCopy(slotPtr(f, i), s, kKeySlotBytes);
    return true;
}

void keyFileClearSlot(KeyFile& f, u32 i) {
    u8* s = slotPtr(f, i);
    memSet(s, 0, kKeySlotBytes);
    checksum(s, kSlotCheckOffset, s + kSlotCheckOffset);
}

bool keyFileRemoveSlot(KeyFile& f, u32 slot, String& err) {
    if (slot >= kKeySlots) return errSet(err, "no such key slot");
    KeySlotInfo info;
    keyFileSlot(f, slot, info);
    if (info.state == kSlotEmpty) return errSet(err, "that key slot is empty");
    u32 others = 0;
    for (u32 i = 0; i < kKeySlots; ++i) {
        KeySlotInfo s;
        keyFileSlot(f, i, s);
        if (s.state == kSlotActive && i != slot) ++others;
    }
    if (others == 0)
        return errSet(err, "refusing to remove the last usable key slot: no passphrase would open the file, "
                           "and the backups made with it would be unreadable");
    keyFileClearSlot(f, slot);
    return true;
}

bool keyFileCreate(const Key& master, StringView pass, const KdfParams& kdf, KeyFile& out, String& err) {
    memSet(out.bytes, 0, kKeyFileBytes);
    memCopy(out.bytes, kMagic, sizeof kMagic);
    storeU16LE(out.bytes + 8, kKeyFileVersion);
    storeU16LE(out.bytes + 10, kKeySlots);
    keyIdOf(master, out.bytes + 16);
    checksum(out.bytes, kHeaderAuthBytes, out.bytes + kHeaderAuthBytes);
    for (u32 i = 0; i < kKeySlots; ++i) keyFileClearSlot(out, i);
    return keyFileSetSlot(out, 0, master, pass, kdf, err);
}

bool keyFileUnlock(const KeyFile& f, StringView pass, Key& master, u32& slot, u32& kdfFailed, String& err) {
    u32 tried = 0, damaged = 0;
    kdfFailed = 0;
    String kdfWhy;
    for (u32 i = 0; i < kKeySlots; ++i) {
        KeySlotInfo info;
        keyFileSlot(f, i, info);
        if (info.state == kSlotDamaged) { ++damaged; continue; }
        if (info.state != kSlotActive) continue;
        ++tried;
        const u8* s = slotPtr(f, i);
        AeadKey st;
        if (!slotKek(pass, s + kOffSalt, info.kdf, st, kdfWhy)) { kdfFailed |= 1u << i; continue; }
        u8 aad[kAadBytes];
        slotAad(f, i, aad);
        const bool ok = aeadOpen(st, s + kOffNonce, aad, sizeof aad, s + kSlotParamBytes, kKeyBytes, master.b);
        secureZero(&st, sizeof st);
        if (!ok) continue;
        u8 id[kIdBytesKF];
        keyIdOf(master, id);
        if (!memEqual(id, keyFileId(f), kIdBytesKF)) {
            secureZero(master.b, kKeyBytes);
            return errSet(err, "key slot unwraps to a key that does not match the file's key ID (damaged file)");
        }
        slot = i;
        return true;
    }
    if (tried == 0)
        return errSet(err, damaged ? "every key slot is damaged" : "damaged key file (no key slot in use)");
    if (kdfFailed) {
        u32 n = 0;
        for (u32 m = kdfFailed; m; m &= m - 1) ++n;
        if (n == tried) return errSet(err, "no key slot could be tried: ", kdfWhy.view());
        return errSet(err, "wrong passphrase, or one of the slots that could not be tried (", kdfWhy.view(), ")");
    }
    if (damaged)
        return errSet(err, "wrong passphrase (damaged key slots were skipped; `bu key info` lists them)");
    return errSet(err, "wrong passphrase");
}

bool kdfParamsWeak(const KdfParams& k) {
    const u32 mib = k.memKiB >> 10;
    return mib < kKdfWeakMemMiB || (k.passes < kKdfWeakPasses && mib < kKdfWeakOnePassMemMiB);
}

u32 kdfAutoMemMiB() {
    const long pages = sysconf(_SC_PHYS_PAGES), pageSize = sysconf(_SC_PAGESIZE);
    u64 quarter = kKdfDefaultMaxMemMiB;
    if (pages > 0 && pageSize > 0) quarter = (u64(pages) * u64(pageSize) >> 20) / 4;
    if (quarter > kKdfDefaultMaxMemMiB) quarter = kKdfDefaultMaxMemMiB;
    if (quarter < kKdfAutoMinMemMiB) quarter = kKdfAutoMinMemMiB;
    return u32(quarter);
}

namespace {

i64 monoNs() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return i64(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}

// Milliseconds one Argon2id run with these parameters takes here.
bool timeKdf(u32 passes, u32 memKiB, double& ms, String& err) {
    const u8 salt[kKdfSaltBytes] = {};
    u8 out[kKeyBytes];
    const i64 t0 = monoNs();
    if (!kdfArgon2id("calibration", 11, salt, passes, memKiB, out, sizeof out, err)) return false;
    ms = double(monoNs() - t0) / 1e6;
    return true;
}

} // namespace

bool kdfCalibrate(u32 targetMs, u32 memMiB, KdfParams& out, String& err) {
    // Like cryptsetup's benchmark: fix the memory, then find the passes that
    // fill the target time. One run of one pass and one of two separate the
    // per-run cost (mapping and touching the memory, the first and last
    // blocks) from the per-pass cost, which a single run would lump together
    // and so undershoot the target by the fixed part.
    const bool autoMem = memMiB == 0;
    if (autoMem) memMiB = kdfAutoMemMiB();
    for (;;) {
        double one = 0, two = 0;
        if (!timeKdf(1, memMiB << 10, one, err) || !timeKdf(2, memMiB << 10, two, err)) return false;
        double perPass = two - one;
        if (perPass <= 0.01) perPass = one > 0.01 ? one : 0.01;
        double fixed = one - perPass;
        if (fixed < 0) fixed = 0;
        // Automatic memory gives way first: three passes (RFC 9106's second
        // recommendation) should fit the target before memory stays this big.
        if (autoMem && fixed + 3 * perPass > double(targetMs) && memMiB / 2 >= kKdfAutoMinMemMiB) {
            memMiB /= 2;
            continue;
        }
        double passes = (double(targetMs) - fixed) / perPass;
        u32 p = passes < 1 ? 1 : (passes > kKdfMaxPasses ? kKdfMaxPasses : u32(passes + 0.5));
        if (p < kKdfMinPasses) p = kKdfMinPasses;
        out.passes = p;
        out.memKiB = memMiB << 10;
        return true;
    }
}

bool keyFileRead(const char* path, KeyFile& out, String& err) {
    Array<u8> data;
    if (!readWholeFile(path, 4096, data, err)) return false;
    String why;
    const bool ok = keyFileParse(data.ptr, data.count, out, why);
    secureZero(data.ptr, data.count);
    if (!ok) return errSet(err, path, ": ", why.view());
    return true;
}

bool keyFileWriteNew(const char* path, const KeyFile& f, String& err) {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        if (errno == EEXIST) return errSet(err, path, ": already exists; bu never overwrites a key file");
        return errSet(err, path, ": ", strerror(errno));
    }
    bool ok = writeAll(fd, f.bytes, kKeyFileBytes) && fsync(fd) == 0;
    const int e = errno;
    if (::close(fd) != 0) ok = false;
    if (!ok) { ::unlink(path); return errSet(err, path, ": ", strerror(e)); }
    return true;
}

bool keyFileCheckReplaceable(const char* path, String& err) {
    struct stat st;
    if (lstat(path, &st) != 0) return errSet(err, path, ": ", strerror(errno));
    if (S_ISLNK(st.st_mode))
        return errSet(err, path, ": is a symbolic link; bu replaces a key file by renaming a new one over it, "
                                 "which would replace the link and leave the file it points to unchanged; "
                                 "name the file itself (realpath ", path, ")");
    if (!S_ISREG(st.st_mode)) return errSet(err, path, ": not a regular file");
    if (st.st_nlink > 1)
        return errSet(err, path, ": has other hard links; replacing it would leave them with the old slots; "
                                 "remove the other names or work on a copy");
    return true;
}

bool keyFileReplace(const char* path, const KeyFile& f, String& err) {
    if (!keyFileCheckReplaceable(path, err)) return false;
    return writeFileAtomic(path, f.bytes, kKeyFileBytes, err);
}

} // namespace bk
