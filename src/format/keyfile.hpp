// keyfile.hpp — the key file: a random master key, stored only wrapped in
// passphrase keyslots (the LUKS design; docs/design.md §3, docs/format.md).
//
// The 32-byte master key K is drawn from getrandom once, by `bu key init`,
// and is never typed, printed or stored in the clear. Each of up to
// kKeySlots slots holds K sealed with AES-256-GCM under a key-encryption key
// that Argon2id stretches from one passphrase and the slot's own salt. Any
// slot's passphrase recovers the same K, so passphrases can be added,
// changed and removed without touching a single backup: everything in a
// backup is derived from K (format/segment.hpp), never from a passphrase.
//
// Fixed layout, 944 bytes (docs/format.md has it byte by byte):
//
//   header  48 bytes: magic "BUKEY\r\n\x1a" | u16 version 2 | u16 slot count 8
//           | u32 reserved | key ID[16] | checksum[16]
//   slot    112 bytes × 8: u8 state | u8 kdf | u16 lanes | u32 passes
//           | u32 memory KiB | u32 reserved | salt[16] | nonce[12]
//           | u32 reserved | wrapped K[32] | tag[16] | checksum[16]
//
// Two layers answer two different questions. The checksums (unkeyed BLAKE3,
// 16 bytes, one for the header and one per slot) catch accidental damage, so
// a flipped bit is reported as a damaged file or slot rather than as a wrong
// passphrase, and a damaged slot is skipped without making the others
// unusable. The AEAD is what stops an attacker: its associated data is the
// header (magic, version, key ID) plus the slot index and every parameter
// byte of the slot, so a slot cannot be moved to another index or file, nor
// its KDF parameters edited, without failing authentication. The key ID, a
// BLAKE3 derive_key output of K, is checked after unwrapping as well.
//
// Rejected: one slot (no second passphrase, no in-place change without a
// window where the only copy is being rewritten); variable-length slots or
// a text format (more parser for no gain: the file is 944 bytes); a raw-key
// slot for automation (unattended runs read a passphrase from a file or a
// descriptor instead, which keeps one slot type and one code path).
#pragma once

#include "core/string.hpp"
#include "crypto/crypto.hpp"

namespace bk {

constexpr u32 kKeySlots = 8;
constexpr u32 kKeyHeaderBytes = 48;
constexpr u32 kKeySlotBytes = 112;
constexpr u32 kKeyFileBytes = kKeyHeaderBytes + kKeySlots * kKeySlotBytes;
constexpr u16 kKeyFileVersion = 2;
constexpr u8 kKdfArgon2id = 1;

// Bounds on KDF parameters, enforced both on the command line (refused, not
// clamped) and when reading a slot (a slot outside them is unusable: a
// tampered file must not be able to ask for 4 TiB of memory).
constexpr u32 kKdfMinMemMiB = 8;
constexpr u32 kKdfMaxMemMiB = 4096;
constexpr u32 kKdfMinPasses = 1;
constexpr u32 kKdfMaxPasses = 100;
// Calibration (kdfCalibrate): the time one unlock should take, and the
// memory used when none is given: min(1 GiB, a quarter of physical memory),
// halved down to 64 MiB while three passes would not fit the target.
constexpr u32 kKdfDefaultTargetMs = 2000;
constexpr u32 kKdfDefaultMaxMemMiB = 1024;
constexpr u32 kKdfAutoMinMemMiB = 64;
// Below these a slot is reported as weak (kdfParamsWeak): RFC 9106's second
// recommended option is 64 MiB and three passes. Its first option, 2 GiB and
// one pass, is not weak, so fewer passes are fine at 2 GiB and up.
constexpr u32 kKdfWeakMemMiB = 64;
constexpr u32 kKdfWeakPasses = 3;
constexpr u32 kKdfWeakOnePassMemMiB = 2048;

constexpr u32 kPassphraseMax = 1024;

struct KdfParams {
    u32 passes = 0;
    u32 memKiB = 0;
};

struct KeyFile {
    u8 bytes[kKeyFileBytes];
};

enum KeySlotState : u8 { kSlotEmpty = 0, kSlotActive = 1, kSlotDamaged = 2 };

struct KeySlotInfo {
    KeySlotState state = kSlotEmpty;
    KdfParams kdf;           // only for kSlotActive
    const char* why = "";    // only for kSlotDamaged; never null
};

// Validate a key file image: size, magic, version, header checksum. A
// bu-key-1 plaintext key (the format before keyslots) is refused by name.
// Slots are not checked here; keyFileSlot does that per slot.
[[nodiscard]] bool keyFileParse(const u8* data, usize n, KeyFile& out, String& err);
void keyFileSlot(const KeyFile& f, u32 slot, KeySlotInfo& out);
// The first 16 bytes of BLAKE3 derive_key(kCtxKeyId, K), as stored.
const u8* keyFileId(const KeyFile& f);

// A new key file holding `master` in slot 0 under `pass`.
[[nodiscard]] bool keyFileCreate(const Key& master, StringView pass, const KdfParams& kdf, KeyFile& out,
                                 String& err);
// Try every intact active slot with `pass`. On success `master` holds K and
// `slot` the index that opened. A slot whose Argon2id run fails (its memory
// cannot be allocated on this host) is skipped, not fatal: another slot,
// perhaps made for this host, may still open. `kdfFailed` gets a bit per
// such slot, for the caller to warn about. Errors say "wrong passphrase" only
// when every slot that could be tried was tried and none opened.
[[nodiscard]] bool keyFileUnlock(const KeyFile& f, StringView pass, Key& master, u32& slot, u32& kdfFailed,
                                 String& err);
// (Re)write `slot` with `master` under `pass`: fresh salt and nonce.
[[nodiscard]] bool keyFileSetSlot(KeyFile& f, u32 slot, const Key& master, StringView pass, const KdfParams& kdf,
                                  String& err);
// Mark `slot` empty (zeroes it), unconditionally.
void keyFileClearSlot(KeyFile& f, u32 slot);
// Remove `slot` (active or damaged), refusing an empty slot and the last
// active one: a key file no passphrase opens makes every backup unreadable.
[[nodiscard]] bool keyFileRemoveSlot(KeyFile& f, u32 slot, String& err);

// Parameters that make one unlock take about `targetMs` on this machine.
// memMiB 0 means automatic (see kKdfDefaultMaxMemMiB); otherwise it is used
// as given and only the passes are calibrated.
[[nodiscard]] bool kdfCalibrate(u32 targetMs, u32 memMiB, KdfParams& out, String& err);
// The automatic memory cost on this machine, in MiB.
u32 kdfAutoMemMiB();
// True for parameters below RFC 9106's recommendations (kKdfWeak*). Only a
// warning: the parameters are the user's choice, and the AEAD stops anyone
// else from lowering them.
bool kdfParamsWeak(const KdfParams& k);

// Read and parse; `path` prefixes every error.
[[nodiscard]] bool keyFileRead(const char* path, KeyFile& out, String& err);
// Write a NEW key file: created 0600 with O_EXCL, so an existing file
// (another key, the only way into somebody's backups) is never replaced.
[[nodiscard]] bool keyFileWriteNew(const char* path, const KeyFile& f, String& err);
// Replace an existing key file atomically (temp file, fsync, rename): a
// crash leaves the old file or the new one, never a torn mix of slots.
// Refuses a path that is a symlink or has other hard links (see
// keyFileCheckReplaceable).
[[nodiscard]] bool keyFileReplace(const char* path, const KeyFile& f, String& err);
// Whether keyFileReplace can replace `path` in place. A rename replaces the
// name, not the file behind it: through a symlink the link would become a
// regular file while the file it pointed to kept the old slots, and with a
// second hard link the other name would keep them — so a removed passphrase
// would go on opening the key. Refusing (and naming the real file) was
// chosen over resolving the link and replacing its target: the target's
// directory may not be the user's to write, and a rewrite that silently
// lands somewhere else is the surprise this check exists to prevent.
[[nodiscard]] bool keyFileCheckReplaceable(const char* path, String& err);

} // namespace bk
