// test_keyfile.cpp — the key file (format/keyfile.hpp).
//
// Guards: every slot unwraps the same master key and only under its own
// passphrase; a wrong passphrase is reported as one and damage as damage;
// a slot cannot be moved to another index or into another key file, nor its
// KDF parameters edited, even by someone who fixes up the checksum (the AEAD's
// associated data covers them); all eight slots work and a ninth does not
// exist; the last usable slot cannot be removed; and the old bu-key-1
// plaintext format is refused by name. KDF costs are the minimum bu accepts
// (8 MiB, one pass) so the file runs in well under a second.

#include "core/bytes.hpp"
#include "format/keyfile.hpp"
#include "test.hpp"

using namespace bk;

namespace {

const KdfParams kCheap = {1, 8u << 10};

Key keyOf(u8 v) {
    Key k;
    memSet(k.b, v, kKeyBytes);
    return k;
}

u8* slotAt(KeyFile& f, u32 i) { return f.bytes + kKeyHeaderBytes + i * kKeySlotBytes; }

// What an attacker who edits a slot would do so that the damage check passes.
void fixChecksum(KeyFile& f, u32 i) {
    u8 h[32];
    blake3Hash(slotAt(f, i), kKeySlotBytes - 16, h);
    memCopy(slotAt(f, i) + kKeySlotBytes - 16, h, 16);
}

bool opens(const KeyFile& f, StringView pass, const Key& want, u32 wantSlot) {
    Key k;
    u32 slot = 99;
    String err;
    return keyFileUnlock(f, pass, k, slot, err) && memEqual(k.b, want.b, kKeyBytes) && slot == wantSlot;
}

bool failsWith(const KeyFile& f, StringView pass, StringView msg) {
    Key k;
    u32 slot = 0;
    String err;
    return !keyFileUnlock(f, pass, k, slot, err) && err.view().startsWith(msg);
}

} // namespace

BK_TEST(keyfile_wraps_and_unwraps_one_key_under_each_passphrase) {
    const Key master = keyOf(7);
    KeyFile f;
    String err;
    BK_REQUIRE(keyFileCreate(master, "first"_s, kCheap, f, err));
    BK_CHECK(opens(f, "first"_s, master, 0));
    BK_CHECK(failsWith(f, "First"_s, "wrong passphrase"_s));
    BK_CHECK(failsWith(f, "firs"_s, "wrong passphrase"_s));
    BK_REQUIRE(keyFileSetSlot(f, 3, master, "second"_s, kCheap, err));
    BK_CHECK(opens(f, "second"_s, master, 3));
    BK_CHECK(opens(f, "first"_s, master, 0));
    // The image round-trips through the parser, and the master key appears
    // nowhere in it.
    KeyFile g;
    BK_REQUIRE(keyFileParse(f.bytes, kKeyFileBytes, g, err));
    BK_CHECK(opens(g, "second"_s, master, 3));
    bool found = false;
    for (u32 i = 0; i + kKeyBytes <= kKeyFileBytes; ++i) found |= memEqual(f.bytes + i, master.b, kKeyBytes);
    BK_CHECK(!found);
    KeySlotInfo info;
    keyFileSlot(f, 3, info);
    BK_CHECK(info.state == kSlotActive && info.kdf.passes == 1 && info.kdf.memKiB == (8u << 10));
    keyFileSlot(f, 1, info);
    BK_CHECK(info.state == kSlotEmpty);
}

BK_TEST(keyfile_rewrapping_a_slot_changes_its_salt_and_nonce) {
    const Key master = keyOf(1);
    KeyFile f;
    String err;
    BK_REQUIRE(keyFileCreate(master, "pw"_s, kCheap, f, err));
    u8 before[kKeySlotBytes];
    memCopy(before, slotAt(f, 0), kKeySlotBytes);
    BK_REQUIRE(keyFileSetSlot(f, 0, master, "pw"_s, kCheap, err));
    BK_CHECK(!memEqual(before + 16, slotAt(f, 0) + 16, 16));      // salt
    BK_CHECK(!memEqual(before + 32, slotAt(f, 0) + 32, 12));      // nonce
    BK_CHECK(opens(f, "pw"_s, master, 0));
}

BK_TEST(keyfile_damage_is_not_a_wrong_passphrase) {
    const Key master = keyOf(2);
    KeyFile f;
    String err;
    BK_REQUIRE(keyFileCreate(master, "a"_s, kCheap, f, err));
    BK_REQUIRE(keyFileSetSlot(f, 1, master, "b"_s, kCheap, err));
    // A flipped bit in slot 0's wrapped key: the slot reads as damaged and
    // is skipped; slot 1 still opens.
    KeyFile d = f;
    slotAt(d, 0)[60] ^= 1;
    KeySlotInfo info;
    keyFileSlot(d, 0, info);
    BK_CHECK(info.state == kSlotDamaged);
    BK_CHECK(failsWith(d, "a"_s, "wrong passphrase (damaged key slots were skipped"_s));
    BK_CHECK(opens(d, "b"_s, master, 1));
    // Every slot damaged.
    slotAt(d, 1)[0] ^= 0x80;
    BK_CHECK(failsWith(d, "b"_s, "every key slot is damaged"_s));
    // Header damage, the wrong size, other files, the old format.
    KeyFile g;
    u8 img[kKeyFileBytes];
    memCopy(img, f.bytes, kKeyFileBytes);
    img[20] ^= 1;
    BK_CHECK(!keyFileParse(img, kKeyFileBytes, g, err) && err.view().startsWith("damaged key file"_s));
    err.clear();
    BK_CHECK(!keyFileParse(f.bytes, kKeyFileBytes - 1, g, err) && err.view() == "damaged key file (wrong size)"_s);
    err.clear();
    memCopy(img, f.bytes, kKeyFileBytes);
    img[8] = 3;
    BK_CHECK(!keyFileParse(img, kKeyFileBytes, g, err) && err.view() == "unsupported key file version"_s);
    err.clear();
    const char old[] = "bu-key-1 0000000000000000000000000000000000000000000000000000000000000000\n";
    BK_CHECK(!keyFileParse(reinterpret_cast<const u8*>(old), sizeof old - 1, g, err) &&
             err.view().startsWith("a bu-key-1 plaintext key"_s));
    err.clear();
    BK_CHECK(!keyFileParse(reinterpret_cast<const u8*>("hello"), 5, g, err) && err.view() == "not a bu key file"_s);
}

BK_TEST(keyfile_slot_index_header_and_params_are_authenticated) {
    const Key master = keyOf(3);
    KeyFile f;
    String err;
    BK_REQUIRE(keyFileCreate(master, "pw"_s, kCheap, f, err));

    // Moved to another index, checksum intact (it does not cover the index).
    KeyFile moved = f;
    memCopy(slotAt(moved, 5), slotAt(moved, 0), kKeySlotBytes);
    keyFileClearSlot(moved, 0);
    KeySlotInfo info;
    keyFileSlot(moved, 5, info);
    BK_CHECK(info.state == kSlotActive);
    BK_CHECK(failsWith(moved, "pw"_s, "wrong passphrase"_s));

    // Spliced into another key file with the same passphrase: the header
    // (key ID) is part of the associated data.
    KeyFile other;
    BK_REQUIRE(keyFileCreate(keyOf(4), "pw"_s, kCheap, other, err));
    memCopy(slotAt(other, 0), slotAt(f, 0), kKeySlotBytes);
    BK_CHECK(failsWith(other, "pw"_s, "wrong passphrase"_s));

    // Parameters edited and the checksum fixed up: a reserved byte (not an
    // Argon2 input, so only the AAD can notice) ...
    KeyFile tampered = f;
    slotAt(tampered, 0)[13] = 1;
    fixChecksum(tampered, 0);
    keyFileSlot(tampered, 0, info);
    BK_CHECK(info.state == kSlotDamaged);      // reserved must be zero
    // ... and the passes field, which an attacker might lower.
    tampered = f;
    storeU32LE(slotAt(tampered, 0) + 4, 2);
    fixChecksum(tampered, 0);
    BK_CHECK(failsWith(tampered, "pw"_s, "wrong passphrase"_s));
    // Out-of-range parameters are never run (a tampered slot must not be
    // able to ask for terabytes of memory).
    tampered = f;
    storeU32LE(slotAt(tampered, 0) + 8, 0xffffffffu);
    fixChecksum(tampered, 0);
    keyFileSlot(tampered, 0, info);
    BK_CHECK(info.state == kSlotDamaged);
    BK_CHECK(failsWith(tampered, "pw"_s, "every key slot is damaged"_s));
    // The untouched original still opens.
    BK_CHECK(opens(f, "pw"_s, master, 0));
}

BK_TEST(keyfile_eight_slots_and_last_slot_removal_refused) {
    const Key master = keyOf(5);
    KeyFile f;
    String err;
    BK_REQUIRE(keyFileCreate(master, "p0"_s, kCheap, f, err));
    const StringView pw[kKeySlots] = {"p0"_s, "p1"_s, "p2"_s, "p3"_s, "p4"_s, "p5"_s, "p6"_s, "p7"_s};
    for (u32 i = 1; i < kKeySlots; ++i) BK_REQUIRE(keyFileSetSlot(f, i, master, pw[i], kCheap, err));
    for (u32 i = 0; i < kKeySlots; ++i) BK_CHECK(opens(f, pw[i], master, i));
    BK_CHECK(!keyFileSetSlot(f, kKeySlots, master, "p8"_s, kCheap, err));
    // Out-of-range parameters and an empty passphrase are refused on write too.
    BK_CHECK(!keyFileSetSlot(f, 1, master, "x"_s, KdfParams{0, 8u << 10}, err));
    BK_CHECK(!keyFileSetSlot(f, 1, master, "x"_s, KdfParams{1, 4u << 10}, err));
    BK_CHECK(!keyFileSetSlot(f, 1, master, ""_s, kCheap, err));
    BK_CHECK(opens(f, "p1"_s, master, 1));

    for (u32 i = 0; i + 1 < kKeySlots; ++i) BK_REQUIRE(keyFileRemoveSlot(f, i, err));
    BK_CHECK(failsWith(f, "p0"_s, "wrong passphrase"_s));
    err.clear();
    BK_CHECK(!keyFileRemoveSlot(f, 0, err) && err.view() == "that key slot is empty"_s);
    err.clear();
    BK_CHECK(!keyFileRemoveSlot(f, kKeySlots - 1, err) && err.view().startsWith("refusing to remove the last"_s));
    BK_CHECK(opens(f, "p7"_s, master, kKeySlots - 1));
    // A damaged slot does not count as usable: with slot 7 the only intact
    // one, removing it stays refused even though slot 0 holds bytes.
    BK_REQUIRE(keyFileSetSlot(f, 0, master, "p0"_s, kCheap, err));
    slotAt(f, 0)[70] ^= 1;
    err.clear();
    BK_CHECK(!keyFileRemoveSlot(f, kKeySlots - 1, err));
    BK_CHECK(keyFileRemoveSlot(f, 0, err));     // the damaged one may go
}
