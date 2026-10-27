// test_crypto.cpp — known-answer tests for the vendored primitives, run
// through src/crypto's wrappers (so the argument shaping is covered too).
//
// BLAKE3: the official test_vectors.json from the BLAKE3 repository (input is
// the repeating byte sequence 0..250; key "whats the Elvish word for friend";
// derive_key context "BLAKE3 2019-12-27 16:29:52 test vectors context"),
// first 32 bytes of each output. The lengths are picked to hit every dispatch
// path: below one block, exactly one 1 KiB chunk, one past it, and 100 KiB,
// which runs the widest SIMD variant the CPU has (AVX-512, AVX2 or SSE4.1).
//
// Argon2id: two of libsodium's own vectors (test/default/pwhash_argon2id.c,
// tv cases 4 and 6, outputs from its .exp file), through kdfArgon2id, so the
// memory-cost conversion (KiB here, bytes in libsodium) is covered too. They
// run on whichever fill-block kernel this CPU dispatches to.
//
// AES-256-GCM: test cases 13-16 of McGrew & Viega's GCM specification (the
// NIST-submitted vectors), plus tags for longer messages computed with OpenSSL
// by tests/tools/gcm_reference.py, because the official vectors never reach
// the vendored code's 7-block parallel path.

#include "crypto/crypto.hpp"
#include "core/array.hpp"
#include "test.hpp"

using namespace bk;

namespace {

void fill251(Array<u8>& a, u32 n) {
    a.resize(n);
    for (u32 i = 0; i < n; ++i) a[i] = u8(i % 251);
}

bool hex(StringView h, u8* out) { return hexDecode(h, out, h.count / 2); }

struct B3Case { u32 len; const char* hash; const char* keyed; const char* derive; };
const B3Case kB3[] = {
    {0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
        "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"},
    {1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
        "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"},
    {1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
           "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
           "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"},
    {1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
           "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
           "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"},
    {1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
           "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
           "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"},
    {8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
           "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a",
           "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d"},
    {31744, "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
            "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a419",
            "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e"},
    {102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
             "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
             "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6"},
};

} // namespace

BK_TEST(blake3_official_vectors_all_three_modes) {
    Key key;
    memCopy(key.b, "whats the Elvish word for friend", 32);
    Array<u8> in;
    for (const B3Case& c : kB3) {
        fill251(in, c.len);
        u8 out[32];
        blake3Hash(in.ptr, c.len, out);
        BK_CHECK_HEX(out, 32, c.hash);
        blake3Keyed(key, in.ptr, c.len, out, 32);
        BK_CHECK_HEX(out, 32, c.keyed);
        Key d;
        blake3DeriveKey("BLAKE3 2019-12-27 16:29:52 test vectors context"_s, in.ptr, c.len, d);
        BK_CHECK_HEX(d.b, 32, c.derive);
    }
}

BK_TEST(blake3_keyed_truncation_is_a_prefix) {
    // Chunk IDs are the first 16 bytes of the keyed hash; BLAKE3's XOF makes
    // a shorter output a prefix of the longer one, which this pins.
    Key key;
    memCopy(key.b, "whats the Elvish word for friend", 32);
    Array<u8> in;
    fill251(in, 1025);
    u8 a[16], b[32];
    blake3Keyed(key, in.ptr, in.count, a, 16);
    blake3Keyed(key, in.ptr, in.count, b, 32);
    BK_CHECK(memEqual(a, b, 16));
}

BK_TEST(cpu_has_aes_gcm_features) {
    String err;
    BK_CHECK(cryptoCpuCheck(err));
}

namespace {

struct GcmCase { const char* key; const char* iv; const char* pt; const char* aad; const char* ct; const char* tag; };
const GcmCase kGcm[] = {
    // Test case 13: all-zero key, empty message.
    {"0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
     "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"},
    // Test case 14: one zero block.
    {"0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
     "00000000000000000000000000000000", "", "cea7403d4d606b6e074ec5d3baf39d18",
     "d0d1c8a799996bf0265b98b5d48ab919"},
    // Test case 15: four blocks, no AAD.
    {"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b391aafd255", "",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
     "c5f61e6393ba7a0abcc9f662898015ad", "b094dac5d93471bdec1a502270e3cc6c"},
    // Test case 16: partial last block, with AAD.
    {"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
     "b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
     "c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b"},
};

} // namespace

BK_TEST(aes256gcm_spec_test_cases_13_to_16) {
    for (const GcmCase& c : kGcm) {
        Key k; u8 iv[12]; u8 pt[64]; u8 aad[32]; u8 out[80]; u8 back[64];
        const StringView pts(c.pt), aads(c.aad);
        BK_REQUIRE(hex(c.key, k.b) && hex(c.iv, iv) && hex(pts, pt) && hex(aads, aad));
        const u32 n = pts.count / 2;
        AeadKey st;
        aeadInit(st, k);
        aeadSeal(st, iv, aad, aads.count / 2, pt, n, out);
        if (n) BK_CHECK_HEX(out, n, c.ct);
        BK_CHECK_HEX(out + n, 16, c.tag);
        BK_CHECK(aeadOpen(st, iv, aad, aads.count / 2, out, n, back));
        BK_CHECK(memEqual(back, pt, n));
    }
}

BK_TEST(aes256gcm_long_messages_match_openssl) {
    // Tags from tests/tools/gcm_reference.py (OpenSSL EVP): key/IV/AAD of test
    // case 16, plaintext the 0..250 sequence. The tag covers the ciphertext,
    // so a matching tag pins every ciphertext byte as well.
    struct L { u32 n; const char* tag; };
    const L cases[] = {{113, "34ec0e5e6cb8330c6beebca44897dc0c"}, {1000, "984a889e20a1a5a2171abfea5040bee7"},
                       {4099, "2349c9255eb119b0d791edf38cfd1114"}, {65543, "40207d212d2a8995ccc4e964209213ba"}};
    Key k; u8 iv[12]; u8 aad[20];
    BK_REQUIRE(hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"_s, k.b));
    BK_REQUIRE(hex("cafebabefacedbaddecaf888"_s, iv));
    BK_REQUIRE(hex("feedfacedeadbeeffeedfacedeadbeefabaddad2"_s, aad));
    AeadKey st;
    aeadInit(st, k);
    for (const L& c : cases) {
        Array<u8> pt, ct, back;
        fill251(pt, c.n);
        ct.resize(c.n + 16);
        back.resize(c.n);
        aeadSeal(st, iv, aad, 20, pt.ptr, c.n, ct.ptr);
        BK_CHECK_HEX(ct.ptr + c.n, 16, c.tag);
        BK_CHECK(aeadOpen(st, iv, aad, 20, ct.ptr, c.n, back.ptr));
        BK_CHECK(memEqual(back.ptr, pt.ptr, c.n));
    }
}

BK_TEST(aes256gcm_rejects_any_flipped_bit) {
    Key k; memSet(k.b, 7, 32);
    u8 iv[12] = {1}; u8 aad[17] = {1};
    AeadKey st;
    aeadInit(st, k);
    Array<u8> pt, ct, back;
    fill251(pt, 300);
    ct.resize(316); back.resize(300);
    aeadSeal(st, iv, aad, 17, pt.ptr, 300, ct.ptr);
    u32 rejected = 0;
    for (u32 byte = 0; byte < 316; byte += 7) {
        ct[byte] ^= 0x10;
        if (!aeadOpen(st, iv, aad, 17, ct.ptr, 300, back.ptr)) ++rejected;
        ct[byte] ^= 0x10;
    }
    BK_CHECK_EQ(rejected, (316u + 6) / 7);
    aad[3] ^= 1;
    BK_CHECK(!aeadOpen(st, iv, aad, 17, ct.ptr, 300, back.ptr));
    aad[3] ^= 1;
    iv[11] ^= 1;
    BK_CHECK(!aeadOpen(st, iv, aad, 17, ct.ptr, 300, back.ptr));
}

BK_TEST(aes256gcm_roundtrips_every_length_to_300) {
    // Every tail length and every boundary of the 7-block parallel path.
    Key k; memSet(k.b, 0x5a, 32);
    u8 iv[12] = {}; 
    AeadKey st;
    aeadInit(st, k);
    Array<u8> pt, ct, back;
    fill251(pt, 300);
    ct.resize(316); back.resize(300);
    bool ok = true;
    for (u32 n = 0; n <= 300; ++n) {
        iv[0] = u8(n);
        aeadSeal(st, iv, nullptr, 0, pt.ptr, n, ct.ptr);
        if (!aeadOpen(st, iv, nullptr, 0, ct.ptr, n, back.ptr) || !memEqual(back.ptr, pt.ptr, n)) ok = false;
    }
    BK_CHECK(ok);
}

BK_TEST(hex_decode_refuses_bad_input) {
    u8 out[2];
    BK_CHECK(hexDecode("0aFf"_s, out, 2) && out[0] == 0x0a && out[1] == 0xff);
    BK_CHECK(!hexDecode("0aF"_s, out, 2));
    BK_CHECK(!hexDecode("0aFg"_s, out, 2));
}

BK_TEST(argon2id_libsodium_vectors) {
    struct Case { const char* pass; const char* salt; u32 passes, memKiB, outLen; const char* out; };
    // salt: the first 16 bytes of the vector's salt (crypto_pwhash_SALTBYTES);
    // memKiB: the vector's memlimit / 1024, rounded down, as libsodium does.
    const Case cases[] = {
        {"4a857e2ee8aa9b6056f2424e84d24a72473378906ee04a46cb05311502d5250b82"
         "ad86b83c8f20a23dbb74f6da60b0b6ecffd67134d45946ac8ebfb3064294bc097d"
         "43ced68642bfb8bbbdd0f50b30118f5e",
         "39d82eef32010b8b79cc5ba88ed539fb", 3, 1432947 / 1024, 190,
         "08d8cd330c57e1b4643241d05bb468ba4ee4e932cd0858816be9ef15360b27bbd06a87130ee92222be267a29b81f5ae8fe"
         "8613324cfc4832dc49387fd0602f1c57b4d0f3855db94fb7e12eb05f9a484aed4a4307abf586cd3d55c809bc081541e00b"
         "682772fb2066504ff935b8ebc551a2083882f874bc0fae68e56848ae34c91097c3bf0cca8e75c0797eef3efde3f75e0058"
         "15018db3cf7c109a812264c4de69dcb22322dbbcfa447f5b00ecd1b04a7be1569c8e556adb7bba48adf81d"},
        {"b540beb016a5366524d4605156493f9874514a5aa58818cd0c6dfffaa9e90205f17b",
         "44071f6d181561670bda728d43fb79b4", 1, 1631659 / 1024, 231,
         "7fb72409b0987f8190c3729710e98c3f80c5a8727d425fdcde7f3644d467fe973f5b5fee683bd3fce812cb9ae5e9921a2d"
         "06c2f1905e4e839692f2b934b682f11a2fe2b90482ea5dd234863516dba6f52dc0702d324ec77d860c2e181f84472bd710"
         "4fedce071ffa93c5309494ad51623d214447a7b2b1462dc7d5d55a1f6fd5b54ce024118d86f0c6489d16545aaa87b6689d"
         "ad9f2fb47fda9894f8e12b87d978b483ccd4cc5fd9595cdc7a818452f915ce2f7df95ec12b1c72e3788d473441d884f974"
         "8eb14703c21b45d82fd667b85f5b2d98c13303b3fe76285531a826b6fc0fe8e3dddecf"},
    };
    for (const Case& c : cases) {
        u8 pass[128], salt[kKdfSaltBytes], out[256];
        const StringView ph(c.pass);
        BK_REQUIRE(hex(ph, pass) && hex(StringView(c.salt), salt));
        String err;
        BK_REQUIRE(kdfArgon2id(pass, ph.count / 2, salt, c.passes, c.memKiB, out, c.outLen, err));
        BK_CHECK(StringView(c.out).count == 2 * c.outLen);
        char got[2 * 256 + 1];
        testHex(out, c.outLen, got);
        BK_CHECK(StringView(got, 2 * c.outLen) == StringView(c.out));
    }
    // Below libsodium's floor (8 KiB) is refused, not clamped.
    u8 salt[kKdfSaltBytes] = {}, out[32];
    String err;
    BK_CHECK(!kdfArgon2id("x", 1, salt, 1, 4, out, 32, err));
}
