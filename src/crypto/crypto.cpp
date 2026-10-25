// crypto.cpp — thin wrappers over the vendored BLAKE3 and libsodium AES-GCM.
//
// The ONLY translation unit that includes blake3.h or a libsodium header
// (CLAUDE.md hard rule 4). It adds no cryptography of its own: each function
// is a call into upstream code plus the argument shaping our fixed-size types
// need. The known-answer tests in tests/test_crypto.cpp run through these
// wrappers, not around them, so the vectors cover the shaping too.

#include "crypto/crypto.hpp"

extern "C" {
#include "blake3.h"
#include "sodium/crypto_aead_aes256gcm.h"
}

#include <cpuid.h>       // __get_cpuid: our own feature check, see cryptoCpuCheck
#include <errno.h>
#include <string.h>    // explicit_bzero, strerror
#include <sys/random.h> // getrandom

namespace bk {

static_assert(sizeof(AeadKey) == sizeof(crypto_aead_aes256gcm_state), "AeadKey mirrors libsodium's state");
static_assert(crypto_aead_aes256gcm_ABYTES == kTagBytes && crypto_aead_aes256gcm_NPUBBYTES == kNonceBytes,
              "GCM parameters");
static_assert(BLAKE3_KEY_LEN == kKeyBytes, "BLAKE3 key size");

bool cryptoCpuCheck(String& err) {
    // CPUID leaf 1, read directly. __builtin_cpu_supports would do the same
    // but links compiler-rt's __cpu_indicator_init (5.4 KB, a third of the
    // AES-GCM code it guards) to decode every feature bit we never ask about.
    // AVX additionally needs the OS to save YMM state (OSXSAVE + XCR0 bits
    // 1-2), which is what "the CPU has AVX" has to mean for code that uses it.
    // Each feature is named on its own so the message tells the user which one
    // their CPU (or VM CPU model, the common real-world cause) is hiding.
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid(1, &a, &b, &c, &d)) return errSet(err, "cannot query CPU features (CPUID)");
    if (!(c & bit_AES))
        return errSet(err, "this CPU lacks AES-NI, which backu's AES-256-GCM requires "
                           "(every x86-64 CPU since ~2011 has it; check the VM's CPU model)");
    if (!(c & bit_PCLMUL))
        return errSet(err, "this CPU lacks PCLMULQDQ, which backu's AES-256-GCM requires");
    bool avx = (c & bit_AVX) && (c & bit_OSXSAVE);
    if (avx) {
        unsigned lo, hi;
        __asm__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
        avx = (lo & 6) == 6;
    }
    if (!avx) return errSet(err, "this CPU (or OS) lacks AVX, which backu's AES-256-GCM code path requires");
    return true;
}

void blake3Hash(const void* data, usize n, u8 out[32]) {
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, n);
    blake3_hasher_finalize(&h, out, 32);
}

void blake3Keyed(const Key& key, const void* data, usize n, u8* out, usize outLen) {
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key.b);
    blake3_hasher_update(&h, data, n);
    blake3_hasher_finalize(&h, out, outLen);
}

void blake3DeriveKey(StringView context, const void* material, usize n, Key& out) {
    blake3_hasher h;
    blake3_hasher_init_derive_key_raw(&h, context.ptr, context.count);
    blake3_hasher_update(&h, material, n);
    blake3_hasher_finalize(&h, out.b, kKeyBytes);
}

void aeadInit(AeadKey& st, const Key& key) {
    crypto_aead_aes256gcm_beforenm(reinterpret_cast<crypto_aead_aes256gcm_state*>(&st), key.b);
}

void aeadSeal(const AeadKey& st, const u8 nonce[kNonceBytes], const u8* ad, usize adLen,
              const u8* in, usize n, u8* out) {
    crypto_aead_aes256gcm_encrypt_detached_afternm(
        out, out + n, nullptr, in, n, ad, adLen, nullptr, nonce,
        reinterpret_cast<const crypto_aead_aes256gcm_state*>(&st));
}

bool aeadOpen(const AeadKey& st, const u8 nonce[kNonceBytes], const u8* ad, usize adLen,
              const u8* in, usize n, u8* out) {
    // libsodium's decrypt_detached with m == NULL means "verify only"; we
    // always want plaintext, and an empty record still needs a real pointer.
    u8 dummy = 0;
    return crypto_aead_aes256gcm_decrypt_detached_afternm(
               n ? out : &dummy, nullptr, in, n, in + n, ad, adLen, nonce,
               reinterpret_cast<const crypto_aead_aes256gcm_state*>(&st)) == 0;
}

bool randomBytes(void* out, usize n, String& err) {
    u8* p = static_cast<u8*>(out);
    while (n) {
        const ssize_t got = getrandom(p, n, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return errSet(err, "getrandom: ", strerror(errno));
        }
        p += got; n -= usize(got);
    }
    return true;
}

void secureZero(void* p, usize n) { explicit_bzero(p, n); }

void hexEncode(const u8* in, usize n, char* out) {
    static const char kDigits[] = "0123456789abcdef";
    for (usize i = 0; i < n; ++i) { out[2*i] = kDigits[in[i] >> 4]; out[2*i+1] = kDigits[in[i] & 15]; }
}

bool hexDecode(StringView hex, u8* out, usize n) {
    if (hex.count != 2 * n) return false;
    for (usize i = 0; i < 2 * n; ++i) {
        const char c = hex[u32(i)];
        u8 v;
        if (c >= '0' && c <= '9') v = u8(c - '0');
        else if (c >= 'a' && c <= 'f') v = u8(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = u8(c - 'A' + 10);
        else return false;
        if (i & 1) out[i / 2] |= v; else out[i / 2] = u8(v << 4);
    }
    return true;
}

} // namespace bk
