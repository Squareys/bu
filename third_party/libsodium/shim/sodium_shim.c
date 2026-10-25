/* sodium_shim.c — the five libsodium support symbols aead_aes256gcm_aesni.c
 * references, so that ONE file of libsodium can be vendored instead of the
 * library.
 *
 * Not upstream code (written for backu, MIT like the rest of src/). The real
 * definitions live in libsodium's core.c, utils.c, verify.c and runtime.c,
 * which drag in the whole init/RNG machinery; the AES-GCM file only needs:
 *
 *   sodium_misuse()       called on an impossible length; abort, as upstream.
 *   sodium_memzero()      wipe a computed MAC; volatile stores so the compiler
 *                         cannot drop them as dead (upstream uses explicit_bzero
 *                         where available — we do the same).
 *   crypto_verify_16()    constant-time tag compare (same OR-accumulate shape
 *                         as upstream's portable path).
 *   sodium_runtime_has_*  only reached through crypto_aead_aes256gcm_is_available,
 *                         which backu does not call (src/crypto/crypto.cpp asks
 *                         the CPU itself, and --gc-sections drops both). Answered
 *                         from CPUID anyway so the symbols are truthful if linked;
 *                         not __builtin_cpu_supports, which would pull in
 *                         compiler-rt's 5 KB feature decoder.
 */
#include <cpuid.h>
#include <stdlib.h>
#include <string.h>

void sodium_misuse(void) { abort(); }

void sodium_memzero(void* const pnt, const size_t len) {
    explicit_bzero(pnt, len);
}

int crypto_verify_16(const unsigned char* x, const unsigned char* y) {
    volatile unsigned char d = 0;
    for (int i = 0; i < 16; i++) d |= (unsigned char)(x[i] ^ y[i]);
    return (1 & ((d - 1) >> 8)) - 1;
}

static unsigned leaf1_ecx(void) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    __get_cpuid(1, &a, &b, &c, &d);
    return c;
}
int sodium_runtime_has_aesni(void)  { return (leaf1_ecx() & bit_AES) != 0; }
int sodium_runtime_has_pclmul(void) { return (leaf1_ecx() & bit_PCLMUL) != 0; }
int sodium_runtime_has_avx(void)    { return (leaf1_ecx() & bit_AVX) != 0; }
