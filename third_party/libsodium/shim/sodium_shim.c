/* sodium_shim.c — the libsodium support symbols that the vendored AES-GCM and
 * Argon2id files reference, so that a few files of libsodium can be vendored
 * instead of the library.
 *
 * Not upstream code (written for bu, MIT like the rest of src/). The real
 * definitions live in libsodium's core.c, utils.c, verify.c and
 * randombytes.c, which drag in the whole init/RNG/guarded-allocation
 * machinery; the vendored files only need:
 *
 *   sodium_misuse()       called on an impossible length; abort, as upstream.
 *   sodium_memzero()      wipe secrets; explicit_bzero, which the compiler may
 *                         not drop as dead (upstream uses it where available).
 *   sodium_memcmp()       constant-time compare (argon2.c's verify path, which
 *                         bu does not call); same shape as upstream's.
 *   crypto_verify_16()    constant-time tag compare (same OR-accumulate shape
 *                         as upstream's portable path).
 *   randombytes_buf()     only reached from the encoded-string APIs
 *                         (crypto_pwhash_argon2id_str), which bu does not
 *                         call: bu draws salts and nonces through
 *                         src/crypto/crypto.cpp. getrandom(2), and abort on
 *                         failure because the signature has no error return.
 *
 * The sodium_runtime_has_* answers come from upstream's runtime.c (vendored
 * verbatim); src/crypto/crypto.cpp calls _sodium_runtime_get_cpu_features()
 * before picking the Argon2 kernel, as sodium_init() would.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

void sodium_misuse(void) { abort(); }

void sodium_memzero(void* const pnt, const size_t len) {
    explicit_bzero(pnt, len);
}

int sodium_memcmp(const void* const b1_, const void* const b2_, size_t len) {
    const volatile unsigned char* volatile b1 = (const volatile unsigned char* volatile) b1_;
    const volatile unsigned char* volatile b2 = (const volatile unsigned char* volatile) b2_;
    volatile unsigned char d = 0U;
    for (size_t i = 0U; i < len; i++) d |= b1[i] ^ b2[i];
    return (1 & ((d - 1) >> 8)) - 1;
}

int crypto_verify_16(const unsigned char* x, const unsigned char* y) {
    volatile unsigned char d = 0;
    for (int i = 0; i < 16; i++) d |= (unsigned char)(x[i] ^ y[i]);
    return (1 & ((d - 1) >> 8)) - 1;
}

void randombytes_buf(void* const buf, const size_t size) {
    unsigned char* p = (unsigned char*) buf;
    size_t n = size;
    while (n) {
        const ssize_t got = getrandom(p, n, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            abort();
        }
        p += got; n -= (size_t) got;
    }
}
