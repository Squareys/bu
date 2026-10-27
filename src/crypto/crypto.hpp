// crypto.hpp — the only door to the vendored primitives (BLAKE3, AES-256-GCM,
// Argon2id) and to the kernel RNG.
//
// Everything above this layer speaks in fixed-size byte arrays and never sees
// blake3.h or a libsodium header: those are confined to crypto.cpp (hard rule
// in CONTRIBUTING.md), so swapping an implementation is a one-file change and the
// rest of the tree cannot grow a second, subtly different call into either.
//
// docs/design.md §Crypto is the argument for the choices; in one paragraph:
// BLAKE3 keyed mode makes chunk IDs a MAC of the content (equal IDs reveal
// equal plaintext only to a key holder), derive_key mode turns the one master
// key into independent subkeys, and AES-256-GCM over AES-NI + PCLMULQDQ is the
// AEAD every x86-64 CPU since ~2011 accelerates in hardware. Both libraries
// dispatch at run time on CPUID, so one binary runs at full speed on any of
// them; a CPU without AES-NI/PCLMUL/AVX is refused by name (cryptoCpuCheck)
// rather than served by a slow fallback nobody tests.
#pragma once

#include "core/string.hpp"
#include "core/types.hpp"

namespace bk {

constexpr u32 kKeyBytes = 32;    // master key, subkeys, AES-256 keys
constexpr u32 kIdBytes = 16;     // chunk ID: 128-bit keyed BLAKE3 (docs/design.md §IDs)
constexpr u32 kTagBytes = 16;    // GCM tag
constexpr u32 kNonceBytes = 12;  // GCM nonce
constexpr u32 kSaltBytes = 32;   // per-segment salt in every segment header

struct Key { u8 b[kKeyBytes]; };
struct ChunkId { u8 b[kIdBytes]; };

inline bool idEqual(const ChunkId& a, const ChunkId& b) { return memEqual(a.b, b.b, kIdBytes); }
// IDs are keyed-hash outputs, i.e. uniformly random: the first 8 bytes ARE a
// perfect hash, no mixing needed.
inline u64 idHash(const ChunkId& id) { u64 h; memCopy(&h, id.b, 8); return h; }

// True when the CPU has everything the AES-GCM path is compiled for (AES-NI,
// PCLMULQDQ, AVX — libsodium's aesni file targets all three). On false, `err`
// names the missing feature. Every command that encrypts or decrypts calls it
// before the first encryption, so the failure is a sentence, not SIGILL.
bool cryptoCpuCheck(String& err);

// Unkeyed BLAKE3, 32-byte output (tests and the key-file checksum).
void blake3Hash(const void* data, usize n, u8 out[32]);
// BLAKE3 over the concatenation of `n` parts, `outLen` bytes: keyed under
// `key`, or unkeyed when `key` is null (the integrity checks and chunk IDs of
// unencrypted chains, docs/design.md §3).
struct HashPart { const void* ptr; usize len; };
void blake3Parts(const Key* key, const HashPart* parts, u32 n, u8* out, usize outLen);
// Keyed BLAKE3 with arbitrary output length (chunk IDs, header check values).
void blake3Keyed(const Key& key, const void* data, usize n, u8* out, usize outLen);
// BLAKE3 derive_key: `context` must be a hardcoded, globally unique string
// (BLAKE3's own rule); `material` is the input key material.
void blake3DeriveKey(StringView context, const void* material, usize n, Key& out);

// An expanded AES-256-GCM key (round keys + GHASH powers). 512 bytes, 16-byte
// aligned — libsodium's crypto_aead_aes256gcm_state, opaque here.
struct alignas(16) AeadKey { u8 opaque[512]; };

void aeadInit(AeadKey& st, const Key& key);
// out must hold n + kTagBytes bytes: ciphertext then tag. in == out is allowed.
void aeadSeal(const AeadKey& st, const u8 nonce[kNonceBytes], const u8* ad, usize adLen,
              const u8* in, usize n, u8* out);
// in holds n bytes of ciphertext followed by the tag; writes n bytes of
// plaintext. False (and `out` scrubbed by libsodium) on authentication failure.
[[nodiscard]] bool aeadOpen(const AeadKey& st, const u8 nonce[kNonceBytes], const u8* ad,
                            usize adLen, const u8* in, usize n, u8* out);

// Argon2id v1.3 (RFC 9106) with one lane, libsodium's crypto_pwhash_argon2id:
// stretches a passphrase into `outLen` bytes (16 or more). `memKiB` is the
// memory cost in KiB, `passes` the time cost. libsodium's own bounds apply
// (at least 8 KiB of memory and one pass); callers enforce bu's tighter ones.
// False with `err` set when the memory cannot be allocated or a parameter is
// out of libsodium's range. Single-threaded by construction (one lane), and
// the first call picks the widest kernel the CPU has (SSSE3, AVX2, AVX-512F).
constexpr u32 kKdfSaltBytes = 16;
[[nodiscard]] bool kdfArgon2id(const void* pass, usize passLen, const u8 salt[kKdfSaltBytes], u32 passes,
                               u32 memKiB, u8* out, usize outLen, String& err);

// Kernel CSPRNG (getrandom(2), blocking until the pool is initialised).
[[nodiscard]] bool randomBytes(void* out, usize n, String& err);

// Wipe key material in a way the optimiser may not elide.
void secureZero(void* p, usize n);

// Lowercase hex; out must hold 2n bytes.
void hexEncode(const u8* in, usize n, char* out);
// Exactly 2n hex digits into n bytes; false on any other length or digit.
[[nodiscard]] bool hexDecode(StringView hex, u8* out, usize n);

} // namespace bk
