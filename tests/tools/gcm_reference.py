#!/usr/bin/env python3
# gcm_reference.py — independent AES-256-GCM reference for tests/test_crypto.cpp.
#
# The official vectors (McGrew & Viega, "The Galois/Counter Mode of Operation",
# test cases 13-16) are all shorter than seven blocks, so they never reach the
# vendored implementation's 7-block parallel path or its tail handling at
# larger sizes. This script computes tags for longer messages with OpenSSL's
# libcrypto (EVP, through ctypes — no third-party Python packages) so the
# test can pin those too. Run it to regenerate the LONG_* constants:
#
#   python3 -I tests/tools/gcm_reference.py
#
# It first checks itself against test case 16, so a broken ctypes binding
# cannot silently produce wrong reference values.
import ctypes, ctypes.util

lib = ctypes.CDLL(ctypes.util.find_library("crypto"))
lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
EVP_CTRL_GCM_GET_TAG = 0x10

def seal(key, nonce, aad, pt):
    ctx = lib.EVP_CIPHER_CTX_new()
    assert lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, key, nonce) == 1
    n = ctypes.c_int(0)
    if aad:
        assert lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(n), aad, len(aad)) == 1
    out = ctypes.create_string_buffer(len(pt) + 16)
    assert lib.EVP_EncryptUpdate(ctx, out, ctypes.byref(n), pt, len(pt)) == 1
    total = n.value
    assert lib.EVP_EncryptFinal_ex(ctx, ctypes.cast(ctypes.addressof(out) + total, ctypes.c_char_p), ctypes.byref(n)) == 1
    tag = ctypes.create_string_buffer(16)
    assert lib.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1
    lib.EVP_CIPHER_CTX_free(ctx)
    return out.raw[:len(pt)], tag.raw

K = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
IV = bytes.fromhex("cafebabefacedbaddecaf888")
P16 = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
A16 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
_, tag = seal(K, IV, A16, P16)
assert tag.hex() == "76fc6ece0f4e1768cddf8853bb2d551b", "self-check against GCM test case 16 failed"

import hashlib
for n in (113, 1000, 4099, 65536 + 7):
    pt = bytes(i % 251 for i in range(n))
    ct, tag = seal(K, IV, A16, pt)
    print(f"len {n}: tag {tag.hex()} sha256(ct) {hashlib.sha256(ct).hexdigest()}")
