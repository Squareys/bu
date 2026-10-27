// test_codec.cpp — the record payload framing: LZ4 when it helps, stored when
// it does not, and a decoder that refuses every malformed or lying payload
// instead of overrunning (an authenticated payload is still untrusted input).

#include "format/codec.hpp"
#include "core/array.hpp"
#include "test.hpp"

using namespace bk;

BK_TEST(codec_compressible_data_uses_lz4_and_roundtrips) {
    Array<u8> raw, enc, back;
    raw.resize(65536);
    for (u32 i = 0; i < raw.count; ++i) raw[i] = u8("bu.bk "[i % 6]);
    enc.resize(codecBound(raw.count));
    CodecState st;
    const u32 n = codecEncode(st, raw.ptr, raw.count, enc.ptr);
    BK_CHECK(enc[0] == kCodecLz4);
    BK_CHECK(n < raw.count / 10);
    u32 rawLen = 0;
    BK_REQUIRE(codecRawLength(enc.ptr, n, 65536, rawLen) && rawLen == raw.count);
    back.resize(rawLen);
    BK_CHECK(codecDecode(enc.ptr, n, back.ptr, rawLen));
    BK_CHECK(memEqual(back.ptr, raw.ptr, raw.count));
}

BK_TEST(codec_incompressible_data_is_stored_with_one_byte_overhead) {
    Array<u8> raw, enc, back;
    raw.resize(16384);
    u64 x = 88172645463325252ull;
    for (u32 i = 0; i < raw.count; ++i) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; raw[i] = u8(x); }
    enc.resize(codecBound(raw.count));
    CodecState st;
    const u32 n = codecEncode(st, raw.ptr, raw.count, enc.ptr);
    BK_CHECK(enc[0] == kCodecStored);
    BK_CHECK_EQ(n, raw.count + 1);
    u32 rawLen = 0;
    BK_REQUIRE(codecRawLength(enc.ptr, n, 65536, rawLen));
    back.resize(rawLen);
    BK_CHECK(codecDecode(enc.ptr, n, back.ptr, rawLen) && memEqual(back.ptr, raw.ptr, raw.count));
}

BK_TEST(codec_refuses_lying_and_truncated_payloads) {
    Array<u8> raw, enc, back;
    raw.resize(8192);
    for (u32 i = 0; i < raw.count; ++i) raw[i] = u8(i / 64);
    enc.resize(codecBound(raw.count));
    CodecState st;
    const u32 n = codecEncode(st, raw.ptr, raw.count, enc.ptr);
    BK_REQUIRE(enc[0] == kCodecLz4);
    u32 rawLen = 0;
    BK_CHECK(!codecRawLength(enc.ptr, n, 4096, rawLen));          // above the cap
    back.resize(8192);
    BK_CHECK(!codecDecode(enc.ptr, n - 3, back.ptr, 8192));       // truncated stream
    BK_CHECK(!codecDecode(enc.ptr, n, back.ptr, 8000));           // wrong claimed length
    const u8 bogus[2] = {7, 0};
    BK_CHECK(!codecRawLength(bogus, 2, 65536, rawLen));          // unknown codec
}

BK_TEST(codec_sizes_beyond_lz4s_int_range_are_refused_not_wrapped) {
    // Metadata records may reach 3 GiB; LZ4 counts in int. codecBound must
    // not hand LZ4 a wrapped (negative) size, and a payload claiming an LZ4
    // body or output above LZ4's limit is refused before any int cast.
    const u32 big = 0x80000004u;
    BK_CHECK_EQ(codecBound(big), big + 1);                   // stored, one header byte
    BK_CHECK(codecBound(0x7E000000u) > 0x7E000000u);         // still LZ4's bound at the limit
    u8 enc[64] = {kCodecLz4};
    enc[1] = 0x04; enc[2] = 0x00; enc[3] = 0x00; enc[4] = 0x80;    // rawLen 0x80000004
    u32 rawLen = 0;
    BK_CHECK(codecRawLength(enc, sizeof enc, 0xffffffffu, rawLen) && rawLen == big);
    u8 out[16];
    BK_CHECK(!codecDecode(enc, sizeof enc, out, rawLen));     // refused, `out` never touched
}
