// bench.cpp — `bu_bench`: single-thread throughput of each primitive on the
// unit of work bu actually gives it (a 16 KiB chunk), so the numbers say
// what one worker can do per second and which stage bounds a backup.
//
//   bu_bench [MiB]     (default 512 MiB processed per primitive)

#include "chunk/chunker.hpp"
#include "core/array.hpp"
#include "crypto/crypto.hpp"
#include "format/codec.hpp"
#include "io/io.hpp"

#include <stdio.h>
#include <stdlib.h>

using namespace bk;

namespace {

double secondsSince(i64 t0) { return double(nowNs() - t0) / 1e9; }

void line(const char* what, u64 bytes, double secs) {
    printf("  %-40s %8.0f MiB/s\n", what, double(bytes) / secs / double(1 << 20));
}

} // namespace

int main(int argc, char** argv) {
    u64 mib = 512;
    if (argc > 1 && (!parseU64(StringView(argv[1]), mib) || mib == 0)) { fprintf(stderr, "usage: bu_bench [MiB]\n"); return 2; }
    const u64 total = mib << 20;
    const u32 kChunk = 16384;

    // Two inputs: incompressible, and text-like (LZ4 ~3x) for the codec.
    Array<u8> rnd, txt;
    rnd.resize(64u << 20);
    u64 x = 0x9e3779b97f4a7c15ull;
    for (u32 i = 0; i < rnd.count; ++i) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; rnd[i] = u8(x >> 32); }
    txt.resize(64u << 20);
    {
        u32 n = 0, line = 0;
        char buf[128];
        while (n < txt.count) {
            const int k = snprintf(buf, sizeof buf, "2026-10-25T12:%02u:%02u host app[%u]: request %u done in %u ms\n",
                                   line / 60 % 60, line % 60, 4000 + line % 7, line * 7919 % 100000, line % 997);
            for (int i = 0; i < k && n < txt.count; ++i) txt[n++] = u8(buf[i]);
            ++line;
        }
    }
    const u32 nChunks = u32(total / kChunk);
    auto chunkAt = [&](const Array<u8>& a, u32 i) { return a.ptr + (u64(i) * kChunk) % (a.count - kChunk); };

    String err;
    if (!cryptoCpuCheck(err)) { fprintf(stderr, "%.*s\n", int(err.count), err.ptr); return 1; }
    printf("bu_bench: %llu MiB per primitive, 16 KiB chunks, one thread\n", (unsigned long long)mib);

    Key key; memSet(key.b, 3, 32);
    u8 out[32];
    i64 t0 = nowNs();
    for (u32 i = 0; i < nChunks; ++i) blake3Keyed(key, chunkAt(rnd, i), kChunk, out, 16);
    line("BLAKE3 keyed (chunk ID)", total, secondsSince(t0));

    AeadKey st;
    aeadInit(st, key);
    Array<u8> sealed;
    sealed.resize(kChunk + 16);
    u8 nonce[12] = {};
    t0 = nowNs();
    for (u32 i = 0; i < nChunks; ++i) { nonce[0] = u8(i); aeadSeal(st, nonce, out, 17, chunkAt(rnd, i), kChunk, sealed.ptr); }
    line("AES-256-GCM seal", total, secondsSince(t0));
    Array<u8> opened;
    opened.resize(kChunk);
    aeadSeal(st, nonce, out, 17, rnd.ptr, kChunk, sealed.ptr);
    t0 = nowNs();
    u32 bad = 0;
    for (u32 i = 0; i < nChunks; ++i) bad += !aeadOpen(st, nonce, out, 17, sealed.ptr, kChunk, opened.ptr);
    line("AES-256-GCM open", total, secondsSince(t0));

    CodecState cs;
    Array<u8> enc, dec;
    enc.resize(codecBound(kChunk));
    dec.resize(kChunk);
    for (int which = 0; which < 2; ++which) {
        const Array<u8>& src = which ? txt : rnd;
        u64 encBytes = 0;
        t0 = nowNs();
        for (u32 i = 0; i < nChunks; ++i) encBytes += codecEncode(cs, chunkAt(src, i), kChunk, enc.ptr);
        const double secs = secondsSince(t0);
        char label[64];
        snprintf(label, sizeof label, "LZ4 compress (%s, ratio %.2f)", which ? "text" : "random",
                 double(total) / double(encBytes));
        line(label, total, secs);
        const u32 n = codecEncode(cs, src.ptr, kChunk, enc.ptr);
        t0 = nowNs();
        for (u32 i = 0; i < nChunks; ++i) bad += !codecDecode(enc.ptr, n, dec.ptr, kChunk);
        snprintf(label, sizeof label, "LZ4 decompress (%s)", which ? "text" : "random");
        line(label, total, secondsSince(t0));
    }

    t0 = nowNs();
    u64 done = 0, cuts = 0;
    while (done < total) {
        u32 pos = 0;
        while (pos < rnd.count) { pos += cdcNextCut(rnd.ptr + pos, rnd.count - pos); ++cuts; }
        done += rnd.count;
    }
    line("FastCDC chunking (reference, one pass)", done, secondsSince(t0));
    printf("  (average chunk %llu bytes)\n", (unsigned long long)(done / cuts));
    t0 = nowNs();
    done = 0;
    CdcHits hits;
    Array<Cut> cutList;
    while (done < total) {
        hits.hard.clear(); hits.easy.clear(); cutList.clear();
        cdcScan(rnd.ptr, 0, rnd.count, hits);
        cdcSelect(hits, rnd.count, true, cutList);
        done += rnd.count;
    }
    line("FastCDC scan + select (pipeline form)", done, secondsSince(t0));
    return bad ? 1 : 0;
}
