# Contributing to bu

bu — backup utility: encrypted, deduplicating, incremental backups in one
chain file per data set, in one small native binary. Read `docs/design.md`
before changing behaviour and `docs/format.md` before touching anything that
reads or writes bytes on disk.

Bug reports and pull requests are welcome on GitHub. Report security issues
privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Build, test, measure

```
scripts/build.sh [Debug|Release] [--asan|--tsan]   # prints the build dir
scripts/test.sh [--asan|--tsan] [--smoke] [FILTER] # unit + integration tests
scripts/size_report.sh                             # stripped size + breakdown
scripts/bench.sh [--size-mb N] [--dir DIR]         # throughput, increments
```

C++20, clang, CMake + Ninja, Linux x86-64 only. The build directory lives
outside the tree (`~/.cache/bu-build-*`), keyed on the source path and the
configuration.

## Hard rules

1. **No STL.** No `<vector>`, `<string>`, `<map>`, `<algorithm>`, `<thread>`,
   `<atomic>`, not even `<cstdint>`. Use `src/core/`: `Span`, `Array`,
   `StringView`, `String`, `HashIndex`, `ByteWriter`/`ByteReader`, `Mutex`,
   `Cond`, `Thread`, `ThreadPool`, `sortRange`. Core headers include no system
   headers at all; C headers (`<stdio.h>`, never `<cstdio>`) go in `.cpp`
   files only.
2. **No exceptions, no RTTI, no virtuals, no inheritance.** Free functions over
   methods, `struct` not `class`, index-based references (`u32` +
   `kInvalidIndex`) over pointers into growable arrays.
3. **Errors are `bool fn(..., String& err)`.** Library code never prints; the
   command prints the message once. `[[nodiscard]]` on anything whose failure
   matters.
4. **Heavy and vendored headers are confined to one TU each.** `blake3.h` and
   the libsodium headers to `src/crypto/crypto.cpp`, `lz4.h` to
   `src/format/codec.cpp`, `pthread.h` to `src/core/thread.cpp`, `<cpuid.h>`
   to `crypto.cpp`. Nothing else calls a vendored function directly.
5. **The size rule: small by default, speed wins on hot paths.** Size work
   must cost no speed: `-ffunction-sections`/`--gc-sections`, LTO, no unwind
   tables, hidden visibility, stripped output, no unnecessary dependencies,
   cold code (`BK_COLD_SOURCES`) at `-Oz`. Hot code (`BK_HOT_SOURCES`, the
   vendored libraries) stays at `-O2`/`-O3` with every SIMD variant (BLAKE3
   SSE4.1/AVX2/AVX-512, AES-NI/PCLMUL). Every hot entry point called from
   cold code is marked `BK_HOT` (noinline): under LTO an inlined callee takes
   the caller's `-Oz`. Report the size (`scripts/size_report.sh`) when a change
   moves it by more than a couple of KB, and never trade throughput for bytes.
6. **Never roll your own cryptography.** Primitives come from vendored,
   upstream-verbatim sources (third_party/README). bu only composes them,
   and every composition is documented in `docs/design.md` §3. Any change
   to key derivation, nonces or associated data is a format change: bump the
   version, update `docs/format.md`, add a test that old files are refused.
7. **Nonces never repeat under one key.** Every segment has its own random
   salt and so its own AES key; within it, chunk nonces are stream sequence
   numbers (`< 2^63`), metadata nonces are fixed values with the top bit set,
   and record headers use `2^63 + 2^62 + ordinal`. Never add a record without
   a nonce from one of those three spaces.
8. **Everything read from a backup is untrusted, authenticated or not.**
   Decoders use `ByteReader` (bounds-checked, sticky failure), cap every count
   before allocating, and validate paths (`pathIsSafe`). Restore resolves
   every path component with `O_NOFOLLOW` from the target directory's fd.
9. **Nothing refers to a segment by file name or offset.** Parents are found
   by snapshot ID, chunks by chunk ID, across whatever segments the user
   gives; offsets inside a segment are relative to its start. This is what
   keeps chains valid after a merge and after `cat`; do not add a dependency
   on names, positions, salts or order of arguments.
10. **The output does not depend on thread scheduling.** Record order and
    nonces are fixed before work is handed to threads; the in-order writer
    decides dedupe. `tests/integration/01-incremental.sh` checks the chunk-table
    digest across `-j` values.
11. **CLI input is refused by name, never guessed.** Unknown, repeated,
    valueless or out-of-range options exit 2 with the option named; runtime
    failures exit 1; success 0. `create` with warnings (unreadable files) exits
    1 but leaves a valid chain.
12. **No network code.** bu reads and writes file descriptors: files on any
    mount, and stdio. S3, SSH and the like are the caller's mount or pipe.
13. **A chain is never left half-written by bu.** `create` holds the chain's
    lock while appending and truncates back on every failure path it can
    see; readers must survive the partial tail a crash leaves.

## Conventions

- Namespace `bk`, macros `BK_`. PascalCase types, lowerCamel functions with a
  module prefix (`containerOpen`, `snapshotEncode`), `kName` constants,
  PascalCase enumerators; snake_case file names, `#pragma once`.
- 4-space indent, K&R braces, ~100 columns, `T* p`/`T& r`, west const,
  `const` locals where not mutated, `auto` only for lambdas.
- Includes: own header, project headers (relative to `src/`), vendored headers
  in `extern "C" {}`, blank line, `<system.h>` alphabetically.
- `T*` parameter means nullable and checked; a kept `const char*` says at its
  declaration whether it may be null. A literal reaches a `StringView` through
  the `consteval` constructor or `_s`, never a runtime strlen; argv is compared
  as `StringView(argv[i]) == "--flag"_s`.
- Every file opens with `// file.cpp — role.` and paragraphs on why it exists
  and which alternatives were rejected. Comments explain why, not what.
  `static_assert`s sit next to the code they pin.
- stdio (`printf`/`fprintf`/`snprintf`) for messages, `read`/`write`/`pread`/
  `pwrite`/`writev` for data, never iostreams, never mmap (SIGBUS on a file
  truncated under us).

## Tests

- Unit tests: `BK_TEST(snake_case_name)` in `tests/test_*.cpp`, `BK_CHECK`,
  `BK_REQUIRE`, `BK_CHECK_EQ`, `BK_CHECK_HEX`. Each file opens with a comment
  naming what it guards. Known-answer vectors for every primitive.
- Smoke tests (`scripts/test.sh --smoke`): the unit tests and the quick
  integration scripts listed in `SMOKE` in `scripts/test.sh`. CI
  (`.github/workflows/ci.yml`) runs them on the Release build, then the full
  suite plain, under `--asan` and under `--tsan`.
- Integration tests: `tests/integration/NN-name.sh`, sourcing `lib.sh`,
  driving the real binary in a temp dir. Assert byte bounds on increments,
  content and metadata on restores, loud failure on tampering.
- Before a commit that touches `src/`: `scripts/test.sh`, `scripts/test.sh
  --asan`, and `--tsan` when threads are involved.

## Commits

Conventional Commits (`feat(scope): imperative summary`), a body explaining
why, and `- path: what changed` bullets. Every behaviour change updates
`docs/` and `CHANGELOG.md` in the same commit.
