# Changelog

All notable changes to bu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). The on-disk format has its
own version number (docs/format.md); a release that changes it says so.

## [Unreleased]

## [0.1.0] - 2026-10-27

Initial release. Chain file format version 2, key file format version 2.

### Added
- **Chain files.** `bu create (--key KEY | --no-key) CHAIN PATH...` writes
  a full backup into a new chain and appends an increment to an existing
  one. Each backup is a self-contained segment with an authenticated
  trailer; offsets are relative to the segment, so segments written to
  separate files and joined with `cat` form a valid chain.
- **Encryption and authentication.** AES-256-GCM under a fresh key per
  segment, keyed-BLAKE3 chunk IDs, and encrypted file names, sizes,
  timestamps and directory tree. Every record is authenticated and every
  restored chunk re-hashed.
- **Key files with passphrase slots.** `bu key init` draws a random master
  key and stores it only wrapped in up to eight slots, each sealed under a
  key Argon2id derives from a passphrase (calibrated to about 2 s per
  unlock). `bu key add`, `passwd`, `remove` and `info` manage the slots.
  Passphrases come from the terminal, `--passphrase-file` or
  `--passphrase-fd`.
- **Unencrypted chains** with `--no-key`: payloads in the clear, BLAKE3
  checksums detect damage (not tampering).
- **Deduplication and compression.** FastCDC content-defined chunking
  (~20 KiB average), page-sized chunks for SQLite databases, LZ4.
- **Increments from the chain itself.** An increment stores the chunks
  the latest snapshot lacks and skips reading files whose metadata is
  unchanged (files cache; `--no-files-cache` reads everything). Manifests
  are coded as deltas against their parent, with a full manifest written
  whenever the deltas would outweigh it.
- **Safe appends.** `create` locks the chain, appends, fsyncs, and
  truncates the file back on failure or SIGINT/SIGTERM/SIGHUP. After a
  crash, readers skip the partial last segment and the next `create`
  removes it.
- `restore` of the latest snapshot or of selected paths (`-- PATH...`),
  with safe path resolution (`O_NOFOLLOW` from the target directory),
  sparse output for zero chunks, and set-uid/set-gid bits only when run as
  root.
- `merge` collapses a chain into one full segment (in place with `-o`
  naming the input); later increments keep working with it.
- `check`, `list` (control bytes in names escaped) and `index`.
- **Pipes.** `-` is stdin or stdout. `create` streams a segment to a pipe
  with its base from `--base INDEX`; `check`, `list` and `restore` (with
  `--index`) read a chain from a pipe in one pass.
- **Parallel pipeline.** Up to eight reader threads, a chunker, `-j N`
  workers and an in-order writer for `create`, with output that does not
  depend on thread scheduling; parallel `restore`, `check` and `merge`
  reading the chain in large sorted spans.
- One small Linux x86-64 binary (about 270 KB stripped), requiring AES-NI,
  PCLMULQDQ and AVX.
- Known-answer tests for every primitive, unit and integration tests,
  ASan/UBSan and TSan runs, benchmarks (`scripts/bench.sh`,
  `scripts/bench_io.sh`).

[Unreleased]: https://github.com/Squareys/bu/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Squareys/bu/releases/tag/v0.1.0
