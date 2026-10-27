# Changelog

All notable changes to bu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). The on-disk format has its
own version number (docs/format.md); a release that changes it says so.

## [Unreleased]

### Changed
- Renamed the project from backu to bu: binary, help text, message prefixes,
  key-file prefix (`bu-key-1`), build directory and environment variables
  (`BU_BUILD_ROOT`). The file magic (`BUBAK\r\n^Z`) and the BLAKE3
  `derive_key` contexts now name bu, so files and keys made before the rename
  are not readable; the format version stays 1 (no backups existed yet).
- Licensing spelled out in the README: bu is MIT (`LICENSE`); vendored BLAKE3
  (CC0-1.0 / Apache-2.0), LZ4 (BSD-2-Clause) and libsodium (ISC) keep their
  own licences.

## [0.1.0] — 2026-10-25

First release. File format version 1.

### Added
- `create`: deduplicated, LZ4-compressed, AES-256-GCM-encrypted backups
  streamed to stdout; increments from a small index (`--base`,
  `--index-out`), never from the previous backup.
- Files cache: unchanged files (dev, inode, size, mtime, ctime) are not read
  at all on an increment; `--no-files-cache` to read everything.
- FastCDC content-defined chunking (min 4 KiB, ~20 KiB average, max 64 KiB),
  and page-aligned chunking for SQLite databases detected by their header.
- Delta manifests: an increment's file tree is coded against its parent, so
  unchanged files and unchanged parts of large files cost a few bytes.
- `restore` (latest snapshot of a chain, `-C DIR`, `--path PREFIX`), with
  every chunk authenticated and re-hashed, safe path resolution, sparse
  output for zero chunks.
- `merge`: one self-contained file from a chain; later increments keep
  working with it.
- `check`, `list` (backups or an index), `index` (rebuild a lost index,
  files cache included), `keygen`.
- Parallel create pipeline (readers, chunker, `-j N` workers, ordered
  writer) with output independent of thread scheduling; parallel restore,
  check and merge.
- Robustness: files that change size while being read are stored as walked
  and reported; unreadable files are left out and reported (exit 1, backup
  still valid); a backup never contains its own output file; an unwritable
  index location is refused before reading; a key file readable by others
  is reported.
- Known-answer tests for BLAKE3 and AES-256-GCM, unit and integration tests,
  ASan/UBSan and TSan builds, benchmarks (`scripts/bench.sh`).
