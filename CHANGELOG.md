# Changelog

All notable changes to bu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/). The on-disk format has its
own version number (docs/format.md); a release that changes it says so.

## [Unreleased]

### Security
- The key file and the index are replaced through a temp file with a random
  name, created with `O_EXCL | O_NOFOLLOW` and mode 0600, and the directory
  is fsynced after the rename. The old temp name (`PATH.tmp.PID`) was
  predictable and opened with `O_TRUNC`: anyone who could write in the
  directory could plant a symlink there and have bu (as root: any file)
  overwrite its target, or keep a world-readable copy of the wrapped key.
- `bu key add`, `passwd` and `remove` refuse a key path that is a symlink or
  has other hard links, before asking for a passphrase. The rename replaced
  the link, not the file behind it, so the real file kept a removed
  passphrase's slot.
- `bu restore` unlinks a name already in the target and creates the file
  with `O_EXCL` instead of opening it with `O_TRUNC`: a planted hard link is
  no longer written through, and a planted FIFO no longer hangs the restore.
  Directory modes are set through an `O_NOFOLLOW` descriptor, so a directory
  swapped for a symlink cannot redirect the chmod.
- `bu restore` restores set-uid and set-gid bits on files only when run as
  root, as GNU tar does.
- `bu list` escapes control bytes in names and symlink targets (`\n`,
  `\xHH`, `\\`): a file name could send escape sequences to the terminal.
- A key slot whose Argon2id memory cannot be allocated is skipped with a
  warning and the other slots are tried, instead of ending the unlock.
- A passphrase file that group or others can access is warned about, and
  `bu key info` now warns about such a key file, as the other commands did.
- Slots below RFC 9106's KDF recommendations (64 MiB / 3 passes, or 2 GiB /
  1 pass) are warned about when written and marked "(weak)" by `key info`.
- Ctrl-Z at the passphrase prompt no longer stops bu with terminal echo off;
  it takes effect once the terminal is restored.
- LZ4 payloads above its ~2 GiB `int` limit are stored and refused on read,
  instead of reaching LZ4 as wrapped sizes.
- Per-container keys of a backup being written are wiped on destruction.
- docs/design.md: no locking for concurrent `bu key` commands; removing a
  passphrase does not revoke it for someone holding an older copy of the
  key file (only a new key does); the worker threads share one key schedule
  per container (not one per thread).
- Binary size 231 232 → 234 344 bytes.

### Fixed
- `bu create` could hang forever at the end of the file list: readers
  waiting for a free read slot were woken one at a time and not at all when
  the last range was claimed, and the chunker waits for every reader to
  exit. Seen in about 2% of runs with 4 readers on a few CPUs, 7% with 8.

### Performance
- `bu restore` and `bu check` read the backup in spans of consecutive
  records (about 256 KiB per `pread`) and prefetch about 16 MiB ahead,
  instead of one ~20 KiB record per `pread`. From a cold NVMe, `check` of a
  1.2 GB backup takes 0.42 s instead of 0.97 s, faster than one sequential
  read of the file (docs/benchmarks.md).
- `bu restore` writes runs of decoded chunks of one file with one `pwrite`,
  creates the next batch's files while the current batch is written, and
  defaults to 8 threads (`-j` still overrides): 1.45 s instead of 2.05 s
  for 1.5 GiB from and to the same NVMe, at less than half the CPU.
- `bu create` runs up to 8 reader threads (was 4) and a 16 MiB read ring
  (was 12 MiB), and without `-j` it runs the CPUs less three quarters of
  the readers as workers (14 on 20 CPUs, was 20) so the readers do not
  oversubscribe the machine: a full backup from an NVMe to the same disk
  takes 1.69 s instead of 2.01 s (to tmpfs: 0.80 s instead of 1.31 s);
  from tmpfs it is as fast as before.

### Changed
- `scripts/bench_io.sh` sets up its key with `bu key init` (it called a
  `keygen` command that no longer exists), adds increments with 1% of the
  files changed, and prints every run as a multiple of the time to read
  every file once. docs/benchmarks.md has before/after numbers for this
  release and the README's performance section is rewritten around them.
- **Key file format 2: a random master key in passphrase keyslots (the LUKS
  design).** `bu key init KEYFILE` draws the 32-byte master key from
  getrandom and stores it only wrapped in one of eight slots, each sealed
  with AES-256-GCM under a key Argon2id stretches from a passphrase (memory
  min(1 GiB, RAM/4), passes calibrated to ~2 s per unlock; `--kdf-memory`,
  `--kdf-time`, `--kdf-target-ms`). `bu key add`, `passwd`, `remove`
  (`--slot N`; the last usable slot is refused) and `info` manage the slots.
  Every command that takes `--key` now asks for the passphrase on the
  terminal (echo off), or reads it from `--passphrase-file PATH` or
  `--passphrase-fd N` for unattended runs. The backup and index format is
  unchanged: everything is still derived from the master key.
- `bu keygen` and the plaintext `bu-key-1` key file are gone; such a file is
  refused with a message naming the format.
- A damaged key slot is reported as damaged and skipped; a wrong passphrase
  as a wrong passphrase.
- Renamed the project from backu to bu: binary, help text, message prefixes,
  key-file prefix (`bu-key-1`), build directory and environment variables
  (`BU_BUILD_ROOT`). The file magic (`BUBAK\r\n^Z`) and the BLAKE3
  `derive_key` contexts now name bu, so files and keys made before the rename
  are not readable; the format version stays 1 (no backups existed yet).
- Binary size 174 768 → 231 216 bytes (Argon2id and BLAKE2b from libsodium
  1.0.22, the key file and the `bu key` commands).
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
