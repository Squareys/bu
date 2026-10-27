# bu

**Encrypted, deduplicating, incremental backups as a Unix filter.**

bu is a very lightweight take on what BorgBackup does, in one small native
binary (~175 KB stripped, Linux x86-64). `create` writes a backup to stdout
and never opens a network connection, so where it goes (a file, S3, ssh,
tape) is your pipe. There is no repository directory and no server: a key
file, backup files and a small local index are all there is.

- **Encrypted and authenticated.** AES-256-GCM (AES-NI) under a fresh key per
  file; file names, sizes, timestamps and the directory tree are encrypted.
- **Deduplicated.** FastCDC content-defined chunking (~20 KiB average) with
  keyed-BLAKE3 chunk IDs: an edit or an insertion stores only the chunks
  around it.
- **Incremental from a small index.** An increment stores only chunks the
  previous snapshot did not have, and reads only files whose metadata changed
  (a files cache). It needs the index, never the previous backup.
- **Mergeable chains.** `merge full inc1` gives a new full backup; later
  increments keep working with it.
- **SQLite-aware.** Databases are chunked at their page size, so an increment
  after scattered updates is about the size of the changed pages.
- **Fast and multi-threaded.** A parallel pipeline (~4 GB/s create, ~3.7 GB/s
  verified restore on a laptop, data on tmpfs) whose output does not depend on
  the thread count.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Piping backups anywhere](#piping-backups-anywhere)
- [Commands](#commands)
- [Performance](#performance)
- [Security](#security)
- [Limitations](#limitations)
- [Building and testing](#building-and-testing)
- [Documentation](#documentation)
- [Licence](#licence)

## Quick start

```sh
# 1. A key: 32 random bytes. Keep it safe, and NOT next to the backups.
(umask 077; bu keygen > ~/.bu.key)

# 2. A full backup, which also writes the index the next increment needs.
bu create --key ~/.bu.key --index-out data.idx ~/data > full.bk

# 3. Increments: only new chunks are stored, only changed files are read.
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data > inc1.bk
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data > inc2.bk

# 4. Restore the latest state of the chain (files in any order), every chunk verified.
bu restore --key ~/.bu.key -C /restore full.bk inc1.bk inc2.bk

# 5. Roll the chain forward: one file replaces two; inc2.bk keeps working.
bu merge --key ~/.bu.key full.bk inc1.bk > full2.bk && rm full.bk inc1.bk

# 6. Inspect and verify.
bu check --key ~/.bu.key full2.bk inc2.bk               # authenticate everything
bu list  --key ~/.bu.key full2.bk inc2.bk               # what is in there
bu index --key ~/.bu.key -o data.idx full2.bk inc2.bk   # lost the index? rebuild it
```

Reading commands take the whole chain: the full backup (or merged file) and
every increment since. Backups are found by snapshot ID, not by file name, so
renaming files or passing them in any order is fine.

For SQLite, back up a consistent copy (`sqlite3 app.db ".backup app-copy.db"`,
the backup API, or a filesystem snapshot), not a database that is being
written to.

## How it works

```
 files ──► chunk ──────► ID ──────► dedupe ─────► compress ──► encrypt ─────► stdout
           FastCDC, or   keyed      against the   LZ4 block    AES-256-GCM    (file, S3,
           SQLite pages  BLAKE3     index           │          per-file key    ssh, ...)
                                      │
                                      └─ already in the previous snapshot:
                                         reference it, store nothing
```

**Chunking.** Files are cut where a rolling gear hash says so (FastCDC,
4 KiB minimum, ~20 KiB average, 64 KiB maximum), so cut points depend on the
content, not on offsets: an insertion at the start of a file changes only the
first chunk. SQLite databases are recognised by their header and cut at page
boundaries instead.

**Dedupe and the index.** Each chunk's ID is a keyed BLAKE3 hash of its
content. The index is the latest snapshot itself: the set of chunks the next
increment may reference without storing, the base its file list is
delta-encoded against, and a files cache (device, inode, size, mtime, ctime)
that lets unchanged files be skipped without opening them.

**Records.** Each chunk is LZ4-compressed when that helps, then sealed with
AES-256-GCM. Every file has its own random salt and so its own AES key, and
nonces are sequence numbers, so a nonce never repeats under one key. A reader
re-hashes every decrypted chunk against its ID.

**Merge.** `merge` writes one self-contained backup holding the chain's latest
snapshot and exactly the chunks it references, under the same snapshot ID, so
increments made from that snapshot resolve against the merged file. Older
snapshots are not kept: history is what keeping old files is for.

In depth: [docs/design.md](docs/design.md) (why it is built this way) and
[docs/format.md](docs/format.md) (the file format, byte by byte).

## Piping backups anywhere

`create` and `merge` stream to stdout. Reading commands (`restore`, `check`,
`list`, `index`, `merge`) take files on disk, so fetch a chain back before
reading it.

```sh
# To a file
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data > "data-$(date +%F).bk"

# To another machine over ssh
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data \
    | ssh backup-host "cat > backups/data-$(date +%F).bk"

# To S3, keeping the new index only if the upload succeeded
set -o pipefail
bu create --key ~/.bu.key --base data.idx --index-out data.idx.new ~/data \
    | aws s3 cp - "s3://my-bucket/data-$(date +%F).bk" && mv data.idx.new data.idx
```

bu writes the index atomically after the backup was fully written, and a dead
pipe reader is a reported error that leaves the index alone. But bu cannot
see whether the far end stored what it received: when the upload can fail
after bu is done, as with S3 above, write the index to a new name and move it
into place only on success, so the next increment is never based on a backup
that does not exist.

**Rotating chains.** Merging keeps a chain short without breaking it: merge
the full backup with the oldest increments into a new full backup, check it,
then delete the inputs.

```sh
bu merge --key ~/.bu.key full.bk inc1.bk inc2.bk inc3.bk > full-new.bk \
    && bu check --key ~/.bu.key full-new.bk inc4.bk \
    && rm full.bk inc1.bk inc2.bk inc3.bk
```

`merge` needs the chain from a full backup up to the snapshot it merges.
`inc4.bk`, and every increment made later from the index, keeps working with
the merged file.

## Commands

| Command | What it does |
|---|---|
| `bu keygen > KEYFILE` | Make a new random key. |
| `bu create --key KEYFILE --index-out INDEX [--base INDEX] [-j N] [--no-files-cache] [-v] PATH... > BACKUP` | Stream a backup of `PATH...` to stdout. With `--base`, an increment: only chunks the base index does not list are stored, and files whose metadata is unchanged are not read (`--no-files-cache` reads them anyway). Writes the new index atomically; `--index-out` may name the same file as `--base`. |
| `bu restore --key KEYFILE [-C DIR] [--path PREFIX] [-j N] [-v] BACKUP...` | Restore the latest snapshot of the chain into `DIR` (default: the current directory), optionally only paths under `PREFIX`. |
| `bu merge --key KEYFILE [-j N] [-v] BACKUP... > MERGED` | Write one self-contained backup of the chain's latest snapshot, holding only the chunks it references. |
| `bu check --key KEYFILE [-j N] [-v] BACKUP...` | Authenticate every record and verify every snapshot is complete. |
| `bu list --key KEYFILE BACKUP...` or `bu list --key KEYFILE INDEX` | Show the files, and the latest snapshot's tree. |
| `bu index --key KEYFILE -o INDEX BACKUP...` | Rebuild a lost index, files cache included, from the chain. |
| `bu help` | Print usage. |

`-j N` sets the worker threads (default: online CPUs); `create` adds up to
four reader threads, a chunker and a writer. Unknown, repeated or malformed
options are refused by name.

**Exit status**

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Failure, or `create` finished with warnings: unreadable files were left out, or a file changed size while being read. The backup and index are still valid. |
| 2 | Usage error. |

## Performance

Measured with `scripts/bench.sh` on an Intel i7-12700H (6P+8E cores, 20
threads, no AVX-512), data on tmpfs, so these are CPU numbers. The tree is
1 GiB: 40% large random files, 30% text logs, 30% in 3 000 small random files.
Details and per-primitive numbers:
[docs/design.md §9](docs/design.md#9-parallelism-io-and-performance).

| create (full) | -j 1 | -j 2 | -j 4 | -j 8 | -j 20 |
|---|---|---|---|---|---|
| wall time | 0.88 s | 0.70 s | 0.37 s | 0.25 s | 0.33 s |
| throughput | 1.2 GB/s | 1.5 GB/s | 2.7 GB/s | 4.0 GB/s | 3.1 GB/s |

| increment | files cache | no files cache |
|---|---|---|
| unchanged tree | 0.035 s, 0 files read, 43 KB | 0.23 s, 1 GiB read, 43 KB |
| 1% scattered change | 0.17 s, 719 MiB read, 39 MB | 0.23 s, 1 GiB read, 39 MB |

| Other | Result |
|---|---|
| restore (full + increment, verified) | 3.7 GB/s |
| check | 8.5 GB/s |
| merge | 3.0 GB/s |
| SQLite increment, 26 MB database, 2% of rows rewritten at random | 0.99 × changed pages |

The 1% scattered change costs ~3.6× the bytes changed, because each 4 KiB
write dirties one or two ~20 KiB chunks; that is the price of CDC's chunk size,
and why SQLite databases get page-sized chunks.

## Security

**Threat model:** an attacker has every backup file and index and can modify,
delete, reorder, truncate and replay them, but does not have the key file.

- **Encrypted:** file contents, file names, the directory tree, file sizes,
  timestamps, owners, modes and symlink targets, and which chunks backups
  share (chunk IDs are keyed and kept inside encrypted records).
- **Authenticated:** every record (AES-256-GCM), and every chunk is re-hashed
  against its ID on read. Tampering makes `check` and `restore` fail loudly; a
  withheld file is reported as an incomplete chain.
- **Not hidden:** that these are bu files, the format version, the total size
  of each backup and the length of each chunk record (roughly the compressed
  chunk size), and so how much changed between increments. The sequence of
  chunk lengths of a large file can be used to test whether a backup contains
  a *known* file; bu does not pad records.
- **Not detected:** rollback to an older but valid chain. Keep the index, or
  a list of the expected files, somewhere an attacker cannot write.

**Key handling.** The key file holds the 32-byte master key in plaintext;
protect it like an SSH private key and store it apart from the backups (bu
warns when other users can access it). Lose it and every backup is
unreadable, by design. There is no passphrase support: the key file is the
only secret. Use one key per data set if files from two chains must not be
substitutable for each other.

bu does not roll its own primitives: BLAKE3, AES-256-GCM (libsodium) and LZ4
are vendored verbatim from upstream, and every composition is documented in
[docs/design.md §3](docs/design.md#3-cryptography) and
[§11](docs/design.md#11-threat-model).

## Limitations

Deliberately not supported (see
[docs/design.md §12](docs/design.md#12-deliberate-omissions)):

- Hard links (restored as separate files), extended attributes, ACLs and file
  flags. Device files, FIFOs and sockets are skipped with a warning.
- Exclude patterns and a one-file-system switch: back up what you name; the
  walk descends into mounted filesystems.
- More than one snapshot per backup file, and pruning other than by merging.
- Making a live database consistent: give bu a consistent copy.
- More than ~140 million new chunks (~2.8 TB of unique data) in one backup
  file; split larger first backups by directory.
- Platforms other than Linux x86-64, and CPUs without AES-NI, PCLMULQDQ and
  AVX (every x86-64 since ~2011 has them; bu names the missing feature).

Chunks referenced only by older snapshots are forgotten: a file that is
deleted and reappears two increments later is stored again. That is what
keeps the index the size of one snapshot and makes merge safe.

## Building and testing

Needs clang (with lld), CMake ≥ 3.20 and Ninja. The three libraries (BLAKE3,
LZ4, libsodium's AES-GCM) are vendored in `third_party/`; the binary links
only against glibc.

```sh
scripts/build.sh                 # Release build; prints the build directory, bu is in it
scripts/build.sh Debug --asan    # also: Debug, --asan (ASan + UBSan), --tsan
scripts/test.sh                  # unit and integration tests
scripts/test.sh --asan           # the same against a sanitizer build (or --tsan)
scripts/size_report.sh           # stripped size and a per-component breakdown
scripts/bench.sh                 # throughput and increment sizes
```

The build directory lives outside the tree, in
`~/.cache/bu-build-<config>-<hash>` (or under `$BU_BUILD_ROOT`). There is no
install step: copy `bu` wherever you like. The integration tests generate
test data with `openssl`; the SQLite test is skipped without the `sqlite3`
CLI.

## Documentation

- [docs/design.md](docs/design.md): chunking, crypto and the nonce scheme,
  manifests, the files cache, merge semantics, the threat model, performance
  and size.
- [docs/format.md](docs/format.md): the file format, byte by byte.
- [CHANGELOG.md](CHANGELOG.md)

## Licence

MIT, copyright (c) 2026 Jonathan Hale; see [LICENSE](LICENSE). Vendored code in
`third_party/` keeps its own licence, with the licence file beside it: BLAKE3
1.8.7 (CC0-1.0, or Apache-2.0, or Apache-2.0 WITH LLVM-exception), LZ4 1.10.0
(BSD-2-Clause), libsodium 1.0.22 (ISC). A binary contains code from all three,
so keep their notices with it. Details: [third_party/README](third_party/README).
