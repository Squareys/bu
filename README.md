# bu (backup utility)

[![CI](https://github.com/Squareys/bu/actions/workflows/ci.yml/badge.svg)](https://github.com/Squareys/bu/actions/workflows/ci.yml)

**Encrypted, deduplicating, incremental backups in one chain file.**

bu is a lightweight take on what BorgBackup does, in one small native binary
(~270 KB stripped, Linux x86-64). A full backup and its increments belong
together, so they live in one file, the **chain**: `bu create` writes a full
backup into a new chain and appends an increment to an existing one. bu has
no repository directory, no server and no network code. It works through
file descriptors, so a chain can sit on a local disk or a network mount
(NFS, SMB, sshfs, S3 through `rclone mount`), or travel through a pipe.

- **Encrypted and authenticated.** AES-256-GCM (AES-NI) under a fresh key per
  segment. bu encrypts file names, sizes, timestamps and the directory tree.
- **Deduplicated.** FastCDC content-defined chunking (~20 KiB average) with
  keyed-BLAKE3 chunk IDs: after an edit or an insertion, bu stores the chunks
  around it and nothing else.
- **Incremental from the chain itself.** An increment stores the chunks the
  latest snapshot does not have, and reads the files whose metadata changed
  (a files cache). It reads the chain's tail, not the whole chain.
- **Safe to append to.** One writer at a time (a lock). bu truncates a
  failed or interrupted append away, and after a crash readers skip the
  partial last segment.
- **Few round trips.** Readers find everything from the end of the file and
  read only the chunk ranges they need, in large sorted reads: restoring one
  directory reads that directory's data.
- **Mergeable.** `merge` collapses a chain into one full segment, and later
  increments keep working with it.
- **SQLite-aware.** bu chunks databases at their page size, so an increment
  after scattered updates is about the size of the changed pages.
- **Fast and multi-threaded.** A parallel pipeline whose output does not
  depend on the thread count: a full backup takes 2.8× as long as reading
  the data once (see [Performance](#performance)).

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Where backups live](#where-backups-live)
- [Commands](#commands)
- [Performance](#performance)
- [Security](#security)
- [Limitations](#limitations)
- [Building and testing](#building-and-testing)
- [Documentation](#documentation)
- [Licence](#licence)

## Quick start

Make a key file. bu draws a random master key and stores it under your
passphrase, which it asks for twice. Keep a copy of the file somewhere other
than the backups.

```sh
bu key init ~/.bu.key
```

Make a full backup. bu creates the chain file.

```sh
bu create --key ~/.bu.key /backup/data.bu ~/data
```

Run the same command again for each increment. It reads the chain's latest
snapshot, stores the new chunks and reads only the changed files.

```sh
bu create --key ~/.bu.key /backup/data.bu ~/data
```

Restore the latest state. bu verifies each chunk.

```sh
bu restore --key ~/.bu.key -C /restore /backup/data.bu
```

Restore one directory, named as `bu list` shows it (bu stores paths without
the leading `/`). bu reads only that directory's chunks.

```sh
bu restore --key ~/.bu.key -C /restore /backup/data.bu -- home/me/data/notes
```

Authenticate every record of the chain.

```sh
bu check --key ~/.bu.key /backup/data.bu
```

List the segments and the latest snapshot's files.

```sh
bu list --key ~/.bu.key /backup/data.bu
```

Compact the chain: one full segment of the latest state replaces the
history, and increments go on from there.

```sh
bu merge --key ~/.bu.key -o /backup/data.bu /backup/data.bu
```

Each command that takes `--key` asks for the passphrase on the terminal. For
cron jobs and servers, put it in a file that only you can read (bu uses the
first line):

```sh
(umask 077; printf '%s\n' 'the passphrase' > /root/.bu-pass)
```

and name that file:

```sh
bu create --key /root/.bu.key --passphrase-file /root/.bu-pass /backup/srv.bu /srv/data
```

Or hand it over on a file descriptor, here from a password manager:

```sh
bu check --key ~/.bu.key --passphrase-fd 3 /backup/data.bu 3< <(pass show bu)
```

For SQLite, back up a consistent copy (`sqlite3 app.db ".backup app-copy.db"`,
the backup API, or a filesystem snapshot), not a database another process is
writing to.

## How it works

```
 files ──► chunk ──────► ID ──────► dedupe ─────► compress ──► encrypt ─────► append
           FastCDC, or   keyed      against the   LZ4 block    AES-256-GCM    to the
           SQLite pages  BLAKE3     latest          │          per-segment    chain
                                    snapshot        │          key
                                      └─ already in it: reference it, store nothing
```

**Chunking.** bu cuts files where a rolling gear hash says so (FastCDC,
4 KiB minimum, ~20 KiB average, 64 KiB maximum). Cut points depend on the
content, not on offsets: an insertion at the start of a file changes the
first chunk and no other. bu recognises SQLite databases by their header and
cuts them at page boundaries instead.

**Chains and segments.** Each `create` appends one **segment**: its new
chunks, its snapshot (the file tree, coded as a delta against the previous
one) and a chunk table, then a small trailer that says where they are. A
reader starts at the end of the file and walks back from trailer to
trailer, so it never scans the data. Segments are self-contained, so
segments written as separate files and joined with `cat` are a chain too.

**Dedupe and the files cache.** Each chunk's ID is a keyed BLAKE3 hash of
its content. The latest snapshot serves three purposes: the set of chunks
the next increment may reference without storing them, the base its file
list is delta-encoded against, and a files cache (device, inode, size,
mtime, ctime) that lets bu skip unchanged files without opening them.

**Records.** bu compresses each chunk with LZ4 when that makes it smaller,
then seals it with AES-256-GCM. Each segment has its own random salt and so
its own AES key, and nonces are sequence numbers, so a nonce never repeats
under one key. A reader re-hashes each decrypted chunk against its ID.

**Merge.** `merge` writes one segment with the chain's latest snapshot and
the chunks it references, under the same snapshot ID, so increments made
from that snapshot resolve against it. It drops older snapshots; merge into
a new file instead of in place to keep them.

In depth: [docs/design.md](docs/design.md) (why bu is built this way) and
[docs/format.md](docs/format.md) (the file format, byte by byte).

## Where backups live

bu needs a file descriptor, nothing more. On a file it seeks: it reads the
trailers, then only the chunk ranges it needs. On a pipe it reads the stream
once, front to back.

**A local disk or a network mount.** NFS, SMB and sshfs work like a local
path. On a high-latency mount bu batches neighbouring chunks into large
reads and prefetches ahead, so a restore costs few round trips. For an
object store, mount it with rclone:

```sh
rclone mount b2:my-bucket /mnt/backup --vfs-cache-mode writes --daemon
```

```sh
bu create --key ~/.bu.key /mnt/backup/data.bu ~/data
```

rclone uploads a changed file whole, so each increment re-uploads the chain.
For large chains, write one object per increment instead (below).

**Locking.** `create` locks the chain while it appends and fails at once if
another bu holds the lock. bu truncates a failed or interrupted append
away; after a crash, readers skip a partial last segment and the next
`create` removes it. sshfs, rclone and SMB mounts lock only within one
machine, so append to a chain there from one machine only.

**Over ssh.** To append to a chain on another machine, stream the segment
and take the base from a local index (bu cannot read the remote chain back
through a pipe):

```sh
bu create --key ~/.bu.key --base data.idx --index-out data.idx - ~/data \
    | ssh backup-host 'cat >> backups/data.bu'
```

To read it back, stream it. `check` and `list` need nothing else; `restore`
needs the index.

```sh
ssh backup-host cat backups/data.bu | bu restore --key ~/.bu.key --index data.idx -C /restore -
```

**One object per increment**, for S3 and other stores where appending is
impossible: each increment is its own object, and the reading commands take
the objects in order. Run the first create with `--index-out` only, then:

```sh
set -o pipefail
bu create --key ~/.bu.key --base data.idx --index-out data.idx.new - ~/data \
    | aws s3 cp - "s3://my-bucket/data/$(date +%F).bu" && mv data.idx.new data.idx
```

The new index replaces the old one only after the upload succeeded, so no
increment is based on one that does not exist. Over 50 GB, give `aws s3 cp`
the size with `--expected-size`, or it runs out of multipart parts. To
restore, fetch the objects and name them in order (or `cat` them into one
chain file):

```sh
bu restore --key ~/.bu.key -C /restore 2026-10-01.bu 2026-10-02.bu 2026-10-03.bu
```

`bu index -o data.idx CHAIN...` writes an index from a chain, should you
lose the index but still have the chain.

**Rotating chains.** Merge in place to drop history, or merge into a new
chain each month and keep the old one as it is. The new chain starts from a
full segment of the latest state, without reading your data again, and
`create` appends to it from then on.

```sh
bu merge --key ~/.bu.key -o /backup/data-2026-11.bu /backup/data-2026-10.bu
```

**Unencrypted chains.** `--no-key` writes a chain without encryption: no
key file, and the reading commands need no key. Checksums catch damage,
not tampering (see [Security](#security)).

```sh
bu create --no-key /backup/media.bu ~/media
```

## Commands

| Command | What it does |
|---|---|
| `bu key init KEYFILE` | Make a new key file: a random master key in slot 0 under a new passphrase (asked twice). Refuses to overwrite a file. |
| `bu key add KEYFILE` | Unlock with a passphrase, then add another one in a free slot (8 slots). |
| `bu key passwd KEYFILE` | Change the passphrase you unlock with. |
| `bu key remove KEYFILE [--slot N]` | Remove the slot you unlock with, or slot `N`. Refuses to remove the last usable slot. |
| `bu key info KEYFILE` | Show the key ID and each slot's KDF costs. Prints no secret. |
| `bu create (--key KEYFILE \| --no-key) [--base INDEX] [--index-out INDEX] [-j N] [--no-files-cache] [-v] CHAIN PATH...` | Back up `PATH...`: a full backup into a new or empty `CHAIN`, an increment appended to an existing one (store the chunks its latest snapshot lacks, skip reading files whose metadata is unchanged; `--no-files-cache` reads them anyway). `CHAIN` `-` is stdout: a file there is appended to, a pipe gets the segment streamed, with the base from `--base`. `--index-out` writes the new snapshot's index. |
| `bu restore [--key KEYFILE] [--index INDEX] [-C DIR] [-j N] [-v] CHAIN... [-- PATH...]` | Restore the latest snapshot into `DIR` (default: the current directory), or only the `PATH`s after `--`. A chain on a pipe (`-`) needs `--index`. |
| `bu merge [--key KEYFILE] [-o OUT] [-j N] [-v] CHAIN...` | Write one full segment of the latest snapshot, with the chunks it references and no others, to `OUT` (default: stdout). `OUT` may be the chain itself. |
| `bu check [--key KEYFILE] [-j N] [-v] CHAIN...` | Authenticate every record and verify that every snapshot is complete. |
| `bu list [--key KEYFILE] CHAIN...` or `bu list [--key KEYFILE] INDEX` | Show the segments, and the latest snapshot's tree. |
| `bu index [--key KEYFILE] -o INDEX CHAIN...` | Write the index of the latest snapshot, files cache included. |
| `bu help` | Print usage. |

`CHAIN...` is a chain file, or its segments as separate files, in order;
`-` is stdin. Reading commands read the mode from the chain: an encrypted
chain needs `--key`, and an unencrypted one refuses it (`--no-key` may be
given to say so). `-j N` sets the worker threads (default: online CPUs;
`restore`: at most 8; `create`: the CPUs less three quarters of its
readers). `create` adds up to eight reader threads, a chunker and a writer.
bu refuses unknown, repeated or malformed options by name.

**Passphrases.** Each command that unlocks the key file (the commands above
with `--key`, plus `key add`, `passwd` and `remove`) reads the passphrase from
`--passphrase-file PATH` (the first line, without its line ending), from
`--passphrase-fd N` (up to the first newline), or else from the terminal with
echo off. `key add` and `key passwd` read the new passphrase from
`--new-passphrase-file` or `--new-passphrase-fd`; `key init` reads its one
passphrase from `--passphrase-file` or `--passphrase-fd`. With no terminal and
none of these options, the command fails and names them.

**KDF costs.** `key init`, `add` and `passwd` time Argon2id on your machine
and pick the passes so one unlock takes about 2 s, with min(1 GiB, RAM/4) of
memory. `--kdf-target-ms MS` (100–60000) changes the target, `--kdf-memory
MIB` (8–4096) fixes the memory, and `--kdf-time PASSES` (1–100) fixes the
passes and skips the timing. Each machine that unlocks a slot needs that
slot's memory free. For a small server, add a slot on the server, or pass
`--kdf-memory 256`.

**Exit status**

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Failure, or `create` finished with warnings: it left out unreadable files, or a file changed size while bu read it. The chain is still valid. |
| 2 | Usage error. |

## Performance

**Performance.** On a laptop NVMe (i7-12700H, 1.5 GiB in 23,614 files, cold
page cache, backup written to the same disk):

| Run | Time | vs. reading every file once |
|---|---|---|
| Raw read, the ceiling | 0.60 s | 1.0× |
| `cp -a` to the same disk | 3.97 s | 6.7× |
| `bu create`, full | 1.69 s | 2.8× |
| `bu create`, nothing changed | 0.08 s | 0.14× |
| `bu create`, 1 % of files changed | 0.11 s | 0.18× |
| `bu restore` / `bu check` | 1.45 s / 0.42 s | 2.4× / 0.71× |

A backup has to read its data, so the table measures each run against
reading every file once (8 parallel streams, the fastest plain reader on
this disk). A full backup takes 2.8× as long as reading the data once,
with encryption, compression and the write to the same disk included. An
increment skips each file whose inode, size and mtime match the previous
backup and reads the rest, so it finishes in under a fifth of one full
read. [docs/benchmarks.md](docs/benchmarks.md) has the method, the numbers
before and after this release's read-path work, and the other layouts
(tmpfs, one big file, `-j 1`).

## Security

**Threat model:** an attacker has every chain and index file and can modify,
delete, reorder, truncate and replay them, but does not have both the key
file and a passphrase.

- **Encrypted:** file contents, file names, the directory tree, file sizes,
  timestamps, owners, modes and symlink targets, and which chunks segments
  share (chunk IDs are keyed and sit inside encrypted records).
- **Authenticated:** every record (AES-256-GCM) and every segment's layout,
  and bu re-hashes every chunk against its ID on read. Tampering makes
  `check` and `restore` fail with an error; bu reports a withheld segment
  as an incomplete chain.
- **Not hidden:** that these are bu files, the format version, the size and
  generation of each segment and the length of each chunk record (about the
  compressed chunk size), and from those, how much changed between
  increments. Someone holding a *known* file can use the sequence of its
  chunk lengths to test whether a backup contains it; bu does not pad
  records.
- **Not detected:** rollback to an older but valid chain, or a chain cut
  back to a segment boundary. Keep an index, or a note of the chain's size,
  somewhere an attacker cannot write.

**Unencrypted chains** (`--no-key`) hide nothing and authenticate nothing:
BLAKE3 checksums catch damage, but anyone who can write the chain can
change it undetected. Use them for data that is not secret, on storage you
trust. Readers given `--key` refuse an unencrypted chain, so scripts that
always pass `--key` cannot be fooled by a forged unencrypted chain in place
of an encrypted one.

**Key handling.** bu handles keys the way LUKS does:

- **The master key is random.** `bu key init` draws 32 bytes from the
  kernel. You never type or see it, and bu encrypts each segment under keys
  derived from it.
- **The passphrase unlocks the master key and does nothing else.** The key
  file stores the master key wrapped in up to eight slots, each sealed under
  a key that Argon2id derives from one passphrase. A thief with the key file
  still needs a passphrase, and pays an Argon2id run (by default ~1 GiB and
  ~2 s) for each guess.
- **Changing a passphrase re-encrypts nothing.** `key passwd`, `add` and
  `remove` rewrite a 944-byte file; each chain, old and new, opens with any
  current passphrase.
- **You need the key file as much as the passphrase.** Lose every copy of it
  and the backups are unreadable, passphrase or not. Keep a copy somewhere
  other than the backups, as you would keep a LUKS header backup. A copy you
  made earlier keeps the passphrases it had: removing a passphrase from your
  working file leaves it in the copy.

bu warns when other users can read the key file. Use one key per data set if
segments from two chains must not be substitutable for each other.

bu does not roll its own primitives. BLAKE3, AES-256-GCM and Argon2id
(libsodium) and LZ4 come verbatim from upstream, and
[docs/design.md §3](docs/design.md#3-cryptography) and
[§11](docs/design.md#11-threat-model) document each composition.

## Limitations

bu does not support (see
[docs/design.md §12](docs/design.md#12-deliberate-omissions)):

- Hard links (restored as separate files), extended attributes, ACLs and file
  flags. bu skips device files, FIFOs and sockets with a warning.
- Exclude patterns and a one-file-system switch: back up what you name; the
  walk descends into mounted filesystems.
- More than one snapshot per segment, and pruning other than by merging.
- Merging a chain read from a pipe: save it to a file first.
- Making a live database consistent: give bu a consistent copy.
- More than ~140 million new chunks (~2.8 TB of unique data) in one
  segment; split larger first backups by directory.
- Platforms other than Linux x86-64, and, for encrypted chains, CPUs without
  AES-NI, PCLMULQDQ and AVX (x86-64 CPUs since ~2011 have them; bu names the
  missing feature).

bu forgets chunks that only older snapshots reference: if you delete a file
and it reappears two increments later, bu stores it again. That keeps the
base the size of one snapshot and makes merge safe.

## Building and testing

You need clang (with lld), CMake ≥ 3.20 and Ninja. The libraries (BLAKE3,
LZ4, and libsodium's AES-GCM and Argon2id) are vendored in `third_party/`;
the binary links against glibc and nothing else.

```sh
scripts/build.sh                 # Release build; prints the build directory, bu is in it
scripts/build.sh Debug --asan    # also: Debug, --asan (ASan + UBSan), --tsan
scripts/test.sh                  # unit and integration tests
scripts/test.sh --smoke          # smoke tests: unit tests and the quick end-to-end scripts
scripts/test.sh --asan           # the same against a sanitizer build (or --tsan)
scripts/size_report.sh           # stripped size and a per-component breakdown
scripts/bench.sh                 # throughput and increment sizes (tmpfs)
scripts/bench_io.sh --src DIR --dst DIR   # against the disk (docs/benchmarks.md)
```

The build directory lives outside the tree, in
`~/.cache/bu-build-<config>-<hash>` (or under `$BU_BUILD_ROOT`). bu has no
install step: copy `bu` wherever you like. The integration tests generate
test data with `openssl` and skip the SQLite test without the `sqlite3` CLI.
CI (GitHub Actions, `.github/workflows/ci.yml`) runs the smoke tests and
the size report on a Release build, the full suite, and the full suite
under `--asan` and `--tsan`.

## Documentation

- [docs/design.md](docs/design.md): chain files, chunking, crypto, the key
  file and the nonce scheme, manifests, the files cache, merge semantics,
  the threat model, performance and size.
- [docs/format.md](docs/format.md): the file format, byte by byte.
- [docs/benchmarks.md](docs/benchmarks.md): bu against the disk, with raw
  read, raw write and copy baselines.
- [CHANGELOG.md](CHANGELOG.md)

## Licence

MIT, copyright (c) 2026 Jonathan Hale; see [LICENSE](LICENSE). Vendored code in
`third_party/` keeps its own licence, with the licence file beside it: BLAKE3
1.8.7 (CC0-1.0, or Apache-2.0, or Apache-2.0 WITH LLVM-exception), LZ4 1.10.0
(BSD-2-Clause), libsodium 1.0.22 (ISC). A binary contains code from all three,
so keep their notices with it. Details: [third_party/README](third_party/README).
