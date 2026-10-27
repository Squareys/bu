# bu (backup utility)

**Encrypted, deduplicating, incremental backups as a Unix filter.**

bu is a lightweight take on what BorgBackup does, in one small native binary
(~230 KB stripped, Linux x86-64). `create` writes a backup to stdout and never opens a network
connection, so your pipe decides where it goes: a file, S3, ssh or tape. bu
has no repository directory and no server. You keep a key file, the backup
files and a small local index.

- **Encrypted and authenticated.** AES-256-GCM (AES-NI) under a fresh key per
  file. bu encrypts file names, sizes, timestamps and the directory tree.
- **Deduplicated.** FastCDC content-defined chunking (~20 KiB average) with
  keyed-BLAKE3 chunk IDs: after an edit or an insertion, bu stores the chunks
  around it and nothing else.
- **Incremental from a small index.** An increment stores the chunks the
  previous snapshot did not have, and reads the files whose metadata changed
  (a files cache). It needs the index, never the previous backup.
- **Mergeable chains.** `merge full inc1` gives a new full backup, and later
  increments keep working with it.
- **SQLite-aware.** bu chunks databases at their page size, so an increment
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

Make a key file. bu draws a random master key and stores it under your
passphrase, which it asks for twice. Keep a copy of the file somewhere other
than the backups.

```sh
bu key init ~/.bu.key
```

Make a full backup. It also writes the index the next increment needs.

```sh
bu create --key ~/.bu.key --index-out data.idx ~/data > full.bk
```

Make increments. Each stores the new chunks and reads the changed files.

```sh
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data > inc1.bk
```

```sh
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data > inc2.bk
```

Restore the latest state of the chain. The files can come in any order, and
bu verifies each chunk.

```sh
bu restore --key ~/.bu.key -C /restore full.bk inc1.bk inc2.bk
```

Roll the chain forward: one merged file replaces two, and `inc2.bk` keeps
working with it.

```sh
bu merge --key ~/.bu.key full.bk inc1.bk > full2.bk && rm full.bk inc1.bk
```

Authenticate every record of the chain.

```sh
bu check --key ~/.bu.key full2.bk inc2.bk
```

List what the chain holds.

```sh
bu list --key ~/.bu.key full2.bk inc2.bk
```

Rebuild a lost index from the chain.

```sh
bu index --key ~/.bu.key -o data.idx full2.bk inc2.bk
```

Each command that takes `--key` asks for the passphrase on the terminal. For
cron jobs and servers, put it in a file that only you can read (bu uses the
first line):

```sh
(umask 077; printf '%s\n' 'the passphrase' > /root/.bu-pass)
```

and name that file:

```sh
bu create --key /root/.bu.key --passphrase-file /root/.bu-pass \
    --base data.idx --index-out data.idx /srv/data > "/backup/data-$(date +%F).bk"
```

Or hand it over on a file descriptor, here from a password manager:

```sh
bu check --key ~/.bu.key --passphrase-fd 3 full2.bk inc2.bk 3< <(pass show bu)
```

Reading commands take the whole chain: the full backup (or merged file) and
each increment since. bu finds backups by snapshot ID, not by file name, so
you can rename the files and pass them in any order.

For SQLite, back up a consistent copy (`sqlite3 app.db ".backup app-copy.db"`,
the backup API, or a filesystem snapshot), not a database another process is
writing to.

## How it works

```
 files ──► chunk ──────► ID ──────► dedupe ─────► compress ──► encrypt ─────► stdout
           FastCDC, or   keyed      against the   LZ4 block    AES-256-GCM    (file, S3,
           SQLite pages  BLAKE3     index           │          per-file key    ssh, ...)
                                      │
                                      └─ already in the previous snapshot:
                                         reference it, store nothing
```

**Chunking.** bu cuts files where a rolling gear hash says so (FastCDC,
4 KiB minimum, ~20 KiB average, 64 KiB maximum). Cut points depend on the
content, not on offsets: an insertion at the start of a file changes the
first chunk and no other. bu recognises SQLite databases by their header and
cuts them at page boundaries instead.

**Dedupe and the index.** Each chunk's ID is a keyed BLAKE3 hash of its
content. The index is the latest snapshot itself. It serves as the set of
chunks the next increment may reference without storing them, as the base
the next file list is delta-encoded against, and as a files cache (device,
inode, size, mtime, ctime) that lets bu skip unchanged files without opening
them.

**Records.** bu compresses each chunk with LZ4 when that makes it smaller,
then seals it with AES-256-GCM. Each file has its own random salt and so its
own AES key, and nonces are sequence numbers, so a nonce never repeats under
one key. A reader re-hashes each decrypted chunk against its ID.

**Merge.** `merge` writes one self-contained backup with the chain's latest
snapshot and the chunks it references, under the same snapshot ID, so
increments made from that snapshot resolve against the merged file. The
merged file drops older snapshots; keep the old files if you want history.

In depth: [docs/design.md](docs/design.md) (why bu is built this way) and
[docs/format.md](docs/format.md) (the file format, byte by byte).

## Piping backups anywhere

`create` and `merge` stream to stdout. Reading commands (`restore`, `check`,
`list`, `index`, `merge`) take files on disk, so fetch a chain back before
you read it.

To a file:

```sh
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data > "data-$(date +%F).bk"
```

To another machine over ssh:

```sh
bu create --key ~/.bu.key --base data.idx --index-out data.idx ~/data \
    | ssh backup-host "cat > backups/data-$(date +%F).bk"
```

To S3, keeping the new index only if the upload succeeded (one script: the
`pipefail` setting and the pipeline belong together):

```sh
set -o pipefail
bu create --key ~/.bu.key --base data.idx --index-out data.idx.new ~/data \
    | aws s3 cp - "s3://my-bucket/data-$(date +%F).bk" && mv data.idx.new data.idx
```

bu writes the index atomically after it has written the whole backup, and
reports a dead pipe reader as an error without touching the index. bu cannot
see whether the far end stored what it received. When the upload can fail
after bu has finished, as with S3 above, write the index to a new name and
move it into place on success, so you never base an increment on a backup
that does not exist.

**Rotating chains.** Merge the full backup with the oldest increments into a
new full backup, check it, then delete the inputs. The chain stays short and
keeps working.

```sh
bu merge --key ~/.bu.key full.bk inc1.bk inc2.bk inc3.bk > full-new.bk \
    && bu check --key ~/.bu.key full-new.bk inc4.bk \
    && rm full.bk inc1.bk inc2.bk inc3.bk
```

`merge` needs the chain from a full backup up to the snapshot it merges.
`inc4.bk`, and each increment you make later from the index, keeps working
with the merged file.

## Commands

| Command | What it does |
|---|---|
| `bu key init KEYFILE` | Make a new key file: a random master key in slot 0 under a new passphrase (asked twice). Refuses to overwrite a file. |
| `bu key add KEYFILE` | Unlock with a passphrase, then add another one in a free slot (8 slots). |
| `bu key passwd KEYFILE` | Change the passphrase you unlock with. |
| `bu key remove KEYFILE [--slot N]` | Remove the slot you unlock with, or slot `N`. Refuses to remove the last usable slot. |
| `bu key info KEYFILE` | Show the key ID and each slot's KDF costs. Prints no secret. |
| `bu create --key KEYFILE --index-out INDEX [--base INDEX] [-j N] [--no-files-cache] [-v] PATH... > BACKUP` | Stream a backup of `PATH...` to stdout. With `--base`, make an increment: store the chunks the base index does not list, and skip reading files whose metadata is unchanged (`--no-files-cache` reads them anyway). Writes the new index atomically; `--index-out` may name the same file as `--base`. |
| `bu restore --key KEYFILE [-C DIR] [--path PREFIX] [-j N] [-v] BACKUP...` | Restore the latest snapshot of the chain into `DIR` (default: the current directory). With `--path`, restore the paths under `PREFIX`. |
| `bu merge --key KEYFILE [-j N] [-v] BACKUP... > MERGED` | Write one self-contained backup of the chain's latest snapshot, with the chunks it references and no others. |
| `bu check --key KEYFILE [-j N] [-v] BACKUP...` | Authenticate every record and verify that every snapshot is complete. |
| `bu list --key KEYFILE BACKUP...` or `bu list --key KEYFILE INDEX` | Show the files, and the latest snapshot's tree. |
| `bu index --key KEYFILE -o INDEX BACKUP...` | Rebuild a lost index, files cache included, from the chain. |
| `bu help` | Print usage. |

`-j N` sets the worker threads (default: online CPUs; `restore`: at most 8);
`create` adds up to four reader threads, a chunker and a writer. bu refuses unknown, repeated or
malformed options by name.

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
| 1 | Failure, or `create` finished with warnings: it left out unreadable files, or a file changed size while bu read it. The backup and index are still valid. |
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
write dirties one or two ~20 KiB chunks. CDC's chunk size sets that price,
and it is why SQLite databases get page-sized chunks.

## Security

**Threat model:** an attacker has every backup file and index and can modify,
delete, reorder, truncate and replay them, but does not have both the key
file and a passphrase.

- **Encrypted:** file contents, file names, the directory tree, file sizes,
  timestamps, owners, modes and symlink targets, and which chunks backups
  share (chunk IDs are keyed and sit inside encrypted records).
- **Authenticated:** every record (AES-256-GCM), and bu re-hashes every chunk
  against its ID on read. Tampering makes `check` and `restore` fail with an
  error; bu reports a withheld file as an incomplete chain.
- **Not hidden:** that these are bu files, the format version, the total size
  of each backup and the length of each chunk record (about the compressed
  chunk size), and from those, how much changed between increments. Someone
  holding a *known* file can use the sequence of its chunk lengths to test
  whether a backup contains it; bu does not pad records.
- **Not detected:** rollback to an older but valid chain. Keep the index, or
  a list of the expected files, somewhere an attacker cannot write.

**Key handling.** bu handles keys the way LUKS does:

- **The master key is random.** `bu key init` draws 32 bytes from the
  kernel. You never type or see it, and bu encrypts each backup under keys
  derived from it.
- **The passphrase unlocks the master key and does nothing else.** The key
  file stores the master key wrapped in up to eight slots, each sealed under
  a key that Argon2id derives from one passphrase. A thief with the key file
  still needs a passphrase, and pays an Argon2id run (by default ~1 GiB and
  ~2 s) for each guess.
- **Changing a passphrase re-encrypts nothing.** `key passwd`, `add` and
  `remove` rewrite a 944-byte file; each backup, old and new, opens with any
  current passphrase.
- **You need the key file as much as the passphrase.** Lose every copy of it
  and the backups are unreadable, passphrase or not. Keep a copy somewhere
  other than the backups, as you would keep a LUKS header backup. A copy you
  made earlier keeps the passphrases it had: removing a passphrase from your
  working file leaves it in the copy.

bu warns when other users can read the key file. Use one key per data set if
files from two chains must not be substitutable for each other.

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
- More than one snapshot per backup file, and pruning other than by merging.
- Making a live database consistent: give bu a consistent copy.
- More than ~140 million new chunks (~2.8 TB of unique data) in one backup
  file; split larger first backups by directory.
- Platforms other than Linux x86-64, and CPUs without AES-NI, PCLMULQDQ and
  AVX (x86-64 CPUs since ~2011 have them; bu names the missing feature).

bu forgets chunks that only older snapshots reference: if you delete a file
and it reappears two increments later, bu stores it again. That keeps the
index the size of one snapshot and makes merge safe.

## Building and testing

You need clang (with lld), CMake ≥ 3.20 and Ninja. The libraries (BLAKE3,
LZ4, and libsodium's AES-GCM and Argon2id) are vendored in `third_party/`;
the binary links against glibc and nothing else.

```sh
scripts/build.sh                 # Release build; prints the build directory, bu is in it
scripts/build.sh Debug --asan    # also: Debug, --asan (ASan + UBSan), --tsan
scripts/test.sh                  # unit and integration tests
scripts/test.sh --asan           # the same against a sanitizer build (or --tsan)
scripts/size_report.sh           # stripped size and a per-component breakdown
scripts/bench.sh                 # throughput and increment sizes
```

The build directory lives outside the tree, in
`~/.cache/bu-build-<config>-<hash>` (or under `$BU_BUILD_ROOT`). bu has no
install step: copy `bu` wherever you like. The integration tests generate
test data with `openssl` and skip the SQLite test without the `sqlite3` CLI.

## Documentation

- [docs/design.md](docs/design.md): chunking, crypto, the key file and the
  nonce scheme, manifests, the files cache, merge semantics, the threat
  model, performance and size.
- [docs/format.md](docs/format.md): the file format, byte by byte.
- [CHANGELOG.md](CHANGELOG.md)

## Licence

MIT, copyright (c) 2026 Jonathan Hale; see [LICENSE](LICENSE). Vendored code in
`third_party/` keeps its own licence, with the licence file beside it: BLAKE3
1.8.7 (CC0-1.0, or Apache-2.0, or Apache-2.0 WITH LLVM-exception), LZ4 1.10.0
(BSD-2-Clause), libsodium 1.0.22 (ISC). A binary contains code from all three,
so keep their notices with it. Details: [third_party/README](third_party/README).
