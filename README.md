# backu

Deduplicated, compressed, authenticated-encrypted incremental backups in one
small native binary (~175 KB, Linux x86-64). A very lightweight take on what
BorgBackup does, as a Unix filter: `create` writes a backup to stdout and
never opens a network connection, so where it goes (a file, S3, ssh, tape) is
your pipe.

- **Incremental from a small index.** An increment stores only chunks the
  previous snapshot did not have, and reads only files whose metadata changed
  (a Borg-style files cache). It needs the index, never the previous backup.
- **Content-defined chunking** (FastCDC, ~20 KiB average): an edit or an
  insertion stores only the chunks around it.
- **SQLite-aware.** Databases are chunked at their page size, so an increment
  after scattered updates is about the changed pages (measured: 0.99x).
- **Encrypted and authenticated.** AES-256-GCM (AES-NI) under a per-file key,
  keyed-BLAKE3 chunk IDs. File names, sizes and the tree are all encrypted.
- **Mergeable chains.** `merge full inc1` gives a new full backup; later
  increments keep working with it.
- **Fast.** ~4 GB/s create and ~3.7 GB/s verified restore (tmpfs, 14-core
  laptop); a parallel pipeline whose output does not depend on thread count.

## Build

Needs clang, CMake ≥ 3.20 and Ninja. Nothing else: the three libraries
(BLAKE3, LZ4, libsodium's AES-GCM) are vendored in `third_party/`.

```
scripts/build.sh            # prints the build directory; the binary is backu in it
scripts/test.sh             # unit and integration tests (sqlite3 CLI optional)
```

Requires a CPU with AES-NI, PCLMULQDQ and AVX (every x86-64 since ~2011);
backu says so by name if yours lacks one.

## Use

```sh
backu keygen > ~/.backu.key            # keep it safe, and NOT next to the backups

# full backup, then increments from the index
backu create --key ~/.backu.key --index-out data.idx ~/data > full.bk
backu create --key ~/.backu.key --base data.idx --index-out data.idx ~/data > inc1.bk

# straight to S3, keeping the new index only if the upload succeeded
set -o pipefail
backu create --key ~/.backu.key --base data.idx --index-out data.idx.new ~/data \
    | aws s3 cp - "s3://my-bucket/data-$(date +%F).bk" && mv data.idx.new data.idx

# restore the latest state of a chain (any order), every chunk verified
backu restore --key ~/.backu.key -C /restore full.bk inc1.bk inc2.bk

# roll the chain forward: one file replaces two
backu merge --key ~/.backu.key full.bk inc1.bk > full2.bk && rm full.bk inc1.bk

backu check --key ~/.backu.key full2.bk inc2.bk    # authenticate everything
backu list  --key ~/.backu.key full2.bk inc2.bk    # what is in there
backu index --key ~/.backu.key -o data.idx full2.bk inc2.bk   # lost the index?
```

SQLite: back up a consistent copy (`sqlite3 app.db ".backup app-copy.db"` or
the backup API), not a database that is being written to.

`backu help` lists every option. Exit status: 0 ok, 1 failure (or `create`
finished with warnings — unreadable files were left out, the backup is still
valid), 2 usage error.

## Documentation

- [docs/design.md](docs/design.md) — chunking, crypto and the nonce scheme,
  manifests, the files cache, merge semantics, the threat model, performance
  and size.
- [docs/format.md](docs/format.md) — the file format, byte by byte.
- [CHANGELOG.md](CHANGELOG.md)

## Licence

MIT (see [LICENSE](LICENSE)). Vendored code keeps its own licence: BLAKE3
(CC0-1.0 / Apache-2.0), LZ4 (BSD-2-Clause), libsodium (ISC); see
[third_party/README](third_party/README).
