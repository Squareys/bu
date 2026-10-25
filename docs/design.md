# backu design

backu makes deduplicated, compressed, authenticated-encrypted incremental
backups with one small binary and no server, no repository directory and no
network code. This document says why it is built the way it is. The byte
layout is in [format.md](format.md).

## 1. Model

There are three kinds of file:

- the **key file**: 32 random bytes, the only secret;
- **backup files**: one per `create` (or `merge`), written to stdout;
- the **index**: a small local file describing the latest snapshot, which the
  next `create` needs instead of the previous backup.

A **chain** is a full backup (or a merged file) followed by increments. backu
never needs to know where backups are stored: `create` and `merge` stream to
stdout, so `> file`, `| aws s3 cp - s3://...` and `| ssh host 'cat > x'` are
all the same to it. Reading commands (`restore`, `check`, `list`, `index`,
`merge`) take files on disk and may seek. Reading the whole previous backup
to make an increment is never necessary; the index is.

Each backup file contains exactly one **snapshot** (a file tree) and the
chunks that snapshot needed that the base did not have.

## 2. Chunking

### Content-defined chunking for ordinary files

Files are cut with FastCDC (Xia et al., 2016/2020): a 64-bit gear hash
`h = (h << 1) + G[byte]` rolls over the data and a chunk ends where selected
bits of `h` are all zero. Because the left shift pushes each byte out of the
64-bit state after 64 steps, `h` at byte *i* depends only on bytes
*i−63 … i*: cut points are a property of the content, not of offsets. Insert
nine bytes at the start of an 8 MB file and only the first chunk changes; the
rest re-synchronise (integration test 01 measures this).

Parameters: minimum 4 KiB, a hard 15-bit mask up to 16 KiB, an easy 13-bit
mask up to the 64 KiB maximum (FastCDC's normalised chunking, which narrows
the size distribution). The measured average on random data is ~20 KiB
(19.9 KiB over 32 MiB in `tests/test_chunker.cpp`). Mask bits are spread over
the top 32 bits of the hash so every tested bit has 32–64 bytes of context.
The gear table is generated at compile time from a fixed SplitMix64 seed.

Why ~20 KiB: small enough that a scattered 4 KiB write costs one or two
chunks, large enough that per-chunk overhead (≈ 60 bytes across record,
trailer and manifest) stays well under 1% and the index stays small. Borg's
2 MiB default would make the "1% scattered change" benchmark store most of
the data again.

**Two-phase CDC.** The hash is primed over the 63 bytes before the minimum
size, so whether byte *i* is a cut candidate does not depend on where the
current chunk began. The scan for candidates (one load, shift-add and test
per byte, the only per-byte work on the serial path) can therefore run in
parallel on independent blocks, and choosing cuts is a linear walk over a
sparse candidate list. `cdcNextCut` is the plain one-pass definition and a
unit test proves the parallel form cuts identically.

### SQLite databases

SQLite rewrites pages in place: an `UPDATE` touching 2% of rows dirties the
pages holding them and nothing else. CDC would cut across page boundaries, so
one changed page would usually dirty two chunks. backu recognises a database
by its 100-byte header (`"SQLite format 3\0"`, page size as a big-endian `u16`
at offset 16, `1` meaning 65536) and cuts at exact page boundaries, **one page
per chunk** for pages of 4 KiB and up; smaller pages are grouped to 4 KiB,
because below that the ~60 bytes of overhead per chunk stop being small.

Measured (integration test 04): a 26 MB database, 4 000 of 200 000 rows
rewritten at random, 2 999 pages actually differing: the increment was
0.993 × (changed pages × 4096). The overhead per page is smaller than what
LZ4 wins back.

backu does not make a live database consistent. Give it a consistent copy —
`sqlite3 db ".backup copy.db"`, the online backup API, or a filesystem
snapshot — not a file another process is writing (a copy taken mid-write can
be corrupt in ways no backup tool can see).

## 3. Cryptography

### Primitives

| Purpose | Primitive | Implementation |
|---|---|---|
| chunk IDs, subkeys, header check | BLAKE3 (keyed, derive_key) | official C, SSE4.1/AVX2/AVX-512, runtime dispatch |
| encryption + authentication | AES-256-GCM | libsodium's AES-NI + PCLMULQDQ implementation |
| compression | LZ4 block | official lz4.c |
| randomness | `getrandom(2)` | kernel |

**Why BLAKE3:** one primitive with a keyed mode (chunk IDs as a MAC, like
Borg's keyed ID hash) and a key-derivation mode, faster than SHA-256 even with
SHA extensions, and SIMD-parallel inside a single 16 KiB input.

**Why AES-256-GCM:** every x86-64 CPU since about 2011 accelerates it (6.4 GB/s
per core here, see §9), it is the most scrutinised AEAD there is, and
libsodium's AES-NI implementation is self-contained, runtime-targeted and
written by people who do this for a living. It needs AES-NI, PCLMULQDQ and AVX;
backu checks CPUID itself and refuses other CPUs by name rather than ship a
slow, rarely exercised software fallback. (This libsodium release has no
VAES/VPCLMULQDQ wide path; on CPUs that have it, a 4-block-wide GHASH would
roughly double AES-GCM throughput, which is not the bottleneck today.)
ChaCha20-Poly1305 as a fallback was considered and left out: it would add a
second cipher, a second code path to test, and a format flag, for CPUs over a
decade old.

Known-answer tests cover both: BLAKE3's official vectors in all three modes
at lengths that hit every SIMD path, and GCM test cases 13–16 from the GCM
specification plus OpenSSL-computed tags for messages up to 64 KiB (the
official vectors never reach the 7-block parallel path).

### Chunk IDs

`ID = first 16 bytes of keyed-BLAKE3(K_id, chunk)`. Keyed, so an ID reveals
nothing about content to anyone without the key (an unkeyed hash would let an
attacker confirm "this backup contains file X" by hashing X). 128 bits rather
than Borg's 256: the probability of any collision among 2^40 chunks (≈ 20 PB
at 20 KiB) is about 2^-49, and without the key nobody can search for one; the
index and the manifests get half as large. A collision, were one ever to
happen, would silently substitute one chunk for another in a restore; that is
the risk 2^-49 prices.

### Keys and nonces

The master key `K` never touches data. Everything is derived with BLAKE3
`derive_key`, each purpose under its own hardcoded context string:

- `K_id` from `K` alone (IDs must agree across all backups for dedupe);
- per container, a **fresh random 32-byte salt** in the header, and from
  `K ‖ salt` the AES-256 key and the header-check key.

So every file — every backup, every merge output, every index — has its own
AES key. Within a file the 96-bit GCM nonce is a 64-bit counter:

- chunk records use their **stream sequence number**, assigned by the chunker
  in cut order before any worker sees the chunk; it is unique by construction
  and stays below 2^63;
- metadata records use fixed values with bit 63 set (manifest, trailer,
  index), disjoint from chunk nonces.

A nonce therefore never repeats under one key, without any state shared
between runs and without relying on random nonces (whose collision bound,
2^-32 after 2^32 messages, would be uncomfortably close for a tool that may
write billions of chunks under one master key). Merge re-encrypts every chunk
it keeps under the new file's key with new sequence numbers.

The **associated data** of every record is its type byte and its chunk ID
(zeros for metadata). A record cannot be replayed as another type or under
another ID, and the nonce binds it to its position class. On top of the tag,
a reader recomputes the keyed hash of every decoded chunk and compares it
with the ID, which is what makes it safe for `merge` and `restore` to take a
chunk by ID from whichever file has it.

The **header check** (keyed BLAKE3 of the header under a salt-derived key)
distinguishes "wrong key" from "damaged file" before any decryption, and
authenticates the version and kind fields.

## 4. Compression

Each record's plaintext is either stored or one LZ4 block, chosen per record:
LZ4 runs with its output capped below the input size, and if it does not
shrink the payload, the payload is stored with a one-byte header. Incompressible
data costs one fast LZ4 attempt (LZ4 bails out early on random data, ~11 GB/s)
and one byte. LZ4 over zstd: at ~1.5 GB/s per core on text and ~6.5 GB/s
decompressing it is never the bottleneck behind disk or network; zstd would
compress logs better and halve create throughput.

## 5. Manifests

A snapshot is encoded as entries in walk order (depth-first, siblings sorted
by name), paths prefix-coded against the previous entry, every integer a
varint. Entries carry type, mode, uid, gid, mtime and ctime (ns), dev, inode,
size, a symlink target, and a file's chunk list.

**Delta encoding.** An increment's manifest is encoded against its parent
snapshot. Every entry is still listed (a deleted file is simply absent), but
a file's chunk list is a short program over the parent's list for the same
path: `COPY n`, `SEEK ±n`, `NEW n` + IDs. The encoder is greedy and linear:
copy while the lists agree; on a mismatch, seek to the new ID's position in
the old list if it occurs there, otherwise emit new IDs. That captures
in-place page rewrites, insertions, deletions and moved blocks. Without it, an
increment of an unchanged 1 GB database would still carry all its ~262 000
chunk IDs (4 MB); with it, one `COPY`. Measured on the benchmark tree, an
increment of an unchanged 1 GB / 3 090-file tree is 43 KB, ~14 bytes per file.

Decoding a delta needs the parent snapshot, which is looked up by its random
16-byte snapshot ID among the files given — never by file name.

## 6. The index and the files cache

The index is **the latest snapshot itself**, self-contained (no delta), plus an
advisory table of which backup file each chunk was written to. One structure
serves three purposes:

- **dedupe set:** the chunks the next increment may reference without storing
  are exactly the chunks the latest snapshot references;
- **delta base:** the next manifest is encoded against it;
- **files cache:** a regular file whose `(dev, ino, size, mtime_ns, ctime_ns)`
  all equal its entry in the index is **not opened at all**; its chunk list is
  copied. An increment of a 10 GB tree reads only what changed.

ctime is compared as well as mtime because user space cannot set it: `touch -r`
can put an mtime back, but the change to the inode moves the ctime
(integration test 05 checks exactly that trick). One race remains: a file
modified within the same timestamp tick as it was read. A cache entry is
trusted only if its ctime is at least one second older than the moment the
base backup started; younger files are read again once (Git's "racily clean"
rule).

`--no-files-cache` reads every file and still stores nothing that is already
present.

**Chunks not in the latest snapshot are forgotten.** If a file is deleted and
reappears two increments later, its chunks are stored again. This is
deliberate: it is what makes merge safe (§7) and keeps the index the size of
one snapshot.

A lost index is rebuilt from the chain with `backu index`; because manifests
carry dev/ino/ctime too, the rebuilt index has the files cache intact.

## 7. Merge

`merge FILES... > out` writes one backup containing **the chain's latest
snapshot, fully expanded, and exactly the chunks it references**. Older
snapshots are not kept: history is what keeping old files is for, and one
snapshot per file keeps the format and every command simple.

The merged snapshot **keeps its snapshot ID and generation**. The input must
reach back to a full backup (the output is self-contained); every chunk is
authenticated and re-hashed on the way through and re-sealed under the new
file's key without recompression.

**Why later increments keep working.** Write `S_k` for the snapshot of
increment *k* and `R(S)` for the chunks it references. Increment *k+1* is made
from the index of `S_k`, so it references only chunks in `R(S_k)` (the index's
dedupe set *is* `R(S_k)`) or chunks it stores itself, and its manifest names
`S_k`'s ID as parent. `merge(…, inc_k)` contains exactly `R(S_k)` and `S_k`
under its original ID. So inc *k+1* resolves against the merged file with no
reference to the files it replaced. By induction this holds for any sequence
of merges and increments, and for increments made before or after a merge.
Integration test 02 runs a three-step chain merged twice with increments in
between.

Chains are a list of files in any order; the latest snapshot is the one with
the highest generation (ties: the file named last).

## 8. Restore and check

`restore` resolves the latest snapshot (recursively through parents), counts
missing chunks **before writing anything**, then restores files in batches:
each chunk is an independent task — `pread`, GCM-open, decompress, verify the
ID, `pwrite` at its offset — on a thread pool. Files are created with
`ftruncate` to their size first, and all-zero chunks are not written, so
sparse files stay sparse. Directories get their final mode and mtime last.

Every path is resolved component by component with `O_NOFOLLOW` from the
target directory's descriptor, missing parents are created, and symlinks are
created as links, never followed — a symlink in the restored tree or planted
in the target cannot redirect a write. Ownership is restored when running as
root; set-uid bits are applied after chown.

`check` authenticates every record of every file, re-hashes every chunk,
resolves every snapshot and confirms every reference is present.

## 9. Parallelism, I/O and performance

`create` is a pipeline with bounded memory (~12 MiB of read blocks plus
~65 KiB per job slot, 4 slots per worker):

1. **walk** (main thread): `fdopendir`/`readdir` (getdents64) and `fstatat`
   relative to directory fds, children sorted by name; the files cache is
   applied here.
2. **readers** (up to 4): claim `(file, offset)` ranges in walk order with the
   next ring slot, `pread` 1 MiB plus the 63 bytes CDC needs before it,
   `posix_fadvise` SEQUENTIAL on open and DONTNEED on each range after reading
   (a backup should not evict everybody else's page cache), `O_NOATIME` when
   permitted (silently dropped after the first EPERM), `openat` relative to a
   cached directory fd. Several readers keep several reads in flight (NVMe
   wants queue depth; many small files want their opens overlapped) and run
   CDC phase 1 while the block is hot in cache.
3. **chunker**: takes blocks strictly in ring order, moves the previous
   block's short tail into the new block's headroom, selects cuts, numbers
   chunks. No file data is copied: jobs point into the blocks, which are
   reference-counted.
4. **workers** (`-j N`, default: online CPUs): keyed-BLAKE3 ID, dedupe lookup,
   LZ4, AES-GCM.
5. **writer** (main thread): takes finished jobs strictly in sequence, drops
   duplicates (first occurrence wins), `writev`s the records straight from the
   job slots.

**Determinism.** Sequence numbers (and so nonces and record order) are fixed
by the chunker; dedupe is decided by the in-order writer. Thread count and
scheduling change only the speed: the chunk table of a backup is the same for
`-j 1` and `-j 7` (test 01 compares digests; the files differ only by salt).

No `mmap` (a file truncated while mapped raises SIGBUS), no io_uring (with
1 MiB reads the syscall rate is ~3 000/s per GB/s, nothing to win, and it
would cost size and complexity). Output goes through a 4 MiB buffer or
`writev`, with EINTR and partial writes handled; SIGPIPE is ignored so a dead
pipe reader is a reported error and the index is not updated.

`restore`, `check` and `merge` use a thread pool over independent chunk tasks.

**Files that change underneath.** The backup is of the tree as walked: a file
is read up to the size the walk saw. One that grew or shrank by the time it
is opened is backed up anyway (what is there, up to the walked size) with a
"changed size" warning; one that cannot be opened or read is left out with a
warning. Either way `create` exits 1 while the backup and index stay valid,
which is Borg's convention for "completed with warnings". A backup written
into the tree it is backing up (`backu create . > x.bk`) skips its own output
file by inode, and an index location that cannot be written is refused
before anything is read.

### Measurements

Intel i7-12700H (6P+8E cores, 20 threads, no AVX-512), data on tmpfs (so
these are CPU numbers; on disk the readers' queue depth matters instead).
`scripts/bench.sh`, 1 GiB tree: 40% large random files, 30% text logs, 30%
3 000 small random files.

| Primitive, one thread, 16 KiB chunks | MiB/s |
|---|---|
| BLAKE3 keyed (AVX2 here) | 3 070 |
| AES-256-GCM seal / open | 6 390 / 6 580 |
| LZ4 compress, random / text (3.4×) | 10 900 / 1 540 |
| LZ4 decompress, text | 6 570 |
| FastCDC one pass / scan + select | 2 620 / 1 990 |

| create (full) | -j 1 | -j 2 | -j 4 | -j 8 | -j 20 |
|---|---|---|---|---|---|
| wall time | 0.88 s | 0.70 s | 0.37 s | 0.25 s | 0.33 s |
| throughput | 1.2 GB/s | 1.5 GB/s | 2.7 GB/s | 4.0 GB/s | 3.1 GB/s |

Beyond ~8 workers the writer's copy into the output file and the E-cores
flatten the curve.

| increment | files cache | no files cache |
|---|---|---|
| unchanged tree | 0.035 s, 0 files read, 43 KB | 0.23 s, 1 GiB read, 43 KB |
| 1% scattered change | 0.17 s, 719 MiB read, 39 MB | 0.23 s, 1 GiB read, 39 MB |

The 1% change rewrites 4 KiB at ~1 000 random offsets in the large files
(every one of them is touched, hence 719 MiB still read), appends to every
log and rewrites 1% of the small files. Each 4 KiB write dirties one or two
~20 KiB chunks, so the increment is ~3.6× the bytes changed: that is the
price of CDC's chunk size, and why SQLite gets page-sized chunks.

restore (full + increment, verified): 0.27 s, 3.7 GB/s; check: 8.5 GB/s;
merge: 3.0 GB/s.

## 10. Size

Stripped binary: **174 616 bytes** (Linux x86-64, dynamically linked against
glibc, clang 23, LTO). By component (symbol sizes, text + rodata):

| Component | Bytes |
|---|---|
| BLAKE3 (portable + SSE4.1 + AVX2 + AVX-512, -O3) | 64 114 |
| AES-256-GCM (libsodium AES-NI, -O3) | 21 104 |
| LZ4 (inlined into codecEncode/codecDecode) | 8 768 |
| backu hot path (-O2) | 3 862 |
| backu cold path: CLI, walk, pipeline, manifest, restore, merge (-Oz) | 56 067 |
| crt and runtime glue | 4 113 |

The size rule is "small by default, speed wins on hot paths", so the budget
went to the SIMD variants: the AVX-512 BLAKE3 kernel alone is 21 KB, and
building the vendored code at -O2 instead of -O3 would save 5 KB for a 5–8%
slower BLAKE3, which was rejected. What costs no speed is used everywhere:
`-ffunction-sections`/`--gc-sections`, LTO, `--icf=all`, no unwind tables,
hidden visibility, no libstdc++ at all, `-Oz` for cold code (12 KB smaller
than `-Os`, no measurable effect), CPUID read directly instead of
`__builtin_cpu_supports` (saves compiler-rt's 5.4 KB feature decoder), and
the SSE2 BLAKE3 variant compiled out (every AES-NI CPU has SSE4.1). Hot entry
points are `noinline` (`BK_HOT`) so LTO cannot inline them into `-Oz` code.
The "well below 100 KB" target is not met: the vendored hot code alone is
94 KB, and meeting it would mean dropping SIMD paths.

## 11. Threat model

**Assumed:** the attacker has every backup file and index, can modify,
delete, reorder, truncate and replay them, and does not have the key file.

**What they learn:**

- that these are backu files, the format version and kind;
- per backup: the number of new chunks and the length of each chunk record
  (≈ compressed chunk size), the size of the manifest and the trailer
  (≈ number of files and chunks), the total size;
- across backups: how much changed between increments (from their sizes).

**What they do not learn:** file names, directory structure, file sizes,
timestamps, owners, modes, symlink targets, which chunks are shared between
backups (IDs are inside the encrypted trailer, and every file has its own
key), or anything about content beyond the above.

**Known leaks inherent to the design** (Borg shares both): the sequence of
chunk lengths of a large file, which CDC derives from its content, can be
used to test whether a backup contains a *known* file (fingerprinting); and
per-chunk compressibility leaks through record lengths. Padding chunk
records would blunt both at a cost in size; backu does not pad.

**What they can do:**

- *forge or alter data:* no; every record is authenticated, every chunk is
  re-hashed, and any change makes `check` and `restore` fail loudly
  (integration test 03 flips bytes in chunks, header, trailer and footer and
  truncates);
- *delete or withhold files:* yes, which `restore` reports as an incomplete
  chain (missing parent snapshot or missing chunks) rather than as damage;
- *roll back:* present an older but valid chain instead of the current one.
  backu cannot detect that without external state; keep the index (which
  records the latest generation and snapshot ID) or a list of expected files
  somewhere the attacker cannot write;
- *substitute files between two chains made with the same key:* each file is
  internally consistent, so this is detected only where snapshot IDs or
  chunks do not line up. Use one key per data set if that matters.

The key file is stored in plaintext; protect it like an SSH private key.
Losing it makes every backup unreadable, by design.

## 12. Deliberate omissions

- Hard links (restored as separate files), extended attributes, ACLs,
  device files, FIFOs and sockets (skipped with a warning), file flags.
- Exclude patterns; back up what you name.
- More than one snapshot per file, and pruning other than by merging.
- A ChaCha20-Poly1305 fallback for CPUs without AES-NI (§3).
- Fixed-size chunking for caller-chosen files (`--fixed`): SQLite gets page
  chunking automatically and nothing else measured needed it.
- Live-database consistency (§2).
- A parallel walk: stat is cheap next to reading; the readers already overlap
  opens.
- Unbounded backup files: the trailer is capped at 3 GiB (~22 bytes per new
  chunk), i.e. ~140 million new chunks or ~2.8 TB of unique data in one
  backup file. Larger first backups can be split by directory.
