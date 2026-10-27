# bu design

bu makes deduplicated, compressed, authenticated-encrypted incremental
backups into one chain file per data set, with one small binary and no
server, no repository directory and no network code. This document says why it is built the way it is. The byte
layout is in [format.md](format.md).

## 1. Model

There are three kinds of file:

- the **key file**: a random 32-byte master key, stored only wrapped under
  one or more passphrases (§3, *The key file*);
- **chains**: a full backup and the increments after it, as **segments**
  laid end to end in one file (or in several, one segment each);
- **index files**, optional: the latest snapshot of a chain, for writing the
  next segment somewhere the chain cannot be read back from.

Each segment contains exactly one **snapshot** (a file tree) and the chunks
that snapshot needed that its base did not have. A full backup and its
increments are useless apart, so they live together: `bu create CHAIN PATH`
on a new file writes a full backup, and on an existing chain appends an
increment, taking its base (dedupe set, delta base and files cache) from
the chain's own tail.

### Chain files

**A segment is self-contained.** It has its own header, salt and key, its
records, and a fixed 64-byte **trailer** at its end: the segment's length,
where its manifest and its chunk table are, the snapshot's generation, a
check value and a magic. Every offset is relative to the segment's first
byte. Two consequences:

- A reader finds the segments from the end of the file. The trailer gives
  the last segment's length, so its start; the bytes before that end with
  the previous segment's trailer. The walk must land exactly on offset 0.
  Reading a chain's structure costs one small read per segment, and the
  window bu reads around each trailer (256 KiB) usually holds the table, the
  manifest and the header of a small segment, and the trailer before it.
- Segments written separately are a chain once concatenated: `cat a.bu
  b.bu > c.bu` gives the same bytes as appending b to a.
  A segment does not record where it sits, so there is nothing to
  validate or rewrite; what holds a chain together is the snapshot IDs
  (an increment names its parent's) and the chunk IDs, as before.

**Appending.** `create` opens the chain with `O_APPEND`, takes an
exclusive `flock` (failing at once, by name, when another bu holds it: a
second backup of the same chain at the same time is a mistake to report,
not to queue), reads the base from the tail, writes the segment and
fsyncs. On a write error, SIGINT, SIGTERM or SIGHUP, create truncates the
file back to where the segment began, so a chain keeps no half segment
that bu gave up on. The signal handler does the truncate; only the
main thread writes the chain and only it takes those signals (the worker
threads block them), so no write of ours can land after it. A merge
replacing a chain in place holds the same lock, and a create re-checks,
once it has the lock, that the path still names the file it opened.

**What a crash leaves.** After SIGKILL or a power cut, the chain can end
in a partial segment. A reader that finds no valid trailer at the end scans back for the
trailer magic and takes the last position from which a walk to offset 0
succeeds; it reads the chain up to there and says how many bytes it skips.
`check` counts the tail as a problem (unless a create holds the lock at
that moment: then the tail is a backup being written). The next `create`
cuts the tail off before appending. In an encrypted chain only bu with the
key can make a trailer that authenticates, so the first such candidate is
the answer and a broken walk from it is damage; in an unencrypted chain a
trailer can sit inside stored chunk data (a backup of a chain), so a
candidate whose walk fails is skipped.

**Locks on network file systems.** `flock` works between processes on one
machine everywhere, and between machines on NFS (the client maps it to
NFS locks). sshfs and rclone mounts (FUSE) and SMB without the right mount
options only lock locally: two machines appending to one chain there can
interleave their segments into garbage. Give each machine its own chain.
Where `flock` fails outright (`ENOLCK`), create warns and goes on.

### Where chains live

bu reads and writes through file descriptors and never opens a network
connection. Whether a descriptor can seek decides how a chain is read, never
a flag:

- **Seek mode**, a regular file: a path on a local disk, NFS, SMB, sshfs,
  or an object store through `rclone mount`; or `-` when stdin is a file.
  Readers walk the trailers, read the tables, and then only the chunk
  records they need, in spans sorted by offset (§9).
- **Stream mode**, a pipe on stdin: `ssh host cat chain.bu | bu ...`. The
  records are read once, front to back. `check` and `list` need nothing
  else. `restore` needs the snapshot before the data arrives, and the
  chain's manifests sit at the end of each segment, so it takes an index
  (`--index`). `merge` refuses a pipe: what it keeps is decided by the
  latest snapshot, at the end of the chain.

`create` writes to a chain file, to stdout when it is a file (`>> chain`
appends like a path), or to a pipe (`| aws s3 cp - ...`), which it cannot
read back: there the base comes from an index (`--base`) and the next one
is written with `--index-out`. That is also the way to keep **one object
per segment** where appending is impossible or costly (S3 objects are
immutable; rclone re-uploads a modified file whole): each increment goes to
a new file or object, and the reading commands take the files in order.
On a pipe bu raises the pipe buffer to 1 MiB (`F_SETPIPE_SZ`), so each side
wakes once per MiB instead of per 64 KiB.

### Rejected

- *A separate index file next to every chain* (pre-release format 1): two
  files that must stay in step, and the index lived on the machine making
  the backups. The chain's tail holds the same information; the index stays for
  pipes and object stores.
- *tar as the container*: tar has no index (a reader scans every member
  header to find anything), cannot authenticate its structure, and its
  members are files, not chunks shared across increments. A tail index
  would have to be bolted on anyway.
- *A chain-end pointer in the first header*, patched after each append:
  breaks `cat`, needs a writable non-append descriptor, and on object
  stores rewrites the first byte of a huge file.
- *Chunk nonces in the clear* (so a stream reader needs no record header):
  the gaps between the stored sequence numbers show where unchanged data
  lies between changed chunks: for a database, which pages changed.
  *Random nonces in the clear*: no leak, but uniqueness only with high
  probability; the record header keeps it by construction for 25 bytes per
  record.

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
one changed page would usually dirty two chunks. bu recognises a database
by its 100-byte header (`"SQLite format 3\0"`, page size as a big-endian `u16`
at offset 16, `1` meaning 65536) and cuts at exact page boundaries, **one page
per chunk** for pages of 4 KiB and up; smaller pages are grouped to 4 KiB,
because below that the ~60 bytes of overhead per chunk stop being small.

Measured (integration test 04): a 26 MB database, 4 000 of 200 000 rows
rewritten at random, 2 999 pages actually differing: the increment was
0.993 × (changed pages × 4096). The overhead per page is smaller than what
LZ4 wins back.

bu does not make a live database consistent. Give it a consistent copy —
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
| passphrase stretching (key file) | Argon2id (RFC 9106) | libsodium's, SSSE3/AVX2/AVX-512F, runtime dispatch |
| randomness | `getrandom(2)` | kernel |

**Why BLAKE3:** one primitive with a keyed mode (chunk IDs as a MAC, like
Borg's keyed ID hash) and a key-derivation mode, faster than SHA-256 even with
SHA extensions, and SIMD-parallel inside a single 16 KiB input.

**Why AES-256-GCM:** every x86-64 CPU since about 2011 accelerates it (6.4 GB/s
per core here, see §9), it is the most scrutinised AEAD there is, and
libsodium's AES-NI implementation is self-contained, runtime-targeted and
written by people who do this for a living. It needs AES-NI, PCLMULQDQ and AVX;
bu checks CPUID itself and refuses other CPUs by name rather than ship a
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

- `K_id` from `K` alone (IDs must agree across all segments for dedupe);
- per segment, a **fresh random 32-byte salt** in the header, and from
  `K ‖ salt` the AES-256 key and the check key.

So each segment (an increment, a merge output, an index) has its own AES
key. Within a segment the 96-bit GCM nonce is a 64-bit counter,
from one of three spaces that cannot meet:

- chunk bodies use their **stream sequence number**, assigned by the
  chunker in cut order before any worker sees the chunk; it is unique by
  construction and stays below 2^63;
- metadata bodies use fixed values with bit 63 set (manifest, table, index);
- **record headers** use 2^63 + 2^62 + the record's ordinal in the segment.

A nonce therefore never repeats under one key, without any state shared
between runs and without relying on random nonces (whose collision bound,
2^-32 after 2^32 messages, would be uncomfortably close for a tool that may
write billions of chunks under one master key). Merge re-encrypts every chunk
it keeps under the new segment's key with new sequence numbers.

**The record header.** Every record starts with 25 sealed bytes: its type
and its body's nonce. A reader that seeks has both from the table and
skips them (`check` verifies them). A reader streaming a segment from a
pipe meets the chunk records before the table, and the sequence numbers
have gaps where duplicates were dropped, so it could not guess them; it
counts records instead, and the header, sealed under that count, tells it
the rest. The writer seals the headers itself, in order, once it knows
which chunks it stores: 9 bytes of AES-GCM per record, nothing next to the
workers' work. Reordering, dropping or duplicating records in a stream
breaks the count.

The **associated data** of a body is its type byte. A record cannot be
replayed as another type, and the nonce binds it to its place. A chunk is
bound to its ID by content: a reader recomputes the keyed hash of every
decoded chunk and compares it with the ID it was looking for (the table's,
or, streaming, the one the snapshot wants), which is what makes it safe for
`merge` and `restore` to take a chunk by ID from whichever segment has it.
(Pre-release format 1 also put the ID in the associated data; a stream reader does not
know it before decrypting, and the hash check binds it anyway.)

The **header check** (keyed BLAKE3 of the header under a salt-derived key)
distinguishes "wrong key" from "damaged file" before any decryption, and
authenticates the version, kind and flags. The **trailer check** (keyed
BLAKE3 of header and trailer) authenticates the segment's length, the
offsets of its metadata and its generation: a walk back through a chain
only follows trailers made with the key.

### Unencrypted chains

`bu create --no-key` writes segments with header flag bit 0 set and the
same layout, minus encryption: payloads in the clear, chunk IDs as unkeyed
BLAKE3, and every 16-byte tag a checksum (unkeyed BLAKE3 of nonce, type and
payload; for a chunk, its ID, which the reader re-hashes). Readers see the
flag and need no key. This **detects damage, not tampering**: anyone can
write a valid unencrypted chain, or edit one and recompute the checksums.
It is for data that is not secret, on storage you trust, where a key file
is one more thing to lose.

There is no silent default: `create` needs `--key` or `--no-key`. A chain
is one or the other; appending the other kind, or reading a concatenation
of both, is refused. A reader given `--key` refuses an unencrypted chain,
so an attacker cannot replace an encrypted chain with an unencrypted one of
their own making and have it restored, as long as scripts pass `--key`.
Unencrypted segments need neither AES-NI nor a key file, so they also work
on CPUs bu otherwise refuses.

### The key file

The design is LUKS's: a **random master key** `K` that nobody types or sees,
stored only **wrapped in keyslots**, each slot unlocked by one passphrase
stretched with Argon2id. `bu key init` draws `K` from `getrandom` and seals it
into slot 0; `key add`, `key passwd` and `key remove` edit slots around the
same `K` after unlocking with an existing passphrase; every command that
takes `--key` unlocks the file first. Byte layout: [format.md](format.md#key-file-format-2).

Everything in a backup is derived from `K` and nothing from a passphrase, so
the backup format did not change when the key file did, and changing a
passphrase re-encrypts nothing: it rewrites one 112-byte slot. The other side
of the same coin: the key file is as necessary as the passphrase. Lose every
copy of it and the passphrase alone opens nothing, exactly as with a LUKS
header.

**A slot.** `KEK = Argon2id(passphrase, salt, t, m, p = 1)`; `K` is sealed
with AES-256-GCM under `KEK`, a random nonce, and associated data covering
the file header (magic, version, key ID), the slot index and every parameter
byte of the slot. Salt and nonce are fresh on every slot write, so each KEK
seals exactly one message and nonce reuse cannot arise. Binding the index and
the header means a slot cannot be moved to another position or spliced into
another key file; binding the parameters means they cannot be edited (a
lowered cost would change the KEK anyway, but the AEAD makes it a rule rather
than a consequence). AES-GCM is reused because it is already in the binary
and already tested; a dedicated key-wrap mode (AES-KW, RFC 3394) would add a
primitive for no property this construction lacks, since the KEK is unique
per slot write.

**Wrong passphrase or damage.** Each slot and the header carry an unkeyed
16-byte BLAKE3 checksum. A slot whose checksum fails is reported as damaged
and skipped, without making the other slots unusable; only when every intact
slot fails authentication is the answer "wrong passphrase". The checksums
detect accidents, not attacks: an attacker can recompute them, and then the
AEAD refuses the slot (reported as a wrong passphrase, which is the honest
answer: no slot opens). After unwrapping, `K` must reproduce the header's key
ID, a `derive_key` output that `bu key info` also shows as a fingerprint.

**Eight slots.** LUKS2 has 32, sized for multi-user disks and recovery
schemes. A backup key needs one passphrase for the owner, one for a
recovery copy, perhaps one per unattended host: eight covers that with room,
keeps the file a fixed 944 bytes (one parser, no counts to validate), and
bounds the worst case of a wrong passphrase, which runs the KDF once per
used slot.

**KDF costs.** Argon2id with one lane (libsodium's implementation is
single-threaded). Defaults follow cryptsetup's LUKS2 policy: memory is
min(1 GiB, a quarter of physical RAM); the passes are then **calibrated at
slot creation** so one unlock takes about 2 s on the machine that writes the
slot. Calibration times a one-pass and a two-pass run to separate the fixed
cost (mapping and touching the memory) from the per-pass cost. With automatic
memory, if three passes (RFC 9106's second recommended option) would not fit
the target, the memory is halved first, down to 64 MiB. Measured here
(i7-12700H, AVX2 kernel): a one-pass run at 1 GiB takes 0.36 s, mapping
included; calibration chose 1 GiB and 6-7 passes; `bu key init` took 3.0 s
(calibration included) and every unlock 2.1 s with 1 GiB resident.
Parameters are stored per slot, so a slot made on a laptop and one made on a
small server can coexist, and `key passwd` re-calibrates. `--kdf-memory`
(8–4096 MiB), `--kdf-time` (1–100 passes, skips calibration) and
`--kdf-target-ms` (100–60000) override; values outside the bounds are
refused, never clamped, and a slot read from disk with parameters outside
them is treated as damaged, so a tampered file cannot make bu allocate
terabytes. libsodium's MODERATE preset (256 MiB, 3 passes) was the fixed
alternative; calibration was chosen because a fixed cost is too slow on a
small ARM board and needlessly weak on a workstation. The price: a slot
made on a fast machine unlocks proportionally slower on a slow one, and a
1 GiB slot cannot be opened on a host with less free memory; such hosts
want their own slot, added there or with `--kdf-memory`. Unlocking skips a
slot whose memory cannot be allocated, with a warning naming it, and goes on
to the others, so that host's own slot still opens.

Parameters below RFC 9106's recommendations (under 64 MiB, or fewer than
three passes below 2 GiB, its one-pass option) are allowed, since a small
board may need them, but `bu key` warns when it writes such a slot and
`bu key info` marks it "(weak)". Nobody else can lower a slot's parameters:
they are in the AEAD's associated data.

**Unattended runs.** Cron and server backups read the passphrase from
`--passphrase-file PATH` (its first line) or `--passphrase-fd N`; there is no
raw-key slot type. One slot type keeps one code path and one thing to audit;
a raw-key slot would amount to a second plaintext key file under another
name, while a passphrase file on a server is the same exposure with the
Argon2 cost still in front of offline guessing, and can be root-only or
supplied by a secret manager through a descriptor. A passphrase file that
group or others can access is warned about, as a key file is (`bu key info`
included). Interactively the
passphrase is read from `/dev/tty` with echo off (stdin and stdout carry
backup data), never from an environment variable (visible in
`/proc/PID/environ`, inherited by children) or an argument (visible in `ps`).
Without a terminal or a source the command fails and names the flags.
Ctrl-Z is held back while echo is off and stops bu once the terminal is
restored, so a suspended bu never leaves the shell silent.

**Rewriting the file.** `key add`, `passwd` and `remove` replace the whole
file: a new file beside it under a random name, created with `O_EXCL` and
`O_NOFOLLOW` and mode 0600, fsynced, renamed over the old one, and the
directory fsynced so the rename survives a crash. A predictable temp name
would let anyone who can write in the directory plant a symlink there and
have bu write through it. A rename replaces a name, not the file behind it,
so these commands refuse a key path that is a symlink or has other hard
links (and say so before asking for a passphrase): the real file would keep
its old slots, and a removed passphrase would go on opening it. Resolving
the link and rewriting its target was the alternative; refusing was chosen
because the target's directory may not be the user's to write and a
rewrite should land where the user pointed. There is no lock: two key
commands run at once on one file both start from the old slots and the
later rename wins, losing the other's change. Key management is rare and
interactive; a lock file would be one more thing to go stale.

**Memory hygiene.** The passphrase, the KEK and its AES schedule, and `K` are
wiped (`explicit_bzero`) on every path once used; `MasterKey` wipes itself on
destruction, and so do the derived per-segment keys (`SegKeys`, wherever
they are copied). `mlock` is not used: `K` lives for the whole run and is
expanded into one AES schedule per segment, which the worker threads read
in place, so locking only the passphrase buffer would protect the least
valuable secret, and
locking all of it would need more than the default `RLIMIT_MEMLOCK`. Swap is
the swap's to encrypt.

**Rejected.**

- *A plaintext key file* (bu's first format, `bu-key-1 <hex>`): one stolen
  file reads every backup, with no second factor, and there is no way to
  rotate access without re-encrypting everything.
- *The master key derived directly from the passphrase* (`K = KDF(pw)`):
  changing the passphrase would change `K` and orphan every existing backup
  (or force re-encryption of all of them), there could be only one
  passphrase, and the KDF salt would have to live somewhere anyway. The
  keyslot indirection costs 944 bytes.
- *A raw-key slot for automation*: see above.
- *Public-key recipients* (RSA or X25519 slots, as in age): would let a
  machine write backups that only an offline key can read. A sound later
  feature, as another slot type sealing `K` to a public key; it needs a
  second primitive and a different trust story, and nothing in the slot
  layout precludes it (the state and KDF bytes are there to grow).

## 4. Compression

Each record's plaintext is either stored or one LZ4 block, chosen per record:
LZ4 runs with its output capped below the input size, and if it does not
shrink the payload, the payload is stored with a one-byte header. Incompressible
data costs one fast LZ4 attempt (LZ4 bails out early on random data, ~11 GB/s)
and one byte. LZ4 counts in `int`, so a payload above its ~2 GiB input limit
(only a metadata record can be that large) is always stored, and a reader
refuses an LZ4 payload claiming more. LZ4 over zstd: at ~1.5 GB/s per core on text and ~6.5 GB/s
decompressing it is never the bottleneck behind disk or network; zstd would
compress logs better and halve create throughput.

## 5. Manifests

A snapshot is encoded as entries in walk order (depth-first, siblings sorted
by name), paths prefix-coded against the previous entry, every integer a
varint. Entries carry type, mode, uid, gid, mtime and ctime (ns), dev, inode,
size, a symlink target, and a file's chunk list, each chunk with its size.
The sizes (a varint per new chunk) make a snapshot say where every chunk
goes on its own; a restore from a pipe needs that, because each segment's
table, which also has them, arrives after its data.

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
16-byte snapshot ID among the segments given, never by file name or
offset.

**Checkpoints.** Deltas chain: resolving the latest snapshot reads every
manifest back to a self-contained one. To bound that, `create` writes a
self-contained manifest instead of a delta when the delta bytes since the
last self-contained one would exceed its size. Resolving then reads at most
about twice a full manifest, however long the chain, and the checkpoints
cost at most as much again as the deltas. A self-contained manifest keeps
its parent's ID (for lineage), with a flag saying it needs no parent to
decode. The counters travel in the index for increments written to pipes.

## 6. The index and the files cache

The base of an increment is **the latest snapshot itself**. `create`
appending to a chain reads it from the chain's tail (walking back only as
far as the last checkpoint needs); an index file is the same snapshot,
self-contained, for an increment written to a pipe or to a separate file.
One structure serves three purposes:

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

`bu index` writes the index of a chain's latest snapshot; because manifests
carry dev/ino/ctime too, it has the files cache intact. The index of
pre-release format 1 also had a table of which backup file held each
chunk; nothing used it, and it is gone.

## 7. Merge

`merge -o NEW CHAIN...` writes a chain of one segment containing **the
chain's latest snapshot, fully expanded, and exactly the chunks it
references**. Older snapshots are not kept: history is what keeping the old
chain is for, and one snapshot per segment keeps the format and every
command simple. It reads the chain like restore (spans of nearby records,
§9) and needs a file, not a pipe.

The merged snapshot **keeps its snapshot ID and generation**. The input must
reach back to a full backup (the output is self-contained); every chunk is
authenticated and re-hashed on the way through and re-sealed under the new
segment's key without recompression. An unencrypted chain merges to an
unencrypted one.

**Rotation.** `bu merge -o chain.bu chain.bu` compacts a chain in place: the
output goes to a temp file beside it and is renamed over it, under the
chain's lock, so a create cannot slip a segment in that the rename would
drop. To keep history instead, merge into a new file and append to that
from then on (`bu merge -o 2026-11.bu 2026-10.bu`): the old chain stays as
it was, and the new one starts from a full segment of the latest state
without reading the source data again.

**Why later increments keep working.** Write `S_k` for the snapshot of
increment *k* and `R(S)` for the chunks it references. Increment *k+1* is made
from the base `S_k` (the chain's tail or its index), so it references only
chunks in `R(S_k)` (the base's dedupe set *is* `R(S_k)`) or chunks it stores
itself, and its manifest names `S_k`'s ID as parent. `merge(…, inc_k)`
contains exactly `R(S_k)` and `S_k` under its original ID. So inc *k+1*
resolves against the merged segment with no reference to the segments it
replaced. By induction this holds for any sequence
of merges and increments, and for increments made before or after a merge.
Integration test 02 runs a chain compacted in place with increments
appended after it, and a chain of separate files merged a prefix at a
time.

A chain may be given as several files, normally in order; segments are
found by ID, so the order matters only for ties. The latest snapshot is the
one with the highest generation, read from the trailers (ties: the later
segment). `create` appending to a chain takes its last segment's snapshot
as the base.

## 8. Restore and check

`restore` resolves the latest snapshot (recursively through parents), counts
missing chunks **before writing anything**, then restores files in batches
on a thread pool, reading the chain in spans (§9). PATHs after `--` restore
those files and directories only, and only their chunks are read. Files are
created with `ftruncate` to their size first, and all-zero chunks are not
written, so sparse files stay sparse. Directories get their final mode and
mtime last.

**From a pipe** the snapshot comes from `--index`, which must be one of the
stream's snapshots (bu says so when it is not the latest). Every file is
created and sized first; then each chunk record is opened, decoded and
hashed on the pool as it streams past, and the chunks the snapshot uses are
written to every place they go, in one pass with nothing staged on disk.
Missing chunks show only at the end, and are reported then. Files are
opened again to be written, with `O_NOFOLLOW`, and refused unless they are
still the inode restore created.

Every path is resolved component by component with `O_NOFOLLOW` from the
target directory's descriptor, missing parents are created, and symlinks are
created as links, never followed — a symlink in the restored tree or planted
in the target cannot redirect a write. A name that already exists where a
file is restored is unlinked and created anew with `O_EXCL`, never opened:
opening it would write through a hard link planted there to a file outside
the tree, or block on a planted FIFO. Directory modes are set through a
descriptor opened `O_NOFOLLOW | O_DIRECTORY`, so a directory swapped for a
symlink after the check cannot pass the chmod on.

Ownership is restored when running as root; set-uid bits are applied after
chown. Set-uid and set-gid bits on files are restored only for root, as GNU
tar does: for another user they would make a file from the backup run with
that user's identity. A directory's set-gid bit (group inheritance, no
privilege) is kept.

`list` prints names and symlink targets with control bytes escaped (`\n`,
`\t`, `\r`, `\xHH`, and `\\` for a backslash): a file name may hold any
byte but `/` and NUL, and one carrying escape sequences must not drive the
terminal of whoever lists the backup.

`check` authenticates every record of every segment (headers included),
re-hashes every chunk, resolves every snapshot and confirms every reference
is present. From a pipe it does the same in one pass, and compares each
segment's table with the records that came before it.

## 9. Parallelism, I/O and performance

`create` is a pipeline with bounded memory (~16 MiB of read blocks plus
~65 KiB per job slot, 4 slots per worker):

1. **walk** (main thread): `fdopendir`/`readdir` (getdents64) and `fstatat`
   relative to directory fds, children sorted by name; the files cache is
   applied here.
2. **readers** (up to 8): claim `(file, offset)` ranges in walk order with the
   next ring slot, `pread` 1 MiB plus the 63 bytes CDC needs before it,
   `posix_fadvise` SEQUENTIAL on open and DONTNEED on each range after reading
   (a backup should not evict everybody else's page cache), `O_NOATIME` when
   permitted (silently dropped after the first EPERM), `openat` relative to a
   cached directory fd. Several readers keep several reads in flight (NVMe
   wants queue depth; many small files want their opens overlapped) and run
   CDC phase 1 while the block is hot in cache. A reader scans as well as
   reads, so it keeps less than one read in flight on average: on an NVMe,
   8 readers made a full backup of a tree of small files 1.3-1.4× faster
   than 4, and of one big file 1.4× (with the ring grown from 12 to 16
   blocks to feed them). Without `-j`, readers are min(8, CPUs / 2); with
   `-j N`, (N + 1) / 2, at most 8. Readers sleep on a disk but are busy on
   a fast source, so 8 readers plus a worker per CPU oversubscribed a
   20-CPU machine and cost 8% on tmpfs; the default worker count leaves
   them room (14 workers: tmpfs back to the old speed, nothing lost on the
   NVMe; 12 was faster on tmpfs but 10% slower reading the NVMe). A big file is
   read as 1 MiB ranges handed out in turn, so each reader's descriptor
   sees a strided pattern; that did not defeat the kernel's readahead
   (four threads reading 1 MiB ranges in turn from separate descriptors
   read a cold file within 6% of four contiguous extents), so the ranges
   stay as they are.
3. **chunker**: takes blocks strictly in ring order, moves the previous
   block's short tail into the new block's headroom, selects cuts, numbers
   chunks. No file data is copied: jobs point into the blocks, which are
   reference-counted.
4. **workers** (`-j N`; default: the online CPUs less three quarters of the
   readers, 14 on 20 CPUs): keyed-BLAKE3 ID, dedupe lookup,
   LZ4, AES-GCM.
5. **writer** (main thread): takes finished jobs strictly in sequence, drops
   duplicates (first occurrence wins), `writev`s the records straight from the
   job slots.

**Determinism.** Sequence numbers (and so nonces and record order) are fixed
by the chunker; dedupe is decided by the in-order writer. Thread count and
scheduling change only the speed: the chunk table of a backup is the same for
`-j 1` and `-j 7` (test 01 compares digests; the segments differ only by salt).

No `mmap` (a file truncated while mapped raises SIGBUS), no io_uring (with
1 MiB reads the syscall rate is ~3 000/s per GB/s, nothing to win, and it
would cost size and complexity). Output goes through a 4 MiB buffer or
`writev`, with EINTR and partial writes handled; SIGPIPE is ignored so a dead
pipe reader is a reported error and the index is not updated. The writer
seals each stored record's header in that `writev` loop: only it knows the
record's ordinal, and a 9-byte seal per record is lost in the noise (a
1 GiB tree backs up as fast as before on tmpfs).

`restore`, `check` and `merge` use a thread pool over independent tasks and
read the chain in **spans**: runs of nearby records of one segment (about
256 KiB) read with one `pread` and opened from memory. Each
task also asks the kernel (`POSIX_FADV_WILLNEED`) for the span about 16 MiB
ahead, so the disk keeps a deep queue of large reads whatever `-j` is.
Reading one ~20 KiB record per `pread` from many threads at scattered
offsets ran at half the disk's sequential speed; spans of 256 KiB measured
better than 1-2 MiB (less CPU, and more tasks to spread over threads). A
full backup restores as long runs of consecutive records because the
snapshot lists chunks in the order `create` wrote them. Restore sorts each
batch's chunks by their place in the chain, so chunks of one segment that
increments scattered across the tree come back together, and a span may
read through up to 64 KiB of records nobody needs rather than split: on a
network mount a round trip costs more than the bytes. A chunk used in
several places (all-zero pages) is decoded once per span. `merge` builds
its spans the same way, in output order.

`restore` gathers decoded chunks that continue each other in one output file
into one `pwrite` (up to 1 MiB) and overlaps two batches of files: the main
thread creates and sizes the next batch's files (a third of the wall time on
ext4) while a finisher thread runs the current batch on the pool and then
sets its files' owner, mode and times. Batches hold up to 4 096 files and
1 GiB; restore raises the soft descriptor limit towards the hard one for
that, and uses smaller batches when it cannot. It runs 8 threads unless
`-j` says otherwise: with the prefetch, 8 read as fast as 20, and 20 threads
writing into the page cache spent twice the kernel CPU for no gain in wall
time.

**Files that change underneath.** The backup is of the tree as walked: a file
is read up to the size the walk saw. One that grew or shrank by the time it
is opened is backed up anyway (what is there, up to the walked size) with a
"changed size" warning; one that cannot be opened or read is left out with a
warning. Either way `create` exits 1 while the segment is complete and the
chain valid, which is Borg's convention for "completed with warnings". A
chain inside the tree it is backing up (`bu create x.bu .`) skips itself by
inode, and an index location that cannot be written is refused before
anything is read.

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
| wall time | 0.91 s | 0.78 s | 0.42 s | 0.26 s | 0.29 s |
| throughput | 1.2 GB/s | 1.4 GB/s | 2.6 GB/s | 4.2 GB/s | 3.7 GB/s |

Beyond ~8 workers the writer's copy into the output file and the E-cores
flatten the curve. (Median of three runs on a development build of 27 October 2026. `-j 20` runs 8
readers on top of 20 workers; without `-j`, create runs 14 workers on this
machine for that reason.)

| increment | files cache | no files cache |
|---|---|---|
| unchanged tree | 0.038 s, 0 files read, 44 KB | 0.16 s, 1 GiB read, 44 KB |
| 1% scattered change | 0.13 s, 719 MiB read, 39 MB | 0.17 s, 1 GiB read, 39 MB |

The 1% change rewrites 4 KiB at ~1 000 random offsets in the large files
(every one of them is touched, hence 719 MiB still read), appends to every
log and rewrites 1% of the small files. Each 4 KiB write dirties one or two
~20 KiB chunks, so the increment is ~3.6× the bytes changed: that is the
price of CDC's chunk size, and why SQLite gets page-sized chunks.

restore (full + increment, verified): 0.29 s, 3.7 GB/s; check: 0.09 s,
12 GB/s (was 8.5); merge: 3.0 GB/s. On tmpfs restore is bound by creating
and writing the files, so the span reads change its time little but halve
its CPU. The disk-bound picture, where they matter, is in
[benchmarks.md](benchmarks.md): from a cold NVMe, check went from 0.97 s to
0.42 s for a 1.2 GB backup, restore to the same disk from 2.05 s to 1.45 s,
and create from 2.01 s to 1.69 s.

## 10. Size

Stripped binary: **273 272 bytes** (Linux x86-64, dynamically linked against
glibc, clang 23, LTO). By component (symbol sizes, text + rodata):

| Component | Bytes |
|---|---|
| BLAKE3 (portable + SSE4.1 + AVX2 + AVX-512, -O3) | 64 114 |
| Argon2id + BLAKE2b (libsodium, ref + SSSE3 + AVX2 + AVX-512F kernels, -O3) | 32 377 |
| AES-256-GCM (libsodium AES-NI, -O3) | 21 323 |
| LZ4 (inlined into codecEncode/codecDecode) | 8 510 |
| bu hot path (-O2) | 4 279 |
| bu cold path: CLI, key file, walk, pipeline, chains, manifest, restore, merge (-Oz) | 109 900 |
| crt and runtime glue | 6 678 |

The remaining ~21 KB of the file are ELF headers, dynamic-linking tables
(`.dynsym`, `.dynstr`, relocations for the ~90 glibc symbols used) and
section alignment.

The passphrase key file (§3) added 56 KB: 32 KB of Argon2id and BLAKE2b and
18 KB of key-file, passphrase and `bu key` code and help text. The Argon2
SIMD kernels stay: unlock time is a security parameter, and a faster kernel
buys more passes or memory in the same two seconds. The security fixes
after it (safe temp files, restore hardening, escaped listings, warnings)
added 3 KB of cold code. The read-path work (spans, prefetch, merged writes
and the overlapped batches in restore, eight readers in create) added 4.5 KB.
Chain files added 34.5 KB of cold code: finding segments from the end and
past an interrupted append, the stream reader and stream restore, record
headers, locking and truncate-on-failure, in-place merge with spans,
unencrypted segments, and the longer help text.

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

**Assumed:** the attacker has every chain and index file, can modify,
delete, reorder, truncate and replay them, and does not have both the key
file and one of its passphrases (having one without the other: see the key
file paragraph below). For an unencrypted chain (§3) none of this section's
protection applies beyond the detection of accidental damage.

**What they learn:**

- that these are bu files, the format version, kind and mode;
- per segment: its generation (in the trailer), the number of new chunks
  and the length of each chunk record (≈ compressed chunk size), the size of
  the manifest and the table (≈ number of files and chunks), the total size;
- across segments: how much changed between increments (from their sizes).

**What they do not learn:** file names, directory structure, file sizes,
timestamps, owners, modes, symlink targets, which chunks are shared between
segments (IDs are inside the encrypted table, and every segment has its own
key), where in the stream the stored chunks sit (their sequence numbers are
inside the sealed record headers), or anything about content beyond the
above.

**Known leaks inherent to the design** (Borg shares both): the sequence of
chunk lengths of a large file, which CDC derives from its content, can be
used to test whether a backup contains a *known* file (fingerprinting); and
per-chunk compressibility leaks through record lengths. Padding chunk
records would blunt both at a cost in size; bu does not pad.

**What they can do:**

- *forge or alter data:* no; every record is authenticated, every chunk is
  re-hashed, every trailer authenticates its segment's layout, and any
  change makes `check` and `restore` fail loudly (integration test 03 flips
  bytes in chunks, record headers, the header and the trailer, and
  truncates);
- *delete or withhold segments:* yes, which `restore` reports as an
  incomplete chain (missing parent snapshot or missing chunks) rather than
  as damage;
- *roll back:* present an older but valid chain instead of the current one,
  or cut a chain file back to a segment boundary. bu cannot detect that
  without external state; keep an index (which records the latest
  generation and snapshot ID) or a list of expected sizes somewhere the
  attacker cannot write. Cutting inside a segment is visible: readers
  report the incomplete tail and `check` fails;
- *substitute segments between two chains made with the same key:* each
  segment is internally consistent, so this is detected only where
  snapshot IDs or chunks do not line up. Use one key per data set if that
  matters;
- *replace an encrypted chain with an unencrypted one of their own:* only
  against readers run without `--key`. With `--key`, bu refuses an
  unencrypted chain by name.

**The key file** holds `K` only wrapped under passphrases (§3). Someone who
steals it still needs a passphrase, and can only guess offline at the cost of
one Argon2id run (by default 1 GiB and ~2 s here) per guess per slot; a
strong passphrase is what makes that infeasible. Someone who has a
passphrase but no copy of the key file has nothing. Losing every copy of the
key file makes every backup unreadable, by design. Removing a passphrase
edits one copy of the file: an older copy still accepts it, as an old LUKS
header backup does. So `key remove` and `key passwd` do not revoke anything
from someone who may already hold a copy of the file and the old
passphrase: against them only a new key (`bu key init`) and a new full
backup help, since `K` itself is what they can recover.

## 12. Deliberate omissions

- Hard links (restored as separate files), extended attributes, ACLs,
  device files, FIFOs and sockets (skipped with a warning), file flags.
- Exclude patterns and a one-file-system switch; back up what you name (the
  walk descends into mounted filesystems).
- More than one snapshot per segment, and pruning other than by merging.
- Merging from a pipe: what to keep is known only at the end of the chain.
  Save the stream to a file first.
- Loading the tables of a chain's segments in parallel. On a network mount
  each large segment costs a round trip at open; merging a long chain
  keeps that small.
- Locks that hold across machines on FUSE and SMB mounts (§1): bu cannot
  make a filesystem lock what it does not; one chain per writing machine.
- A ChaCha20-Poly1305 fallback for CPUs without AES-NI (§3).
- Fixed-size chunking for caller-chosen files (`--fixed`): SQLite gets page
  chunking automatically and nothing else measured needed it.
- Live-database consistency (§2).
- A parallel walk: stat is cheap next to reading; the readers already overlap
  opens.
- Unbounded segments: the chunk table is capped at 3 GiB (~22 bytes per new
  chunk), i.e. ~140 million new chunks or ~2.8 TB of unique data in one
  segment. Larger first backups can be split by directory, into chains of
  their own.
