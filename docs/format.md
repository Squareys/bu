# bu file format

Three kinds of file: the **key file** (key file format 2), **chains** and
**index files** (format 2). Chains and indexes share one segment format. All
integers are little-endian unless stated otherwise. `varint` is unsigned
LEB128 (7 bits per byte, low groups first, at most 10 bytes, the 10th
carrying only bit 63); `svarint` is a zigzag-encoded signed value in a
varint.

The code that defines each part: `src/format/keyfile.cpp` (key file),
`src/format/segment.cpp` (segments, keys, records, trailer),
`src/format/codec.cpp` (payloads), `src/format/snapshot.cpp` (manifest, index
body), `src/cmd/chain.cpp` (finding segments in a chain).

## Key file (format 2)

The key file holds the 32-byte **master key** `K`, never in the clear: `K` is
stored only wrapped in up to eight **keyslots**, each sealed under a key that
Argon2id derives from one passphrase. The file is exactly 944 bytes: a
48-byte header and eight 112-byte slots. Format 1 (`bu-key-1 <64 hex
digits>`, a plaintext key) is refused with a message naming it.

### Header (48 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `42 55 4b 45 59 0d 0a 1a` (`BUKEY\r\n^Z`) |
| 8 | 2 | key file format version, `2` |
| 10 | 2 | number of slots, `8` |
| 12 | 4 | reserved, `0` |
| 16 | 16 | key ID: first 16 bytes of `derive_key("bu 2026-10-27 key file key id v2", K)` |
| 32 | 16 | checksum: first 16 bytes of unkeyed BLAKE3(header[0..32)) |

### Slot (112 bytes, slot *i* at offset 48 + 112·*i*)

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | state: `0` empty, `1` passphrase slot |
| 1 | 1 | KDF: `1` Argon2id v1.3 |
| 2 | 2 | lanes (Argon2 parallelism), `1` |
| 4 | 4 | passes (Argon2 time cost *t*), 1 ..= 100 |
| 8 | 4 | memory (Argon2 memory cost *m*) in KiB, 8 MiB ..= 4 GiB |
| 12 | 4 | reserved, `0` |
| 16 | 16 | salt, random per slot write |
| 32 | 12 | AES-GCM nonce, random per slot write |
| 44 | 4 | reserved, `0` |
| 48 | 32 | `K`, encrypted |
| 80 | 16 | GCM tag |
| 96 | 16 | checksum: first 16 bytes of unkeyed BLAKE3(slot[0..96)) |

An empty slot is 96 zero bytes followed by their checksum.

**Wrapping.** `KEK = Argon2id(passphrase, salt, t = passes, m = memory,
p = 1, 32 bytes)` (libsodium `crypto_pwhash_argon2id`, i.e. RFC 9106 with no
secret and no associated data). `K` is sealed with AES-256-GCM under `KEK`
with the slot's nonce and **associated data** `header[0..32) ‖ u8 i ‖
slot[0..48)`: the magic, version and key ID, the slot index, and every
parameter byte of the slot. The passphrase is the bytes given, without a
line ending; 1 ..= 1024 bytes.

**Reading.** A reader checks size, magic, version and the header checksum
(failure: damaged file). A slot whose checksum fails, whose reserved fields
are not zero, whose KDF or lanes are unknown or whose passes and memory are
outside the bounds above is *damaged* and skipped without running the KDF.
Each remaining passphrase slot is tried in order; the first whose tag
verifies yields `K`, which must reproduce the key ID. If none opens, the
passphrase is wrong (and the message says so, noting damaged slots that were
skipped). The checksums are not a security mechanism: an attacker can
recompute them, and the AEAD is what refuses an edited slot.

**Keys from K.** Everything a backup uses is derived from `K` with BLAKE3
`derive_key` (context strings are part of the segment format and never
change within a version):

| Key | Derivation | Used for |
|---|---|---|
| `K_id` | `derive_key("bu 2026-10-25 chunk id v1", K)` | chunk IDs (keyed BLAKE3) |
| `K_aes(salt)` | `derive_key("bu 2026-10-27 segment aes-256-gcm key v2", K ‖ salt)` | AES-256-GCM key of one segment |
| `K_check(salt)` | `derive_key("bu 2026-10-27 segment check v2", K ‖ salt)` | header and trailer check values |

No passphrase or KEK enters this derivation, which is why adding, changing
or removing a passphrase changes nothing in any backup.

## Chain

A chain is a file of **segments** laid end to end, oldest first. A chain
made by `bu create` appending to one file and the same segments written to
separate files and joined with `cat` are byte for byte the same thing.
Nothing in a segment depends on where it sits in the file: every offset in
it is relative to its own first byte.

```
segment 0 | segment 1 | ... | segment n-1
```

A reader finds the segments from the end: the last 64 bytes of the file are
the last segment's trailer, whose first field is that segment's length, so
the segment starts at `end - length`; the bytes before it end with the
previous segment's trailer, and so on, until a segment starts at offset 0.
A walk that does not land exactly on 0 is a damaged chain.

**An incomplete last segment** (a `create` killed while appending) leaves
bytes after the last complete segment that end in no valid trailer. A reader
that finds no valid trailer at the end scans back for the trailer magic and
takes the last position from which a walk back to 0 succeeds. In an
encrypted chain the first candidate whose trailer authenticates decides
(only bu with the key can make one); in an unencrypted chain, chunk data can
contain trailer bytes (a backup of a chain), so a candidate whose walk fails
is skipped. The bytes after it are ignored by readers and cut off by the
next `create`.

A reader streaming the chain (a pipe) reads it front to back instead:
header, records, trailer, next header. It ends cleanly only at a segment
boundary.

## Segment

```
offset  size  field
0       64    header
64      ...   records: chunks, then the manifest, then the table
L-64    64    trailer
```

### Header (64 bytes, plaintext)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `42 55 42 41 4b 0d 0a 1a` (`BUBAK\r\n^Z`) |
| 8 | 2 | format version, `2` |
| 10 | 2 | kind: `1` segment, `2` index |
| 12 | 2 | flags: bit 0 = unencrypted; other bits `0` |
| 14 | 2 | reserved, `0` |
| 16 | 32 | salt: 32 random bytes, fresh for every segment |
| 48 | 16 | check: keyed-BLAKE3(`K_check(salt)`, header[0..48)), 16 bytes; unencrypted: unkeyed BLAKE3(header[0..48)), 16 bytes |

The check value lets a reader tell "wrong key" from "damaged data" before the
first decryption, and binds version, kind and flags to the key. The magic's
CR LF ^Z bytes make a newline-converting transfer fail at byte 5 instead of
deep inside a record. A reader refuses a chain whose segments do not all
have the same bit 0.

### Records

```
u32  L                 length of what follows: 25 + body length
25   record header     sealed { u8 type | u64 body nonce }
L-25 body              sealed payload
```

**Record header.** 9 bytes of plaintext — the record's type and its body's
nonce — sealed with AES-256-GCM under `K_aes(salt)`, nonce `2^63 + 2^62 +
ordinal` (the record's position in the segment, counted from 0 over all its
records), empty associated data: 9 bytes of ciphertext, then the 16-byte
tag. A reader that seeks gets each chunk's nonce from the table and may
skip the header; a reader streaming the segment opens it to learn the
body's type and nonce.

**Body.** The payload sealed with AES-256-GCM under `K_aes(salt)`:
ciphertext, then the 16-byte tag.

- **Nonce** (12 bytes): `u64` counter, little-endian, then four zero bytes.
  Chunk bodies use their stream sequence number (0, 1, 2, ... in the order
  the chunker cut them; gaps where a duplicate was dropped; strictly
  increasing within a segment, below `2^63`). Metadata bodies use fixed
  values with bit 63 set: manifest `2^63`, table `2^63 + 1`, index
  `2^63 + 2`. Record headers use `2^63 + 2^62 + ordinal`. The three spaces
  do not overlap.
- **Associated data** (1 byte): the record type. Types: `1` chunk,
  `2` manifest, `3` table, `4` index.
- **Plaintext** (the *payload*):

  ```
  u8   codec           0 = stored, 1 = LZ4 block
  u32  raw length      only when codec = 1
  ...  body            raw bytes (codec 0) or one LZ4 block (codec 1)
  ```

  A writer uses codec 1 only when it is strictly smaller.

A chunk's plaintext body is the raw chunk; its **ID** is the first 16 bytes
of keyed-BLAKE3(`K_id`, raw chunk). A reader checks the tag and that the
decoded chunk hashes to its ID (from the table, or, streaming, the ID it
looks the chunk up by).

**Unencrypted segments** (flags bit 0) have the same layout with no
encryption: every payload is stored in the clear, and each 16-byte tag is
a checksum instead —

| Where | Tag |
|---|---|
| record header | unkeyed BLAKE3(nonce[12] ‖ plaintext[9]), 16 bytes |
| chunk body | the chunk ID: unkeyed BLAKE3(raw chunk), 16 bytes |
| metadata body | unkeyed BLAKE3(nonce[12] ‖ type ‖ payload), 16 bytes |

Chunk IDs are unkeyed BLAKE3 of the raw chunk, truncated to 16 bytes.

### Trailer (64 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | segment length L, header to trailer inclusive |
| 8 | 8 | manifest record offset, from the segment's first byte |
| 16 | 8 | table record offset (index file: where the table would start) |
| 24 | 4 | manifest record L (index file: the index record's) |
| 28 | 4 | table record L (index file: `0`) |
| 32 | 8 | the snapshot's generation |
| 40 | 16 | check: keyed-BLAKE3(`K_check(salt)`, header[0..64) ‖ trailer[0..40)), 16 bytes; unencrypted: unkeyed BLAKE3 of the same |
| 56 | 8 | magic `42 55 45 4e 44 0d 0a 1a` (`BUEND\r\n^Z`) |

The records must tile the segment: table offset = manifest offset + 4 +
manifest L, and L = table offset + 4 + table L + 64. The chunk records fill
`[64, manifest offset)`. The generation lets a reader find the latest
snapshot without decrypting a manifest, and must equal the manifest's.

### Table (record type 3, body)

```
varint  version            2
varint  n                  number of chunk records
n × {
  16    chunk ID
  varint record L           the record's length prefix
  varint nonce delta        nonce − previous nonce (first: nonce − 0)
  varint raw length         decoded chunk size, ≤ 65536
}
```

Record offsets are implicit: chunk `i` starts at `64 + Σ_{j<i}(4 + L_j)`,
and the sum over all chunks must equal the manifest offset. Nonces must
strictly increase and stay below `2^63`. The chunk records' headers carry
ordinals 0 to n−1, the manifest's n, the table's n+1. A reader that seeks
reads the trailer, the table and the manifests it needs, and the chunk
records it needs, nothing else.

### Manifest (record type 2, body)

```
varint  version            2
16      snapshot ID         random, kept by merge
u8      flags               bit 0: has a parent; bit 1: delta (needs bit 0)
[16]    parent snapshot ID  only if bit 0
varint  generation          1 for a full backup, parent's + 1 for an increment
svarint created             ns since the epoch, when create started
varint  entry count
varint  reference count     total chunk references over all files
entries...
```

Entry:

```
varint  shared prefix length   bytes shared with the previous entry's path
varint  suffix length
...     suffix                 path = previous[0..shared) ‖ suffix
u8      type                   1 file, 2 directory, 3 symlink
varint  mode                   permission bits (07777)
varint  uid
varint  gid
svarint mtime                  ns
svarint ctime                  ns (files cache)
varint  dev                    (files cache)
varint  ino                    (files cache)
file:    varint size | u8 base | varint op count | ops
symlink: varint target length | target
```

Paths are relative, `/`-separated, with no empty, `.` or `..` component; a
reader refuses anything else. Entries are in depth-first order with siblings
sorted by name (bytewise), so a directory precedes its contents.

A **delta** manifest (bit 1) is decoded against its parent snapshot, found
by ID among the chain's segments; a **self-contained** one (bit 1 clear)
decodes alone, whether it has a parent (a checkpoint, written by `create`
when the deltas since the last self-contained manifest would outweigh it)
or not (a full backup, a merge).

A file's chunk list is a program of ops over a *source list*: the parent
snapshot's list for the same path if `base` = 1 (only in a delta manifest;
the parent must have a regular file there), else the empty list. Every
entry of the list is a chunk ID with its raw length.

```
op = varint (n << 2 | kind)
kind 0  COPY n   append source[j .. j+n), j += n
kind 1  SEEK     j += zigzag-decode(n)    (0 ≤ j ≤ source length)
kind 2  NEW n    followed by n × { 16-byte chunk ID | varint raw length (1 ..= 65536) }, appended
```

`j` starts at 0. A self-contained manifest uses only NEW. The file's content
is the concatenation of its chunks; the sum of their raw lengths must equal
`size`. The lengths make the manifest alone say where every chunk goes,
which a restore from a pipe needs (the tables arrive after the data).

## Index file (kind 2)

```
header (kind 2) | index record (type 4, ordinal 0, nonce 2^63 + 2) | trailer
```

The trailer's table offset is where the index record ends and its table L
is 0. Index body:

```
varint  version            2
varint  manifest length
...     manifest           the latest snapshot, self-contained
varint  delta bytes        manifest bytes written as deltas since the last self-contained one
varint  full bytes         the last self-contained manifest's bytes
```

The two counters carry `create`'s checkpoint rule from one run to the next
when the chain cannot be read back (an increment written to a pipe or a
separate file). An index file is encrypted or not like the chain it
describes, and is refused by the other mode.

## Versioning

A reader refuses any version it does not know (the key file, and the
segment header, table, manifest and index bodies each carry one). Any
change to the derivation contexts, the nonce layout, the associated data or
a record body is a new format version. Format 1 (bu 0.1.0: one backup per
file, a footer instead of a trailer, no record headers) is refused by its
version.
