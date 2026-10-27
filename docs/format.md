# bu file format

Three kinds of file: the **key file** (key file format 2), and **backup
files** and **index files** (container format 1). Backups and indexes share
one container format. All integers are little-endian unless stated
otherwise. `varint` is unsigned LEB128 (7 bits per byte, low groups first, at
most 10 bytes, the 10th carrying only bit 63); `svarint` is a zigzag-encoded
signed value in a varint.

The code that defines each part: `src/format/keyfile.cpp` (key file),
`src/format/container.cpp` (container, keys, records, trailer),
`src/format/codec.cpp` (payloads), `src/format/snapshot.cpp` (manifest, index
body).

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
`derive_key` (context strings are part of the container format and never
change within a version):

| Key | Derivation | Used for |
|---|---|---|
| `K_id` | `derive_key("bu 2026-10-25 chunk id v1", K)` | chunk IDs (keyed BLAKE3) |
| `K_aes(salt)` | `derive_key("bu 2026-10-25 container aes-256-gcm key v1", K ‖ salt)` | AES-256-GCM key of one container |
| `K_check(salt)` | `derive_key("bu 2026-10-25 container header check v1", K ‖ salt)` | header check value |

No passphrase or KEK enters this derivation, which is why adding, changing
or removing a passphrase changes nothing in any backup.

## Container

```
offset  size  field
0       64    header
64      ...   records
end-16  16    footer
```

### Header (64 bytes, plaintext)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `42 55 42 41 4b 0d 0a 1a` (`BUBAK\r\n^Z`) |
| 8 | 2 | format version, `1` |
| 10 | 2 | kind: `1` backup, `2` index |
| 12 | 4 | reserved, `0` |
| 16 | 32 | salt: 32 random bytes, fresh for every file |
| 48 | 16 | check: keyed-BLAKE3(`K_check(salt)`, header[0..48)), 16 bytes |

The check value lets a reader tell "wrong key" from "damaged data" before the
first decryption, and binds version and kind to the key. The magic's CR LF ^Z
bytes make a newline-converting transfer fail at byte 5 instead of deep inside
a record.

### Records

```
u32  length            = ciphertext length + 16
...  ciphertext        AES-256-GCM under K_aes(salt)
16   tag
```

- **Nonce** (12 bytes): `u64` counter, little-endian, then four zero bytes.
  Chunk records use their stream sequence number (0, 1, 2, ... in the order
  the chunker cut them; gaps where a duplicate was dropped). Metadata records
  use fixed values with bit 63 set: manifest `2^63`, trailer `2^63 + 1`, index
  `2^63 + 2`.
- **Associated data** (17 bytes): record type, then the chunk ID (16 zero
  bytes for metadata). Types: `1` chunk, `2` manifest, `3` trailer, `4` index.
- **Plaintext** (the *payload*):

  ```
  u8   codec           0 = stored, 1 = LZ4 block
  u32  raw length      only when codec = 1
  ...  body            raw bytes (codec 0) or one LZ4 block (codec 1)
  ```

  A writer uses codec 1 only when it is strictly smaller.

### Footer (16 bytes, plaintext)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | offset of the last record (trailer or index) |
| 8 | 4 | `BKFT` |
| 12 | 4 | reserved, `0` |

The last record must end exactly at the footer.

## Backup file (kind 1)

```
header | chunk record × n | manifest record | trailer record | footer
```

Chunk records hold only chunks that were not in the base index (or appeared
twice in this backup). A chunk's plaintext body is the raw chunk; its **ID**
is the first 16 bytes of keyed-BLAKE3(`K_id`, raw chunk). A reader checks both
the GCM tag (which covers the ID through the associated data) and that the
decoded chunk hashes to its ID.

### Trailer (record type 3, body)

```
varint  version            1
varint  n                  number of chunk records
n × {
  16    chunk ID
  varint record length      ciphertext + tag (the record's u32 prefix)
  varint nonce delta        nonce − previous nonce (first: nonce − 0)
  varint raw length         decoded chunk size, ≤ 65536
}
varint  manifest record length
```

Record offsets are implicit: chunk `i` starts at `64 + Σ_{j<i}(4 + len_j)`,
the manifest follows the last chunk, the trailer follows the manifest. Nonces
must strictly increase and stay below `2^63`. A reader that can seek finds the
trailer through the footer and never scans the chunks.

### Manifest (record type 2, body)

```
varint  version            1
16      snapshot ID         random, kept by merge
u8      flags               bit 0: delta (has a parent)
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

A file's chunk list is a program of ops over a *source list*: the parent
snapshot's list for the same path if `base` = 1 (the parent must have a
regular file there), else the empty list.

```
op = varint (n << 2 | kind)
kind 0  COPY n   append source[j .. j+n), j += n
kind 1  SEEK     j += zigzag-decode(n)    (0 ≤ j ≤ source length)
kind 2  NEW n    followed by n × 16-byte chunk IDs, appended
```

`j` starts at 0. A full manifest (no parent) uses only NEW. The file's content
is the concatenation of its chunks; the sum of their raw lengths must equal
`size`.

## Index file (kind 2)

```
header | index record (type 4, nonce 2^63 + 2) | footer
```

Index body:

```
varint  version            1
varint  manifest length
...     manifest           the latest snapshot, always full (flags = 0)
varint  b                  number of backup IDs
b × 16  backup ID          first 16 bytes of a backup file's salt
varint  d                  number of distinct chunk IDs in the snapshot
d × varint                 per distinct ID, in first-appearance order: index into the backup IDs
```

The location table is advisory: restore finds chunks by ID in whatever files
it is given and never consults it.

## Versioning

A reader refuses any version it does not know (the key file, and the
container header, trailer, manifest and index bodies each carry one). Any change to the derivation contexts, the nonce
layout, the associated data or a record body is a new format version.
