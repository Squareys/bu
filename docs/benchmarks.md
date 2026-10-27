# Benchmarks: bu against the disk

How close does bu get to what the hardware allows? A backup cannot be faster
than reading the source, and cannot be faster than writing the backup; on one
disk it shares the disk between the two. This page puts bu next to those
caps and next to the plain copy tools, on the same data, the same source and
destination, with a cold page cache.

`scripts/bench.sh` (README, design.md §9) runs on tmpfs and measures CPU
throughput; this page is the disk-bound counterpart.

## Method

`scripts/bench_io.sh --src DIR --dst DIR [--size-mb N] [--runs N]` generates
the data set under `--src`, writes everything to `--dst`, and prints one table.
Each case runs `--runs` times; the table shows the median wall time.

**Data.** A deterministic tree of `--size-mb` MiB (1536 here, 23 614 files):

| Share | Content |
|---|---|
| 40% | 4 large incompressible files (AES-CTR keystream) |
| 25% | 16 syslog-style text logs (about 3.4x LZ4-compressible) |
| 25% | ~100 KiB incompressible files (3 933 files) |
| 10% | 8 KiB text files, source-tree-like (19 661 files) |

The full backup of it is 1.12 GiB. A second case is one incompressible file
of the same size (rows marked `1f`).

**Cold cache without root.** Before every run: `sync`, then
`posix_fadvise(POSIX_FADV_DONTNEED)` on every file under the source and the
destination (`fincore` confirms that 0 pages stay resident). `sudo -n`
drop_caches is used as well when it works non-interactively; it did not on
this machine. File data is evicted; the dentry and inode caches stay warm,
so directory walks and `stat` calls are cheaper than on a truly cold
machine. On tmpfs nothing can be evicted (the cache is the data), which is
what makes the tmpfs layouts CPU caps.

**Every timed command ends with `sync -f DST`**, so buffered writes are
paid for inside the timing. GB/s is 10^9 bytes of logical data (the sum of
file sizes; for `check` and "read: backup file", the backup's size) per
second. CPU is user + sys of the command and its children (GNU time);
`cpu/wall` is the number of cores busy on average. Kernel work done on behalf
of the process in other threads (dm-crypt's kcryptd, writeback) is not
counted.

**Baselines**

| Row | Command | Caps |
|---|---|---|
| read: tar \| cat | `tar -cf - data \| cat > /dev/null` | serial read of the tree, the classic tool |
| read: N streams, tree | a small C reader (compiled by the script): `read(2)` into a 1 MiB buffer, N files at a time | what parallel reads get from the source |
| read: O_DIRECT big files | `dd iflag=direct bs=4M` | the device, no page cache (no root needed for the raw device: it reads files) |
| read: backup file | the C reader on `full.bk` | reading the backup, for `check` and `restore` |
| write: O_DIRECT | `dd oflag=direct bs=4M` from a RAM file | the device's write speed |
| write: buffered + fsync | `dd conv=fsync bs=4M` | the same through the page cache |
| copy: cp -a | `cp -a --reflink=never` | a plain copy |
| copy: tar to file | `tar -cf DST/x.tar data` | the closest thing to `bu create` without CPU work |
| copy: tar extract | `tar -xf DST/x.tar -C DST/out` | the closest thing to `bu restore` |

`cat file > /dev/null` is not used: on tmpfs it measured 40 GB/s, i.e. GNU
cat moved no data (splice/copy offload to /dev/null). The C reader copies
every byte into user space as bu does.

**bu rows.** `create` (default `-j`, i.e. 20 workers and 4 readers here, and
`-j 1`, i.e. one worker and one reader), the increment of the unchanged tree
and of a 1% scattered change (both with the files cache), `restore` of the
full backup into the destination, `check` of it. `vs` = baseline time / bu
time: 100% means as fast as the baseline, above 100% faster.

## Hardware

Intel i7-12700H (6P + 8E cores, 20 threads, no AVX-512), 32 GiB RAM, on AC,
`powersave` governor with the `balanced` platform profile. One 1 TB NVMe SSD. The root file system is ext4 (`noatime`, no
`discard`) on LUKS/dm-crypt, 95% full (6 GB free). Linux 7.2.9 (CachyOS),
`vm.dirty_bytes` 256 MiB and `vm.dirty_background_bytes` 64 MiB (the
distribution's settings: buffered writers are throttled early). tmpfs is the
16 GiB `/tmp`. Measured 2026-10-27, bu at commit ce485c7, 5 runs per case.

Every NVMe number includes dm-crypt (AES-XTS in the kernel, in both
directions); a disk without encryption would read and write faster, and
that encryption work competes with bu's workers for cores.

## Results

### NVMe -> same NVMe (the realistic same-disk case)

| Case | wall s | GB/s | cores busy | bu vs baseline |
|---|---|---|---|---|
| read: tar \| cat | 5.54 | 0.29 | 0.45 | |
| read: 1 stream, tree | 4.60 | 0.35 | 0.30 | |
| read: 4 streams, tree | 1.10 | 1.47 | 0.82 | |
| read: 8 streams, tree | 0.78 | 2.06 | 1.12 | |
| read: O_DIRECT big files | 0.32 | 2.01 | 0.06 | |
| write: O_DIRECT | 0.64 | 2.54 | 0.39 | |
| write: buffered + fsync | 0.59 | 2.75 | 0.96 | |
| copy: cp -a | 4.85 | 0.33 | 0.38 | |
| copy: tar to file | 6.21 | 0.26 | 0.37 | |
| copy: tar extract | 2.04 | 0.79 | 0.57 | |
| **bu create** | 2.18 | **0.74** | 3.46 | 285% of tar to file, 36% of 8-stream read |
| bu create -j 1 | 3.69 | 0.44 | 1.27 | 168% of tar to file |
| bu increment, unchanged | 0.09 | | 0.77 | |
| bu increment, 1% changed | 0.61 | | 3.30 | (1 GiB of changed files read) |
| **bu restore** | 1.99 | **0.81** | 5.68 | 103% of tar extract, 244% of cp -a |
| bu restore -j 1 | 2.73 | 0.59 | 0.85 | 75% of tar extract |
| read: backup file | 0.59 | 2.04 | 0.53 | |
| **bu check** | 1.15 | **1.04** | 5.30 | 51% of reading the backup |
| bu check -j 1 | 1.89 | 0.63 | 0.89 | 31% of reading the backup |
| 1f read: 1 stream | 0.67 | 2.42 | 0.59 | |
| 1f read: O_DIRECT | 0.51 | 3.15 | 0.04 | |
| 1f copy: cp | 2.16 | 0.75 | 0.43 | |
| **1f bu create** | 1.98 | **0.81** | 4.31 | 109% of cp |
| 1f bu create -j 1 | 2.18 | 0.74 | 1.67 | 99% of cp |
| **1f bu restore** | 1.99 | **0.81** | 6.54 | 108% of cp |

On one disk the source is read and the backup written through the same
device. If the reads and the writes did not overlap at all, the best case
would be "read the tree with 8 streams, then write 1.2 GB": 0.78 + 0.44 s =
1.22 s, 1.32 GB/s. bu create is at 56% of that; for the single file
(0.67 + 0.59 s) at 63%.

### NVMe -> tmpfs (the disk-read cap)

| Case | wall s | GB/s | cores busy | bu vs baseline |
|---|---|---|---|---|
| read: tar \| cat | 3.99 | 0.40 | 0.39 | |
| read: 1 stream, tree | 2.89 | 0.56 | 0.34 | |
| read: 4 streams, tree | 0.92 | 1.75 | 1.11 | |
| read: 8 streams, tree | 0.62 | 2.60 | 1.84 | |
| read: O_DIRECT big files | 0.21 | 3.02 | 0.05 | |
| copy: cp -a | 3.26 | 0.49 | 0.45 | |
| copy: tar to file | 5.17 | 0.31 | 0.38 | |
| **bu create** | 1.37 | **1.18** | 6.36 | 378% of tar to file, 67% of 4-stream read, 45% of 8-stream read |
| bu create -j 1 | 3.34 | 0.48 | 1.31 | 155% of tar to file |
| bu increment, unchanged | 0.07 | | 0.90 | |
| bu increment, 1% changed | 0.47 | | 4.37 | |
| 1f read: 1 stream | 0.66 | 2.44 | 0.59 | |
| 1f read: O_DIRECT | 0.52 | 3.10 | 0.04 | |
| 1f copy: cp | 0.90 | 1.79 | 0.67 | |
| **1f bu create** | 0.84 | **1.92** | 6.55 | 107% of cp, 79% of 1-stream read, 62% of O_DIRECT |
| 1f bu create -j 1 | 1.71 | 0.94 | 1.95 | 53% of cp |

(restore and check here read and write tmpfs: same as tmpfs -> tmpfs.)

### tmpfs -> NVMe (the disk-write cap)

| Case | wall s | GB/s | cores busy | bu vs baseline |
|---|---|---|---|---|
| write: O_DIRECT | 0.80 | 2.01 | 0.42 | |
| write: buffered + fsync | 0.59 | 2.75 | 0.94 | |
| copy: cp -a | 0.87 | 1.84 | 0.86 | |
| copy: tar to file | 0.80 | 2.01 | 0.86 | |
| copy: tar extract | 2.24 | 0.72 | 0.53 | |
| **bu create** | 0.92 | **1.75** | 7.93 | 87% of tar to file |
| bu create -j 1 | 1.56 | 1.03 | 2.20 | 51% of tar to file |
| bu increment, unchanged | 0.08 | | 0.90 | |
| bu increment, 1% changed | 0.32 | | 5.63 | |
| **bu restore** | 1.89 | **0.85** | 5.52 | 118% of tar extract, 46% of cp -a |
| bu restore -j 1 | 2.75 | 0.59 | 0.84 | 82% of tar extract |
| read: backup file | 0.66 | 1.81 | 0.48 | |
| **bu check** | 1.00 | **1.20** | 6.25 | 66% of reading the backup |
| 1f copy: cp | 0.52 | 3.10 | 0.94 | |
| **1f bu create** | 0.60 | **2.68** | 8.10 | 86% of cp |
| **1f bu restore** | 2.98 | **0.54** | 6.20 | 17% of cp (18.5 s of CPU; see below) |

"tar extract" and bu restore read their input from the destination, the
NVMe, while cp -a reads from tmpfs; tar extract is the like-for-like row.

### tmpfs -> tmpfs (CPU cap; reproduces scripts/bench.sh)

| Case | wall s | GB/s | cores busy | bu vs baseline |
|---|---|---|---|---|
| read: 8 streams, tree | 0.09 | 17.1 | 5.96 | |
| copy: cp -a | 0.49 | 3.26 | 0.97 | |
| copy: tar to file | 0.46 | 3.50 | 0.96 | |
| copy: tar extract | 0.45 | 3.59 | 0.98 | |
| **bu create** | 0.62 | **2.60** | 9.47 | 74% of tar to file |
| bu create -j 1 | 1.41 | 1.14 | 2.19 | 33% of tar to file |
| bu increment, unchanged | 0.07 | | 0.77 | |
| bu increment, 1% changed | 0.26 | | 6.83 | |
| **bu restore** | 0.45 | **3.57** | 13.1 | 100% of tar extract |
| bu restore -j 1 | 1.81 | 0.89 | 0.99 | 25% of tar extract |
| **bu check** | 0.18 | **6.66** | 17.1 | 64% of reading the backup (10.3 GB/s) |
| 1f copy: cp | 0.37 | 4.38 | 0.98 | |
| **1f bu create** | 0.42 | **3.83** | 9.71 | 88% of cp |
| **1f bu restore** | 0.43 | **3.75** | 16.8 | 86% of cp |

These match the README's tmpfs numbers (create 2.6 here vs 2.7-4.0 GB/s
there on a 1 GiB tree with fewer small files).

## Conclusions

**bu is disk-bound, not CPU-bound, as soon as a real disk is involved.**
`bu create` from the NVMe runs at 1.18 GB/s with 6.4 cores busy, while the
same work from tmpfs runs at 2.60 GB/s: the CPU could do twice as much. At
`-j 1` bu is CPU-bound (one core does ~1.1 GB/s of hashing, compression and
encryption), and on disk it is held back further by its single reader
(0.48 GB/s, close to the 0.56 GB/s of one read stream).

**bu create is 2.2-3.8x faster than tar and cp on a tree of many files**, and as
fast as cp on one big file, encryption and compression included. The classic
tools read one file at a time at queue depth 1 (0.29-0.49 GB/s from this
NVMe); bu's four readers keep several reads in flight. Restore keeps pace
with `tar -x` (100-118%).

**The gap to the cap is reading.** An 8-stream reader gets 2.06-2.60 GB/s
out of this NVMe for the tree; bu create gets 36-45% of that. Three things
are worth a look, in order of expected gain:

1. **restore and check read the backup one chunk at a time.** From a cold
   backup on the NVMe both plateau at ~1.13 GB/s from `-j 4` upwards (1.6 GB
   single-file backup: 1.42 s at -j 4, 8 and 20), while reading the same file
   with one plain 1 MiB stream takes 0.66 s (2.0-2.4 GB/s). Each task
   `pread`s one ~20 KiB record; many threads issuing small reads at
   scattered offsets of one file defeat the readahead that a sequential
   reader gets. Reading the backup in large sequential spans (1-4 MiB of
   consecutive records, as create's readers do for the source) and handing
   the records out from memory should bring restore and check close to the
   read cap. This is the largest gap measured (check: 51-66% of reading its
   input on NVMe).
2. **More readers for create when the source is a disk.** For the tree, 4
   read streams give 1.75 GB/s and 8 give 2.60 GB/s (+50%); bu uses 4
   readers and reaches 67% of the 4-stream figure. With small files every
   read is a separate open/read/close at queue depth 4. Eight readers (or
   readers scaling with `-j`, keeping the cap at 4 for tmpfs, where they
   cost CPU for nothing) is a small change that likely helps.
3. **Readers split one big file into interleaved 1 MiB ranges.** On the
   single file bu gets 1.92 GB/s against 2.44 for one sequential stream and
   3.10 for O_DIRECT. Each of the 4 readers has its own descriptor and sees
   every fourth MiB, so the kernel's per-descriptor readahead sees a strided
   pattern. Handing a reader a longer contiguous extent of a big file (say
   8-16 MiB) before moving on would keep each descriptor sequential. This is
   a hypothesis; it was not tested.

**Restore spends a lot of CPU in the kernel when writing to ext4.** Writing
one 1.5 GiB file to the NVMe (backup on tmpfs): -j 1 2.0 s, -j 4 0.81 s,
-j 8 0.66 s, -j 20 0.74 s, with sys time growing from 0.5 s to 6 s.
Twenty threads `pwrite`ing ~20 KiB pieces into the same file contend on the
inode lock and on dirty-page throttling (`vm.dirty_bytes` is 256 MiB here).
In the full benchmark the same restore, reading its backup from the NVMe too,
took 2.98 s at 18.5 s of CPU: the worst case seen, and the most variable.
Coalescing consecutive chunks of a file into one larger write, or capping
the number of concurrent writers per file (about 8), would cut the CPU cost
and likely the variance; the wall time at -j 8 is the best already.

**Increments are cheap everywhere.** The unchanged increment takes
0.07-0.09 s on any layout (metadata only; note the warm dentry cache). The
1% change reads 1 GiB of changed files in 0.26 s from tmpfs and 0.47 s
from the NVMe (2.2 GB/s, near the read cap: big files read sequentially).

**Anomalies and caveats.**
- O_DIRECT write (2.0-2.5 GB/s) was slower than buffered + fsync (2.75
  GB/s): 4 MiB synchronous direct writes at queue depth 1 through dm-crypt.
- The disk is 95% full and mounted without `discard`; after each run's
  deletion the SSD has less clean space, which adds variance to the write
  rows. Restore to the NVMe varied most between runs (single file:
  1.69 s in a 3-run pass, 2.98 s median in the 5-run pass).
- Same-disk single-file copy with cp (0.75 GB/s) is far below both the read
  (2.42) and the write (2.75) caps: cp alternates reading and writing on
  one disk, which bu matches rather than beats.
- One data set size (1.5 GiB, limited by free disk space); dentry and inode
  caches warm (no root).

## Reproducing

```
scripts/bench_io.sh --src /path/on/disk --dst /path/on/disk --size-mb 1536
scripts/bench_io.sh --src /path/on/disk --dst /tmp          # read cap
scripts/bench_io.sh --src /tmp --dst /path/on/disk          # write cap
scripts/bench_io.sh --src /tmp --dst /tmp                   # CPU cap
```

The script checks free space first (source + backup + restored copy on the
destination, everything on one file system when they share one), cleans up
after itself, and needs GNU time, `cc`, python3 and openssl.
