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
destination (`fincore` confirms that 0 pages stay resident). The script
also runs drop_caches through `sudo -n` when that works without a password;
it did not on this machine. Eviction drops file data, but the dentry and
inode caches stay warm, so directory walks and `stat` calls cost less than
on a cold machine. On tmpfs nothing can be evicted (the cache is the data), which is
what makes the tmpfs layouts CPU caps.

**Every timed command ends with `sync -f DST`**, so buffered writes are
paid for inside the timing. GB/s is 10^9 bytes of logical data (the sum of
file sizes; for `check` and "read: backup file", the backup's size) per
second. CPU is user + sys of the command and its children (GNU time);
`cpu/wall` is the number of cores busy on average. GNU time does not see
kernel work done for the process in other threads (dm-crypt's kcryptd,
writeback).

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

The baselines avoid `cat file > /dev/null`: on tmpfs it measured 40 GB/s,
because GNU cat moved no data (splice/copy offload to /dev/null). The C reader copies
every byte into user space as bu does.

**bu rows.** `create` with the default threads (here 8 readers and 14
workers; before this round 4 readers and 20 workers) and with `-j 1` (one
worker, one reader); three increments with the files cache; `restore` of the
full backup into the destination (default: 8 threads; before: 20) and `check`
of it (20 threads), each also at `-j 1`. The increments, each made from the
index of the previous backup:

- *unchanged*: nothing touched since the full backup;
- *1% of files*: every 100th file of the sorted file list, from the 51st on,
  rewritten with new bytes at the same size (236 files, 5.4 MiB; none of the
  four big files);
- *1% scattered*: 1% of the bytes, as 4 KiB overwrites in the big files,
  appended log lines and 1% of the ~100 KiB files rewritten. The overwrites
  touch every big file, so bu reads 1 GB of changed files.

The script also prints every tree row as a multiple of the time it takes to
read every file once with 8 streams, the fastest plain reader.

**Before and after.** "Before" is bu at 1da8070, "after" at 47cc455, both
run by the same script (with the key-setup fix in this commit). Each case
runs 5 times; the tables show the median. Two complete passes ran on an
idle machine: pass 2 with both binaries, pass 3 with the final binary only
(it changed create's default thread counts after pass 2). The tables leave
out a first pass that overlapped another job's builds. Where a row's code is the
same in both after-binaries (baselines, restore, check, `-j 1`) and the two
passes differ by more than 10%, the after column shows their mean: marked ¹
when they differ by less than 1.5×, ² when one pass caught a disk stall
(below). Default `create` rows and the increments come from pass 3 alone.

## Hardware

Intel i7-12700H (6P + 8E cores, 20 threads, no AVX-512), 32 GiB RAM, on AC,
`powersave` governor with the `balanced` platform profile. One 1 TB NVMe SSD. The root file system is ext4 (`noatime`, no
`discard`) on LUKS/dm-crypt, 95% full (6 GB free). Linux 7.2.9 (CachyOS),
`vm.dirty_bytes` 256 MiB and `vm.dirty_background_bytes` 64 MiB (the
distribution's settings: buffered writers are throttled early). tmpfs is the
16 GiB `/tmp`. Measured 2026-10-27.

Every NVMe number includes dm-crypt (AES-XTS in the kernel, in both
directions); a disk without encryption would read and write faster, and
that encryption work competes with bu's workers for cores.

## Results

### NVMe -> same NVMe (the realistic same-disk case)

| Case | before s | after s | after GB/s | cores busy | after vs before |
|---|---|---|---|---|---|
| read: tar \| cat¹ | 5.230 | 5.492 | 0.29 | 0.44 |  |
| read: 1 stream, big files² | 0.260 | 0.516 | 1.25 | 0.43 |  |
| read: 1 stream, tree¹ | 3.157 | 3.657 | 0.44 | 0.32 |  |
| read: 4 streams, tree¹ | 1.169 | 1.113 | 1.44 | 0.88 |  |
| read: 8 streams, tree | 0.614 | 0.595 | 2.71 | 1.75 |  |
| read: O_DIRECT big files¹ | 0.228 | 0.246 | 2.62 | 0.08 |  |
| write: O_DIRECT¹ | 0.849 | 0.798 | 2.01 | 0.48 |  |
| write: buffered + fsync | 0.617 | 0.603 | 2.67 | 0.95 |  |
| copy: cp -a¹ | 3.698 | 3.973 | 0.40 | 0.40 |  |
| copy: tar to file | 6.299 | 5.709 | 0.28 | 0.36 |  |
| copy: tar extract | 2.175 | 2.006 | 0.80 | 0.58 |  |
| bu create -j 1 | 3.677 | 3.628 | 0.44 | 1.28 | 1.01x |
| **bu create** | 2.013 | 1.688 | 0.95 | 6.14 | 1.19x |
| bu increment, unchanged | 0.078 | 0.082 |  | 0.85 | 0.95x |
| bu restore -j 1 | 2.675 | 2.013 | 0.80 | 0.94 | 1.33x |
| **bu restore** | 2.046 | 1.450 | 1.11 | 3.23 | 1.41x |
| read: backup file | 0.592 | 0.689 | 1.74 | 0.45 |  |
| bu check -j 1 | 1.861 | 1.323 | 0.91 | 0.96 | 1.41x |
| **bu check**¹ | 0.972 | 0.422 | 2.84 | 5.82 | 2.30x |
| bu increment, 1% of files | 0.086 | 0.109 |  | 0.92 | 0.79x |
| bu increment, 1% scattered | 0.493 | 0.409 |  | 5.94 | 1.21x |
| 1f read: 1 stream¹ | 0.664 | 0.716 | 2.26 | 0.56 |  |
| 1f read: O_DIRECT¹ | 0.497 | 0.554 | 2.91 | 0.05 |  |
| 1f copy: cp¹ | 2.075 | 2.226 | 0.72 | 0.43 |  |
| 1f bu create -j 1 | 2.200 | 2.341 | 0.69 | 1.61 | 0.94x |
| **1f bu create** | 1.786 | 1.773 | 0.91 | 5.50 | 1.01x |
| **1f bu restore**² | 1.764 | 2.875 | 0.56 | 1.96 | 0.61x |

### NVMe -> tmpfs (the disk-read cap)

| Case | before s | after s | after GB/s | cores busy | after vs before |
|---|---|---|---|---|---|
| read: tar \| cat | 5.084 | 5.067 | 0.32 | 0.46 |  |
| read: 1 stream, big files¹ | 0.263 | 0.320 | 2.01 | 0.47 |  |
| read: 1 stream, tree | 2.929 | 3.113 | 0.52 | 0.33 |  |
| read: 4 streams, tree | 0.896 | 0.921 | 1.75 | 1.04 |  |
| read: 8 streams, tree | 0.610 | 0.614 | 2.62 | 1.84 |  |
| read: O_DIRECT big files | 0.237 | 0.220 | 2.93 | 0.09 |  |
| write: O_DIRECT | 0.423 | 0.421 | 3.83 | 0.97 |  |
| write: buffered + fsync | 0.419 | 0.418 | 3.85 | 0.98 |  |
| copy: cp -a | 3.222 | 3.308 | 0.49 | 0.43 |  |
| copy: tar to file | 5.245 | 5.341 | 0.30 | 0.36 |  |
| copy: tar extract | 0.488 | 0.488 | 3.30 | 0.98 |  |
| bu create -j 1 | 3.292 | 3.277 | 0.49 | 1.30 | 1.00x |
| **bu create** | 1.315 | 0.800 | 2.01 | 7.45 | 1.64x |
| bu increment, unchanged | 0.069 | 0.069 |  | 0.87 | 1.00x |
| bu restore -j 1 | 1.823 | 1.399 | 1.15 | 1.01 | 1.30x |
| **bu restore** | 0.497 | 0.358 | 4.50 | 6.34 | 1.39x |
| read: backup file | 0.138 | 0.136 | 8.81 | 0.96 |  |
| bu check -j 1 | 1.494 | 1.085 | 1.10 | 0.99 | 1.38x |
| **bu check** | 0.177 | 0.140 | 8.56 | 14.36 | 1.26x |
| bu increment, 1% of files | 0.086 | 0.089 |  | 1.01 | 0.97x |
| bu increment, 1% scattered | 0.477 | 0.322 |  | 6.68 | 1.48x |
| 1f read: 1 stream | 0.660 | 0.661 | 2.44 | 0.59 |  |
| 1f read: O_DIRECT | 0.529 | 0.518 | 3.11 | 0.04 |  |
| 1f copy: cp | 1.189 | 0.917 | 1.76 | 0.68 |  |
| 1f bu create -j 1 | 1.726 | 1.808 | 0.89 | 1.90 | 0.95x |
| **1f bu create** | 0.821 | 0.564 | 2.86 | 9.27 | 1.46x |
| **1f bu restore** | 0.455 | 0.337 | 4.78 | 7.39 | 1.35x |

### tmpfs -> NVMe (the disk-write cap)

| Case | before s | after s | after GB/s | cores busy | after vs before |
|---|---|---|---|---|---|
| read: tar \| cat | 0.536 | 0.535 | 3.01 | 1.35 |  |
| read: 1 stream, big files | 0.078 | 0.076 | 8.48 | 0.92 |  |
| read: 1 stream, tree | 0.230 | 0.228 | 7.06 | 0.92 |  |
| read: 4 streams, tree | 0.097 | 0.097 | 16.60 | 2.99 |  |
| read: 8 streams, tree | 0.092 | 0.091 | 17.70 | 5.93 |  |
| read: O_DIRECT big files | 0.084 | 0.081 | 7.95 | 0.86 |  |
| write: O_DIRECT¹ | 0.816 | 0.738 | 2.18 | 0.41 |  |
| write: buffered + fsync | 0.594 | 0.601 | 2.68 | 0.95 |  |
| copy: cp -a | 0.898 | 0.897 | 1.80 | 0.85 |  |
| copy: tar to file | 0.792 | 0.770 | 2.09 | 0.95 |  |
| copy: tar extract² | 2.074 | 4.284 | 0.38 | 0.34 |  |
| bu create -j 1² | 1.573 | 2.792 | 0.57 | 1.37 | 0.56x |
| **bu create** | 0.909 | 0.917 | 1.76 | 7.73 | 0.99x |
| bu increment, unchanged | 0.084 | 0.084 |  | 0.71 | 1.00x |
| bu restore -j 1 | 2.677 | 1.950 | 0.83 | 0.94 | 1.37x |
| **bu restore** | 1.912 | 1.381 | 1.17 | 2.91 | 1.38x |
| read: backup file¹ | 0.604 | 0.707 | 1.70 | 0.50 |  |
| bu check -j 1 | 1.860 | 1.292 | 0.93 | 0.96 | 1.44x |
| **bu check**² | 0.995 | 0.651 | 1.84 | 4.56 | 1.53x |
| bu increment, 1% of files | 0.090 | 0.089 |  | 1.01 | 1.01x |
| bu increment, 1% scattered | 0.335 | 0.264 |  | 7.27 | 1.27x |
| 1f read: 1 stream | 0.188 | 0.186 | 8.66 | 0.97 |  |
| 1f read: O_DIRECT | 0.183 | 0.182 | 8.85 | 0.93 |  |
| 1f copy: cp | 0.537 | 0.529 | 3.04 | 0.95 |  |
| 1f bu create -j 1 | 1.282 | 1.291 | 1.25 | 2.56 | 0.99x |
| **1f bu create** | 0.606 | 0.613 | 2.63 | 7.88 | 0.99x |
| **1f bu restore**¹ | 1.657 | 1.283 | 1.25 | 4.40 | 1.29x |

### tmpfs -> tmpfs (CPU cap)

| Case | before s | after s | after GB/s | cores busy | after vs before |
|---|---|---|---|---|---|
| read: tar \| cat | 0.536 | 0.519 | 3.10 | 1.41 |  |
| read: 1 stream, big files | 0.079 | 0.080 | 8.05 | 0.88 |  |
| read: 1 stream, tree | 0.222 | 0.222 | 7.26 | 0.95 |  |
| read: 4 streams, tree | 0.094 | 0.097 | 16.60 | 2.99 |  |
| read: 8 streams, tree | 0.090 | 0.089 | 18.10 | 6.07 |  |
| read: O_DIRECT big files | 0.084 | 0.082 | 7.86 | 0.85 |  |
| write: O_DIRECT | 0.397 | 0.401 | 4.02 | 0.97 |  |
| write: buffered + fsync | 0.397 | 0.398 | 4.05 | 0.98 |  |
| copy: cp -a | 0.514 | 0.518 | 3.11 | 0.97 |  |
| copy: tar to file | 0.487 | 0.495 | 3.25 | 0.97 |  |
| copy: tar extract | 0.467 | 0.471 | 3.42 | 0.98 |  |
| bu create -j 1 | 1.401 | 1.441 | 1.12 | 2.22 | 0.97x |
| **bu create** | 0.633 | 0.640 | 2.52 | 9.03 | 0.99x |
| bu increment, unchanged | 0.066 | 0.069 |  | 0.87 | 0.96x |
| bu restore -j 1 | 1.780 | 1.367 | 1.18 | 1.02 | 1.30x |
| **bu restore** | 0.466 | 0.344 | 4.68 | 6.45 | 1.35x |
| read: backup file | 0.119 | 0.120 | 9.99 | 0.92 |  |
| bu check -j 1 | 1.437 | 1.071 | 1.12 | 0.99 | 1.34x |
| **bu check** | 0.181 | 0.134 | 8.95 | 15.52 | 1.35x |
| bu increment, 1% of files | 0.072 | 0.077 |  | 1.30 | 0.94x |
| bu increment, 1% scattered | 0.264 | 0.205 |  | 9.46 | 1.29x |
| 1f read: 1 stream | 0.186 | 0.189 | 8.52 | 0.95 |  |
| 1f read: O_DIRECT | 0.184 | 0.184 | 8.75 | 0.98 |  |
| 1f copy: cp | 0.400 | 0.402 | 4.01 | 0.97 |  |
| 1f bu create -j 1 | 1.143 | 1.141 | 1.41 | 2.46 | 1.00x |
| **1f bu create** | 0.449 | 0.457 | 3.52 | 9.45 | 0.98x |
| **1f bu restore** | 0.448 | 0.321 | 5.02 | 7.41 | 1.40x |

¹ mean of two passes that differed by 10-50%. ² mean of two passes where one
caught a stall of the SSD (cpu/wall collapses, wall time doubles or more):
NVMe -> NVMe `1f bu restore` took 4.16 s in pass 2 and 1.59 s in pass 3; an
interleaved rerun of that case alone (7 runs each, before and after
alternating) gave 1.69 s before and 1.29 s after, at 11.0 and 5.4 s of
CPU. tmpfs -> NVMe `bu create -j 1` (1.58 s, 4.00 s) and `copy: tar
extract` (2.06 s, 6.51 s) stalled in pass 3.

On tmpfs the source reads are 0.09 s, so the multiple-of-read view applies
to the NVMe source only. NVMe -> same NVMe, relative to reading every file
once with 8 streams (0.595 s):

| Run | Time | vs. reading every file once |
|---|---|---|
| read: 8 streams | 0.595 s | 1.0× |
| copy: cp -a | 3.97 s | 6.7× |
| bu create | 1.69 s | 2.8× (before: 2.01 s, 3.3×) |
| bu create -j 1 | 3.63 s | 6.1× |
| bu increment, unchanged | 0.082 s | 0.14× |
| bu increment, 1% of files | 0.109 s | 0.18× |
| bu increment, 1% scattered | 0.409 s | 0.69× |
| bu restore | 1.45 s | 2.4× (before: 2.05 s, 3.3×) |
| bu check | 0.42 s | 0.71× (before: 0.97 s, 1.6×) |

## The four gaps, measured

The previous version of this page named four gaps between bu and the disk.
Each change below has before and after numbers from interleaved runs
(alternating binaries, 5-7 runs each, cold cache), and bu keeps only the
changes that helped; the tables above show the full suite after all of them.

**1. Restore and check read one record per `pread`.** They plateaued near
1.1 GB/s while one sequential stream reads the backup at 2.0-2.4 GB/s.
They now read spans of consecutive records with one `pread` and open the
records from memory, and each task asks the kernel (`WILLNEED`) for the
span 16 MiB ahead. Span size, measured on `check` from the NVMe: 128 KiB
0.315 s, 256 KiB 0.272 s, 512 KiB 0.271 s, 1 MiB 0.294 s, 2 MiB 0.330 s,
4 MiB 0.332 s, against 0.86 s for one record per `pread`; 256 KiB has the
lowest CPU and gives 20 threads enough tasks. Result, NVMe -> NVMe: check
0.97 -> 0.42 s (2.3×; it now beats a single sequential read of the backup,
0.69 s), restore 2.05 -> 1.45 s. Reading the backup from the NVMe into
tmpfs, restore went 1.23 -> 0.52 s in the A/B runs.

**2. Create used 4 readers where 8 streams read 50% faster.** Eight readers
and a 16-block ring (12 blocks held 8 readers back: 1.33 vs 1.24 s NVMe ->
tmpfs; 24 blocks gained nothing) took create NVMe -> tmpfs from 1.31 to
0.80 s and one big file from 0.82 to 0.56 s; 12 and 16 readers were no
better than 8. The extra readers cost 8% on tmpfs while create also ran a
worker per CPU (30 threads on 20 CPUs). Without `-j`, create now runs the
CPUs less three quarters of the readers as workers (14 here): tmpfs ->
tmpfs 0.633 -> 0.640 s, tmpfs -> NVMe 0.909 -> 0.917 s, NVMe -> same NVMe
2.01 -> 1.69 s. 12 workers were faster on tmpfs (0.61 s) and 10% slower
from the NVMe.

**3. Big files read as interleaved 1 MiB ranges defeat readahead.** The
hypothesis failed. A small reader on the cold 1.6 GB file with four
threads took 0.315 s for 1 MiB ranges handed out in turn (a descriptor per
thread), 0.320 s with one shared descriptor and 0.296 s for four contiguous
extents; one sequential thread took 0.662 s. Interleaving costs 6%. bu's
gap on the big file came from queue depth: a reader also runs the CDC scan,
so four readers keep fewer than four reads in flight. Eight readers closed
it (gap 2). A `WILLNEED` hint 4-16 MiB ahead helped four readers as much
and added nothing to eight, so bu does not use it.

**4. Restore spends sys CPU on many writer threads.** The measurements
bear this out. Restore now writes decoded chunks that continue each other
in a file with one `pwrite` of up to 1 MiB, and defaults to 8 threads; with
the prefetch, 8 threads read as fast as 20. A gate that let 4 or 8 of 20
threads write at once ran slower than plain 8 threads (0.84 and 1.17 s
against 0.62 s for one big file tmpfs -> NVMe), so bu does not use it.
Restore's CPU fell by half or more in every layout: NVMe -> NVMe 10.97 -> 4.69 s, one big file tmpfs -> NVMe
12.5 -> 5.6 s, tmpfs -> tmpfs 5.98 -> 2.22 s. Restore also creates the next
batch's files while the finisher thread writes the current batch: creating
23,614 files took a quarter of the wall time on ext4, with the pool idle.

## Conclusions

**A full backup from the NVMe to the same disk takes 2.8× as long as
reading every file once** (it was 3.3×). Reading the tree with 8 streams
and writing 1.2 GB with no overlap would take 0.60 + 0.44 s, 1.04 s;
create needs 1.69 s. Restore and check gained most; check now outruns a
plain sequential read of the backup because it reads with queue depth.

**Increments with the files cache take under a fifth of a full read.**
Unchanged: 0.08 s (0.14×), with 0 files read. 1% of the files: 0.11 s
(0.18×) for 236 files and a 6.1 MB increment. The dentry and inode caches
stay warm without root (see Method), so a cold machine pays more for the
walk's `stat` calls.

**On tmpfs bu is CPU-bound, and this round left create where it was**
(0.633 -> 0.640 s) while restore (0.466 -> 0.344 s) and check (0.181 ->
0.134 s) got faster from fewer, larger reads and writes.

**Anomalies and caveats.**
- The SSD stalls at times: a run's wall time doubles or triples with the
  CPU idle. The disk is 95% full and mounted without `discard`, so after
  each run's deletions the SSD has little clean space; writes to it stall
  most. Five-run medians absorb a single stall; whole passes still differed
  (see ¹ and ²).
- The first benchmark pass overlapped another job's builds and test suites:
  its 8-stream read took 1.11 s against 0.60-0.62 s in the clean passes.
  The tables leave it out.
- The second pass also exposed a hang in `create`: a lost wake-up between
  readers that could leave some asleep after the last range went out.
  It predates this round (2 hangs in 100 runs with 4 readers on 4 CPUs, 7 in
  100 with 8). The fix wakes every waiting reader, and
  `tests/integration/13-create-no-hang.sh` guards it.
- O_DIRECT writes (1.9-2.5 GB/s) are slower than buffered + fsync (2.7
  GB/s): 4 MiB synchronous direct writes at queue depth 1 through dm-crypt.
- Same-disk copy of one big file with cp (0.72-0.78 GB/s) stays far below
  both the read (2.4) and the write (2.7) caps: cp alternates reading and
  writing on one disk.
- One data set size (1.5 GiB, limited by free disk space).

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
