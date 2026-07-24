# 2. One reader auto-detects FAT12/FAT16/FAT32 and exFAT

Date: 2026-07-24
Status: Accepted

## Context

"FAT" is four related but structurally distinct filesystems. FAT12/16/32 share
a BIOS Parameter Block (BPB) and a File Allocation Table but differ in FAT
entry width (12/16/28 bits) and root-directory placement (a fixed region on
FAT12/16, a cluster chain on FAT32). exFAT is a different layout entirely — a
128-byte boot region with a checksum sector, a typed directory entry-set model,
and optional contiguous (`NoFatChain`) allocation.

A caller holding an evidence image usually does not know which variant it is;
the fleet's VFS abstraction (`ronin-issen/CLAUDE.md`, "VFS & Universal
Container Abstraction") requires that a consumer "MUST NOT know one … format
from another." Forcing the caller to pick a variant would push format
detection into every consumer.

## Decision

Expose a **single** `FatFs` type whose `FatFs::open` auto-detects the variant
from the boot sector and then serves uniform navigation (`root`, `read_dir`,
`lookup`, `meta`, `read_at`) across all four (`core/src/fs.rs`,
`core/src/boot.rs`). Variant detection follows the canonical rule —
count-of-clusters against the `FAT12_MAX_CLUSTERS = 4085` / `FAT16_MAX_CLUSTERS
= 65525` thresholds (`core/src/boot.rs`), and the exFAT boot signature is
recognized separately (`core/src/exfat.rs`). `FatFs::variant()` reports the
detected `FatVariant`. FAT12/16/32 landed first; exFAT was wired into the same
`FatFs` navigation later (git `4b68635` "wire exFAT into FatFs navigation,
TSK-validated") rather than shipping a parallel `ExFatFs`.

## Consequences

- Consumers call one entry point; the reader owns the variant decision, so the
  `forensic-vfs` adapter and any downstream carver stay format-agnostic.
- The four variants' quirks (12-bit split entries, fixed vs chained root,
  exFAT contiguous runs) are internal to `fat-core`, not the caller's problem.
- The variant enum is public, so a consumer that *does* care (e.g. a report
  label) can read it without branching on internals.
