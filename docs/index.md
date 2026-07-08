# fat-forensic

A pure-Rust, panic-free forensic suite for the FAT family — **FAT12, FAT16,
FAT32 and exFAT** — in one reader.

- **`fat-core`** (`use fat::…`) — the reader. `FatFs::open` auto-detects the
  variant from the boot sector, walks directory trees and cluster chains,
  reassembles VFAT long names and exFAT name-entry sets, and exposes deleted
  directory entries (first byte `0xE5`). Optional `forensic_vfs::FileSystem`
  adapter behind the `vfs` feature.
- **`fat-forensic`** — the analyzer. `audit` / `audit_reader` surface invalid
  BPBs, FAT1/FAT2 disagreements, bad / cross-linked / orphaned cluster chains,
  exFAT boot-checksum mismatches and deleted directory entries as graded
  [`forensicnomicon::report`](https://crates.io/crates/forensicnomicon)
  findings. Each finding carries the offending value.

## Trust but verify

The reader parses untrusted, attacker-controllable disk images: it never panics,
never reads out of bounds, and never trusts a length field (bounds-checked
integer readers, range-checked counts/offsets/clusters, capped allocations). It
is fuzzed per parsed structure and validated against **The Sleuth Kit** on
self-minted FAT12/16/32/exFAT images — see [Validation](validation.md).

Findings are observations ("consistent with"), never legal conclusions.
