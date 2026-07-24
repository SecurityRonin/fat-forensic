# fat-forensic — Design (Purpose & Scope)

> This is a **library** repo, not a product. It ships no examiner-facing binary
> (the `fat4n6` CLI member is `publish = false`, a debug/dev tool only — the
> fleet end-user CLIs are `issen` / `disk4n6`). This document states purpose,
> scope, and non-goals; the load-bearing decisions and their rationale live in
> [`docs/decisions/`](decisions/).

## Purpose

Provide the fleet's FAT-family support as two composable Rust libraries:

- **`fat-core`** (imported as `fat`) — a pure-Rust reader that auto-detects
  FAT12, FAT16, FAT32, or exFAT from the boot sector and serves uniform
  navigation over all four: directory-tree traversal, cluster-chain (and exFAT
  contiguous) reads, VFAT long-name and exFAT name-entry-set reassembly, packed
  date/time decode, and exposure of deleted directory entries for recovery.
- **`fat-forensic`** — an anomaly auditor over the same volumes that surfaces
  the structural and integrity problems a happy-path reader normalizes away, as
  graded `forensicnomicon` findings ("consistent with", never a verdict).

## Users (who links these crates)

- **The fleet** — `issen` / `disk4n6` for correlation and the user-facing CLI,
  and `forensic-vfs` / `disk-forensic` for format-agnostic mounting (via the
  opt-in `vfs` feature, ADR 0008).
- **Third-party Rust developers** — who want a dependency-light, panic-free FAT
  reader with no C-FFI. `fat-core`'s low MSRV floor (ADR 0006) and lean default
  features exist for exactly this audience.

## What it does

| Capability | Crate | Notes |
|---|---|---|
| Auto-detect FAT12/16/32/exFAT | `fat-core` | `FatFs::open`; caller never chooses (ADR 0002) |
| Directory / cluster-chain navigation | `fat-core` | `root`, `read_dir`, `lookup`, `meta`, `read_at` |
| VFAT LFN + exFAT name-entry-set reassembly | `fat-core` | long names reconstructed from entry sets |
| Deleted directory entries | `fat-core` | `0xE5`-deleted slots exposed for recovery |
| `forensic-vfs` mount adapter | `fat-core` | opt-in `vfs` feature (ADR 0008) |
| Boot-signature / BPB validation | `fat-forensic` | `FAT-BOOT-SIG-INVALID`, `FAT-BPB-INVALID` |
| FAT1 vs FAT2 mirror comparison | `fat-forensic` | `FAT-MIRROR-MISMATCH` |
| exFAT boot-region checksum check | `fat-forensic` | `EXFAT-BOOT-CHECKSUM-MISMATCH` |
| Deleted-entry surfacing as a finding | `fat-forensic` | `FAT-DIR-ENTRY-DELETED` |

Every `fat-forensic` anomaly carries its offending value as `Evidence` — with a
byte-offset location where one applies (three of the five anomalies; the exFAT
boot-checksum and deleted-entry evidence has no single meaningful offset) — and
converts to a `forensicnomicon::report::Finding` (ADR 0005).

## Scope

- Read and audit FAT12, FAT16, FAT32, and exFAT volumes from a `Read + Seek`
  byte source (a raw image, or any container the fleet VFS layer decodes).
- Behave safely on untrusted, possibly-malformed images: `forbid(unsafe)`,
  panic-free by lint, bounds-checked reads, allocation caps, cycle-defeating
  chain caps (ADR 0003, ADR 0007).

## Non-goals

- **Writing / repair.** These are read-only readers and auditors; no FAT
  mutation, no in-place recovery.
- **An examiner-facing product.** No shipped CLI/GUI/MCP; presentation,
  correlation, and the analyst UX belong to `issen` / `disk4n6`. The `fat4n6`
  binary is a debug aid, unpublished (ADR 0001).
- **Container / mounting logic.** Decoding E01/VMDK/… and composing filesystem
  stacks is the job of `disk-forensic` / `forensic-vfs`; `fat-core` only
  implements the FAT `FileSystem` adapter behind the `vfs` feature.
- **Deep semantic timelining.** `fat-forensic` reports structural anomalies;
  cross-artifact timeline correlation is orchestration-layer work.

## Validation approach

Correctness is established against an **independent oracle — The Sleuth Kit** —
on self-minted FAT12/16/32/exFAT images (git `d8e8a0a`, `4b68635`
"TSK-validated"; see `docs/validation.md`). Robustness is enforced two ways: the
static panic-free lint pair (`unwrap_used` / `expect_used = deny`) plus
`forbid(unsafe)`, and empirical `cargo-fuzz` targets per parsed structure —
`bpb`, `dir_entry`, `exfat_boot`, `exfat_dir`, `fat_chain`, and a
`fuzz_forensic` target driving the full audit pipeline (`fuzz/fuzz_targets/`) —
whose invariant is "must not panic." Both published libraries hold 100% line
coverage (git `480b8f7`).
