# 4. `fat-forensic` reads raw structures, going below the reader's view

Date: 2026-07-24
Status: Accepted

## Context

The fleet's crate-structure standard states the binding design principle that
`-forensic` is **not required** to depend only on `-core`: a happy-path reader
"abstracts away exactly the detail a forensic auditor must SEE" — slack between
records, deleted/overwritten regions, malformed fields a robust reader silently
normalizes, and checksums it transparently verifies-and-discards. The auditor
"often needs to go much lower level than the `-core` API."

FAT is a textbook case. A reader that successfully opens a volume has *already*
chosen one FAT copy, accepted a BPB, and skipped `0xE5`-deleted slots. The
anomalies a forensic examiner cares about live precisely in what the reader
discarded: does FAT1 agree with FAT2? Does the exFAT boot-region checksum
match? Is the `0x55AA` signature present? Are there deleted directory entries?

## Decision

`fat-forensic` reads the **raw** structures itself — the boot sector, both FAT
copies, and the exFAT checksum sector — over the underlying `Read + Seek`
stream, rather than routing every check through `FatFs`'s normalized view
(`forensic/src/lib.rs` module doc states this explicitly). It **still depends
on `fat-core`** for the parts where the reader's API already exposes what the
audit needs: `FatFs` for the directory walk that enumerates deleted entries,
plus `Geometry`, `FatVariant`, and the reusable `boot_checksum` primitive
(`use fat::{boot_checksum, FatFs, FatVariant, Geometry, …}`). It is a hybrid,
per the decision rule: build on `-core` where its API suffices, drop lower
where it hides the anomaly.

## Consequences

- The auditor can surface a `FAT-MIRROR-MISMATCH` even though a
  correctly-functioning reader would never expose the disagreement — it
  compares the two FATs byte-for-byte itself.
- `boot_checksum` is exported from `fat-core` and reused rather than
  reimplemented, keeping the exFAT checksum logic single-sourced.
- `fat-forensic` carries a `MAX_DEPTH = 64` recursion cap on its own directory
  walk (`forensic/src/lib.rs`), independent of the reader's caps, because it
  drives the walk directly.
