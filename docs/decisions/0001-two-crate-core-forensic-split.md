# 1. Two-crate core/forensic split with an unpublished debug CLI

Date: 2026-07-24
Status: Accepted

## Context

FAT is a single artifact family with four on-disk variants (FAT12, FAT16,
FAT32, exFAT). The fleet's crate-structure standard (`ronin-issen/CLAUDE.md`,
"Crate-structure standard — reader/analyzer split") mandates a **Pattern A**
single-format repo: exactly two published crates — `<x>-core` (the raw
reader/parser, no findings) and `<x>-forensic` (the anomaly auditor emitting
`forensicnomicon` findings) — plus an optional debug CLI member.

A `-core` reader is built to read *valid* data robustly, so it abstracts away
exactly the byte-level detail a forensic auditor must see (slack, mirror
disagreements, deleted slots). Keeping the reader and the auditor in one repo
but as separate crates lets third-party consumers depend on the lean reader
alone, while the analyzer layers findings on top.

## Decision

Ship three workspace members (`Cargo.toml` `members = ["core", "forensic",
"cli"]`):

1. **`core/` → `fat-core`** — the pure reader. Auto-detects the variant, walks
   directory trees and cluster chains, reassembles VFAT long names and exFAT
   name entry-sets, exposes deleted entries. No findings.
2. **`forensic/` → `fat-forensic`** — the anomaly auditor. `AnomalyKind` +
   `audit_path` emitting graded `forensicnomicon::report::Finding` via
   `impl Observation`.
3. **`cli/` → `fat-forensic-cli`** (binary `fat4n6`), marked
   **`publish = false`**. Its manifest states the rationale verbatim:
   "Debug/standalone CLI — the fleet end-user CLI is issen/disk4n6. Not
   published." It exists for local inspection, not as an examiner-facing
   product.

## Consequences

- The repo is **library tier**: the two published artifacts are libraries that
  are only linked; the analyst-facing surface is `issen`/`disk4n6`, not
  `fat4n6`. Documentation is intent-level (`docs/PRD.md`).
- A third-party consumer who only wants to read FAT volumes takes `fat-core`
  and never pulls `forensicnomicon`.
- Adding a new anomaly touches only `fat-forensic`; adding a new navigation
  capability touches only `fat-core`.
