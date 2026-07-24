# 5. Anomalies are graded `forensicnomicon` observations, never verdicts

Date: 2026-07-24
Status: Accepted

## Context

The fleet standardizes on one reporting model (`ronin-issen/CLAUDE.md`, "The
Reporting Model — `forensicnomicon::report`"): every analyzer keeps its own
typed anomaly enum (domain knowledge) but converts to canonical `Finding`s so
orchestration (`issen`/`disk4n6`) and a future GUI render all analyzers
uniformly. `code` is a published contract (scheme-prefixed SCREAMING-KEBAB), a
finding is an **observation** ("consistent with"), never a legal conclusion,
and `severity` is graded.

## Decision

`fat-forensic` defines a typed `AnomalyKind` enum and grades each variant,
converting to `forensicnomicon::report::Finding` via `impl Observation`
(`forensic/src/lib.rs`). The published codes are:

| `code` | meaning |
|---|---|
| `FAT-BOOT-SIG-INVALID` | boot sector `0x55AA` signature absent |
| `FAT-BPB-INVALID` | BPB fails validation |
| `FAT-MIRROR-MISMATCH` | FAT1 and FAT2 disagree at an entry |
| `EXFAT-BOOT-CHECKSUM-MISMATCH` | computed vs stored boot-region checksum differ |
| `FAT-DIR-ENTRY-DELETED` | a `0xE5`-deleted directory entry is present |

Each anomaly carries its **evidence** — always the offending value, plus a
byte-offset location where one applies (`fn evidence() -> Vec<Evidence>`), e.g.
the mismatching FAT entries at their FAT offset, or the computed-vs-stored
checksum pair (which has no single meaningful offset, so it carries the value
alone) — honoring the fleet's "show the unrecognized value" rule. Notes are phrased as "consistent with" (a post-hoc edit, a wiped
boot sector), never as a determination.

## Consequences

- Findings aggregate into one `forensicnomicon::report::Report` alongside every
  other fleet analyzer, with no bespoke `FatAnalysis` type for `issen` to learn.
- The codes are a stability contract: a shipped code is never repurposed; a new
  anomaly gets a new code.
- Severity is emitted per variant so triage tooling can filter
  (`findings_at_least`) without re-deriving it.
