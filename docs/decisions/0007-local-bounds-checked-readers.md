# 7. Local bounds-checked integer readers (`bytes.rs`) instead of the fleet `safe-read` crate

Date: 2026-07-24
Status: Accepted (deviation from fleet standard — flagged as migration debt)

## Context

The fleet robustness standard (`ronin-issen/CLAUDE.md`, "Paranoid Gatekeeper")
is explicit: every integer field read should route through the published
**`safe-read`** crate (`no_std`, `forbid(unsafe)`, fuzzed) — the fleet's single
audited implementation — and crates should **"NEVER hand-roll a per-crate
`bytes.rs`,"** because hand-rolled copies drift and some `data.get(off..off+N)`
variants can overflow `usize` (which `safe-read`'s `checked_add` avoids).

This repo does the opposite: `core/src/bytes.rs` is a local module of
bounds-checked little-endian readers (`u8_at`, `le_u16`, `le_u32`, `le_u64`),
introduced in its own RED/GREEN pair (git `3199d01` / `e4b9b14`, "bounds-checked
le integer readers"). The commits and code carry no recorded reason for not
adopting `safe-read`.

## Decision

Keep, for now, the local `bytes.rs` readers. They **do** match `safe-read`'s
safety semantics — each reader returns `0` when the window falls outside the
buffer (never panics), and the internal `window::<N>` helper uses
`off.checked_add(N)` so the offset arithmetic is overflow-safe
(`core/src/bytes.rs`), exactly the `usize`-overflow class the fleet rule warns
about. Callers still range-check the *meaning* of a value (cluster in range,
count within the `MAX_FAT_BYTES` / `MAX_DIR_BYTES` caps in `core/src/fs.rs`)
before acting on it.

**Rationale reconstructed from structure; original intent not recovered in
available history.** No commit message, comment, or manifest note explains why
`safe-read` was passed over rather than depended on. The most likely
reconstructed reasons are keeping `fat-core` dependency-light for a low MSRV, or
that the readers predate wiring `safe-read` into this repo — but neither is
confirmed by the record.

## Consequences

- The safety posture is currently equivalent to `safe-read` (0-out-of-range,
  overflow-checked), so there is no known robustness gap today.
- It is nonetheless a **DRY + robustness deviation** from the fleet standard: a
  second copy of the readers that can drift from the audited one. This is
  recorded as **migration debt** — replace `bytes.rs` with `safe-read` (or its
  re-export via `forensic-vfs`) in a follow-up, verifying the fuzz targets stay
  green, unless a low-MSRV or `no_std` constraint is deliberately chosen and
  documented at that point.
