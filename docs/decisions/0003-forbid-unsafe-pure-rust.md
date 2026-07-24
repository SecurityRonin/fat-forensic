# 3. Pure-Rust, `forbid(unsafe)`, no C-FFI

Date: 2026-07-24
Status: Accepted

## Context

These crates parse untrusted, attacker-controllable disk images. The fleet's
unsafe law (`ronin-issen/CLAUDE.md` → global "unsafe Is an Avoidable
Cost-Benefit Exception" + "Paranoid Gatekeeper") makes `unsafe_code = "forbid"`
the default *and the goal* — a provable, badge-able "zero places a crafted
input can corrupt memory." A downgrade to `deny` + a bounded per-site
`#[allow(unsafe_code)]` is justified only by a concrete benefit (e.g. an `mmap`
scanner, as in `ewf`/`memory-forensic`), and a C-FFI `-sys` dependency is a
categorically worse liability because the compiler has zero visibility into C.

FAT/exFAT parsing is pure byte arithmetic over a seekable stream. It has no
performance argument for `mmap` and no need for any C library, so nothing here
earns even a bounded `unsafe`.

## Decision

Set `unsafe_code = "forbid"` at the workspace level (`Cargo.toml`
`[workspace.lints.rust]`), applied to every member via `[lints] workspace =
true`. Reads go through the crate's own bounds-checked integer readers
(`core/src/bytes.rs`, see ADR 0007), never raw pointer casts. No C-FFI or
`-sys` dependency is taken; the whole tree is pure Rust. Robustness is enforced
statically by the panic-free lint pair `unwrap_used = "deny"` / `expect_used =
"deny"` and empirically by `cargo-fuzz` targets per parsed structure (ADR 0004
reporting model aside; fuzz targets live in `fuzz/fuzz_targets/`).

## Consequences

- The repo earns the honest **`unsafe forbidden`** README badge — unlike the
  fleet's mmap readers, which are `deny` + bounded-allow and correctly skip
  that badge.
- `rg 'unsafe'` over the source is expected to return nothing in production
  code; any future `unsafe` is a hard compile error, forcing an explicit,
  reviewed downgrade if ever genuinely warranted.
- Memory-corruption / RCE from a crafted FAT image is excluded by
  construction, not by review.
