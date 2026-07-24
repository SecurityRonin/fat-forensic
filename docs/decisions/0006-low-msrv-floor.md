# 6. Low CI-verified MSRV floor (1.85) decoupled from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md` + global "Rust MSRV & Toolchain
Policy") separates the **dev toolchain** (what you build/lint with — pinned to
the current stable, fleet-wide) from the **declared MSRV** (`rust-version`, a
downstream-facing compatibility promise). Apps declare MSRV = the pin; but
**published libraries keep a low, CI-verified MSRV** because raising it narrows
the crates.io audience and is a near-breaking change.

`fat-core` and `fat-forensic` are published libraries meant for third-party
reuse (a consumer may take `fat-core` as a plain FAT reader).

## Decision

Pin the dev toolchain to the current fleet stable — `rust-toolchain.toml`
`channel = "1.96.0"` with `clippy` + `rustfmt` components declared in the toml
(the single source of truth). Declare the **library MSRV floor low**:
`Cargo.toml` `[workspace.package] rust-version = "1.85"`, with the rationale
inline ("Published libraries keep a low, CI-verified MSRV (a compatibility
promise)"). The two numbers are deliberately different: `1.85` is the promise,
`1.96.0` is the build environment.

## Consequences

- A downstream crate on Rust 1.85 can depend on `fat-core` without being forced
  to upgrade its toolchain.
- The floor is a real guarantee only if CI verifies it — a dedicated low-MSRV
  job must build against 1.85 (fleet CI shape); raising `rust-version` later is
  treated as a near-breaking change needing an explicit reason.
- Bumping the dev toolchain is a deliberate fleet-wide pass (also re-pinning
  `ci.yml`), and never silently drags the promised MSRV up with it.
