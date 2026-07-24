# 8. `forensic-vfs` adapter is an opt-in `vfs` feature, off by default

Date: 2026-07-24
Status: Accepted

## Context

`fat-core` can be mounted into the fleet's unified filesystem layer
(`forensic-vfs`) so a whole stack reads as one `ImageSource` (`ronin-issen/
CLAUDE.md`, "VFS & Universal Container Abstraction"). But `fat-core` is also
published for third-party reuse as a standalone FAT reader.

The fleet's batteries-included rule bans `default-features = false` as a way to
slim a *fleet* dependency graph or dodge a gate — capability an analyst needs
must be compiled in. That rule, however, carves out the exact case here: "The
library's `default` may stay lean for third-party reuse … The slim path is for
outside consumers, never for our own tools." A `-core` reader exposed on
crates.io is that outside-consumer surface.

## Decision

Gate the `forensic-vfs` `FileSystem` adapter behind a non-default `vfs` feature
(`core/Cargo.toml`: `default = []`, `vfs = ["dep:forensic-vfs"]`,
`forensic-vfs` an optional dependency; adapter in `core/src/vfs.rs` behind
`#[cfg(feature = "vfs")]`). The manifest states the reason: "opt-in so
third-party consumers who only want the reader do not pull the VFS type graph."
Fleet consumers that mount FAT (`disk-forensic` / `forensic-vfs-engine`) enable
the feature explicitly; a bare `cargo add fat-core` stays lean.

## Consequences

- A third party using `fat-core` as a plain reader does not drag in the
  `forensic-vfs` trait graph or its transitive deps.
- Fleet mounting is unaffected — consumers opt in with `features = ["vfs"]`.
- This is consistent with the batteries-included law: the slim default serves
  outside consumers only; every fleet *tool* that needs the adapter turns it on.
