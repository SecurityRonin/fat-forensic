# fat-forensic

[![Crates.io: fat-core](https://img.shields.io/crates/v/fat-core?label=fat-core)](https://crates.io/crates/fat-core)
[![Crates.io: fat-forensic](https://img.shields.io/crates/v/fat-forensic?label=fat-forensic)](https://crates.io/crates/fat-forensic)
[![Docs.rs](https://img.shields.io/docsrs/fat-core?label=docs.rs)](https://docs.rs/fat-core)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=githubsponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/fat-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/fat-forensic/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue)](https://securityronin.github.io/fat-forensic/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Fuzzed](https://img.shields.io/badge/fuzzed-cargo--fuzz-success.svg)](fuzz/)

**Audit a FAT12/FAT16/FAT32/exFAT volume for tampering, and read every file — one pure-Rust reader, no C-FFI.**

```rust
// Surface structural anomalies a happy-path reader silently trusts:
// invalid BPBs, FAT1/FAT2 disagreements, exFAT boot-checksum mismatches,
// bad/cross-linked/orphaned chains, deleted directory entries.
for anomaly in fat_forensic::audit_path("evidence.img".as_ref())? {
    println!("[{:?}] {}: {}", anomaly.severity(), anomaly.code(), anomaly.note());
}
// [High] FAT-MIRROR-MISMATCH: FAT1 and FAT2 disagree at entry 42
//   (0x0003 vs 0x0000) — consistent with post-hoc edit of one copy
```

Each anomaly is an observation ("consistent with"), never a verdict, and converts
to a [`forensicnomicon`](https://crates.io/crates/forensicnomicon) `Finding`.

## Read any FAT variant with one reader

`fat-core` (imported as `fat`) auto-detects FAT12, FAT16, FAT32 or exFAT from the
boot sector — the caller does not choose:

```rust
use fat::FatFs;
let fs = FatFs::open(std::fs::File::open("evidence.img")?)?;
println!("variant: {:?}", fs.variant());          // Fat12 | Fat16 | Fat32 | ExFat

let root = fs.root();
let hello = fs.lookup(root, b"HELLO.TXT")?.expect("present");
let meta = fs.meta(hello)?;                        // size, times, attributes
let mut buf = vec![0u8; meta.size as usize];
fs.read_at(hello, 0, &mut buf)?;                   // cluster chain (or exFAT contiguous)
```

VFAT long names and exFAT File-Name entry sets are reassembled; deleted directory
entries (first byte `0xE5`) are exposed for recovery.

Mount it into the [forensic-vfs](https://crates.io/crates/forensic-vfs) unified
filesystem layer with the `vfs` feature:

```toml
fat-core = { version = "0.1", features = ["vfs"] }
```

## Install

```toml
[dependencies]
fat-core = "0.1"        # the reader (import: `fat`)
fat-forensic = "0.1"    # the auditor
```

## Safety

`#![forbid(unsafe_code)]`, panic-free on untrusted input (bounds-checked reads,
range-checked cluster/offset/count fields, allocation caps), and `cargo-fuzz`
targets per parsed structure assert the parser and audit pipeline never panic.
Correctness is established against **The Sleuth Kit** on self-minted
FAT12/16/32/exFAT images — see the
[validation notes](https://securityronin.github.io/fat-forensic/validation/).

---

[Privacy Policy](https://securityronin.github.io/fat-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/fat-forensic/terms/) · © 2026 Security Ronin Ltd
