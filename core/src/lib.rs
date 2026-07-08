//! fat-core: pure-Rust forensic reader for FAT12/16/32 and exFAT.
//!
//! Imported as `fat` (`[lib] name = "fat"`). [`FatFs::open`] auto-detects the
//! variant from the boot sector and exposes uniform navigation across all four.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
// Bottom-up TDD scaffold: leaf parsers (bytes/boot/fat/dirent/exfat) land before
// their FatFs/vfs consumers. This allow is REMOVED in the final wiring commit,
// where any genuinely-dead code then surfaces.
#![allow(dead_code)]

mod boot;
mod bytes;
mod error;

pub use error::{FatError, Result};
