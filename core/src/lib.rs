//! fat-core: pure-Rust forensic reader for FAT12/16/32 and exFAT.
//!
//! Imported as `fat` (`[lib] name = "fat"`). [`FatFs::open`] auto-detects the
//! variant from the boot sector and exposes uniform navigation across all four.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod boot;
mod bytes;
mod error;

pub use error::{FatError, Result};
