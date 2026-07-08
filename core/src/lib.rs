//! fat-core: pure-Rust forensic reader for FAT12/16/32 and exFAT.
//!
//! Imported as `fat` (`[lib] name = "fat"`). [`FatFs::open`] auto-detects the
//! variant from the boot sector and exposes uniform navigation across all four.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod boot;
mod bytes;
mod dirent;
mod error;
mod exfat;
mod fat;
mod fs;
mod time;
#[cfg(feature = "vfs")]
mod vfs;

pub use boot::{FatVariant, Geometry};
pub use error::{FatError, Result};
pub use exfat::{boot_checksum, parse_boot as parse_exfat_boot};
pub use fs::{FatFs, FileId, Node};
pub use time::FatTimestamp;

/// Entry points for `cargo-fuzz` targets only — compiled solely under
/// `--cfg fuzzing`, so they never widen the public API or affect coverage. Each
/// drives one parsed structure over arbitrary bytes; the invariant is
/// "must not panic". NOT a stable API.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod __fuzz {
    use crate::boot::{FatVariant, Geometry};

    /// FAT12/16/32 boot sector (BPB) parse.
    pub fn parse_bpb(data: &[u8]) {
        let _ = Geometry::parse(data);
    }

    /// exFAT main boot sector parse.
    pub fn parse_exfat_boot(data: &[u8]) {
        let _ = crate::exfat::parse_boot(data);
    }

    /// FAT 8.3 / VFAT long-name directory decode.
    pub fn parse_dir_entry(data: &[u8]) {
        let _ = crate::dirent::parse_directory(data);
    }

    /// exFAT typed directory-entry-set decode.
    pub fn parse_exfat_dir(data: &[u8]) {
        let _ = crate::exfat::parse_directory(data);
    }

    /// FAT cluster-chain following (variant + start cluster derived from input).
    pub fn walk_fat_chain(data: &[u8]) {
        if data.len() < 5 {
            return;
        }
        let variant = match data[0] & 3 {
            0 => FatVariant::Fat12,
            1 => FatVariant::Fat16,
            2 => FatVariant::Fat32,
            _ => FatVariant::ExFat,
        };
        let start = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        let _ = crate::fat::follow_chain(&data[5..], variant, start, 100_000);
    }
}
