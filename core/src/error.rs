//! Error type for the FAT/exFAT reader.
//!
//! A *bootstrap* failure (unrecognized/invalid boot sector, unreadable
//! prerequisite) surfaces loud as an error carrying the offending value; a
//! per-node miss (a name not found) is a normal `Ok(None)`, never an error.

use std::io;

/// Errors raised while opening or navigating a FAT/exFAT volume.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FatError {
    /// Underlying reader failed during the named operation.
    #[error("I/O error during {op}: {source}")]
    Io {
        /// The operation being attempted (e.g. `"read boot sector"`).
        op: &'static str,
        /// The originating I/O error.
        source: io::Error,
    },

    /// The boot sector is structurally invalid; the message names the offending
    /// field and value (fail-loud, show-the-value).
    #[error("invalid boot sector: {0}")]
    InvalidBoot(String),

    /// The volume is not a recognized FAT or exFAT filesystem; the message
    /// carries the bytes/signature that were found instead.
    #[error("not a FAT/exFAT volume: {0}")]
    NotFat(String),

    /// A structure was internally inconsistent while navigating.
    #[error("corrupt structure: {0}")]
    Corrupt(String),
}

impl FatError {
    /// Wrap an I/O error with the operation label.
    pub(crate) fn io(op: &'static str, source: io::Error) -> Self {
        FatError::Io { op, source }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, FatError>;
