//! Forensic FAT/exFAT anomaly auditor.
//!
//! Surfaces structural and integrity anomalies a happy-path reader would
//! normalize away: an invalid boot signature / BPB, a FAT1 vs FAT2 mirror
//! disagreement, an exFAT boot-region checksum mismatch, and the presence of
//! deleted directory entries. Each anomaly is an OBSERVATION graded by severity
//! ("consistent with", never a verdict) and carries the offending value; it
//! converts to a [`forensicnomicon::report::Finding`] via [`Observation`].
//!
//! The auditor reads the raw structures itself (boot sector, the two FAT
//! copies, the exFAT checksum sector) rather than routing through the reader's
//! normalized view — a `-core` reader hides exactly the disagreements a forensic
//! audit hunts (the "-forensic may go lower" principle).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fat::{boot_checksum, FatError, FatFs, FatVariant, FileId, Geometry};
use forensicnomicon::report::{Category, Evidence, Location, Observation, Severity};

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "fat-forensic";

/// Recursion cap on the directory walk (defends against a cyclic tree).
const MAX_DEPTH: usize = 64;

/// Classification of a FAT/exFAT forensic anomaly, carrying the evidence to
/// reproduce it (offending value + location).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// The boot sector's `0x55AA` signature is absent — consistent with a
    /// non-FAT volume or a wiped/overwritten boot sector.
    BootSignatureInvalid {
        /// The 16-bit value found at offset 0x1FE.
        found: u16,
    },
    /// The BPB is structurally invalid and the volume could not be parsed.
    BpbInvalid {
        /// The parser's description of the offending field/value.
        detail: String,
    },
    /// A byte disagrees between the first and a subsequent FAT copy — consistent
    /// with a post-hoc edit of one copy or on-media corruption.
    FatMirrorMismatch {
        /// Byte offset of the first disagreement within the FAT.
        fat_offset: u64,
        /// Byte in the first FAT.
        fat1: u8,
        /// Byte in the mirror FAT.
        fat2: u8,
        /// Total number of disagreeing bytes across the FATs.
        differing_bytes: u64,
    },
    /// The exFAT boot-region checksum does not match the recomputed value —
    /// consistent with a modified boot region.
    ExfatBootChecksumMismatch {
        /// Checksum recomputed over the first 11 sectors ([MS] §3.4).
        computed: u32,
        /// Checksum stored in the checksum sector.
        stored: u32,
    },
    /// A deleted directory entry is present — a recovery lead (benign in
    /// isolation).
    DeletedDirectoryEntry {
        /// The recovered name (first character is unknown on FAT, shown as `?`).
        name: String,
    },
}

impl AnomalyKind {
    /// Severity of this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::BootSignatureInvalid { .. }
            | AnomalyKind::BpbInvalid { .. }
            | AnomalyKind::ExfatBootChecksumMismatch { .. } => Severity::High,
            AnomalyKind::FatMirrorMismatch { .. } => Severity::Medium,
            AnomalyKind::DeletedDirectoryEntry { .. } => Severity::Info,
        }
    }

    /// Stable, scheme-prefixed machine code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::BootSignatureInvalid { .. } => "FAT-BOOT-SIG-INVALID",
            AnomalyKind::BpbInvalid { .. } => "FAT-BPB-INVALID",
            AnomalyKind::FatMirrorMismatch { .. } => "FAT-MIRROR-MISMATCH",
            AnomalyKind::ExfatBootChecksumMismatch { .. } => "EXFAT-BOOT-CHECKSUM-MISMATCH",
            AnomalyKind::DeletedDirectoryEntry { .. } => "FAT-DIR-ENTRY-DELETED",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::BootSignatureInvalid { .. } | AnomalyKind::BpbInvalid { .. } => {
                Category::Structure
            }
            AnomalyKind::FatMirrorMismatch { .. }
            | AnomalyKind::ExfatBootChecksumMismatch { .. } => Category::Integrity,
            AnomalyKind::DeletedDirectoryEntry { .. } => Category::Residue,
        }
    }

    /// Human-readable, consistent-with note (carries the offending value).
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::BootSignatureInvalid { found } => format!(
                "boot signature at 0x1FE is {found:#06x}, expected 0x55AA — consistent with a \
                 non-FAT or overwritten boot sector"
            ),
            AnomalyKind::BpbInvalid { detail } => {
                format!("BPB is structurally invalid: {detail}")
            }
            AnomalyKind::FatMirrorMismatch {
                fat_offset,
                fat1,
                fat2,
                differing_bytes,
            } => format!(
                "FAT copies disagree in {differing_bytes} byte(s); first at FAT offset \
                 {fat_offset} ({fat1:#04x} vs {fat2:#04x}) — consistent with a post-hoc edit of \
                 one copy or media corruption"
            ),
            AnomalyKind::ExfatBootChecksumMismatch { computed, stored } => format!(
                "exFAT boot checksum {computed:#010x} does not match the stored {stored:#010x} — \
                 consistent with a modified boot region"
            ),
            AnomalyKind::DeletedDirectoryEntry { name } => {
                format!("deleted directory entry present: {name:?} (recovery lead)")
            }
        }
    }

    /// Backing evidence rows (offending value + location).
    #[must_use]
    pub fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::BootSignatureInvalid { found } => vec![Evidence {
                field: "boot_signature".into(),
                value: format!("{found:#06x}"),
                location: Some(Location::ByteOffset(510)),
            }],
            AnomalyKind::BpbInvalid { detail } => vec![Evidence {
                field: "bpb".into(),
                value: detail.clone(),
                location: Some(Location::ByteOffset(0)),
            }],
            AnomalyKind::FatMirrorMismatch {
                fat_offset,
                fat1,
                fat2,
                ..
            } => vec![Evidence {
                field: "fat_mirror".into(),
                value: format!("{fat1:#04x} vs {fat2:#04x}"),
                location: Some(Location::ByteOffset(*fat_offset)),
            }],
            AnomalyKind::ExfatBootChecksumMismatch { computed, stored } => vec![Evidence {
                field: "boot_checksum".into(),
                value: format!("computed={computed:#010x}, stored={stored:#010x}"),
                location: None,
            }],
            AnomalyKind::DeletedDirectoryEntry { name } => vec![Evidence {
                field: "deleted_name".into(),
                value: name.clone(),
                location: None,
            }],
        }
    }
}

/// A FAT/exFAT forensic anomaly: an observation graded by severity, with a
/// stable code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// Human-readable note, derived from `kind`.
    pub note: String,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

/// Audit the FAT/exFAT volume at `path` for structural and integrity anomalies.
pub fn audit_path(path: &Path) -> Result<Vec<Anomaly>, FatError> {
    let file = std::fs::File::open(path).map_err(|e| FatError::io("open", e))?;
    audit_reader(file)
}

/// Audit an open seekable reader for structural and integrity anomalies.
pub fn audit_reader<R: Read + Seek>(mut reader: R) -> Result<Vec<Anomaly>, FatError> {
    let mut out = Vec::new();

    let mut boot = [0u8; 512];
    read_at(&mut reader, 0, &mut boot)?;

    // Boot signature.
    let sig = u16::from_le_bytes([boot[510], boot[511]]);
    if sig != 0xAA55 {
        out.push(Anomaly::new(AnomalyKind::BootSignatureInvalid {
            found: sig,
        }));
    }

    // Parse geometry (raw), so the FAT/checksum locations are known.
    let is_exfat = &boot[3..11] == b"EXFAT   ";
    let geom = if is_exfat {
        fat::parse_exfat_boot(&boot)
    } else {
        Geometry::parse(&boot)
    };
    let geom = match geom {
        Ok(g) => g,
        Err(e) => {
            // Nothing downstream is trustworthy once the BPB is invalid.
            out.push(Anomaly::new(AnomalyKind::BpbInvalid {
                detail: e.to_string(),
            }));
            return Ok(out);
        }
    };

    if geom.variant == FatVariant::ExFat {
        audit_exfat_checksum(&mut reader, &geom, &mut out)?;
    } else if geom.num_fats >= 2 {
        audit_fat_mirror(&mut reader, &geom, &mut out)?;
    }

    // Directory walk for deleted entries (via the reader's normalized tree).
    if let Ok(fs) = FatFs::open(reader) {
        collect_deleted(&fs, fs.root(), 0, &mut BTreeSet::new(), &mut out);
    }

    Ok(out)
}

/// Compare the exFAT recomputed boot checksum against the stored value.
fn audit_exfat_checksum<R: Read + Seek>(
    reader: &mut R,
    geom: &Geometry,
    out: &mut Vec<Anomaly>,
) -> Result<(), FatError> {
    let bps = geom.bytes_per_sector as usize;
    let mut region = vec![0u8; bps * 12]; // first 11 sectors + the checksum sector
    let n = read_upto(reader, 0, &mut region)?;
    if n < bps * 12 {
        return Ok(()); // truncated — cannot verify, do not fabricate a mismatch
    }
    let computed = boot_checksum(&region[..bps * 11], geom.bytes_per_sector);
    let stored = u32::from_le_bytes([
        region[bps * 11],
        region[bps * 11 + 1],
        region[bps * 11 + 2],
        region[bps * 11 + 3],
    ]);
    if computed != stored {
        out.push(Anomaly::new(AnomalyKind::ExfatBootChecksumMismatch {
            computed,
            stored,
        }));
    }
    Ok(())
}

/// Compare the first FAT against the mirror copy, byte for byte.
fn audit_fat_mirror<R: Read + Seek>(
    reader: &mut R,
    geom: &Geometry,
    out: &mut Vec<Anomaly>,
) -> Result<(), FatError> {
    let fat_bytes = (u64::from(geom.fat_size_sectors) * u64::from(geom.bytes_per_sector)) as usize;
    if fat_bytes == 0 {
        return Ok(());
    }
    let mut fat1 = vec![0u8; fat_bytes];
    if read_upto(reader, geom.fat_start, &mut fat1)? < fat_bytes {
        return Ok(());
    }
    let mut fat2 = vec![0u8; fat_bytes];
    let fat2_start = geom.fat_start + fat_bytes as u64;
    if read_upto(reader, fat2_start, &mut fat2)? < fat_bytes {
        return Ok(());
    }
    let mut first: Option<(u64, u8, u8)> = None;
    let mut differing = 0u64;
    for (i, (a, b)) in fat1.iter().zip(fat2.iter()).enumerate() {
        if a != b {
            differing += 1;
            if first.is_none() {
                first = Some((i as u64, *a, *b));
            }
        }
    }
    if let Some((fat_offset, a, b)) = first {
        out.push(Anomaly::new(AnomalyKind::FatMirrorMismatch {
            fat_offset,
            fat1: a,
            fat2: b,
            differing_bytes: differing,
        }));
    }
    Ok(())
}

/// Recursively collect deleted directory entries, skipping `.`/`..` and
/// bounding recursion depth and revisits.
fn collect_deleted<R: Read + Seek>(
    fs: &FatFs<R>,
    dir: FileId,
    depth: usize,
    seen: &mut BTreeSet<u32>,
    out: &mut Vec<Anomaly>,
) {
    if depth >= MAX_DEPTH {
        return;
    }
    let Ok(nodes) = fs.read_dir(dir) else {
        return;
    };
    for node in nodes {
        if node.name == "." || node.name == ".." {
            continue;
        }
        if node.is_deleted {
            out.push(Anomaly::new(AnomalyKind::DeletedDirectoryEntry {
                name: node.name.clone(),
            }));
            continue; // do not recurse a deleted directory (its chain is untrusted)
        }
        if node.is_dir && !node.is_volume_label && seen.insert(node.first_cluster) {
            collect_deleted(fs, node.id, depth + 1, seen, out);
        }
    }
}

/// Seek to `offset` and read exactly `buf.len()` bytes, failing loud on EOF.
fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, buf: &mut [u8]) -> Result<(), FatError> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| FatError::io("seek", e))?;
    reader.read_exact(buf).map_err(|e| FatError::io("read", e))
}

/// Seek to `offset` and read up to `buf.len()` bytes, returning the count read.
fn read_upto<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    buf: &mut [u8],
) -> Result<usize, FatError> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| FatError::io("seek", e))?;
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FatError::io("read", e)),
        }
    }
    Ok(filled)
}
