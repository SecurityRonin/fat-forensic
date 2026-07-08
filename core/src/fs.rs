//! [`FatFs`] — the unified reader. [`FatFs::open`] auto-detects FAT12/16/32
//! (exFAT is wired in a later unit), then serves uniform navigation: `root`,
//! `read_dir`, `lookup`, `meta`, `read_at`.

use std::io::{Read, Seek, SeekFrom};
use std::sync::Mutex;

use crate::boot::{FatVariant, Geometry};
use crate::dirent::{parse_directory, DirEntry};
use crate::error::{FatError, Result};
use crate::fat::follow_chain;
use crate::time::{decode as decode_time, FatTimestamp};

/// Cap on bytes materialized for one directory (defends against a lying chain).
const MAX_DIR_BYTES: usize = 64 * 1024 * 1024;
/// Cap on the cached FAT region (defends against an absurd `fat_size`).
const MAX_FAT_BYTES: u64 = 256 * 1024 * 1024;
/// Marker `dir_cluster` value meaning "the FAT12/16 fixed root region".
const FIXED_ROOT: u32 = u32::MAX;

/// A handle to a node. The root is distinct; every other node is addressed by
/// its parent directory's first cluster plus its 32-byte slot index — so the
/// entry (including a deleted one) can always be re-read from the structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileId {
    /// The volume root directory.
    Root,
    /// A directory entry: `dir_cluster` is the parent directory's first cluster
    /// (or [`FIXED_ROOT`] for the FAT12/16 fixed root), `index` the slot.
    Entry {
        /// First cluster of the parent directory (or the fixed-root marker).
        dir_cluster: u32,
        /// 32-byte slot index of the entry within its directory.
        index: u16,
    },
}

/// A resolved node: identity plus the fields a caller needs to navigate or read.
#[derive(Debug, Clone)]
pub struct Node {
    /// Stable handle to this node.
    pub id: FileId,
    /// Effective name (long name if valid, else 8.3).
    pub name: String,
    /// Raw 8.3 short name.
    pub short_name: String,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// Whether this entry is deleted (`0xE5`).
    pub is_deleted: bool,
    /// Whether this is the volume-label entry.
    pub is_volume_label: bool,
    /// File size in bytes (0 for directories).
    pub size: u64,
    /// Raw attribute byte.
    pub attributes: u8,
    /// First cluster of the node's data (0 = empty).
    pub first_cluster: u32,
    /// Decoded creation timestamp (local time), if set.
    pub created: Option<FatTimestamp>,
    /// Decoded last-modified timestamp (local time), if set.
    pub modified: Option<FatTimestamp>,
    /// Decoded last-access timestamp (date only; local time), if set.
    pub accessed: Option<FatTimestamp>,
}

/// Where a directory's raw bytes live.
#[derive(Clone, Copy)]
enum DirLoc {
    /// FAT12/16 fixed root region.
    FixedRoot,
    /// A cluster chain starting at the given cluster.
    Cluster(u32),
}

/// A pure-Rust reader over a FAT12/16/32 volume.
pub struct FatFs<R> {
    inner: Mutex<R>,
    geom: Geometry,
    fat: Vec<u8>,
    max_clusters: usize,
}

impl<R: Read + Seek> FatFs<R> {
    /// Open a FAT volume, auto-detecting the variant from the boot sector.
    ///
    /// Fails loud if the boot sector is not a recognized FAT filesystem. (exFAT
    /// volumes are detected and rejected here until the exFAT unit lands.)
    pub fn open(mut reader: R) -> Result<Self> {
        let mut boot = [0u8; 512];
        read_exact_into(&mut reader, 0, &mut boot)?;

        if &boot[3..11] == b"EXFAT   " {
            return Err(FatError::NotFat(
                "exFAT volume (EXFAT signature at 0x03) — not yet supported by this reader".into(),
            ));
        }

        let geom = Geometry::parse(&boot)?;
        // Cache FAT1. Its size is bounded by the (validated) BPB but capped
        // against an absurd fat_size claim.
        let fat_bytes = u64::from(geom.fat_size_sectors) * u64::from(geom.bytes_per_sector);
        let fat_len = usize::try_from(fat_bytes.min(MAX_FAT_BYTES)).unwrap_or(0);
        let fat = read_upto(&mut reader, geom.fat_start, fat_len)?;
        let max_clusters = geom.count_of_clusters as usize + 2;

        Ok(FatFs {
            inner: Mutex::new(reader),
            geom,
            fat,
            max_clusters,
        })
    }

    /// The detected FAT variant.
    pub fn variant(&self) -> FatVariant {
        self.geom.variant
    }

    /// Resolved geometry (crate-internal; used by the vfs adapter).
    pub(crate) fn geometry(&self) -> &Geometry {
        &self.geom
    }

    /// Contiguous image byte runs backing node `id`'s data, merging physically
    /// adjacent clusters. The FAT12/16 fixed root is a single region run.
    pub(crate) fn runs(&self, id: FileId) -> Result<Vec<(u64, u64)>> {
        let (chain, total) = self.data_extent(id)?;
        if chain.is_empty() {
            return Ok(if total == 0 {
                Vec::new()
            } else {
                vec![(self.geom.root_dir_start, total)]
            });
        }
        let cluster_size = u64::from(self.geom.cluster_size);
        let mut runs: Vec<(u64, u64)> = Vec::new();
        let mut remaining = total;
        for &c in &chain {
            if remaining == 0 {
                break;
            }
            let Some(off) = self.geom.cluster_offset(c) else {
                break; // cov:unreachable: chain clusters are >= 2 by construction
            };
            let len = cluster_size.min(remaining);
            remaining -= len;
            match runs.last_mut() {
                Some(last) if last.0 + last.1 == off => last.1 += len,
                _ => runs.push((off, len)),
            }
        }
        Ok(runs)
    }

    /// The root directory handle.
    pub fn root(&self) -> FileId {
        FileId::Root
    }

    /// List the entries of the directory `id` (allocated and deleted).
    pub fn read_dir(&self, id: FileId) -> Result<Vec<Node>> {
        let loc = self.own_dirloc(id)?;
        let marker = loc_marker(loc);
        let bytes = self.read_dir_bytes(loc)?;
        Ok(parse_directory(&bytes)
            .into_iter()
            .map(|e| node_from(marker, e))
            .collect())
    }

    /// Resolve a single child of `dir` by name (allocated entries only).
    pub fn lookup(&self, dir: FileId, name: &[u8]) -> Result<Option<FileId>> {
        for node in self.read_dir(dir)? {
            if !node.is_deleted && !node.is_volume_label && node.name.as_bytes() == name {
                return Ok(Some(node.id));
            }
        }
        Ok(None)
    }

    /// Resolve metadata for `id`.
    pub fn meta(&self, id: FileId) -> Result<Node> {
        match id {
            FileId::Root => Ok(root_node()),
            FileId::Entry { .. } => self.resolve_entry(id),
        }
    }

    /// Read up to `buf.len()` bytes at byte offset `off` within node `id`.
    /// Returns the number of bytes read (0 at or past the end of the data).
    pub fn read_at(&self, id: FileId, off: u64, buf: &mut [u8]) -> Result<usize> {
        let (chain, total) = self.data_extent(id)?;
        if off >= total {
            return Ok(0);
        }
        let cluster_size = u64::from(self.geom.cluster_size);
        let end = off.saturating_add(buf.len() as u64).min(total);
        let mut pos = off;
        let mut written = 0usize;
        while pos < end {
            let ci = usize::try_from(pos / cluster_size).unwrap_or(usize::MAX);
            let Some(&cluster) = chain.get(ci) else {
                break; // chain shorter than the size field claims → stop, no panic
            };
            let Some(base) = self.geom.cluster_offset(cluster) else {
                break; // cov:unreachable: chain clusters are >= 2 by construction
            };
            let intra = pos % cluster_size;
            let avail = cluster_size - intra;
            let want = usize::try_from((end - pos).min(avail)).unwrap_or(0);
            let got = self.read_region(base + intra, &mut buf[written..written + want])?;
            if got == 0 {
                break; // truncated image
            }
            written += got;
            pos += got as u64;
        }
        Ok(written)
    }

    // ---- internals -------------------------------------------------------

    /// The [`DirLoc`] of the directory that `id` *is* (for enumerating it).
    fn own_dirloc(&self, id: FileId) -> Result<DirLoc> {
        match id {
            FileId::Root => Ok(if self.geom.variant == FatVariant::Fat32 {
                DirLoc::Cluster(self.geom.root_cluster)
            } else {
                DirLoc::FixedRoot
            }),
            FileId::Entry { .. } => {
                let node = self.resolve_entry(id)?;
                if !node.is_dir {
                    return Err(FatError::Corrupt(format!(
                        "{:?} is not a directory",
                        node.name
                    )));
                }
                Ok(DirLoc::Cluster(node.first_cluster))
            }
        }
    }

    /// Re-read the directory entry an [`FileId::Entry`] points at.
    fn resolve_entry(&self, id: FileId) -> Result<Node> {
        let FileId::Entry { dir_cluster, index } = id else {
            return Ok(root_node()); // cov:unreachable: callers pass Entry only
        };
        let loc = if dir_cluster == FIXED_ROOT {
            DirLoc::FixedRoot
        } else {
            DirLoc::Cluster(dir_cluster)
        };
        let bytes = self.read_dir_bytes(loc)?;
        parse_directory(&bytes)
            .into_iter()
            .find(|e| e.index == index)
            .map(|e| node_from(dir_cluster, e))
            .ok_or_else(|| FatError::Corrupt(format!("no directory entry at slot {index}")))
    }

    /// The cluster chain and total byte length backing `id`'s data.
    fn data_extent(&self, id: FileId) -> Result<(Vec<u32>, u64)> {
        match id {
            FileId::Root => match self.own_dirloc(id)? {
                DirLoc::FixedRoot => Ok((Vec::new(), u64::from(self.geom.root_dir_bytes))),
                DirLoc::Cluster(c) => {
                    let chain = self.chain(c);
                    let total = chain.len() as u64 * u64::from(self.geom.cluster_size);
                    Ok((chain, total))
                }
            },
            FileId::Entry { .. } => {
                let node = self.resolve_entry(id)?;
                if node.is_dir {
                    let chain = self.chain(node.first_cluster);
                    let total = chain.len() as u64 * u64::from(self.geom.cluster_size);
                    Ok((chain, total))
                } else {
                    Ok((self.chain(node.first_cluster), node.size))
                }
            }
        }
    }

    /// Read the raw bytes of a directory.
    fn read_dir_bytes(&self, loc: DirLoc) -> Result<Vec<u8>> {
        match loc {
            DirLoc::FixedRoot => {
                self.read_region_vec(self.geom.root_dir_start, self.geom.root_dir_bytes as usize)
            }
            DirLoc::Cluster(c) => {
                let cluster_size = self.geom.cluster_size as usize;
                let mut out = Vec::new();
                for cluster in self.chain(c) {
                    if out.len() >= MAX_DIR_BYTES {
                        break;
                    }
                    let Some(base) = self.geom.cluster_offset(cluster) else {
                        break; // cov:unreachable: chain clusters are >= 2
                    };
                    out.extend(self.read_region_vec(base, cluster_size)?);
                }
                Ok(out)
            }
        }
    }

    /// The (capped) cluster chain starting at `start`.
    fn chain(&self, start: u32) -> Vec<u32> {
        if start < 2 {
            return Vec::new();
        }
        follow_chain(&self.fat, self.geom.variant, start, self.max_clusters)
    }

    /// Read up to `buf.len()` bytes at `offset`, returning the count read.
    fn read_region(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| FatError::Corrupt("reader lock poisoned".into()))?;
        guard
            .seek(SeekFrom::Start(offset))
            .map_err(|e| FatError::io("seek", e))?;
        read_fill(&mut *guard, buf)
    }

    /// Read `len` bytes at `offset` into a fresh vector (short read tolerated).
    fn read_region_vec(&self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_region(offset, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

/// The marker `dir_cluster` for children enumerated under `loc`.
fn loc_marker(loc: DirLoc) -> u32 {
    match loc {
        DirLoc::FixedRoot => FIXED_ROOT,
        DirLoc::Cluster(c) => c,
    }
}

/// The synthetic root node.
fn root_node() -> Node {
    Node {
        id: FileId::Root,
        name: String::new(),
        short_name: String::new(),
        is_dir: true,
        is_deleted: false,
        is_volume_label: false,
        size: 0,
        attributes: crate::dirent::ATTR_DIRECTORY,
        first_cluster: 0,
        created: None,
        modified: None,
        accessed: None,
    }
}

/// Build a [`Node`] from a decoded directory entry under parent `marker`.
fn node_from(marker: u32, e: DirEntry) -> Node {
    Node {
        id: FileId::Entry {
            dir_cluster: marker,
            index: e.index,
        },
        name: e.name,
        short_name: e.short_name,
        is_dir: e.is_dir,
        is_deleted: e.deleted,
        is_volume_label: e.is_volume_label,
        size: u64::from(e.size),
        attributes: e.attributes,
        first_cluster: e.first_cluster,
        created: decode_time(e.created.0, e.created.1, e.created.2),
        modified: decode_time(e.modified.0, e.modified.1, 0),
        accessed: decode_time(e.accessed, 0, 0),
    }
}

/// Seek to `offset` and read exactly `buf.len()` bytes, failing loud on EOF.
fn read_exact_into<R: Read + Seek>(reader: &mut R, offset: u64, buf: &mut [u8]) -> Result<()> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| FatError::io("seek", e))?;
    reader
        .read_exact(buf)
        .map_err(|e| FatError::io("read boot sector", e))
}

/// Seek to `offset` and read up to `len` bytes (short read tolerated).
fn read_upto<R: Read + Seek>(reader: &mut R, offset: u64, len: usize) -> Result<Vec<u8>> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| FatError::io("seek", e))?;
    let mut buf = vec![0u8; len];
    let n = read_fill(reader, &mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// Fill `buf` as far as the reader allows, returning the byte count (a short
/// read at EOF is not an error — a truncated image degrades, never panics).
fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
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

#[cfg(test)]
mod tests {
    use super::FatFs;
    use crate::boot::FatVariant;
    use std::io::Cursor;

    /// Build a small but structurally-valid FAT32 image: 512 B sectors, 32
    /// reserved, 2 FATs of 512 sectors, root at cluster 2 with one file
    /// `TEST.TXT` at cluster 3. The claimed volume size yields > 65525 clusters
    /// (→ FAT32) while only the used clusters are physically backed.
    fn synth_fat32() -> Vec<u8> {
        let bps = 512usize;
        let reserved = 32usize;
        let fat_sectors = 512usize;
        let num_fats = 2usize;
        let data_start = (reserved + num_fats * fat_sectors) * bps; // cluster 2
        let mut img = vec![0u8; data_start + 4 * bps];

        // Boot sector / BPB.
        img[0] = 0xEB;
        img[2] = 0x90;
        img[11..13].copy_from_slice(&512u16.to_le_bytes());
        img[13] = 1; // sectors/cluster
        img[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        img[16] = num_fats as u8;
        img[32..36].copy_from_slice(&70000u32.to_le_bytes()); // total sectors 32
        img[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
        img[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        img[510] = 0x55;
        img[511] = 0xAA;

        // FAT1: cluster 2 (root) and cluster 3 (file) each end-of-chain.
        let fat = reserved * bps;
        img[fat + 8..fat + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        img[fat + 12..fat + 16].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());

        // Root directory (cluster 2): one short entry TEST.TXT → cluster 3, 9 B.
        let mut e = [0u8; 32];
        e[0..11].copy_from_slice(b"TEST    TXT");
        e[11] = 0x20;
        e[26..28].copy_from_slice(&3u16.to_le_bytes());
        e[28..32].copy_from_slice(&9u32.to_le_bytes());
        img[data_start..data_start + 32].copy_from_slice(&e);

        // File data (cluster 3).
        img[data_start + bps..data_start + bps + 9].copy_from_slice(b"hi fat32\n");
        img
    }

    #[test]
    fn opens_and_reads_synthetic_fat32() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        assert_eq!(fs.variant(), FatVariant::Fat32);

        let root = fs.root();
        let nodes = fs.read_dir(root).unwrap();
        let test = nodes.iter().find(|n| n.name == "TEST.TXT").unwrap();
        assert_eq!(test.size, 9);
        assert!(!test.is_dir);

        let id = fs.lookup(root, b"TEST.TXT").unwrap().unwrap();
        assert_eq!(fs.meta(id).unwrap().size, 9);

        let mut buf = vec![0u8; 16];
        let n = fs.read_at(id, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi fat32\n");
    }

    #[test]
    fn read_at_past_eof_returns_zero() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let id = fs.lookup(fs.root(), b"TEST.TXT").unwrap().unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(fs.read_at(id, 100, &mut buf).unwrap(), 0);
    }

    #[test]
    fn open_rejects_non_fat() {
        let img = vec![0u8; 1024];
        assert!(FatFs::open(Cursor::new(img)).is_err());
    }

    #[test]
    fn lookup_absent_name_is_none() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        assert!(fs.lookup(fs.root(), b"NOPE.TXT").unwrap().is_none());
    }
}
