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
#[allow(clippy::struct_excessive_bools)] // a metadata record, not a state machine
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
    /// Raw attribute bits (FAT 8-bit attr or exFAT 16-bit `FileAttributes`).
    pub attributes: u32,
    /// First cluster of the node's data (0 = empty).
    pub first_cluster: u32,
    /// Whether the data is contiguous (exFAT NoFatChain; always false on FAT).
    pub contiguous: bool,
    /// Decoded creation timestamp (local time), if set.
    pub created: Option<FatTimestamp>,
    /// Decoded last-modified timestamp (local time), if set.
    pub modified: Option<FatTimestamp>,
    /// Decoded last-access timestamp (date only; local time), if set.
    pub accessed: Option<FatTimestamp>,
}

/// Where a directory's raw bytes live.
#[derive(Clone, Copy)]
enum DirSource {
    /// FAT12/16 fixed root region.
    FixedRoot,
    /// A cluster extent (FAT32/exFAT root, or any subdirectory). `size == 0`
    /// means "follow the whole FAT chain" (FAT directories carry no size).
    Chain {
        first_cluster: u32,
        size: u64,
        contiguous: bool,
    },
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
    /// Fails loud if the boot sector is not a recognized FAT/exFAT filesystem.
    pub fn open(mut reader: R) -> Result<Self> {
        let mut boot = [0u8; 512];
        read_exact_into(&mut reader, 0, &mut boot)?;

        // exFAT is architecturally distinct but shares the cluster-offset math;
        // its boot parser yields a Geometry with variant ExFat.
        let geom = if &boot[3..11] == b"EXFAT   " {
            crate::exfat::parse_boot(&boot)?
        } else {
            Geometry::parse(&boot)?
        };
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

    /// The resolved on-disk volume geometry (variant, sector/cluster sizes, FAT
    /// layout, and byte offsets). Useful to a forensic consumer that needs the
    /// raw layout the reader computed.
    pub fn geometry(&self) -> &Geometry {
        &self.geom
    }

    /// Contiguous image byte runs `(offset, len)` backing node `id`'s data,
    /// merging physically adjacent clusters (the FAT12/16 fixed root is a single
    /// region run). Useful to a forensic consumer that needs the on-disk run
    /// list of a file or directory.
    pub fn runs(&self, id: FileId) -> Result<Vec<(u64, u64)>> {
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
        let source = self.dir_source(id)?;
        let marker = source_marker(source);
        let bytes = self.read_dir_bytes(source)?;
        Ok(self.list_nodes(&bytes, marker))
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

    /// Parse a directory's raw bytes into nodes, dispatching by variant.
    fn list_nodes(&self, bytes: &[u8], marker: u32) -> Vec<Node> {
        if self.geom.variant == FatVariant::ExFat {
            crate::exfat::parse_directory(bytes)
                .into_iter()
                .map(|e| node_from_exfat(marker, e))
                .collect()
        } else {
            parse_directory(bytes)
                .into_iter()
                .map(|e| node_from(marker, e))
                .collect()
        }
    }

    /// Where the directory that `id` *is* stores its bytes.
    fn dir_source(&self, id: FileId) -> Result<DirSource> {
        match id {
            FileId::Root => Ok(if self.root_is_clustered() {
                DirSource::Chain {
                    first_cluster: self.geom.root_cluster,
                    size: 0,
                    contiguous: false,
                }
            } else {
                DirSource::FixedRoot
            }),
            FileId::Entry { .. } => {
                let node = self.resolve_entry(id)?;
                if !node.is_dir {
                    return Err(FatError::Corrupt(format!(
                        "{:?} is not a directory",
                        node.name
                    )));
                }
                Ok(DirSource::Chain {
                    first_cluster: node.first_cluster,
                    size: node.size,
                    contiguous: node.contiguous,
                })
            }
        }
    }

    /// Whether the root directory lives in the cluster heap (FAT32/exFAT) rather
    /// than a fixed region (FAT12/16).
    fn root_is_clustered(&self) -> bool {
        matches!(self.geom.variant, FatVariant::Fat32 | FatVariant::ExFat)
    }

    /// Re-read the directory entry an [`FileId::Entry`] points at. The parent is
    /// read by following its FAT chain (correct for FAT and for single-cluster /
    /// chained exFAT directories).
    fn resolve_entry(&self, id: FileId) -> Result<Node> {
        let FileId::Entry { dir_cluster, index } = id else {
            return Ok(root_node()); // cov:unreachable: callers pass Entry only
        };
        let source = if dir_cluster == FIXED_ROOT {
            DirSource::FixedRoot
        } else {
            DirSource::Chain {
                first_cluster: dir_cluster,
                size: 0,
                contiguous: false,
            }
        };
        let bytes = self.read_dir_bytes(source)?;
        self.list_nodes(&bytes, dir_cluster)
            .into_iter()
            .find(|n| matches!(n.id, FileId::Entry { index: i, .. } if i == index))
            .ok_or_else(|| FatError::Corrupt(format!("no directory entry at slot {index}")))
    }

    /// The cluster chain and total byte length backing `id`'s data.
    fn data_extent(&self, id: FileId) -> Result<(Vec<u32>, u64)> {
        match id {
            FileId::Root => match self.dir_source(id)? {
                DirSource::FixedRoot => Ok((Vec::new(), u64::from(self.geom.root_dir_bytes))),
                DirSource::Chain {
                    first_cluster,
                    size,
                    contiguous,
                } => Ok(self.extent_of(first_cluster, size, contiguous)),
            },
            FileId::Entry { .. } => {
                let node = self.resolve_entry(id)?;
                Ok(self.extent_of(node.first_cluster, node.size, node.contiguous))
            }
        }
    }

    /// The cluster list and total byte length for `(first_cluster, size,
    /// contiguous)`. A `0` size (FAT directories) is taken as the full chain.
    fn extent_of(&self, first_cluster: u32, size: u64, contiguous: bool) -> (Vec<u32>, u64) {
        let clusters = self.clusters(first_cluster, size, contiguous);
        let total = if size > 0 {
            size
        } else {
            clusters.len() as u64 * u64::from(self.geom.cluster_size)
        };
        (clusters, total)
    }

    /// Resolve the cluster list. A contiguous (exFAT NoFatChain) extent is a
    /// sequential run sized from `size`; otherwise the FAT chain is followed.
    fn clusters(&self, first_cluster: u32, size: u64, contiguous: bool) -> Vec<u32> {
        if first_cluster < 2 {
            return Vec::new();
        }
        if contiguous && size > 0 {
            let cluster_size = u64::from(self.geom.cluster_size);
            let n = usize::try_from(size.div_ceil(cluster_size)).unwrap_or(0);
            let last = u64::from(first_cluster) + n as u64;
            (u64::from(first_cluster)..last)
                .take(self.max_clusters)
                .filter_map(|c| u32::try_from(c).ok())
                .collect()
        } else {
            follow_chain(
                &self.fat,
                self.geom.variant,
                first_cluster,
                self.max_clusters,
            )
        }
    }

    /// Read the raw bytes of a directory.
    fn read_dir_bytes(&self, source: DirSource) -> Result<Vec<u8>> {
        let (first_cluster, size, contiguous) = match source {
            DirSource::FixedRoot => {
                return self
                    .read_region_vec(self.geom.root_dir_start, self.geom.root_dir_bytes as usize);
            }
            DirSource::Chain {
                first_cluster,
                size,
                contiguous,
            } => (first_cluster, size, contiguous),
        };
        let cluster_size = self.geom.cluster_size as usize;
        let mut out = Vec::new();
        for cluster in self.clusters(first_cluster, size, contiguous) {
            if out.len() >= MAX_DIR_BYTES {
                break; // cov:unreachable: a real directory chain is far under 64 MiB
            }
            let Some(base) = self.geom.cluster_offset(cluster) else {
                break; // cov:unreachable: chain clusters are >= 2
            };
            out.extend(self.read_region_vec(base, cluster_size)?);
        }
        Ok(out)
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

/// The marker `dir_cluster` for children enumerated under `source`.
fn source_marker(source: DirSource) -> u32 {
    match source {
        DirSource::FixedRoot => FIXED_ROOT,
        DirSource::Chain { first_cluster, .. } => first_cluster,
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
        attributes: u32::from(crate::dirent::ATTR_DIRECTORY),
        first_cluster: 0,
        contiguous: false,
        created: None,
        modified: None,
        accessed: None,
    }
}

/// Build a [`Node`] from a decoded FAT directory entry under parent `marker`.
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
        attributes: u32::from(e.attributes),
        first_cluster: e.first_cluster,
        contiguous: false,
        created: decode_time(e.created.0, e.created.1, e.created.2),
        modified: decode_time(e.modified.0, e.modified.1, 0),
        accessed: decode_time(e.accessed, 0, 0),
    }
}

/// Build a [`Node`] from a decoded exFAT directory entry set under `marker`.
fn node_from_exfat(marker: u32, e: crate::exfat::ExfatDirEntry) -> Node {
    Node {
        id: FileId::Entry {
            dir_cluster: marker,
            index: e.index,
        },
        short_name: e.name.clone(),
        name: e.name,
        is_dir: e.is_dir,
        is_deleted: e.deleted,
        is_volume_label: false,
        size: e.size,
        attributes: u32::from(e.attributes),
        first_cluster: e.first_cluster,
        contiguous: e.contiguous,
        created: e.created,
        modified: e.modified,
        accessed: e.accessed,
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
            // cov:unreachable: EINTR retry — in-memory/file readers never raise it
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FatError::io("read", e)),
        }
    }
    Ok(filled)
}

/// Build a small but structurally-valid FAT32 image: 512 B sectors, 32
/// reserved, 2 FATs of 512 sectors, root at cluster 2 with a handful of files
/// (`TEST`, `BIG` 2-cluster, `TRUNC`, `EOF`, `ZERO`, `HALF`, a deleted `GONE`).
/// The claimed volume size yields > 65525 clusters (→ FAT32) while only the
/// used clusters are physically backed. Shared by the fs and vfs test modules.
#[cfg(test)]
pub(crate) fn synth_fat32() -> Vec<u8> {
    {
        let bps = 512usize;
        let reserved = 32usize;
        let fat_sectors = 512usize;
        let num_fats = 2usize;
        let data_start = (reserved + num_fats * fat_sectors) * bps; // cluster 2
        let mut img = vec![0u8; data_start + 8 * bps]; // clusters 2..=9 backed

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

        // FAT1 (cluster N entry at byte offset N*4). EOC = 0x0FFFFFFF.
        let fat = reserved * bps;
        let eoc = 0x0FFF_FFFFu32.to_le_bytes();
        let put = |img: &mut [u8], c: usize, v: [u8; 4]| {
            img[fat + c * 4..fat + c * 4 + 4].copy_from_slice(&v);
        };
        put(&mut img, 2, eoc); // root
        put(&mut img, 3, eoc); // TEST.TXT
        put(&mut img, 4, 5u32.to_le_bytes()); // BIG.TXT: 4 -> 5
        put(&mut img, 5, eoc);
        put(&mut img, 6, eoc); // TRUNC.TXT (claims more than its chain)
        put(&mut img, 7, 8u32.to_le_bytes()); // HALF.TXT: 7 -> 8 (chain longer than size)
        put(&mut img, 8, eoc);
        put(&mut img, 10, eoc); // EOF.TXT (cluster beyond the image)

        // Root directory (cluster 2): four short entries.
        let entry = |name: &[u8; 11], cluster: u16, size: u32| {
            let mut e = [0u8; 32];
            e[0..11].copy_from_slice(name);
            e[11] = 0x20;
            e[26..28].copy_from_slice(&cluster.to_le_bytes());
            e[28..32].copy_from_slice(&size.to_le_bytes());
            e
        };
        let root = data_start;
        img[root..root + 32].copy_from_slice(&entry(b"TEST    TXT", 3, 9));
        img[root + 32..root + 64].copy_from_slice(&entry(b"BIG     TXT", 4, 600));
        img[root + 64..root + 96].copy_from_slice(&entry(b"TRUNC   TXT", 6, 2000));
        img[root + 96..root + 128].copy_from_slice(&entry(b"EOF     TXT", 10, 512));
        img[root + 128..root + 160].copy_from_slice(&entry(b"ZERO    TXT", 0, 0)); // empty
        img[root + 160..root + 192].copy_from_slice(&entry(b"HALF    TXT", 7, 512)); // 512 B, 2-cluster chain
        let mut del = entry(b"GONE    TXT", 3, 9);
        del[0] = 0xE5; // deleted
        img[root + 192..root + 224].copy_from_slice(&del);

        // File data.
        img[data_start + bps..data_start + bps + 9].copy_from_slice(b"hi fat32\n"); // cluster 3
        for i in 0..600 {
            img[data_start + 2 * bps + i] = (i % 251) as u8; // BIG.TXT spans clusters 4,5
        }
        img
    }
}

#[cfg(test)]
mod tests {
    use super::{synth_fat32, FatFs};
    use crate::boot::FatVariant;
    use std::io::Cursor;

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

    #[test]
    fn reads_multi_cluster_file_across_boundary() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let id = fs.lookup(fs.root(), b"BIG.TXT").unwrap().unwrap();
        assert_eq!(fs.meta(id).unwrap().size, 600);
        let mut buf = vec![0u8; 600];
        assert_eq!(fs.read_at(id, 0, &mut buf).unwrap(), 600);
        for (i, &b) in buf.iter().enumerate() {
            assert_eq!(b, (i % 251) as u8);
        }
        // Two physically-adjacent clusters (4,5) merge into one run.
        let runs = fs.runs(id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].1, 600);
    }

    #[test]
    fn empty_file_has_no_runs() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let id = fs.lookup(fs.root(), b"ZERO.TXT").unwrap().unwrap();
        assert_eq!(fs.meta(id).unwrap().size, 0);
        assert!(fs.runs(id).unwrap().is_empty());
        let mut buf = [0u8; 4];
        assert_eq!(fs.read_at(id, 0, &mut buf).unwrap(), 0);
    }

    #[test]
    fn read_stops_when_chain_shorter_than_size() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let id = fs.lookup(fs.root(), b"TRUNC.TXT").unwrap().unwrap();
        // size claims 2000 B (4 clusters) but the chain is one cluster.
        let mut buf = vec![0u8; 2000];
        assert_eq!(fs.read_at(id, 0, &mut buf).unwrap(), 512);
    }

    #[test]
    fn read_stops_at_truncated_image() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let id = fs.lookup(fs.root(), b"EOF.TXT").unwrap().unwrap();
        // cluster 10 lies beyond the backing image → 0 bytes, no panic.
        let mut buf = vec![0u8; 512];
        assert_eq!(fs.read_at(id, 0, &mut buf).unwrap(), 0);
    }

    #[test]
    fn meta_of_root_is_a_directory() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let m = fs.meta(fs.root()).unwrap();
        assert!(m.is_dir);
        assert_eq!(m.size, 0);
    }

    #[test]
    fn read_dir_of_a_file_errs() {
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let id = fs.lookup(fs.root(), b"TEST.TXT").unwrap().unwrap();
        assert!(fs.read_dir(id).is_err());
    }

    #[test]
    fn size_smaller_than_chain_bounds_the_last_run() {
        // HALF.TXT: 512-byte size but a two-cluster chain (7 -> 8).
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let id = fs.lookup(fs.root(), b"HALF.TXT").unwrap().unwrap();
        let runs = fs.runs(id).unwrap();
        assert_eq!(runs.iter().map(|r| r.1).sum::<u64>(), 512);
    }

    #[test]
    fn runs_of_clustered_root() {
        // data_extent(Root) on a clustered (FAT32) root.
        let fs = FatFs::open(Cursor::new(synth_fat32())).unwrap();
        let runs = fs.runs(fs.root()).unwrap();
        assert!(!runs.is_empty());
    }

    #[test]
    fn read_error_mid_stream_surfaces_loud() {
        // A reader that serves the boot + FAT (offsets < data_start) but fails
        // on data reads, so read_fill returns a loud I/O error.
        struct DataFails {
            img: Vec<u8>,
            pos: u64,
            data_start: u64,
        }
        impl std::io::Read for DataFails {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data_start {
                    return Err(std::io::Error::other("data read blocked"));
                }
                let start = self.pos as usize;
                let n = buf.len().min(self.img.len().saturating_sub(start));
                buf[..n].copy_from_slice(&self.img[start..start + n]);
                self.pos += n as u64;
                Ok(n)
            }
        }
        impl std::io::Seek for DataFails {
            fn seek(&mut self, from: std::io::SeekFrom) -> std::io::Result<u64> {
                if let std::io::SeekFrom::Start(p) = from {
                    self.pos = p;
                }
                Ok(self.pos)
            }
        }
        let img = synth_fat32();
        let data_start = (32 + 2 * 512) * 512;
        let reader = DataFails {
            img,
            pos: 0,
            data_start,
        };
        let fs = FatFs::open(reader).unwrap(); // boot + FAT are before data_start
        assert!(matches!(
            fs.read_dir(fs.root()),
            Err(crate::FatError::Io { .. })
        ));
    }

    #[test]
    fn io_error_surfaces_loud() {
        struct Failing;
        impl std::io::Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        impl std::io::Seek for Failing {
            fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }
        assert!(matches!(
            FatFs::open(Failing),
            Err(crate::FatError::Io { .. })
        ));
    }
}
