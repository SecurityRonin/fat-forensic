//! `impl forensic_vfs::FileSystem for FatFs` — the forensic-vfs adapter
//! (behind the `vfs` feature).
//!
//! FAT nodes are addressed by [`forensic_vfs::FileId::FatDirEntry`] (parent
//! cluster + slot); the volume root maps to `cluster 0, index 0`. Times are
//! volume-local (`TimeZonePolicy::LocalUnknown`), and every fallible fat-core
//! call is translated to a typed [`VfsError`] — never a panic.

use std::io::{Read, Seek};

use forensic_vfs::{
    Allocation, ByteRun, DirEntry, DirStream, ExtentStream, FileId as VfsId, FileSystem, FsKind,
    FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo,
    SectorSizes, SmallHex, StreamId, TimeResolution, TimeSource, TimeStamp, TimeZonePolicy,
    VfsError, VfsResult,
};

use crate::boot::FatVariant;
use crate::error::FatError;
use crate::fs::{FatFs, FileId, Node};
use crate::time::FatTimestamp;

/// Map a fat-core [`FileId`] to the VFS [`FatDirEntry`](VfsId::FatDirEntry)
/// address. The root becomes `cluster 0, index 0` (cluster 0 is never a valid
/// parent, so the mapping is unambiguous).
fn to_vfs_id(id: FileId) -> VfsId {
    match id {
        FileId::Root => VfsId::FatDirEntry {
            cluster: 0,
            index: 0,
        },
        FileId::Entry { dir_cluster, index } => VfsId::FatDirEntry {
            cluster: dir_cluster,
            index,
        },
    }
}

/// Map a VFS address back to a fat-core [`FileId`]. Any non-FAT identity is a
/// caller error, surfaced loud.
fn from_vfs_id(id: VfsId) -> VfsResult<FileId> {
    match id {
        VfsId::FatDirEntry {
            cluster: 0,
            index: 0,
        } => Ok(FileId::Root),
        VfsId::FatDirEntry { cluster, index } => Ok(FileId::Entry {
            dir_cluster: cluster,
            index,
        }),
        other => Err(VfsError::Unsupported {
            layer: "fat file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Only the default data stream exists on FAT; any other stream id is refused
/// loud rather than silently read as the default.
fn require_default(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "fat stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Translate a fat-core error into the VFS error type (I/O kept distinct from a
/// structural decode failure).
fn map_err(e: FatError) -> VfsError {
    match e {
        FatError::Io { op, source } => VfsError::Io { op, source },
        other => VfsError::Decode {
            layer: "fat",
            offset: 0,
            detail: other.to_string(),
            bytes: SmallHex::new(&[]),
        },
    }
}

/// A synthetic metadata address from the physical directory-entry location.
fn ino_of(id: FileId) -> u64 {
    match id {
        FileId::Root => 0,
        FileId::Entry { dir_cluster, index } => (u64::from(dir_cluster) << 16) | u64::from(index),
    }
}

/// Convert a decoded FAT timestamp to a VFS [`TimeStamp`] with FAT provenance.
fn to_ts(ts: FatTimestamp, resolution: TimeResolution) -> TimeStamp {
    TimeStamp {
        unix_nanos: i128::from(ts.unix_seconds) * 1_000_000_000 + i128::from(ts.subsec_nanos),
        source: TimeSource::DirEntry,
        resolution,
    }
}

impl<R: Read + Seek + Send> FileSystem for FatFs<R> {
    fn kind(&self) -> FsKind {
        match self.variant() {
            FatVariant::ExFat => FsKind::ExFat,
            _ => FsKind::Fat,
        }
    }

    fn root(&self) -> VfsId {
        to_vfs_id(self.root())
    }

    fn sector_sizes(&self) -> SectorSizes {
        let g = self.geometry();
        SectorSizes {
            logical: g.bytes_per_sector,
            physical: g.bytes_per_sector,
            cluster_or_block: g.cluster_size,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        // FAT/exFAT store wall-clock local time with no recorded zone.
        TimeZonePolicy::LocalUnknown
    }

    fn read_dir(&self, ino: VfsId) -> VfsResult<DirStream> {
        let id = from_vfs_id(ino)?;
        let nodes = self.read_dir(id).map_err(map_err)?;
        let out: Vec<VfsResult<DirEntry>> = nodes
            .into_iter()
            .filter(|n| !n.is_deleted && !n.is_volume_label && n.name != "." && n.name != "..")
            .map(|n| {
                Ok(DirEntry {
                    name: n.name.clone().into_bytes(),
                    id: to_vfs_id(n.id),
                    kind: node_kind(&n),
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: VfsId, stream: StreamId) -> VfsResult<ExtentStream> {
        require_default(stream)?;
        let id = from_vfs_id(ino)?;
        let runs = self.runs(id).map_err(map_err)?;
        let out: Vec<VfsResult<RunInfo>> = runs
            .into_iter()
            .map(|(offset, len)| {
                Ok(RunInfo {
                    run: ByteRun {
                        image_offset: offset,
                        len,
                        flags: RunFlags::default(),
                    },
                    alloc: RunAlloc::Allocated,
                })
            })
            .collect();
        Ok(ExtentStream::new(out.into_iter()))
    }

    fn lookup(&self, parent: VfsId, name: &[u8]) -> VfsResult<Option<VfsId>> {
        let id = from_vfs_id(parent)?;
        Ok(self.lookup(id, name).map_err(map_err)?.map(to_vfs_id))
    }

    fn meta(&self, ino: VfsId) -> VfsResult<FsMeta> {
        let id = from_vfs_id(ino)?;
        let node = self.meta(id).map_err(map_err)?;
        Ok(build_meta(id, &node))
    }

    fn read_at(&self, ino: VfsId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        require_default(stream)?;
        let id = from_vfs_id(ino)?;
        self.read_at(id, off, buf).map_err(map_err)
    }

    fn read_link(&self, _ino: VfsId, _cap: usize) -> VfsResult<Vec<u8>> {
        // FAT/exFAT have no symlinks; a node reads as an empty target.
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // Recursive deleted-entry carving is a follow-up; the default surface is
        // an empty stream, never a bootstrap failure.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

/// The VFS node kind for a fat-core node.
fn node_kind(n: &Node) -> NodeKind {
    if n.is_dir {
        NodeKind::Dir
    } else {
        NodeKind::File
    }
}

/// Assemble the unified [`FsMeta`] for a resolved node.
fn build_meta(id: FileId, node: &Node) -> FsMeta {
    let times = MacbTimes {
        modified: node.modified.map(|t| to_ts(t, TimeResolution::TwoSeconds)),
        accessed: node.accessed.map(|t| to_ts(t, TimeResolution::Seconds)),
        changed: None,
        born: node.created.map(|t| to_ts(t, TimeResolution::Seconds)),
    };
    FsMeta {
        ino: ino_of(id),
        kind: node_kind(node),
        allocated: if node.is_deleted {
            Allocation::Deleted
        } else {
            Allocation::Allocated
        },
        size: node.size,
        nlink: 1,
        uid: None,
        gid: None,
        mode: None,
        times,
        streams: Vec::new(),
        residency: ResidencyKind::NonResident,
        link_target: None,
    }
}

#[cfg(test)]
mod tests {
    use crate::FatFs;
    use forensic_vfs::{FileSystem, FsKind, NodeKind, StreamId, TimeZonePolicy};
    use std::io::Cursor;

    fn open() -> FatFs<Cursor<Vec<u8>>> {
        let img = include_bytes!("../../tests/data/fat12.img").to_vec();
        FatFs::open(Cursor::new(img)).unwrap()
    }

    #[test]
    fn kind_and_zone() {
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        assert_eq!(vfs.kind(), FsKind::Fat);
        assert_eq!(vfs.timestamp_zone(), TimeZonePolicy::LocalUnknown);
    }

    #[test]
    fn exfat_reports_exfat_kind() {
        let img = include_bytes!("../../tests/data/exfat.img").to_vec();
        let fs = FatFs::open(Cursor::new(img)).unwrap();
        let vfs: &dyn FileSystem = &fs;
        assert_eq!(vfs.kind(), FsKind::ExFat);
        let id = vfs.lookup(vfs.root(), b"HELLO.TXT").unwrap().unwrap();
        let mut buf = vec![0u8; 17];
        let n = vfs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello from exFAT\n");
    }

    #[test]
    fn root_lists_known_entries() {
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let names: Vec<String> = vfs
            .read_dir(vfs.root())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "HELLO.TXT"));
        assert!(names.iter().any(|n| n == "subdir"));
    }

    #[test]
    fn lookup_meta_read_extents() {
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let id = vfs.lookup(vfs.root(), b"HELLO.TXT").unwrap().unwrap();
        let m = vfs.meta(id).unwrap();
        assert_eq!(m.size, 17);
        assert_eq!(m.kind, NodeKind::File);
        assert!(m.times.modified.is_some());

        let mut buf = vec![0u8; 17];
        let n = vfs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello from FAT12\n");

        let runs: Vec<_> = vfs
            .extents(id, StreamId::Default)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(!runs.is_empty());
        assert!(runs[0].run.len >= 1);
    }

    #[test]
    fn nested_dir_navigable() {
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let sub = vfs.lookup(vfs.root(), b"subdir").unwrap().unwrap();
        assert_eq!(vfs.meta(sub).unwrap().kind, NodeKind::Dir);
        let nested = vfs.lookup(sub, b"NESTED.TXT").unwrap().unwrap();
        assert_eq!(vfs.meta(nested).unwrap().size, 23);
    }

    #[test]
    fn extents_of_fixed_root_region() {
        // The FAT12/16 fixed root is a single contiguous region run.
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let runs: Vec<_> = vfs
            .extents(vfs.root(), StreamId::Default)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert_eq!(runs.len(), 1);
        assert!(runs[0].run.len > 0);
    }

    #[test]
    fn sector_sizes_reported() {
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let s = vfs.sector_sizes();
        assert_eq!(s.logical, 512);
        assert_eq!(s.cluster_or_block, 512);
    }

    #[test]
    fn deleted_unalloc_readlink_are_empty() {
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        assert_eq!(vfs.deleted().unwrap().count(), 0);
        assert_eq!(vfs.unallocated().unwrap().count(), 0);
        assert_eq!(vfs.read_link(vfs.root(), 4096).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unsupported_stream_is_refused() {
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let id = vfs.lookup(vfs.root(), b"HELLO.TXT").unwrap().unwrap();
        assert!(vfs.read_at(id, StreamId::Slack, 0, &mut [0u8; 4]).is_err());
        assert!(vfs.extents(id, StreamId::Named(1)).is_err());
    }

    #[test]
    fn foreign_file_id_is_refused() {
        use forensic_vfs::FileId as VfsId;
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let foreign = VfsId::NtfsRef { entry: 5, seq: 1 };
        assert!(vfs.read_dir(foreign).is_err());
        assert!(vfs.meta(foreign).is_err());
    }

    #[test]
    fn error_maps_through_adapter() {
        use forensic_vfs::{Allocation, FileId as VfsId};
        // A structural error (read_dir on a file) maps to VfsError::Decode.
        let fs = open();
        let vfs: &dyn FileSystem = &fs;
        let file = vfs.lookup(vfs.root(), b"HELLO.TXT").unwrap().unwrap();
        assert!(vfs.read_dir(file).is_err());
        // meta on the root reports ino 0 and Allocated.
        let m = vfs.meta(vfs.root()).unwrap();
        assert_eq!(m.ino, 0);

        // A deleted node (synthetic FAT32) maps to Allocation::Deleted.
        let synth = crate::fs::synth_fat32();
        let dfs = FatFs::open(Cursor::new(synth)).unwrap();
        let dvfs: &dyn FileSystem = &dfs;
        // GONE.TXT is the deleted entry at slot 6 under the clustered root (cluster 2).
        let deleted = VfsId::FatDirEntry {
            cluster: 2,
            index: 6,
        };
        assert_eq!(dvfs.meta(deleted).unwrap().allocated, Allocation::Deleted);
    }

    #[test]
    fn io_error_maps_to_vfs_io() {
        // A reader that opens (boot + FAT) but fails on data reads → VfsError::Io.
        struct DataFails {
            img: Vec<u8>,
            pos: u64,
            data_start: u64,
        }
        impl std::io::Read for DataFails {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.pos >= self.data_start {
                    return Err(std::io::Error::other("blocked"));
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
        let reader = DataFails {
            img: crate::fs::synth_fat32(),
            pos: 0,
            data_start: (32 + 2 * 512) * 512,
        };
        let fs = FatFs::open(reader).unwrap();
        let vfs: &dyn FileSystem = &fs;
        assert!(matches!(
            vfs.read_dir(vfs.root()),
            Err(forensic_vfs::VfsError::Io { .. })
        ));
    }
}
