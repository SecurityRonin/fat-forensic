//! `impl forensic_vfs::FileSystem for FatFs` — the forensic-vfs adapter
//! (behind the `vfs` feature).
//!
//! FAT nodes are addressed by [`forensic_vfs::FileId::FatDirEntry`] (parent
//! cluster + slot); the volume root maps to `cluster 0, index 0`. Times are
//! volume-local (`TimeZonePolicy::LocalUnknown`), and every fallible fat-core
//! call is translated to a typed [`VfsError`] — never a panic.

#[cfg(test)]
mod tests {
    use crate::FatFs;
    use forensic_vfs::{FileSystem, FsKind, NodeKind, StreamId, TimeZonePolicy};
    use std::io::Cursor;

    fn fs() -> FatFs<Cursor<Vec<u8>>> {
        let img = include_bytes!("../../tests/data/fat12.img").to_vec();
        FatFs::open(Cursor::new(img)).unwrap()
    }

    #[test]
    fn kind_and_zone() {
        let fs = fs();
        assert_eq!(fs.kind(), FsKind::Fat);
        assert_eq!(fs.timestamp_zone(), TimeZonePolicy::LocalUnknown);
    }

    #[test]
    fn root_lists_known_entries() {
        let fs = fs();
        let names: Vec<String> = fs
            .read_dir(fs.root())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "HELLO.TXT"));
        assert!(names.iter().any(|n| n == "subdir"));
    }

    #[test]
    fn lookup_meta_read_extents() {
        let fs = fs();
        let id = fs.lookup(fs.root(), b"HELLO.TXT").unwrap().unwrap();
        let m = fs.meta(id).unwrap();
        assert_eq!(m.size, 17);
        assert_eq!(m.kind, NodeKind::File);
        assert!(m.times.modified.is_some());

        let mut buf = vec![0u8; 17];
        let n = fs.read_at(id, StreamId::Default, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello from FAT12\n");

        let runs: Vec<_> = fs
            .extents(id, StreamId::Default)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(!runs.is_empty());
        assert!(runs[0].run.len >= 1);
    }

    #[test]
    fn nested_dir_navigable() {
        let fs = fs();
        let sub = fs.lookup(fs.root(), b"subdir").unwrap().unwrap();
        assert_eq!(fs.meta(sub).unwrap().kind, NodeKind::Dir);
        let nested = fs.lookup(sub, b"NESTED.TXT").unwrap().unwrap();
        assert_eq!(fs.meta(nested).unwrap().size, 23);
    }

    #[test]
    fn sector_sizes_reported() {
        let s = fs().sector_sizes();
        assert_eq!(s.logical, 512);
        assert_eq!(s.cluster_or_block, 512);
    }

    #[test]
    fn deleted_unalloc_readlink_are_empty() {
        let fs = fs();
        assert_eq!(fs.deleted().unwrap().count(), 0);
        assert_eq!(fs.unallocated().unwrap().count(), 0);
        assert_eq!(fs.read_link(fs.root(), 4096).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unsupported_stream_is_refused() {
        let fs = fs();
        let id = fs.lookup(fs.root(), b"HELLO.TXT").unwrap().unwrap();
        assert!(fs.read_at(id, StreamId::Slack, 0, &mut [0u8; 4]).is_err());
        assert!(fs.extents(id, StreamId::Named(1)).is_err());
    }
}
