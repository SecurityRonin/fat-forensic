//! [`FatFs`] — the unified reader. [`FatFs::open`] auto-detects FAT12/16/32
//! (exFAT is wired in a later unit), then serves uniform navigation: `root`,
//! `read_dir`, `lookup`, `meta`, `read_at`.

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
