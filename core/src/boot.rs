//! FAT12/16/32 boot sector (BIOS Parameter Block) parse, geometry, and the
//! cluster-count FAT-type decision (fatgen103 §3.5): `< 4085` → FAT12,
//! `< 65525` → FAT16, else FAT32.

#[cfg(test)]
mod tests {
    use super::{FatVariant, Geometry};

    /// A classic 1.44 MiB floppy BPB: 512 B/sector, 1 sector/cluster,
    /// 1 reserved, 2 FATs of 9 sectors, 224 root entries, 2880 total sectors.
    fn fat12_boot() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x3C;
        b[2] = 0x90;
        b[11..13].copy_from_slice(&512u16.to_le_bytes()); // bytes/sector
        b[13] = 1; // sectors/cluster
        b[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved
        b[16] = 2; // num FATs
        b[17..19].copy_from_slice(&224u16.to_le_bytes()); // root entries
        b[19..21].copy_from_slice(&2880u16.to_le_bytes()); // total sectors 16
        b[22..24].copy_from_slice(&9u16.to_le_bytes()); // FAT size 16
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    /// A minimal FAT32 BPB: 512 B/sector, 1 sector/cluster, 32 reserved,
    /// 2 FATs of 512 sectors, 0 root entries, root cluster 2, 70000 sectors.
    fn fat32_boot() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[2] = 0x90;
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 1;
        b[14..16].copy_from_slice(&32u16.to_le_bytes());
        b[16] = 2;
        b[17..19].copy_from_slice(&0u16.to_le_bytes());
        b[19..21].copy_from_slice(&0u16.to_le_bytes()); // total16 = 0 → use total32
        b[22..24].copy_from_slice(&0u16.to_le_bytes()); // fat16 = 0 → use fat32
        b[32..36].copy_from_slice(&70000u32.to_le_bytes()); // total sectors 32
        b[36..40].copy_from_slice(&512u32.to_le_bytes()); // FAT size 32
        b[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    #[test]
    fn detects_fat12_geometry() {
        let g = Geometry::parse(&fat12_boot()).unwrap();
        assert_eq!(g.variant, FatVariant::Fat12);
        assert_eq!(g.bytes_per_sector, 512);
        assert_eq!(g.sectors_per_cluster, 1);
        assert_eq!(g.cluster_size, 512);
        // root_dir_sectors = (224*32+511)/512 = 14; data = 2880-(1+18+14)=2847
        assert_eq!(g.count_of_clusters, 2847);
        assert_eq!(g.fat_start, 512);
        assert_eq!(g.root_dir_start, 19 * 512);
        assert_eq!(g.root_dir_bytes, 14 * 512);
        assert_eq!(g.data_start, 33 * 512);
    }

    #[test]
    fn detects_fat32_geometry() {
        let g = Geometry::parse(&fat32_boot()).unwrap();
        assert_eq!(g.variant, FatVariant::Fat32);
        assert_eq!(g.root_entry_count, 0);
        assert_eq!(g.root_cluster, 2);
        assert_eq!(g.root_dir_bytes, 0);
        // data = 70000 - (32 + 2*512 + 0) = 68944 clusters (>= 65525 → FAT32)
        assert_eq!(g.count_of_clusters, 68944);
        assert_eq!(g.data_start, (32 + 1024) * 512);
    }

    #[test]
    fn detects_fat16_boundary() {
        // 5000 clusters → FAT16 (>= 4085, < 65525)
        let mut b = fat12_boot();
        b[17..19].copy_from_slice(&0u16.to_le_bytes()); // no root region for simplicity
        b[19..21].copy_from_slice(&0u16.to_le_bytes());
        b[32..36].copy_from_slice(&5033u32.to_le_bytes()); // total32
        b[22..24].copy_from_slice(&0u16.to_le_bytes());
        b[36..40].copy_from_slice(&16u32.to_le_bytes()); // fat32 slot as fat_size fallback
                                                         // total = 5033, reserved 1, 2 FATs*16 = 32, root 0 → data 5000 → FAT16
        let g = Geometry::parse(&b).unwrap();
        assert_eq!(g.variant, FatVariant::Fat16);
        assert_eq!(g.count_of_clusters, 5000);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut b = fat12_boot();
        b[510] = 0x00;
        let e = Geometry::parse(&b).unwrap_err();
        assert!(format!("{e}").contains("55")); // reports the offending signature
    }

    #[test]
    fn rejects_non_power_of_two_sector() {
        let mut b = fat12_boot();
        b[11..13].copy_from_slice(&513u16.to_le_bytes());
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_zero_fats() {
        let mut b = fat12_boot();
        b[16] = 0;
        assert!(Geometry::parse(&b).is_err());
    }

    #[test]
    fn rejects_oversize_reserved_region() {
        // reserved region larger than the volume → data underflow, must fail loud
        let mut b = fat12_boot();
        b[14..16].copy_from_slice(&9000u16.to_le_bytes());
        assert!(Geometry::parse(&b).is_err());
    }
}
