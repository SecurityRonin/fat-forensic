//! exFAT reader primitives: the main boot-sector parse, the boot-region
//! checksum ([MS] §3.4), and the typed 32-byte directory-entry-set decode
//! (File 0x85 + Stream Extension 0xC0 + File Name 0xC1).
//!
//! exFAT is architecturally distinct from FAT12/16/32: the allocation bitmap —
//! not the FAT — records cluster allocation, contiguous files set a NoFatChain
//! flag and skip the FAT entirely, and names are UTF-16 across File Name
//! entries rather than 8.3 + VFAT.

#[cfg(test)]
mod tests {
    use super::{boot_checksum, parse_boot};
    use crate::boot::FatVariant;

    fn synth_boot() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[0] = 0xEB;
        b[1] = 0x76;
        b[2] = 0x90;
        b[3..11].copy_from_slice(b"EXFAT   ");
        b[80..84].copy_from_slice(&24u32.to_le_bytes()); // FatOffset (sectors)
        b[84..88].copy_from_slice(&8u32.to_le_bytes()); // FatLength
        b[88..92].copy_from_slice(&32u32.to_le_bytes()); // ClusterHeapOffset
        b[92..96].copy_from_slice(&100u32.to_le_bytes()); // ClusterCount
        b[96..100].copy_from_slice(&5u32.to_le_bytes()); // root cluster
        b[108] = 9; // BytesPerSectorShift → 512
        b[109] = 3; // SectorsPerClusterShift → 8 sectors → 4096-byte cluster
        b[110] = 1; // NumberOfFats
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    #[test]
    fn parses_exfat_geometry() {
        let g = parse_boot(&synth_boot()).unwrap();
        assert_eq!(g.variant, FatVariant::ExFat);
        assert_eq!(g.bytes_per_sector, 512);
        assert_eq!(g.cluster_size, 4096);
        assert_eq!(g.fat_start, 24 * 512);
        assert_eq!(g.data_start, 32 * 512); // cluster heap
        assert_eq!(g.root_cluster, 5);
        assert_eq!(g.count_of_clusters, 100);
    }

    #[test]
    fn rejects_bad_signature() {
        let mut b = synth_boot();
        b[510] = 0;
        assert!(parse_boot(&b).is_err());
    }

    #[test]
    fn rejects_out_of_range_sector_shift() {
        let mut b = synth_boot();
        b[108] = 20; // 1 MiB sector — out of the 512..4096 range
        assert!(parse_boot(&b).is_err());
    }

    #[test]
    fn checksum_excludes_volume_flags_and_percent_in_use() {
        // 11 sectors of 0x00 except a couple of set bytes; the spec excludes
        // indices 106, 107, 112 from the sum, so mutating them must NOT change it.
        let bps = 512usize;
        let mut region = vec![0u8; 11 * bps];
        region[3] = 0x41;
        let base = boot_checksum(&region, bps as u32);
        region[106] = 0xFF;
        region[107] = 0xFF;
        region[112] = 0xFF;
        assert_eq!(boot_checksum(&region, bps as u32), base);
        // A byte outside the excluded set does change it.
        region[5] = 0xFF;
        assert_ne!(boot_checksum(&region, bps as u32), base);
    }
}
