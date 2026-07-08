//! exFAT reader primitives: the main boot-sector parse, the boot-region
//! checksum ([MS] §3.4), and the typed 32-byte directory-entry-set decode
//! (File 0x85 + Stream Extension 0xC0 + File Name 0xC1).
//!
//! exFAT is architecturally distinct from FAT12/16/32: the allocation bitmap —
//! not the FAT — records cluster allocation, contiguous files set a NoFatChain
//! flag and skip the FAT entirely, and names are UTF-16 across File Name
//! entries rather than 8.3 + VFAT.

use crate::boot::{FatVariant, Geometry};
use crate::bytes::{le_u32, u8_at};
use crate::error::{FatError, Result};

/// Parse the exFAT main boot sector into a [`Geometry`] (variant
/// [`FatVariant::ExFat`]). `data_start` is set to the cluster-heap offset so
/// the shared `cluster_offset` maps clusters uniformly with the FAT path.
///
/// Fails loud, naming the offending value, on any invalid field.
pub fn parse_boot(boot: &[u8]) -> Result<Geometry> {
    if boot.get(3..11) != Some(b"EXFAT   ") {
        return Err(FatError::NotFat(format!(
            "exFAT signature at 0x03 is {:02X?}, expected \"EXFAT   \"",
            boot.get(3..11).unwrap_or(&[])
        )));
    }
    let sig = crate::bytes::le_u16(boot, 510);
    if sig != 0xAA55 {
        return Err(FatError::InvalidBoot(format!(
            "boot signature at 0x1FE is {sig:#06x}, expected 0x55AA"
        )));
    }

    let bps_shift = u8_at(boot, 108);
    if !(9..=12).contains(&bps_shift) {
        return Err(FatError::InvalidBoot(format!(
            "BytesPerSectorShift at 0x6C is {bps_shift}, not in 9..=12 (512..4096)"
        )));
    }
    let spc_shift = u8_at(boot, 109);
    // Cluster size (bytes) must not exceed 32 MiB (shift sum <= 25) per [MS] §3.1.6.
    if u32::from(bps_shift) + u32::from(spc_shift) > 25 {
        return Err(FatError::InvalidBoot(format!(
            "SectorsPerClusterShift at 0x6D is {spc_shift}; cluster size exceeds 32 MiB"
        )));
    }
    let bytes_per_sector = 1u32 << bps_shift;
    let sectors_per_cluster = 1u32 << spc_shift;

    let num_fats = u8_at(boot, 110);
    if num_fats == 0 || num_fats > 2 {
        return Err(FatError::InvalidBoot(format!(
            "NumberOfFats at 0x6E is {num_fats}, must be 1 or 2"
        )));
    }

    let fat_offset = le_u32(boot, 80);
    let fat_length = le_u32(boot, 84);
    let cluster_heap_offset = le_u32(boot, 88);
    let count_of_clusters = le_u32(boot, 92);
    let root_cluster = le_u32(boot, 96);

    if root_cluster < 2 || root_cluster > count_of_clusters.saturating_add(1) {
        return Err(FatError::InvalidBoot(format!(
            "root cluster {root_cluster} outside 2..={}",
            count_of_clusters.saturating_add(1)
        )));
    }

    let bps = u64::from(bytes_per_sector);
    Ok(Geometry {
        variant: FatVariant::ExFat,
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size: bytes_per_sector * sectors_per_cluster,
        reserved_sectors: 0,
        num_fats: u32::from(num_fats),
        fat_size_sectors: fat_length,
        root_entry_count: 0,
        total_sectors: crate::bytes::le_u64(boot, 72),
        root_cluster,
        count_of_clusters,
        fat_start: u64::from(fat_offset) * bps,
        root_dir_start: 0,
        root_dir_bytes: 0,
        data_start: u64::from(cluster_heap_offset) * bps,
    })
}

/// The four-byte boot-region checksum over the first 11 sectors, excluding the
/// `VolumeFlags` (offsets 106, 107) and `PercentInUse` (offset 112) fields
/// ([MS] §3.4). A mismatch against the stored checksum is a tamper signal.
pub fn boot_checksum(sectors: &[u8], bytes_per_sector: u32) -> u32 {
    let n = (bytes_per_sector as usize)
        .saturating_mul(11)
        .min(sectors.len());
    let mut checksum: u32 = 0;
    for (i, &b) in sectors.iter().take(n).enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        checksum = checksum.rotate_right(1).wrapping_add(u32::from(b));
    }
    checksum
}

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
