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
    use super::{boot_checksum, parse_boot, parse_directory};
    use crate::boot::FatVariant;

    /// exFAT File directory entry (0x85, or 0x05 when deleted).
    fn file_entry(deleted: bool, secondary_count: u8, attrs: u16) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = if deleted { 0x05 } else { 0x85 };
        e[1] = secondary_count;
        e[4..6].copy_from_slice(&attrs.to_le_bytes());
        e
    }

    /// exFAT Stream Extension entry (0xC0, or 0x40 when deleted).
    fn stream_ext(
        deleted: bool,
        no_fat_chain: bool,
        name_len: u8,
        first: u32,
        size: u64,
    ) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = if deleted { 0x40 } else { 0xC0 };
        e[1] = if no_fat_chain { 0x03 } else { 0x01 }; // AllocationPossible|NoFatChain
        e[3] = name_len;
        e[20..24].copy_from_slice(&first.to_le_bytes());
        e[24..32].copy_from_slice(&size.to_le_bytes());
        e
    }

    /// exFAT File Name entry (0xC1, or 0x41 when deleted), up to 15 UTF-16 units.
    fn file_name(deleted: bool, chars: &[u16]) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = if deleted { 0x41 } else { 0xC1 };
        for (i, &c) in chars.iter().take(15).enumerate() {
            e[1 + i * 2..3 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        e
    }

    fn entry_set(
        deleted: bool,
        name: &str,
        attrs: u16,
        contiguous: bool,
        first: u32,
        size: u64,
    ) -> Vec<u8> {
        let chars: Vec<u16> = name.encode_utf16().collect();
        let mut v = Vec::new();
        v.extend_from_slice(&file_entry(deleted, 2, attrs));
        v.extend_from_slice(&stream_ext(
            deleted,
            contiguous,
            chars.len() as u8,
            first,
            size,
        ));
        v.extend_from_slice(&file_name(deleted, &chars));
        v
    }

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
    fn parses_a_file_entry_set() {
        let mut dir = Vec::new();
        dir.extend_from_slice(&entry_set(false, "Hi.txt", 0x20, true, 10, 5));
        let entries = parse_directory(&dir);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.name, "Hi.txt");
        assert_eq!(e.size, 5);
        assert_eq!(e.first_cluster, 10);
        assert!(e.contiguous);
        assert!(!e.is_dir);
        assert!(!e.deleted);
    }

    #[test]
    fn parses_directory_and_deleted_and_skips_system_entries() {
        let mut dir = Vec::new();
        // an allocation-bitmap primary (0x81) must be skipped, not treated as a file
        let mut bitmap = [0u8; 32];
        bitmap[0] = 0x81;
        dir.extend_from_slice(&bitmap);
        dir.extend_from_slice(&entry_set(false, "sub", 0x10, false, 20, 0)); // directory
        dir.extend_from_slice(&entry_set(true, "gone.txt", 0x20, true, 30, 7)); // deleted
        let entries = parse_directory(&dir);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "sub");
        assert!(entries[0].is_dir);
        assert_eq!(entries[1].name, "gone.txt");
        assert!(entries[1].deleted);
    }

    #[test]
    fn stops_at_end_of_directory_marker() {
        let mut dir = Vec::new();
        dir.extend_from_slice(&entry_set(false, "a.txt", 0x20, true, 5, 1));
        dir.extend_from_slice(&[0u8; 32]); // type 0x00 → end
        dir.extend_from_slice(&entry_set(false, "b.txt", 0x20, true, 6, 1));
        assert_eq!(parse_directory(&dir).len(), 1);
    }

    #[test]
    fn long_name_spans_two_file_name_entries() {
        // 20-char name → two File Name entries (15 + 5).
        let name = "twentycharsname_ok!!";
        let chars: Vec<u16> = name.encode_utf16().collect();
        let mut dir = Vec::new();
        dir.extend_from_slice(&file_entry(false, 3, 0x20));
        dir.extend_from_slice(&stream_ext(false, true, chars.len() as u8, 40, 3));
        dir.extend_from_slice(&file_name(false, &chars[..15]));
        dir.extend_from_slice(&file_name(false, &chars[15..]));
        assert_eq!(parse_directory(&dir)[0].name, name);
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
