//! FAT table access for FAT12/16/32: decode a cluster's next-pointer, classify
//! end-of-chain / bad / free markers, and follow a cluster chain with a hard
//! cap that defeats cycles and runaway allocation.

use crate::boot::FatVariant;
use crate::bytes::{le_u16, le_u32};

/// Decode the FAT entry (next-cluster pointer) for `cluster`. Returns `0`
/// (free) if the entry falls outside the FAT slice — never panics.
pub fn fat_entry(fat: &[u8], variant: FatVariant, cluster: u32) -> u32 {
    match variant {
        FatVariant::Fat12 => {
            // Two 12-bit entries share three bytes: offset = cluster * 3 / 2.
            let off = (cluster as usize).saturating_mul(3) / 2;
            let raw = u32::from(le_u16(fat, off));
            if cluster & 1 == 1 {
                raw >> 4
            } else {
                raw & 0x0FFF
            }
        }
        FatVariant::Fat16 => {
            let off = (cluster as usize).saturating_mul(2);
            u32::from(le_u16(fat, off))
        }
        // exFAT uses the same 32-bit layout as FAT32 for its (fragmented-only) FAT.
        FatVariant::Fat32 | FatVariant::ExFat => {
            let off = (cluster as usize).saturating_mul(4);
            le_u32(fat, off) & 0x0FFF_FFFF
        }
    }
}

/// The end-of-chain threshold for `variant`: a value `>=` this marks the last
/// cluster of a chain.
fn eoc_threshold(variant: FatVariant) -> u32 {
    match variant {
        FatVariant::Fat12 => 0x0FF8,
        FatVariant::Fat16 => 0xFFF8,
        FatVariant::Fat32 | FatVariant::ExFat => 0x0FFF_FFF8,
    }
}

/// Whether `value` is an end-of-chain marker for `variant`.
pub fn is_eoc(variant: FatVariant, value: u32) -> bool {
    value >= eoc_threshold(variant)
}

/// Whether `value` is the bad-cluster marker for `variant` (EOC threshold − 1).
pub fn is_bad(variant: FatVariant, value: u32) -> bool {
    value == eoc_threshold(variant) - 1
}

/// Follow the cluster chain starting at `start`, returning the clusters in
/// order. Stops at an EOC marker, a bad/free/reserved pointer, or an
/// out-of-range next-cluster; `max_clusters` hard-caps the length so a cyclic
/// or absurd chain can never hang or exhaust memory.
pub fn follow_chain(fat: &[u8], variant: FatVariant, start: u32, max_clusters: usize) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut cluster = start;
    while chain.len() < max_clusters {
        if cluster < 2 {
            break;
        }
        chain.push(cluster);
        let next = fat_entry(fat, variant, cluster);
        if next < 2 || is_bad(variant, next) || is_eoc(variant, next) {
            break;
        }
        cluster = next;
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::{fat_entry, follow_chain, is_bad, is_eoc};
    use crate::boot::FatVariant::{Fat12, Fat16, Fat32};

    #[test]
    fn fat12_packs_two_entries_per_three_bytes() {
        // entry[2]=0x123, entry[3]=0xABC packed at byte offset 3..6.
        let mut fat = vec![0u8; 16];
        fat[3] = 0x23;
        fat[4] = 0xC1;
        fat[5] = 0xAB;
        assert_eq!(fat_entry(&fat, Fat12, 2), 0x123);
        assert_eq!(fat_entry(&fat, Fat12, 3), 0xABC);
    }

    #[test]
    fn fat16_entries_are_u16() {
        let mut fat = vec![0u8; 16];
        fat[4..6].copy_from_slice(&0x1234u16.to_le_bytes()); // cluster 2
        assert_eq!(fat_entry(&fat, Fat16, 2), 0x1234);
    }

    #[test]
    fn fat32_masks_to_28_bits() {
        let mut fat = vec![0u8; 32];
        fat[8..12].copy_from_slice(&0xF123_4567u32.to_le_bytes()); // cluster 2
        assert_eq!(fat_entry(&fat, Fat32, 2), 0x0123_4567); // top nibble ignored
    }

    #[test]
    fn out_of_range_cluster_reads_zero() {
        assert_eq!(fat_entry(&[], Fat16, 9999), 0);
    }

    #[test]
    fn classifies_eoc_and_bad_markers() {
        assert!(is_eoc(Fat12, 0xFF8));
        assert!(is_eoc(Fat12, 0xFFF));
        assert!(!is_eoc(Fat12, 0xFF7));
        assert!(is_bad(Fat12, 0xFF7));

        assert!(is_eoc(Fat16, 0xFFF8));
        assert!(is_bad(Fat16, 0xFFF7));

        assert!(is_eoc(Fat32, 0x0FFF_FFF8));
        assert!(is_bad(Fat32, 0x0FFF_FFF7));
        assert!(!is_eoc(Fat32, 0x0000_0003));
    }

    #[test]
    fn follows_a_simple_chain_to_eoc() {
        // 2 -> 3 -> EOC (FAT16: cluster N entry at byte offset N*2)
        let mut fat = vec![0u8; 32];
        fat[4..6].copy_from_slice(&3u16.to_le_bytes()); // cluster 2 -> 3
        fat[6..8].copy_from_slice(&0xFFFFu16.to_le_bytes()); // cluster 3 -> EOC
        assert_eq!(follow_chain(&fat, Fat16, 2, 100), vec![2, 3]);
    }

    #[test]
    fn chain_cap_defeats_a_self_cycle() {
        // cluster 2 -> 2 forever; the cap bounds it.
        let mut fat = vec![0u8; 32];
        fat[4..6].copy_from_slice(&2u16.to_le_bytes());
        let chain = follow_chain(&fat, Fat16, 2, 5);
        assert_eq!(chain.len(), 5); // capped, no hang
    }

    #[test]
    fn free_or_reserved_terminates_chain() {
        let fat = vec![0u8; 32]; // all zero → cluster 2 points to free (0)
        assert_eq!(follow_chain(&fat, Fat16, 2, 100), vec![2]);
    }

    #[test]
    fn reserved_start_cluster_yields_empty_chain() {
        assert!(follow_chain(&[0u8; 32], Fat16, 1, 100).is_empty());
    }
}
