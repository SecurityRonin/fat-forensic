//! FAT table access for FAT12/16/32: decode a cluster's next-pointer, classify
//! end-of-chain / bad / free markers, and follow a cluster chain with a hard
//! cap that defeats cycles and runaway allocation.

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
        // 2 -> 3 -> EOC
        let mut fat = vec![0u8; 32];
        fat[8..10].copy_from_slice(&3u16.to_le_bytes()); // cluster 2 -> 3
        fat[6..8].copy_from_slice(&0xFFFFu16.to_le_bytes()); // cluster 3 -> EOC
        assert_eq!(follow_chain(&fat, Fat16, 2, 100), vec![2, 3]);
    }

    #[test]
    fn chain_cap_defeats_a_self_cycle() {
        // cluster 2 -> 2 forever; the cap bounds it.
        let mut fat = vec![0u8; 32];
        fat[8..10].copy_from_slice(&2u16.to_le_bytes());
        let chain = follow_chain(&fat, Fat16, 2, 5);
        assert_eq!(chain.len(), 5); // capped, no hang
    }

    #[test]
    fn free_or_reserved_terminates_chain() {
        let fat = vec![0u8; 32]; // all zero → cluster 2 points to free (0)
        assert_eq!(follow_chain(&fat, Fat16, 2, 100), vec![2]);
    }
}
