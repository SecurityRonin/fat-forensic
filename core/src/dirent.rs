//! FAT12/16/32 directory entries: 32-byte short (8.3) records, VFAT long-name
//! (LFN) reassembly with checksum binding, and the packed date/time decode.
//!
//! Deleted entries (first byte `0xE5`) are surfaced with `deleted = true` for
//! recovery rather than dropped.

#[cfg(test)]
mod tests {
    use super::{parse_directory, ATTR_DIRECTORY};

    /// Little-endian short-entry builder: 11-byte 8.3 name, attr, cluster, size.
    fn short_entry(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0..11].copy_from_slice(name);
        e[11] = attr;
        e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes()); // hi
        e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes()); // lo
        e[28..32].copy_from_slice(&size.to_le_bytes());
        e
    }

    /// VFAT short-name checksum over the 11 raw name bytes.
    fn lfn_checksum(name: &[u8; 11]) -> u8 {
        let mut sum: u8 = 0;
        for &b in name {
            sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
        }
        sum
    }

    /// One LFN slot carrying up to 13 UTF-16 code units.
    fn lfn_entry(seq: u8, last: bool, checksum: u8, chars: &[u16]) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0] = if last { seq | 0x40 } else { seq };
        e[11] = 0x0F; // LFN attribute
        e[13] = checksum;
        let put = |e: &mut [u8; 32], slot: usize, v: u16| {
            e[slot..slot + 2].copy_from_slice(&v.to_le_bytes());
        };
        // char slots: 1..11 (5), 14..26 (6), 28..32 (2); pad with 0x0000 then 0xFFFF.
        let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (i, &off) in offsets.iter().enumerate() {
            let v = match chars.get(i) {
                Some(&c) => c,
                None if i == chars.len() => 0x0000,
                None => 0xFFFF,
            };
            put(&mut e, off, v);
        }
        e
    }

    #[test]
    fn decodes_short_entry() {
        let e = short_entry(b"HELLO   TXT", 0x20, 5, 17);
        let entries = parse_directory(&e);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "HELLO.TXT");
        assert_eq!(entries[0].first_cluster, 5);
        assert_eq!(entries[0].size, 17);
        assert!(!entries[0].is_dir);
        assert!(!entries[0].deleted);
    }

    #[test]
    fn flags_directory_and_deleted() {
        let mut dir = Vec::new();
        dir.extend_from_slice(&short_entry(b"SUBDIR     ", ATTR_DIRECTORY, 10, 0));
        let mut del = short_entry(b"GONE    TXT", 0x20, 7, 3);
        del[0] = 0xE5;
        dir.extend_from_slice(&del);
        let entries = parse_directory(&dir);
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_dir);
        assert!(entries[1].deleted);
    }

    #[test]
    fn reassembles_long_name() {
        let short = b"README~1TXT";
        let sum = lfn_checksum(short);
        let chars: Vec<u16> = "readme file.txt".encode_utf16().collect();
        // 15 chars -> two LFN slots (13 + 2), stored in reverse (seq 2 then 1).
        let mut dir = Vec::new();
        dir.extend_from_slice(&lfn_entry(2, true, sum, &chars[13..]));
        dir.extend_from_slice(&lfn_entry(1, false, sum, &chars[..13]));
        dir.extend_from_slice(&short_entry(short, 0x20, 5, 42));
        let entries = parse_directory(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "readme file.txt");
        assert_eq!(entries[0].short_name, "README~1.TXT");
    }

    #[test]
    fn volume_label_marked() {
        let e = short_entry(b"MYVOLUME   ", 0x08, 0, 0);
        let entries = parse_directory(&e);
        assert!(entries[0].is_volume_label);
    }

    #[test]
    fn stops_at_end_marker() {
        let mut dir = Vec::new();
        dir.extend_from_slice(&short_entry(b"FIRST   TXT", 0x20, 5, 1));
        dir.extend_from_slice(&[0u8; 32]); // first byte 0x00 → end of directory
        dir.extend_from_slice(&short_entry(b"AFTER   TXT", 0x20, 6, 1));
        let entries = parse_directory(&dir);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "FIRST.TXT");
    }

    #[test]
    fn mismatched_lfn_checksum_falls_back_to_short() {
        let short = b"HELLO   TXT";
        let chars: Vec<u16> = "orphan.txt".encode_utf16().collect();
        let mut dir = Vec::new();
        dir.extend_from_slice(&lfn_entry(1, true, 0xAB, &chars)); // wrong checksum
        dir.extend_from_slice(&short_entry(short, 0x20, 5, 1));
        let entries = parse_directory(&dir);
        assert_eq!(entries[0].name, "HELLO.TXT"); // LFN ignored, 8.3 used
    }
}
