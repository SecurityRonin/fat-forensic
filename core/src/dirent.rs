//! FAT12/16/32 directory entries: 32-byte short (8.3) records, VFAT long-name
//! (LFN) reassembly with checksum binding, and the packed date/time decode.
//!
//! Deleted entries (first byte `0xE5`) are surfaced with `deleted = true` for
//! recovery rather than dropped.

use crate::bytes::le_u16;

/// Read-only attribute bit.
pub const ATTR_READ_ONLY: u8 = 0x01;
/// Hidden attribute bit.
pub const ATTR_HIDDEN: u8 = 0x02;
/// System attribute bit.
pub const ATTR_SYSTEM: u8 = 0x04;
/// Volume-label attribute bit.
pub const ATTR_VOLUME_ID: u8 = 0x08;
/// Directory attribute bit.
pub const ATTR_DIRECTORY: u8 = 0x10;
/// Archive attribute bit.
pub const ATTR_ARCHIVE: u8 = 0x20;
/// The attribute value marking a VFAT long-name component (`RO|HID|SYS|VOL`).
pub const ATTR_LFN: u8 = 0x0F;

/// Sentinel first byte marking a deleted directory entry.
const DELETED: u8 = 0xE5;
/// Sentinel first byte marking the end of the directory.
const END: u8 = 0x00;

/// One decoded FAT directory entry (short record, with any long name applied).
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// The effective name (reassembled long name if valid, else the 8.3 name).
    pub name: String,
    /// The raw 8.3 short name.
    pub short_name: String,
    /// The raw attribute byte.
    pub attributes: u8,
    /// Whether this entry is a subdirectory.
    pub is_dir: bool,
    /// Whether this entry is the volume-label record.
    pub is_volume_label: bool,
    /// Whether this entry is deleted (`0xE5` first byte).
    pub deleted: bool,
    /// First cluster of the entry's data (`0` = empty).
    pub first_cluster: u32,
    /// File size in bytes (`0` for directories).
    pub size: u32,
    /// 32-byte slot index of this short entry within its directory.
    pub index: u16,
    /// Raw creation `(date, time, tenths)` fields.
    pub created: (u16, u16, u8),
    /// Raw last-modified `(date, time)` fields.
    pub modified: (u16, u16),
    /// Raw last-access date field.
    pub accessed: u16,
}

/// Parse a directory's raw bytes into decoded entries, reassembling VFAT long
/// names and surfacing deleted entries. Stops at the first end-of-directory
/// marker (`0x00`).
pub fn parse_directory(data: &[u8]) -> Vec<DirEntry> {
    let mut out = Vec::new();
    // Pending LFN components for the next short entry: (sequence, 13 code units).
    let mut lfn_parts: Vec<(u8, [u16; 13])> = Vec::new();
    let mut lfn_checksum: Option<u8> = None;

    for (idx, chunk) in data.chunks_exact(32).enumerate() {
        let first = chunk[0];
        if first == END {
            break;
        }
        let attr = chunk[11];

        if first == DELETED {
            // A deleted entry breaks any pending (live) LFN association.
            lfn_parts.clear();
            lfn_checksum = None;
            if attr == ATTR_LFN {
                continue;
            }
            out.push(decode_short(chunk, idx, None, true));
            continue;
        }

        if attr == ATTR_LFN {
            let seq = first & 0x1F;
            lfn_parts.push((seq, lfn_chars(chunk)));
            lfn_checksum = Some(chunk[13]);
            continue;
        }

        let long = reassemble_long(&lfn_parts, lfn_checksum, &chunk[0..11]);
        out.push(decode_short(chunk, idx, long, false));
        lfn_parts.clear();
        lfn_checksum = None;
    }
    out
}

/// Decode a 32-byte short entry, applying `long_name` if present.
fn decode_short(chunk: &[u8], idx: usize, long_name: Option<String>, deleted: bool) -> DirEntry {
    let attr = chunk[11];
    let is_volume_label = attr & ATTR_VOLUME_ID != 0 && attr != ATTR_LFN;
    let short_name = decode_short_name(&chunk[0..11], is_volume_label, deleted);
    let first_cluster = (u32::from(le_u16(chunk, 20)) << 16) | u32::from(le_u16(chunk, 26));
    DirEntry {
        name: long_name.unwrap_or_else(|| short_name.clone()),
        short_name,
        attributes: attr,
        is_dir: attr & ATTR_DIRECTORY != 0 && !is_volume_label,
        is_volume_label,
        deleted,
        first_cluster,
        size: u32::from(le_u16(chunk, 28)) | (u32::from(le_u16(chunk, 30)) << 16),
        index: u16::try_from(idx).unwrap_or(u16::MAX),
        created: (le_u16(chunk, 16), le_u16(chunk, 14), chunk[13]),
        modified: (le_u16(chunk, 24), le_u16(chunk, 22)),
        accessed: le_u16(chunk, 18),
    }
}

/// Render the 8.3 short name from the 11 raw bytes.
fn decode_short_name(raw: &[u8], is_volume_label: bool, deleted: bool) -> String {
    let mut bytes = [0u8; 11];
    bytes.copy_from_slice(&raw[0..11]);
    // 0x05 in the first byte encodes a literal 0xE5 lead byte (Kanji).
    if bytes[0] == 0x05 {
        bytes[0] = 0xE5;
    }
    if deleted {
        bytes[0] = b'?'; // the true first char was overwritten by 0xE5
    }
    if is_volume_label {
        return trim(&bytes);
    }
    let base = trim(&bytes[0..8]);
    let ext = trim(&bytes[8..11]);
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// Right-trim ASCII spaces and lossily decode as Latin-1/ASCII text.
fn trim(bytes: &[u8]) -> String {
    let end = bytes.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
    bytes[..end].iter().map(|&b| b as char).collect()
}

/// Extract the 13 UTF-16 code units from an LFN slot (offsets 1, 14, 28).
fn lfn_chars(chunk: &[u8]) -> [u16; 13] {
    const OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut chars = [0u16; 13];
    for (i, &off) in OFFSETS.iter().enumerate() {
        chars[i] = le_u16(chunk, off);
    }
    chars
}

/// Reassemble the long name from pending LFN parts, but only if the checksum
/// binds them to this short entry (else the caller falls back to the 8.3 name).
fn reassemble_long(
    parts: &[(u8, [u16; 13])],
    checksum: Option<u8>,
    short_raw: &[u8],
) -> Option<String> {
    let checksum = checksum?;
    if parts.is_empty() || checksum != short_checksum(short_raw) {
        return None;
    }
    let mut ordered: Vec<&(u8, [u16; 13])> = parts.iter().collect();
    ordered.sort_by_key(|(seq, _)| *seq);
    let mut units: Vec<u16> = Vec::new();
    for (_, chars) in ordered {
        for &c in chars {
            if c == 0x0000 {
                break;
            }
            if c == 0xFFFF {
                continue;
            }
            units.push(c);
        }
    }
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

/// The VFAT checksum of an 11-byte short name.
fn short_checksum(name: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for &b in &name[0..11.min(name.len())] {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
    }
    sum
}

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
