//! Bounds-checked little-endian integer readers over untrusted image bytes.
//!
//! Every reader yields `0` when the requested window falls outside `data`
//! rather than panicking (Paranoid Gatekeeper): a truncated or lying image can
//! never index out of bounds. Callers range-check the *meaning* of a value
//! (cluster in range, count within caps) before acting on it.

// Leaf toolkit: individual readers are consumed as the boot/FAT/dir/exFAT units
// land; the allow is removed once every reader has a caller.
#![allow(dead_code)]

/// One byte at `off`, or `0` if out of range.
pub(crate) fn u8_at(data: &[u8], off: usize) -> u8 {
    data.get(off).copied().unwrap_or(0)
}

/// The `N`-byte window at `off`, or `None` if out of range (overflow-safe).
fn window<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    let slice = data.get(off..end)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Some(out)
}

/// Little-endian `u16` at `off`, or `0` if the 2-byte window is out of range.
pub(crate) fn le_u16(data: &[u8], off: usize) -> u16 {
    window::<2>(data, off).map_or(0, u16::from_le_bytes)
}

/// Little-endian `u32` at `off`, or `0` if the 4-byte window is out of range.
pub(crate) fn le_u32(data: &[u8], off: usize) -> u32 {
    window::<4>(data, off).map_or(0, u32::from_le_bytes)
}

/// Little-endian `u64` at `off`, or `0` if the 8-byte window is out of range.
pub(crate) fn le_u64(data: &[u8], off: usize) -> u64 {
    window::<8>(data, off).map_or(0, u64::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::{le_u16, le_u32, le_u64, u8_at};

    #[test]
    fn reads_within_bounds() {
        let d = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(u8_at(&d, 0), 0x01);
        assert_eq!(le_u16(&d, 0), 0x0201);
        assert_eq!(le_u32(&d, 0), 0x0403_0201);
        assert_eq!(le_u64(&d, 0), 0x0807_0605_0403_0201);
    }

    #[test]
    fn out_of_range_yields_zero_never_panics() {
        let d = [0xAAu8, 0xBB];
        assert_eq!(u8_at(&d, 9), 0);
        assert_eq!(le_u16(&d, 1), 0); // straddles the end
        assert_eq!(le_u32(&d, 0), 0); // only 2 bytes available
        assert_eq!(le_u64(&d, 0), 0);
        assert_eq!(le_u16(&[], 0), 0);
    }
}
