//! Bounds-checked little-endian integer readers over untrusted image bytes.
//!
//! Every reader yields `0` when the requested window falls outside `data`
//! rather than panicking (Paranoid Gatekeeper): a truncated or lying image can
//! never index out of bounds. Callers range-check the *meaning* of a value
//! (cluster in range, count within caps) before acting on it.

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
