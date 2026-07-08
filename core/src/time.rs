//! FAT packed date/time decode.
//!
//! FAT stores wall-clock local time: a 16-bit date (day/month/year-since-1980)
//! and a 16-bit time (2-second resolution), with an optional 10 ms "tenths"
//! field on creation. There is no timezone — consumers treat these as local.

#[cfg(test)]
mod tests {
    use super::{decode, FatTimestamp};

    #[test]
    fn decodes_a_known_datetime() {
        // 2021-06-15 13:37:20, tenths = 0.
        // date: year=(2021-1980)=41<<9 | month=6<<5 | day=15
        let date = (41u16 << 9) | (6 << 5) | 15;
        // time: hour=13<<11 | min=37<<5 | (sec/2)=10
        let time = (13u16 << 11) | (37 << 5) | 10;
        let ts = decode(date, time, 0).unwrap();
        // 2021-06-15T13:37:20Z == 1623764240 unix seconds
        assert_eq!(ts.unix_seconds, 1_623_764_240);
        assert_eq!(ts.subsec_nanos, 0);
    }

    #[test]
    fn tenths_add_sub_second_and_carry() {
        let date = (41u16 << 9) | (6 << 5) | 15;
        let time = (13u16 << 11) | (37 << 5) | 10;
        // tenths = 150 → +1 second and 500 ms.
        let ts = decode(date, time, 150).unwrap();
        assert_eq!(ts.unix_seconds, 1_623_764_241);
        assert_eq!(ts.subsec_nanos, 500_000_000);
    }

    #[test]
    fn zero_date_is_unset() {
        assert!(decode(0, 0, 0).is_none());
    }

    #[test]
    fn epoch_1980_is_positive() {
        // 1980-01-01 00:00:00
        let date = (0u16 << 9) | (1 << 5) | 1;
        let ts = decode(date, 0, 0).unwrap();
        assert_eq!(ts.unix_seconds, 315_532_800); // 1980-01-01T00:00:00Z
    }

    #[test]
    fn typed_fields_accessible() {
        let _ = FatTimestamp {
            unix_seconds: 0,
            subsec_nanos: 0,
        };
    }
}
