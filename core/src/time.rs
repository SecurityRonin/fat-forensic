//! FAT packed date/time decode.
//!
//! FAT stores wall-clock local time: a 16-bit date (day/month/year-since-1980)
//! and a 16-bit time (2-second resolution), with an optional 10 ms "tenths"
//! field on creation. There is no timezone — consumers treat these as local.

/// A decoded FAT timestamp as seconds since the Unix epoch plus a sub-second
/// remainder. The value is wall-clock local time (FAT carries no zone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatTimestamp {
    /// Seconds since 1970-01-01 (interpreting the fields as if UTC).
    pub unix_seconds: i64,
    /// Sub-second remainder in nanoseconds (from the 10 ms tenths field).
    pub subsec_nanos: u32,
}

/// Decode a packed FAT `(date, time, tenths)` triple. Returns `None` for an
/// unset entry (`date == 0`). Out-of-range fields are clamped rather than
/// rejected — a corrupt timestamp still yields a value, never a panic.
pub fn decode(date: u16, time: u16, tenths: u8) -> Option<FatTimestamp> {
    if date == 0 {
        return None;
    }
    let day = i64::from(date & 0x1F);
    let month = i64::from((date >> 5) & 0x0F);
    let year = 1980 + i64::from((date >> 9) & 0x7F);

    let two_sec = i64::from(time & 0x1F);
    let minute = i64::from((time >> 5) & 0x3F);
    let hour = i64::from((time >> 11) & 0x1F);

    let days = days_from_civil(year, month.clamp(1, 12), day.clamp(1, 31));
    let base = days * 86_400 + hour.min(23) * 3600 + minute.min(59) * 60 + two_sec * 2;

    let tenths = i64::from(tenths);
    let unix_seconds = base + tenths / 100;
    let subsec_nanos = u32::try_from((tenths % 100) * 10_000_000).unwrap_or(0);
    Some(FatTimestamp {
        unix_seconds,
        subsec_nanos,
    })
}

/// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
/// algorithm). Valid for any in-range civil date.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::{decode, FatTimestamp};

    /// Pack a FAT date field from a civil date.
    fn mk_date(year: u16, month: u16, day: u16) -> u16 {
        ((year - 1980) << 9) | (month << 5) | day
    }

    /// Pack a FAT time field (seconds are stored halved).
    fn mk_time(hour: u16, minute: u16, second: u16) -> u16 {
        (hour << 11) | (minute << 5) | (second / 2)
    }

    #[test]
    fn decodes_a_known_datetime() {
        let ts = decode(mk_date(2021, 6, 15), mk_time(13, 37, 20), 0).unwrap();
        // 2021-06-15T13:37:20Z == 1623764240 unix seconds
        assert_eq!(ts.unix_seconds, 1_623_764_240);
        assert_eq!(ts.subsec_nanos, 0);
    }

    #[test]
    fn tenths_add_sub_second_and_carry() {
        // tenths = 150 → +1 second and 500 ms.
        let ts = decode(mk_date(2021, 6, 15), mk_time(13, 37, 20), 150).unwrap();
        assert_eq!(ts.unix_seconds, 1_623_764_241);
        assert_eq!(ts.subsec_nanos, 500_000_000);
    }

    #[test]
    fn zero_date_is_unset() {
        assert!(decode(0, 0, 0).is_none());
    }

    #[test]
    fn epoch_1980_is_positive() {
        let ts = decode(mk_date(1980, 1, 1), 0, 0).unwrap();
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
