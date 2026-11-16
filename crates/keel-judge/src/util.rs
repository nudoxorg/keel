//! Time and number formatting shared by the loop's log line and the status table.

use std::time::{SystemTime, UNIX_EPOCH};

/// RFC 3339 in UTC with millisecond precision. Written by hand because the crate needs
/// nothing else from a date library.
pub fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let ms = d.subsec_millis();
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, day) = civil_from_days(days);
    format!("{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

pub fn now_rfc3339() -> String {
    rfc3339(SystemTime::now())
}

/// `20261115T231500Z`: a UTC instant that is safe in a file name (no colons) and sorts as time.
pub fn compact_utc(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let rem = secs.rem_euclid(86_400);
    let (y, m, day) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}{m:02}{day:02}T{:02}{:02}{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Unix seconds now, for the metrics file's timestamps.
pub fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// The inverse of `rfc3339`: `YYYY-MM-DDTHH:MM:SS[.fraction]Z` as unix seconds. `None` for
/// anything else, so a record whose time was never written (or by another tool) is
/// skipped and counted instead of being given a made-up date.
pub fn parse_rfc3339(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let digits = |from: usize, n: usize| -> Option<i64> {
        let part = b.get(from..from + n)?;
        part.iter().all(u8::is_ascii_digit).then(|| part.iter().fold(0, |acc, d| acc * 10 + i64::from(d - b'0')))
    };
    let at = |i: usize, c: u8| b.get(i) == Some(&c);
    if !(at(4, b'-') && at(7, b'-') && at(10, b'T') && at(13, b':') && at(16, b':')) {
        return None;
    }
    let (y, m, d) = (digits(0, 4)?, digits(5, 2)? as u32, digits(8, 2)? as u32);
    let (hh, mm, ss) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    let frac = match b.get(19)? {
        b'Z' if b.len() == 20 => 0.0,
        b'.' => {
            let end = b.len().checked_sub(1).filter(|e| b[*e] == b'Z' && *e > 20)?;
            if !b[20..end].iter().all(u8::is_ascii_digit) {
                return None;
            }
            // Parsed as a decimal fraction so ".123" is 0.123 and not a sum of rounded digits.
            format!("0.{}", &s[20..end]).parse::<f64>().ok()?
        }
        _ => return None,
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&m) || d < 1 || d > month_days[m as usize - 1] || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    Some((days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss) as f64 + frac)
}

// The same algorithm's other direction.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2.8e7` for large counts, the plain number for small ones.
pub fn sci(n: u64) -> String {
    if n < 10_000 { n.to_string() } else { format!("{:.1e}", n as f64) }
}

/// `466k` for rates of a thousand or more.
pub fn per_sec(x: f64) -> String {
    if x >= 1000.0 { format!("{:.0}k", x / 1000.0) } else { format!("{x:.0}") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_millis(1_700_000_000_123)), "2023-11-14T22:13:20.123Z");
        // A leap day, to exercise the March-based year.
        assert_eq!(rfc3339(UNIX_EPOCH + Duration::from_secs(1_709_164_800)), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn compact_utc_has_no_separators() {
        assert_eq!(compact_utc(UNIX_EPOCH), "19700101T000000Z");
        assert_eq!(compact_utc(UNIX_EPOCH + Duration::from_secs(1_709_164_800 + 23 * 3600 + 15 * 60)), "20240229T231500Z");
    }

    #[test]
    fn parse_is_the_inverse_of_what_the_logs_hold() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00.000Z"), Some(0.0));
        assert_eq!(parse_rfc3339("2023-11-14T22:13:20.123Z"), Some(1_700_000_000.123));
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(1_709_164_800.0));
        // Before the epoch and across a century that is not a leap year.
        assert_eq!(parse_rfc3339("1969-12-31T23:59:59.500Z"), Some(-0.5));
        assert_eq!(parse_rfc3339("2100-03-01T00:00:00Z"), Some(4_107_542_400.0));
        for ms in [0u64, 1, 86_399_999, 1_700_000_000_123, 4_107_542_399_999] {
            let t = UNIX_EPOCH + Duration::from_millis(ms);
            let got = parse_rfc3339(&rfc3339(t)).unwrap();
            assert!((got - ms as f64 / 1000.0).abs() < 1e-6, "{ms}: {got}");
        }
    }

    #[test]
    fn parse_refuses_what_it_cannot_place() {
        for bad in [
            "",
            "t",
            "2023-11-14",
            "2023-11-14T22:13:20",
            "2023-11-14T22:13:20.Z",
            "2023-11-14T22:13:20.12x3Z",
            "2023-11-14 22:13:20Z",
            "2023-11-14T22:13:20+01:00",
            "2023-13-14T22:13:20Z",
            "2023-02-29T00:00:00Z",
            "2023-11-31T00:00:00Z",
            "2023-11-14T24:00:00Z",
            "2023-11-14T22:60:00Z",
            "2023-11-14T22:13:20Zjunk",
            "20x3-11-14T22:13:20Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn counts_and_rates_read_short() {
        assert_eq!(sci(28_000_000), "2.8e7");
        assert_eq!(sci(512), "512");
        assert_eq!(per_sec(466_000.0), "466k");
        assert_eq!(per_sec(37.4), "37");
    }
}
