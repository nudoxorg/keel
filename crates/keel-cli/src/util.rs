//! Small helpers shared by the subcommands: a temp directory, RFC 3339 times
//! and compact durations. None of the workspace's date or tempfile crates are
//! in the root dependency table, and these are each a few lines.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A uniquely named directory removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> std::io::Result<TempDir> {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "keel-cli-{label}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir)?;
        Ok(TempDir(dir))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Seconds since the epoch, now.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// `2026-11-14T08:12:03Z`.
pub fn rfc3339(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        t / 3600,
        t % 3600 / 60,
        t % 60
    )
}

/// Seconds since the epoch of an RFC 3339 time (`Z` or `+hh:mm`, optional
/// fraction); `None` if it is not one.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |a: usize, n: usize| -> Option<i64> {
        let part = s.get(a..a + n)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (h, mi, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let offset = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let off = num(i + 1, 2)? * 3600 + num(i + 4, 2)? * 60;
            if *sign == b'+' { off } else { -off }
        }
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

/// `3m55s`, `1.2s`, `40ms`: what a person reads in a PR comment.
pub fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else if ms < 60_000 {
        let tenths = (ms + 50) / 100;
        if tenths.is_multiple_of(10) {
            format!("{}s", tenths / 10)
        } else {
            format!("{}.{}s", tenths / 10, tenths % 10)
        }
    } else {
        let s = (ms + 500) / 1000;
        if s >= 3600 {
            format!("{}h{:02}m", s / 3600, s % 3600 / 60)
        } else {
            format!("{}m{:02}s", s / 60, s % 60)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trips_and_handles_offsets() {
        let t = parse_rfc3339("2026-11-14T08:12:03Z").unwrap();
        assert_eq!(rfc3339(t), "2026-11-14T08:12:03Z");
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-14T10:12:03.500+02:00"), Some(t));
        assert_eq!(parse_rfc3339("2026-11-14 08:12:03"), None);
        assert_eq!(parse_rfc3339("yesterday"), None);
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn durations_are_compact() {
        assert_eq!(fmt_ms(40), "40ms");
        assert_eq!(fmt_ms(1200), "1.2s");
        assert_eq!(fmt_ms(3000), "3s");
        assert_eq!(fmt_ms(235_400), "3m55s");
        assert_eq!(fmt_ms(3_900_000), "1h05m");
    }
}
