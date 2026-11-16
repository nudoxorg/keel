//! What a libFuzzer run prints, reduced to the numbers and markers the supervisor records.

/// Everything learned from one run's output so far. Fed line by line while the run is
/// alive so that a killed run still has its latest numbers.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Parsed {
    /// Seconds from spawn to `INITED`.
    pub inited_s: Option<f64>,
    pub cov_inited: Option<u64>,
    pub ft_inited: Option<u64>,
    /// The latest `#N` status line: executions, coverage, features, exec/s.
    pub last_execs: Option<u64>,
    pub cov: Option<u64>,
    pub ft: Option<u64>,
    pub last_exec_per_sec: Option<u64>,
    pub stat_execs: Option<u64>,
    pub stat_exec_per_sec: Option<f64>,
    pub new_units: Option<u64>,
    pub peak_rss_mb: Option<u64>,
    pub slowest_unit_s: Option<f64>,
    pub interrupted: bool,
    pub deadly_signal: bool,
    pub asan: bool,
    pub timeout: bool,
    pub oom: bool,
    pub leak: bool,
    pub panic: bool,
    /// Paths named by `Test unit written to`.
    pub test_units: Vec<String>,
}

impl Parsed {
    pub fn feed(&mut self, line: &str, elapsed_s: f64) {
        if let Some(s) = status_line(line) {
            self.last_execs = Some(s.n);
            self.cov = Some(s.cov);
            self.ft = Some(s.ft);
            if s.exec_s.is_some() {
                self.last_exec_per_sec = s.exec_s;
            }
            if s.tag == "INITED" && self.inited_s.is_none() {
                self.inited_s = Some(elapsed_s);
                self.cov_inited = Some(s.cov);
                self.ft_inited = Some(s.ft);
            }
            return;
        }
        if let Some(rest) = line.strip_prefix("stat::") {
            if let Some((name, value)) = rest.split_once(':') {
                let value = value.trim();
                match name {
                    "number_of_executed_units" => self.stat_execs = value.parse().ok(),
                    "average_exec_per_sec" => self.stat_exec_per_sec = value.parse().ok(),
                    "new_units_added" => self.new_units = value.parse().ok(),
                    "peak_rss_mb" => self.peak_rss_mb = value.parse().ok(),
                    "slowest_unit_time_sec" => self.slowest_unit_s = value.parse().ok(),
                    _ => {}
                }
            }
            return;
        }
        self.interrupted |= line.contains("libFuzzer: run interrupted; exiting");
        self.deadly_signal |= line.contains("ERROR: libFuzzer: deadly signal");
        self.asan |= line.contains("ERROR: AddressSanitizer:");
        self.timeout |= line.contains("ERROR: libFuzzer: timeout after");
        self.oom |= line.contains("ERROR: libFuzzer: out-of-memory");
        self.leak |= line.contains("ERROR: LeakSanitizer");
        self.panic |= line.contains("panicked at");
        if let Some((_, path)) = line.split_once("Test unit written to ") {
            self.test_units.push(path.trim().to_string());
        }
    }

    /// Executions: the final stats when printed, else the latest `#N`.
    pub fn execs(&self) -> Option<u64> {
        self.stat_execs.or(self.last_execs)
    }

    pub fn exec_per_sec(&self) -> Option<f64> {
        self.stat_exec_per_sec.or(self.last_exec_per_sec.map(|e| e as f64))
    }
}

struct StatusLine<'a> {
    n: u64,
    tag: &'a str,
    cov: u64,
    ft: u64,
    exec_s: Option<u64>,
}

fn status_line(line: &str) -> Option<StatusLine<'_>> {
    let rest = line.strip_prefix('#')?;
    let (n, rest) = rest.split_once(char::is_whitespace)?;
    let n = n.parse().ok()?;
    let (tag, rest) = rest.trim_start().split_once(char::is_whitespace)?;
    Some(StatusLine { n, tag, cov: field(rest, "cov:")?, ft: field(rest, "ft:")?, exec_s: field(rest, "exec/s:") })
}

fn field(s: &str, key: &str) -> Option<u64> {
    let i = s.find(key)?;
    s[i + key.len()..].trim_start().split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lines from bench/fuzz/out/libfuzzer/log_both_1.txt and log_rust-only_1.txt.
    const RUN: &str = "\
INFO: Seed: 1
#2\tINITED cov: 12 ft: 12 corp: 1/1b exec/s: 0 rss: 43Mb
#4\tNEW    cov: 14 ft: 14 corp: 2/2b lim: 4 exec/s: 0 rss: 43Mb L: 1/1 MS: 2 ShuffleBytes-ChangeBit-
\tNEW_FUNC[1/1]: 0x000104861f4c in keel_demo_decode_record+0x0 (demo-libfuzzer:arm64+0x100001f4c)
#8\tpulse  cov: 18 ft: 18 corp: 3/3b lim: 4 exec/s: 2 rss: 45Mb
#1378\tREDUCE cov: 24 ft: 25 corp: 7/21b lim: 14 exec/s: 344 rss: 45Mb L: 8/8 MS: 3 ShuffleBytes-CrossOver-EraseBytes-
#60001529\tDONE   cov: 21 ft: 21 corp: 6/11b lim: 4096 exec/s: 983631 rss: 622Mb
Done 60001529 runs in 61 second(s)
stat::number_of_executed_units: 60001529
stat::average_exec_per_sec:     983631
stat::new_units_added:          7
stat::slowest_unit_time_sec:    0
stat::peak_rss_mb:              622";

    fn parse(text: &str) -> Parsed {
        let mut p = Parsed::default();
        for (i, l) in text.lines().enumerate() {
            p.feed(l, 0.5 + i as f64);
        }
        p
    }

    #[test]
    fn inited_and_status_lines() {
        let p = parse(RUN);
        assert_eq!(p.inited_s, Some(1.5));
        assert_eq!((p.cov_inited, p.ft_inited), (Some(12), Some(12)));
        assert_eq!((p.cov, p.ft), (Some(21), Some(21)));
        assert_eq!(p.last_execs, Some(60_001_529));
        assert_eq!(p.last_exec_per_sec, Some(983_631));
    }

    #[test]
    fn final_stats_win_over_the_last_status_line() {
        let p = parse(RUN);
        assert_eq!(p.execs(), Some(60_001_529));
        assert_eq!(p.exec_per_sec(), Some(983_631.0));
        assert_eq!((p.new_units, p.peak_rss_mb, p.slowest_unit_s), (Some(7), Some(622), Some(0.0)));
    }

    #[test]
    fn without_final_stats_execs_fall_back_to_the_last_status_line() {
        let p = parse("#2\tINITED cov: 12 ft: 12 corp: 1/1b exec/s: 0 rss: 43Mb\n#512\tpulse  cov: 23 ft: 23 corp: 6/13b lim: 6 exec/s: 128 rss: 45Mb");
        assert_eq!(p.stat_execs, None);
        assert_eq!(p.execs(), Some(512));
        assert_eq!(p.exec_per_sec(), Some(128.0));
    }

    #[test]
    fn read_lines_without_coverage_are_not_status_lines() {
        let p = parse("#1024\tREAD   units: 5 exec/s: 0\nINFO: -max_len is not provided");
        assert_eq!(p, Parsed::default());
    }

    #[test]
    fn crash_markers_and_the_written_unit() {
        let p = parse(
            "thread '<unnamed>' panicked at src/lib.rs:70:26:\n\
             ==93869==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x606000139440 at pc 0x0001052071b4\n\
             ==93869==ABORTING\n\
             artifact_prefix='art_both_1/'; Test unit written to art_both_1/crash-caa5ee1638139cf506ee2e32766fef0eca668fb0",
        );
        assert!(p.panic && p.asan);
        assert!(!p.timeout && !p.oom && !p.leak && !p.interrupted && !p.deadly_signal);
        assert_eq!(p.test_units, vec!["art_both_1/crash-caa5ee1638139cf506ee2e32766fef0eca668fb0".to_string()]);
    }

    #[test]
    fn libfuzzer_failure_and_interrupt_lines() {
        let p = parse("==7== ERROR: libFuzzer: deadly signal\n==7== ERROR: libFuzzer: timeout after 10 seconds\n==7== ERROR: libFuzzer: out-of-memory (used: 4097Mb; limit: 4096Mb)\n==7== INFO: libFuzzer: run interrupted; exiting\n==7== ERROR: LeakSanitizer: detected memory leaks");
        assert!(p.deadly_signal && p.timeout && p.oom && p.interrupted && p.leak);
    }
}
