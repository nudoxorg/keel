//! `keel-judge expect`: a service's metrics are its test surface. The expectations are
//! data (a JSON spec, written once in Nix next to the module) and this is the one checker
//! that evaluates them, in the VM test, in a local soak and against the live host, so no
//! test needs its own parser for the logs.
//!
//! The input is the exposition text, from the metrics file the supervisor writes or
//! computed from the state logs the way `status --prometheus` does.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::metrics::{self, escape};
use crate::state::State;
use crate::targets::TargetsFile;
use crate::util::unix_now;

pub const SPEC_SCHEMA: &str = "keel.judge.expect.v1";

/// Two values closer than this, relative to their size (and absolutely below 1), are equal
/// for `==` and `!=`: a selection sums several samples, and a sum of floats is not exactly
/// the number a person wrote. Ordering ops are exact, because a bound is a bound.
const TOLERANCE: f64 = 1e-9;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
    Absent,
    AgeBelow,
    Increases,
}

const OPS: [(&str, Op); 9] = [
    ("==", Op::Eq),
    ("!=", Op::Ne),
    (">=", Op::Ge),
    ("<=", Op::Le),
    (">", Op::Gt),
    ("<", Op::Lt),
    ("absent", Op::Absent),
    ("age_below", Op::AgeBelow),
    ("increases", Op::Increases),
];

impl Op {
    fn word(self) -> &'static str {
        OPS.iter().find(|(_, o)| *o == self).map_or("?", |(w, _)| w)
    }

    fn takes_value(self) -> bool {
        !matches!(self, Op::Absent | Op::Increases)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Expectation {
    pub name: String,
    pub metric: String,
    pub labels: BTreeMap<String, String>,
    pub op: Op,
    pub value: Option<f64>,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Spec {
    pub expectations: Vec<Expectation>,
}

impl Expectation {
    /// `metric{label="value",...}`, without braces for no labels, as the exposition writes it.
    fn series(&self) -> String {
        if self.labels.is_empty() {
            return self.metric.clone();
        }
        let parts: Vec<String> = self.labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape(v))).collect();
        format!("{}{{{}}}", self.metric, parts.join(","))
    }

    /// `>= 8`, `age_below 180`, `increases`.
    fn wanted(&self) -> String {
        match self.value {
            Some(v) => format!("{} {}", self.op.word(), v),
            None => self.op.word().to_string(),
        }
    }
}

impl Spec {
    /// `increases` compares two reads, so a check that reads once cannot hold one.
    pub fn check_usage(&self, within: Duration) -> Result<(), String> {
        if within.is_zero()
            && let Some(e) = self.expectations.iter().find(|e| e.op == Op::Increases)
        {
            return Err(format!(
                "expectation {:?} uses `increases`, which compares two reads of {}, and --within is 0s so there is only one; pass --within longer than the metric's update interval",
                e.name,
                e.series()
            ));
        }
        Ok(())
    }
}

/// Reads a spec. Every message names the expectation by its index in the list and the
/// field, since the name itself may be what is wrong. Unknown fields are refused: a typo
/// in `labels` would otherwise select everything and pass.
pub fn parse_spec(text: &str) -> Result<Spec, String> {
    let root: Value =
        serde_json::from_str(text).map_err(|e| format!("the spec is not JSON ({e}); write it as {{\"schema\": \"{SPEC_SCHEMA}\", \"expectations\": [...]}}"))?;
    let root = root.as_object().ok_or_else(|| format!("the spec is not a JSON object; write {{\"schema\": \"{SPEC_SCHEMA}\", \"expectations\": [...]}}"))?;
    if let Some(k) = root.keys().find(|k| !matches!(k.as_str(), "schema" | "expectations")) {
        return Err(format!("the spec has an unknown field {k:?}; it has only `schema` and `expectations`"));
    }
    match root.get("schema").and_then(Value::as_str) {
        Some(SPEC_SCHEMA) => {}
        Some(other) => return Err(format!("the spec's schema is {other:?}, this build reads {SPEC_SCHEMA:?}; use the keel-judge that wrote the spec, or rewrite the spec")),
        None => return Err(format!("the spec has no `schema`; add \"schema\": \"{SPEC_SCHEMA}\"")),
    }
    let list = root
        .get("expectations")
        .and_then(Value::as_array)
        .ok_or_else(|| "the spec's `expectations` is missing or not a list; write a list of {name, metric, labels, op, value, why}".to_string())?;
    if list.is_empty() {
        return Err("the spec's `expectations` is empty: nothing would be checked, and a check that cannot fail proves nothing; list at least one".into());
    }
    let mut names = BTreeSet::new();
    let mut out = Vec::new();
    for (i, item) in list.iter().enumerate() {
        let e = parse_expectation(i, item)?;
        if !names.insert(e.name.clone()) {
            return Err(format!("expectations[{i}] repeats the name {:?}; names identify the lines of the report, so give each its own", e.name));
        }
        out.push(e);
    }
    Ok(Spec { expectations: out })
}

fn parse_expectation(i: usize, item: &Value) -> Result<Expectation, String> {
    let obj = item.as_object().ok_or_else(|| format!("expectations[{i}] is not an object; write {{name, metric, labels, op, value, why}}"))?;
    let label = match obj.get("name").and_then(Value::as_str) {
        Some(n) => format!("expectations[{i}] ({n:?})"),
        None => format!("expectations[{i}]"),
    };
    if let Some(k) = obj.keys().find(|k| !matches!(k.as_str(), "name" | "metric" | "labels" | "op" | "value" | "why")) {
        return Err(format!("{label} has an unknown field {k:?}; the fields are name, metric, labels, op, value and why"));
    }
    let text = |field: &str| -> Result<String, String> {
        match obj.get(field) {
            Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
            _ => Err(format!("{label}.{field} is missing or not a non-empty string; write it as text")),
        }
    };
    let name = text("name")?;
    let metric = text("metric")?;
    if !metric.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_' || c == ':') || !metric.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') {
        return Err(format!("{label}.metric is {metric:?}, which is not a metric name; use letters, digits, `_` and `:`, like keel_judge_quanta_total"));
    }
    let why = text("why")?;
    let mut labels = BTreeMap::new();
    match obj.get("labels") {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => {
            for (k, v) in m {
                let v = v.as_str().ok_or_else(|| format!("{label}.labels.{k} is {v}, not a string; label values are text, write \"{v}\" quoted"))?;
                labels.insert(k.clone(), v.to_string());
            }
        }
        Some(other) => return Err(format!("{label}.labels is {other}, not an object; write {{\"target\": \"alpha\"}} or leave it out")),
    }
    let op_word = text("op")?;
    let op = OPS
        .iter()
        .find(|(w, _)| *w == op_word)
        .map(|(_, o)| *o)
        .ok_or_else(|| format!("{label}.op is {op_word:?}, expected one of {}", OPS.map(|(w, _)| w).join(", ")))?;
    let value = match obj.get("value") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_f64().ok_or_else(|| format!("{label}.value is {v}, not a number; write it without quotes"))?),
    };
    match (op.takes_value(), value) {
        (true, None) => return Err(format!("{label}.value is missing, and `{}` compares against one; add the number", op.word())),
        (false, Some(_)) => return Err(format!("{label}.value is set, and `{}` takes none; remove it", op.word())),
        _ => {}
    }
    Ok(Expectation { name, metric, labels, op, value, why })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

/// The text exposition format as `metrics::render` and node exporter's textfiles write it:
/// comments and blank lines skipped, `name{labels} value [timestamp]`.
pub fn parse_exposition(text: &str) -> Result<Vec<Sample>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(parse_sample(line).map_err(|why| format!("line {} is not a sample ({why}): {line:?}", n + 1))?);
    }
    Ok(out)
}

fn parse_sample(line: &str) -> Result<Sample, &'static str> {
    let b = line.as_bytes();
    let name_end = line.find(['{', ' ', '\t']).ok_or("no value")?;
    let name = line[..name_end].to_string();
    if name.is_empty() {
        return Err("no metric name");
    }
    let mut labels = BTreeMap::new();
    let mut i = name_end;
    if b[i] == b'{' {
        i += 1;
        loop {
            while b.get(i) == Some(&b' ') {
                i += 1;
            }
            if b.get(i) == Some(&b'}') {
                i += 1;
                break;
            }
            let eq = line[i..].find('=').ok_or("a label without =")? + i;
            let key = line[i..eq].trim().to_string();
            if key.is_empty() || b.get(eq + 1) != Some(&b'"') {
                return Err("a label without a quoted value");
            }
            i = eq + 2;
            let mut value = Vec::new();
            loop {
                match b.get(i) {
                    None => return Err("an unterminated label value"),
                    Some(b'"') => break,
                    Some(b'\\') => {
                        value.push(match b.get(i + 1) {
                            Some(b'n') => b'\n',
                            Some(b'\\') => b'\\',
                            Some(b'"') => b'"',
                            _ => return Err("a bad escape in a label value"),
                        });
                        i += 2;
                    }
                    Some(c) => {
                        value.push(*c);
                        i += 1;
                    }
                }
            }
            i += 1;
            labels.insert(key, String::from_utf8(value).map_err(|_| "a label value that is not UTF-8")?);
            match b.get(i) {
                Some(b',') => i += 1,
                Some(b'}') => {}
                _ => return Err("a label set not closed by }"),
            }
        }
    }
    // The value, then an optional timestamp that nothing here uses.
    let value = line[i..].split_whitespace().next().ok_or("no value")?.parse::<f64>().map_err(|_| "a value that is not a float")?;
    Ok(Sample { name, labels, value })
}

/// The sum of the values of the samples of `metric` whose labels include every pair of
/// `labels`; `None` when no sample matches, which is not the same as a sum of 0.
pub fn select(samples: &[Sample], metric: &str, labels: &BTreeMap<String, String>) -> Option<f64> {
    let mut hits = samples.iter().filter(|s| s.name == metric && labels.iter().all(|(k, v)| s.labels.get(k) == Some(v))).map(|s| s.value).peekable();
    hits.peek()?;
    Some(hits.sum())
}

/// Everything the checker touches outside itself, so the clock and the reads can be
/// scripted in tests.
pub trait World {
    /// Unix seconds now.
    fn unix_now(&self) -> f64;
    /// Seconds since the check began.
    fn elapsed(&self) -> f64;
    fn sleep(&mut self, d: Duration);
    /// The exposition text, or why it cannot be had (yet).
    fn read(&mut self) -> Result<String, String>;
}

#[derive(Debug, Clone, Default)]
struct Track {
    /// `Some` after the first read of the run; the inner value is what that read found.
    baseline: Option<Option<f64>>,
    risen: bool,
}

impl Track {
    fn see(&mut self, got: Option<f64>) {
        match self.baseline {
            None => self.baseline = Some(got),
            Some(Some(first)) if got.is_some_and(|g| g > first) => self.risen = true,
            _ => {}
        }
    }
}

fn holds(e: &Expectation, got: Option<f64>, now: f64, track: &Track) -> bool {
    let want = e.value.unwrap_or(0.0);
    match e.op {
        Op::Absent => got.is_none(),
        Op::Increases => track.risen,
        _ => match got {
            None => false,
            Some(g) => match e.op {
                Op::Eq => close(g, want),
                Op::Ne => !close(g, want) && !g.is_nan(),
                Op::Ge => g >= want,
                Op::Le => g <= want,
                Op::Gt => g > want,
                Op::Lt => g < want,
                Op::AgeBelow => now - g < want,
                Op::Absent | Op::Increases => unreachable!(),
            },
        },
    }
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= TOLERANCE * a.abs().max(b.abs()).max(1.0)
}

#[derive(Debug, PartialEq)]
pub struct Report {
    pub lines: Vec<String>,
    pub failed: usize,
}

/// Reads until every expectation holds at the same read, or `within` is over; with a zero
/// `within` it reads once. An `increases` expectation is sticky once the value has risen,
/// the others are judged on the latest read. A read that fails is retried, and only when
/// no read ever succeeded does that decide the outcome: after one success the last good
/// read stands, and the expectations about time (`age_below`) see it grow stale.
pub fn check(spec: &Spec, world: &mut dyn World, within: Duration, every: Duration) -> Report {
    let (within, every) = (within.as_secs_f64(), every.as_secs_f64());
    let mut tracks = vec![Track::default(); spec.expectations.len()];
    let mut samples: Option<Vec<Sample>> = None;
    let mut unreadable = String::new();
    let mut verdicts: Vec<(Option<f64>, bool)>;
    loop {
        match world.read().and_then(|t| parse_exposition(&t)) {
            Ok(fresh) => {
                for (e, t) in spec.expectations.iter().zip(&mut tracks) {
                    t.see(select(&fresh, &e.metric, &e.labels));
                }
                samples = Some(fresh);
            }
            Err(why) => unreadable = why,
        }
        let now = world.unix_now();
        verdicts = spec
            .expectations
            .iter()
            .zip(&tracks)
            .map(|(e, t)| {
                let got = samples.as_deref().and_then(|s| select(s, &e.metric, &e.labels));
                (got, samples.is_some() && holds(e, got, now, t))
            })
            .collect();
        let left = within - world.elapsed();
        if verdicts.iter().all(|v| v.1) || left <= 0.0 {
            break;
        }
        world.sleep(Duration::from_secs_f64(every.min(left)));
    }

    let after = world.elapsed().round() as u64;
    let mut lines = Vec::new();
    if samples.is_none() {
        lines.push(format!("{unreadable}; waited {after} s"));
    }
    let mut failed = 0;
    for (e, (got, pass)) in spec.expectations.iter().zip(&verdicts) {
        let shown = match (got, samples.is_some()) {
            (Some(v), _) => v.to_string(),
            (None, true) => "absent".to_string(),
            (None, false) => "unreadable".to_string(),
        };
        if *pass {
            lines.push(format!("ok   {}: {} = {} ({})", e.name, e.series(), shown, e.wanted()));
        } else {
            failed += 1;
            lines.push(format!("FAIL {}: {} is {}, expected {}, after {} s; {}", e.name, e.series(), shown, e.wanted(), after, e.why));
        }
    }
    Report { lines, failed }
}

#[derive(Debug, Clone)]
pub enum Source {
    Metrics(PathBuf),
    State { dir: PathBuf, targets: Option<PathBuf> },
}

struct Live {
    source: Source,
    began: Instant,
}

impl World for Live {
    fn unix_now(&self) -> f64 {
        unix_now()
    }

    fn elapsed(&self) -> f64 {
        self.began.elapsed().as_secs_f64()
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn read(&mut self) -> Result<String, String> {
        match &self.source {
            Source::Metrics(path) => std::fs::read_to_string(path).map_err(|e| {
                format!(
                    "cannot read {} (the metrics file the service writes): {e}; start the service with --metrics, give this user read access, or fix --metrics",
                    path.display()
                )
            }),
            Source::State { dir, targets } => {
                // State::load treats a missing log as an empty one, which would turn a typo
                // into a service that has run nothing.
                if !dir.is_dir() {
                    return Err(format!("cannot read {} (the state directory); the service has not created it, or fix --state", dir.display()));
                }
                let st = State::load(dir).map_err(|e| format!("cannot read the state in {}: {e:#}", dir.display()))?;
                let tf = targets.as_deref().map(TargetsFile::load).transpose().map_err(|e| format!("{e:#}"))?;
                Ok(metrics::render(&metrics::from_logs(&st, tf.as_ref())))
            }
        }
    }
}

pub struct Config {
    pub spec: PathBuf,
    pub source: Source,
    pub within: Duration,
    pub every: Duration,
}

fn read_spec(path: &Path) -> Result<Spec, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {} (the expectations): {e}; pass --spec <file.json>", path.display()))?;
    parse_spec(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Exit 0 when every expectation holds, 1 when any does not, 2 when the spec or the
/// arguments cannot be used.
pub fn command(c: Config) -> ExitCode {
    let spec = match read_spec(&c.spec).and_then(|s| s.check_usage(c.within).map(|()| s)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("keel-judge: error: {e}");
            return ExitCode::from(2);
        }
    };
    let report = check(&spec, &mut Live { source: c.source, began: Instant::now() }, c.within, c.every);
    for l in &report.lines {
        println!("{l}");
    }
    if report.failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "\
# HELP keel_judge_quanta_total Quanta.
# TYPE keel_judge_quanta_total counter
keel_judge_quanta_total 8
keel_judge_state_damaged_lines 0
keel_judge_metrics_written_timestamp_seconds 1000.5
keel_judge_target_quanta_total{target=\"alpha\"} 5
keel_judge_target_quanta_total{target=\"zero\"} 2
keel_judge_target_quanta_total{target=\"crashy\"} 1
keel_judge_findings{target=\"crashy\",kind=\"rust-panic\"} 1
keel_judge_findings{target=\"crashy\",kind=\"timeout\"} 2
keel_judge_findings{target=\"alpha\",kind=\"timeout\"} 4
keel_judge_target_chosen_total{target=\"zero\",chosen_by=\"starved\"} 1 1700000000
";

    fn ex(op: &str, value: Option<f64>, metric: &str, labels: &[(&str, &str)]) -> Expectation {
        Expectation {
            name: "n".into(),
            metric: metric.into(),
            labels: labels.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            op: OPS.iter().find(|(w, _)| *w == op).unwrap().1,
            value,
            why: "because".into(),
        }
    }

    /// Scripted reads and a clock that moves only when the checker sleeps.
    struct Fake {
        reads: Vec<Result<String, String>>,
        next: usize,
        t: f64,
        unix0: f64,
        slept: Vec<f64>,
    }

    impl Fake {
        fn new(reads: Vec<Result<String, String>>) -> Fake {
            Fake { reads, next: 0, t: 0.0, unix0: 1000.0, slept: vec![] }
        }

        fn texts(texts: &[&str]) -> Fake {
            Fake::new(texts.iter().map(|t| Ok(t.to_string())).collect())
        }
    }

    impl World for Fake {
        fn unix_now(&self) -> f64 {
            self.unix0 + self.t
        }
        fn elapsed(&self) -> f64 {
            self.t
        }
        fn sleep(&mut self, d: Duration) {
            self.t += d.as_secs_f64();
            self.slept.push(d.as_secs_f64());
        }
        fn read(&mut self) -> Result<String, String> {
            let r = self.reads[self.next.min(self.reads.len() - 1)].clone();
            self.next += 1;
            r
        }
    }

    fn once(e: Expectation, text: &str) -> Report {
        check(&Spec { expectations: vec![e] }, &mut Fake::texts(&[text]), Duration::ZERO, Duration::from_secs(2))
    }

    fn passes(op: &str, value: Option<f64>, metric: &str, labels: &[(&str, &str)]) -> bool {
        once(ex(op, value, metric, labels), TEXT).failed == 0
    }

    #[test]
    fn every_comparison_op_holds_and_fails_where_it_should() {
        let q = "keel_judge_quanta_total";
        for (op, yes, no) in [("==", 8.0, 9.0), ("!=", 9.0, 8.0), (">=", 8.0, 9.0), ("<=", 8.0, 7.0), (">", 7.0, 8.0), ("<", 9.0, 8.0)] {
            assert!(passes(op, Some(yes), q, &[]), "{op} {yes}");
            assert!(!passes(op, Some(no), q, &[]), "{op} {no}");
        }
    }

    #[test]
    fn an_absent_value_fails_every_comparison_and_only_absent_accepts_it() {
        for op in ["==", "!=", ">=", "<=", ">", "<"] {
            assert!(!passes(op, Some(0.0), "keel_judge_nothing", &[]), "{op}");
        }
        assert!(!passes("age_below", Some(10.0), "keel_judge_nothing", &[]));
        assert!(passes("absent", None, "keel_judge_nothing", &[]));
        assert!(passes("absent", None, "keel_judge_target_quanta_total", &[("target", "laws")]));
        assert!(!passes("absent", None, "keel_judge_quanta_total", &[]));
        // A series that exists with the value 0 is not absent.
        assert!(!passes("absent", None, "keel_judge_state_damaged_lines", &[]));
    }

    #[test]
    fn labels_select_by_subset_and_the_selection_is_summed() {
        let q = "keel_judge_target_quanta_total";
        assert!(passes("==", Some(8.0), q, &[]));
        assert!(passes("==", Some(5.0), q, &[("target", "alpha")]));
        // Over kinds, for one target.
        assert!(passes("==", Some(3.0), "keel_judge_findings", &[("target", "crashy")]));
        assert!(passes("==", Some(1.0), "keel_judge_findings", &[("target", "crashy"), ("kind", "rust-panic")]));
        assert!(passes("==", Some(7.0), "keel_judge_findings", &[]));
        assert!(passes("==", Some(6.0), "keel_judge_findings", &[("kind", "timeout")]));
        // One pair that matches and one that does not selects nothing.
        assert!(passes("absent", None, "keel_judge_findings", &[("target", "crashy"), ("kind", "oom")]));
        // A label value is compared whole, not as a prefix.
        assert!(passes("absent", None, q, &[("target", "alp")]));
    }

    #[test]
    fn equality_tolerates_float_sums_but_ordering_is_exact() {
        let text = "m{a=\"1\"} 0.1\nm{a=\"2\"} 0.2\n";
        let eq = once(ex("==", Some(0.3), "m", &[]), text);
        assert_eq!(eq.failed, 0, "{:?}", eq.lines);
        assert_eq!(once(ex("!=", Some(0.3), "m", &[]), text).failed, 1);
        // 0.1 + 0.2 is 0.30000000000000004, so the exact bound `<= 0.3` refuses it.
        assert_eq!(once(ex("<=", Some(0.3), "m", &[]), text).failed, 1);
    }

    #[test]
    fn age_below_uses_the_clock_it_is_given() {
        let e = || Spec { expectations: vec![ex("age_below", Some(180.0), "keel_judge_metrics_written_timestamp_seconds", &[])] };
        let run = |unix0: f64| {
            let mut w = Fake::texts(&[TEXT]);
            w.unix0 = unix0;
            check(&e(), &mut w, Duration::ZERO, Duration::from_secs(2)).failed
        };
        assert_eq!(run(1000.5 + 179.0), 0);
        assert_eq!(run(1000.5 + 180.0), 1);
        // A timestamp in the future is younger than any age.
        assert_eq!(run(900.0), 0);
    }

    #[test]
    fn a_file_that_goes_stale_while_polling_fails_age_below() {
        // The second expectation never holds, which keeps the check polling the whole window.
        let spec = Spec {
            expectations: vec![
                ex("age_below", Some(10.0), "keel_judge_metrics_written_timestamp_seconds", &[]),
                Expectation { name: "never".into(), ..ex("==", Some(99.0), "keel_judge_quanta_total", &[]) },
            ],
        };
        let mut w = Fake::texts(&[TEXT]);
        w.unix0 = 1000.5 + 8.0;
        let r = check(&spec, &mut w, Duration::from_secs(6), Duration::from_secs(2));
        assert_eq!(r.failed, 2, "{:?}", r.lines);
        assert!(r.lines[0].starts_with("FAIL n: ") && r.lines[0].ends_with("after 6 s; because"), "{:?}", r.lines);
    }

    #[test]
    fn increases_compares_the_first_read_with_a_later_one() {
        let spec = Spec { expectations: vec![ex("increases", None, "keel_judge_quanta_total", &[])] };
        let mut w = Fake::texts(&["keel_judge_quanta_total 4\n", "keel_judge_quanta_total 4\n", "keel_judge_quanta_total 5\n"]);
        let r = check(&spec, &mut w, Duration::from_secs(30), Duration::from_secs(2));
        assert_eq!(r.failed, 0, "{:?}", r.lines);
        assert_eq!(r.lines, ["ok   n: keel_judge_quanta_total = 5 (increases)"]);
        // It stopped at the read that passed.
        assert_eq!(w.slept, [2.0, 2.0]);
    }

    #[test]
    fn increases_that_never_rises_fails_after_the_whole_window() {
        let spec = Spec { expectations: vec![ex("increases", None, "keel_judge_quanta_total", &[])] };
        let mut w = Fake::texts(&["keel_judge_quanta_total 4\n"]);
        let r = check(&spec, &mut w, Duration::from_secs(5), Duration::from_secs(2));
        assert_eq!(r.lines, ["FAIL n: keel_judge_quanta_total is 4, expected increases, after 5 s; because"]);
        // The last sleep is cut to what was left of the window.
        assert_eq!(w.slept, [2.0, 2.0, 1.0]);
    }

    #[test]
    fn increases_needs_a_value_at_the_first_read() {
        let spec = Spec { expectations: vec![ex("increases", None, "keel_judge_quanta_total", &[])] };
        let mut w = Fake::texts(&["", "keel_judge_quanta_total 1\n", "keel_judge_quanta_total 9\n"]);
        let r = check(&spec, &mut w, Duration::from_secs(6), Duration::from_secs(2));
        assert_eq!(r.lines, ["FAIL n: keel_judge_quanta_total is 9, expected increases, after 6 s; because"]);
        let r = check(&spec, &mut Fake::texts(&[""]), Duration::from_secs(2), Duration::from_secs(2));
        assert_eq!(r.lines, ["FAIL n: keel_judge_quanta_total is absent, expected increases, after 2 s; because"]);
    }

    #[test]
    fn polling_stops_at_the_first_read_where_everything_holds() {
        let spec = Spec { expectations: vec![ex(">=", Some(8.0), "keel_judge_quanta_total", &[])] };
        let mut w = Fake::texts(&["keel_judge_quanta_total 3\n", "keel_judge_quanta_total 8\n", "keel_judge_quanta_total 1\n"]);
        let r = check(&spec, &mut w, Duration::from_secs(300), Duration::from_secs(2));
        assert_eq!(r.failed, 0);
        assert_eq!(w.next, 2);
        // With a zero window there is one read and no sleep.
        let mut w = Fake::texts(&["keel_judge_quanta_total 3\n", "keel_judge_quanta_total 8\n"]);
        let r = check(&spec, &mut w, Duration::ZERO, Duration::from_secs(2));
        assert_eq!((r.failed, w.next, w.slept.len()), (1, 1, 0));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_retried_then_fails_naming_it() {
        let spec = Spec { expectations: vec![ex("==", Some(0.0), "keel_judge_state_damaged_lines", &[])] };
        let gone = Err("cannot read /m/x.prom (the metrics file the service writes): No such file".to_string());
        let mut w = Fake::new(vec![gone.clone(), gone.clone(), Ok("keel_judge_state_damaged_lines 0\n".into())]);
        assert_eq!(check(&spec, &mut w, Duration::from_secs(10), Duration::from_secs(2)).failed, 0);
        assert_eq!(w.next, 3);

        let r = check(&spec, &mut Fake::new(vec![gone]), Duration::from_secs(4), Duration::from_secs(2));
        assert_eq!(
            r.lines,
            [
                "cannot read /m/x.prom (the metrics file the service writes): No such file; waited 4 s",
                "FAIL n: keel_judge_state_damaged_lines is unreadable, expected == 0, after 4 s; because"
            ]
        );
    }

    #[test]
    fn a_file_that_stops_being_readable_keeps_its_last_good_read() {
        let spec = Spec { expectations: vec![ex("==", Some(0.0), "keel_judge_state_damaged_lines", &[])] };
        let mut w = Fake::new(vec![Ok("keel_judge_state_damaged_lines 3\n".into()), Err("gone".into())]);
        let r = check(&spec, &mut w, Duration::from_secs(4), Duration::from_secs(2));
        assert_eq!(r.lines, ["FAIL n: keel_judge_state_damaged_lines is 3, expected == 0, after 4 s; because"]);
    }

    #[test]
    fn a_text_that_is_not_exposition_is_a_failed_read() {
        let spec = Spec { expectations: vec![ex("absent", None, "m", &[])] };
        let r = check(&spec, &mut Fake::texts(&["m{a=\"1\" 2\n"]), Duration::ZERO, Duration::from_secs(2));
        assert_eq!(r.failed, 1);
        assert!(r.lines[0].starts_with("line 1 is not a sample (a label set not closed by })"), "{:?}", r.lines);
    }

    #[test]
    fn the_report_lines_read_exactly() {
        let spec = Spec {
            expectations: vec![
                Expectation { name: "cold-start".into(), ..ex(">=", Some(8.0), "keel_judge_quanta_total", &[]) },
                Expectation { name: "no-laws".into(), ..ex("absent", None, "keel_judge_target_quanta_total", &[("target", "laws")]) },
                Expectation { name: "crashy-once".into(), why: "a target with a finding must not run again".into(), ..ex("==", Some(1.0), "keel_judge_target_quanta_total", &[("target", "crashy")]) },
                Expectation { name: "fresh".into(), ..ex("age_below", Some(180.0), "keel_judge_metrics_written_timestamp_seconds", &[]) },
                Expectation { name: "missing".into(), why: "w".into(), ..ex("<", Some(2.5), "keel_judge_nothing", &[("a", "b\"c"), ("z", "1")]) },
            ],
        };
        let r = check(&spec, &mut Fake::texts(&[TEXT]), Duration::ZERO, Duration::from_secs(2));
        assert_eq!(
            r.lines,
            [
                "ok   cold-start: keel_judge_quanta_total = 8 (>= 8)",
                "ok   no-laws: keel_judge_target_quanta_total{target=\"laws\"} = absent (absent)",
                "ok   crashy-once: keel_judge_target_quanta_total{target=\"crashy\"} = 1 (== 1)",
                "ok   fresh: keel_judge_metrics_written_timestamp_seconds = 1000.5 (age_below 180)",
                "FAIL missing: keel_judge_nothing{a=\"b\\\"c\",z=\"1\"} is absent, expected < 2.5, after 0 s; w",
            ]
        );
        assert_eq!(r.failed, 1);

        let bad = once(Expectation { why: "a target with a finding must not run again".into(), ..ex("==", Some(2.0), "keel_judge_target_quanta_total", &[("target", "crashy")]) }, TEXT);
        assert_eq!(
            bad.lines,
            ["FAIL n: keel_judge_target_quanta_total{target=\"crashy\"} is 1, expected == 2, after 0 s; a target with a finding must not run again"]
        );
    }

    #[test]
    fn the_exposition_parser_reads_escapes_timestamps_and_special_floats() {
        let s = parse_exposition("# c\n\na{k=\"x\\\"y\\\\z\\nw\",j=\"é\"} +Inf 1700\nb NaN\nc{} 1\nd\t2\n").unwrap();
        assert_eq!(s.len(), 4);
        assert_eq!(s[0].labels["k"], "x\"y\\z\nw");
        assert_eq!(s[0].labels["j"], "é");
        assert!(s[0].value.is_infinite() && s[1].value.is_nan());
        assert_eq!((s[2].name.as_str(), s[2].labels.len(), s[3].value), ("c", 0, 2.0));
        for bad in ["a", "a{k=\"v} 1", "a{k=v} 1", "a{k=\"v\"x} 1", "a 1x", "a{k=\"\\q\"} 1", "{a=\"b\"} 1"] {
            assert!(parse_exposition(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn what_the_supervisor_renders_is_what_the_checker_reads() {
        let samples = parse_exposition(include_str!("../tests/data/metrics.prom")).unwrap();
        let sel = |m: &str, l: &[(&str, &str)]| select(&samples, m, &l.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect());
        assert_eq!(sel("keel_judge_quanta_total", &[]), Some(3.0));
        assert_eq!(sel("keel_judge_target_quanta_total", &[]), Some(3.0));
        assert_eq!(sel("keel_judge_findings", &[("target", "pack-decode")]), Some(2.0));
        assert_eq!(sel("keel_judge_target_features", &[("target", "ref-parse")]), None);
        assert_eq!(sel("keel_judge_metrics_written_timestamp_seconds", &[]), Some(1_763_164_800.5));
    }

    fn spec_with(field: &str) -> String {
        format!(r#"{{"schema":"{SPEC_SCHEMA}","expectations":[{{"name":"ok","metric":"m","op":"absent","why":"w"}},{{"name":"bad","metric":"m","op":"==","value":1,"why":"w",{field}}}]}}"#)
    }

    #[test]
    fn a_well_formed_spec_reads_with_defaults() {
        let s = parse_spec(&spec_with(r#""labels":{"target":"a"}"#)).unwrap();
        assert_eq!(s.expectations.len(), 2);
        assert!(s.expectations[0].labels.is_empty() && s.expectations[0].value.is_none());
        assert_eq!(s.expectations[1].labels["target"], "a");
        assert_eq!(s.expectations[1].op, Op::Eq);
        // A null is how a Nix attrset with an unset value may arrive.
        assert!(parse_spec(&spec_with(r#""labels":null"#)).is_ok());
    }

    #[test]
    fn a_malformed_spec_names_the_expectation_and_the_field() {
        let err = |text: String| parse_spec(&text).unwrap_err();
        let base = |item: &str| format!(r#"{{"schema":"{SPEC_SCHEMA}","expectations":[{item}]}}"#);
        let e = err(base(r#"{"name":"a","metric":"m","op":"~","value":1,"why":"w"}"#));
        assert!(e.contains("expectations[0] (\"a\").op is \"~\"") && e.contains("age_below"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"==","why":"w"}"#));
        assert!(e.contains("expectations[0] (\"a\").value is missing"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"absent","value":0,"why":"w"}"#));
        assert!(e.contains(".value is set") && e.contains("remove it"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"==","value":"1","why":"w"}"#));
        assert!(e.contains(".value is \"1\", not a number"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"==","value":1}"#));
        assert!(e.contains("expectations[0] (\"a\").why is missing"), "{e}");
        let e = err(base(r#"{"name":"a","op":"==","value":1,"why":"w"}"#));
        assert!(e.contains(".metric is missing"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"9m","op":"absent","why":"w"}"#));
        assert!(e.contains(".metric is \"9m\""), "{e}");
        let e = err(base(r#"{"metric":"m","op":"absent","why":"w"}"#));
        assert!(e.starts_with("expectations[0].name is missing"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"absent","why":"w","lables":{}}"#));
        assert!(e.contains("unknown field \"lables\""), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"absent","why":"w","labels":{"t":1}}"#));
        assert!(e.contains(".labels.t is 1, not a string"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"absent","why":"w","labels":[]}"#));
        assert!(e.contains(".labels is []"), "{e}");
        let e = err(base(r#"{"name":"a","metric":"m","op":"absent","why":"w"},{"name":"a","metric":"m","op":"absent","why":"w"}"#));
        assert!(e.contains("expectations[1] repeats the name \"a\""), "{e}");
        let e = err(base(r#"3"#));
        assert!(e.starts_with("expectations[0] is not an object"), "{e}");
        let e = err(base(""));
        assert!(e.contains("is empty") && e.contains("proves nothing"), "{e}");
    }

    #[test]
    fn a_spec_for_another_schema_or_not_json_is_refused() {
        assert!(parse_spec("{").unwrap_err().contains("not JSON"));
        assert!(parse_spec("[]").unwrap_err().contains("not a JSON object"));
        let e = parse_spec(r#"{"schema":"keel.judge.expect.v2","expectations":[]}"#).unwrap_err();
        assert!(e.contains("keel.judge.expect.v2") && e.contains(SPEC_SCHEMA), "{e}");
        assert!(parse_spec(&format!(r#"{{"schema":"{SPEC_SCHEMA}"}}"#)).unwrap_err().contains("`expectations`"));
        assert!(parse_spec(&format!(r#"{{"schema":"{SPEC_SCHEMA}","expectations":[],"extra":1}}"#)).unwrap_err().contains("unknown field \"extra\""));
    }

    #[test]
    fn increases_with_a_single_read_is_a_usage_error() {
        let spec = Spec { expectations: vec![Expectation { name: "grows".into(), ..ex("increases", None, "keel_judge_quanta_total", &[]) }] };
        let e = spec.check_usage(Duration::ZERO).unwrap_err();
        assert!(e.contains("\"grows\"") && e.contains("--within"), "{e}");
        assert!(spec.check_usage(Duration::from_secs(1)).is_ok());
        assert!(Spec { expectations: vec![ex("==", Some(1.0), "m", &[])] }.check_usage(Duration::ZERO).is_ok());
    }
}
