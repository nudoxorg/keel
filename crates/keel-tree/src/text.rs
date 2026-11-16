//! Small text helpers shared by resolution and rendering.

/// Levenshtein distance over chars; names here are short, so O(n*m) is fine.
pub fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev[j] + usize::from(ca != cb);
            cur.push(sub.min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Up to `k` candidates close to `name`. A candidate is close when it is a few
/// edits away or shares a long affix; anything farther is noise, and saying
/// nothing is better than suggesting an unrelated crate.
pub fn near<'a>(name: &str, candidates: impl IntoIterator<Item = &'a str>, k: usize) -> Vec<String> {
    let limit = name.len() / 3 + 3;
    let mut scored: Vec<(usize, &str)> = candidates
        .into_iter()
        .map(|c| (distance(name, c), c))
        .filter(|(d, c)| *d <= limit || c.contains(name) || name.contains(c))
        .collect();
    scored.sort();
    scored.dedup();
    scored.into_iter().take(k).map(|(_, c)| c.to_owned()).collect()
}

pub fn list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join(", ")
    }
}

/// Left-aligns every column but the last, two spaces apart.
pub fn table(rows: &[Vec<String>]) -> String {
    let cols = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut width = vec![0usize; cols];
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i + 1 < r.len() {
                width[i] = width[i].max(c.chars().count());
            }
        }
    }
    let mut out = String::new();
    for r in rows {
        let mut line = String::new();
        for (i, c) in r.iter().enumerate() {
            if i + 1 < r.len() {
                line.push_str(c);
                for _ in c.chars().count()..width[i] + 2 {
                    line.push(' ');
                }
            } else {
                line.push_str(c);
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `plural` for counts that are shown with thousands separators.
pub fn counted(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", num(n), if n == 1 { one } else { many })
}

/// Wraps `s` at `width` columns, indenting continuation lines.
pub fn wrap(s: &str, indent: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::from(indent);
    for word in s.split_whitespace() {
        if line.len() > indent.len() && line.len() + 1 + word.len() > width {
            out.push_str(&line);
            out.push('\n');
            line = String::from(indent);
        }
        if line.len() > indent.len() {
            line.push(' ');
        }
        line.push_str(word);
    }
    out.push_str(&line);
    out.push('\n');
    out
}

/// Thousands separators, because 64777 is harder to read than 64,777.
pub fn num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
