//! What the two PR comments (`tree --results --comment`, `plan --comment`) share: the size
//! rule. A comment is a short head that says the verdict and what to do, and the whole
//! report folded under it. The head is never cut; when the body would pass the limit, the
//! folded report is cut at a line and says how much is left out and where the rest is.

use crate::text::num;

/// GitHub refuses a comment body over 65,536 characters and Forgejo's limit is about the
/// same. The margin keeps the head, the fold and the clipping note on the right side of it.
pub const LIMIT: usize = 60_000;

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// A fence longer than any run of backticks in `text`, so a test name or a path with
/// backticks in it cannot end the block early.
fn fence_for(text: &str) -> String {
    let mut longest = 0;
    let mut run = 0;
    for c in text.chars() {
        run = if c == '`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    "`".repeat((longest + 1).max(3))
}

fn block(summary: &str, shown: &str, note: Option<&str>, fence: &str) -> String {
    // The blank line after <summary> is what makes GitHub render the Markdown inside.
    let mut o = format!("<details><summary>{summary}</summary>\n\n{fence}text\n{shown}");
    if !shown.is_empty() && !shown.ends_with('\n') {
        o.push('\n');
    }
    o.push_str(fence);
    o.push('\n');
    if let Some(n) = note {
        o.push('\n');
        o.push_str(n);
        o.push('\n');
    }
    o.push_str("\n</details>\n");
    o
}

/// `head` and `tail` end with a newline (`tail` may be empty); `text` is the whole report,
/// `what` names it in the clipping note ("tree", "plan").
pub fn assemble(head: &str, summary: &str, what: &str, text: &str, tail: &str) -> String {
    let fence = fence_for(text);
    let join = |details: &str| {
        let mut o = format!("{head}\n{details}");
        if !tail.is_empty() {
            o.push('\n');
            o.push_str(tail);
        }
        o
    };
    let whole = join(&block(summary, text, None, &fence));
    if chars(&whole) <= LIMIT {
        return whole;
    }
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let words = |left: usize, shown: usize| {
        (
            format!("{summary} (the first {} of {} lines)", num(shown as u64), num(lines.len() as u64)),
            format!(
                "{} of the {what}'s {} lines are left out so that this comment stays under the size limit. The whole {what} is in the CI log of the run that posted this comment.",
                num(left as u64),
                num(lines.len() as u64)
            ),
        )
    };
    // Counted with the largest numbers the note can carry, so the cut can only come out shorter.
    let (s, n) = words(lines.len(), lines.len());
    let fixed = chars(&join(&block(&s, "", Some(&n), &fence)));
    let budget = LIMIT.saturating_sub(fixed);
    let mut used = 0;
    let mut kept = 0;
    for l in &lines {
        if used + chars(l) > budget {
            break;
        }
        used += chars(l);
        kept += 1;
    }
    let shown: String = lines[..kept].concat();
    let (s, n) = words(lines.len() - kept, kept);
    join(&block(&s, &shown, Some(&n), &fence))
}

/// A test as nextest names it: the binary, then the test's path.
pub fn test_name(id: &str) -> String {
    id.replacen('$', " ", 1)
}

/// `names` as backticked, comma-separated, with how many more there were.
pub fn first_of(names: &[String], k: usize) -> String {
    let mut s: Vec<String> = names.iter().take(k).map(|n| format!("`{n}`")).collect();
    if names.len() > k {
        s.push(format!("and {} more", num((names.len() - k) as u64)));
    }
    s.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_small_report_is_folded_whole() {
        let c = assemble("**head**\n", "The trees", "tree", "a\nb\n", "");
        assert_eq!(c, "**head**\n\n<details><summary>The trees</summary>\n\n```text\na\nb\n```\n\n</details>\n");
    }

    #[test]
    fn a_long_report_is_cut_at_a_line_and_the_head_and_tail_stay_whole() {
        let text: String = (0..20_000).map(|i| format!("line {i} of a very long tree\n")).collect();
        let head = "**Keel: 5 of 6 features fail.**\n";
        let tail = "Not mapped: 2 result lines.\n";
        let c = assemble(head, "The trees", "tree", &text, tail);
        assert!(chars(&c) <= LIMIT, "{} characters", chars(&c));
        assert!(chars(&c) > LIMIT - 300, "the cut leaves room unused: {}", chars(&c));
        assert!(c.starts_with(head) && c.ends_with(&format!("</details>\n\n{tail}")));
        assert!(c.contains("The trees (the first ") && c.contains(" of 20,000 lines)"));
        assert!(c.contains("lines are left out so that this comment stays under the size limit. The whole tree is in the CI log"));
        // Cut between lines, never inside one.
        let body = c.split("```text\n").nth(1).unwrap().split("```").next().unwrap();
        assert!(body.lines().all(|l| l.starts_with("line ") && l.ends_with("a very long tree")));
    }

    #[test]
    fn backticks_in_the_report_get_a_longer_fence() {
        let c = assemble("h\n", "s", "tree", "```\nx\n", "");
        assert!(c.contains("````text\n```\nx\n````\n"));
    }
}
