//! Pattern selectors, matched by ast-grep over tree-sitter syntax trees.
//!
//! `pattern "<language>" "<pattern>"` is an ast-grep pattern: code with
//! metavariables (`$NAME` one node, `$$$ARGS` any run of nodes) that matches
//! the syntax trees of the tracked files of that language. One engine serves
//! every language ast-grep has a grammar for, so a selector can name a C
//! function a Rust crate builds, a TypeScript handler or a Python entry point
//! the same way.
//!
//! The one addition on top of ast-grep is a Rust-only adapter. tree-sitter's
//! Rust grammar makes an attribute a *sibling* of the item it decorates, so
//! `#[tool] async fn $N($$$A) { $$$B }` is two root nodes, which ast-grep
//! refuses as a pattern. Such a pattern is split into its leading attribute
//! patterns and its item pattern: the item matches by ast-grep as usual and
//! each attribute pattern must match one of the attributes directly above it.
//! Every part is still matched by ast-grep; the adapter only joins them.

use ast_grep_core::matcher::{Pattern, PatternNode};
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Language, Node};
use ast_grep_language::SupportLang;
use memchr::memmem;
use rayon::prelude::*;
use serde::Serialize;
use std::path::Path;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Instant;

/// Files over this many bytes are not parsed. Parse time and tree memory grow
/// with size, and the files this large in a repository are almost always
/// generated (a parser table, a bundle, a data dump). Each one skipped is
/// reported, never silently dropped.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct Enclosing {
    pub kind: String,
    pub name: Option<String>,
    /// 1-based, inclusive.
    pub start_line: u32,
    pub end_line: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct Match {
    /// Repo-relative.
    pub path: String,
    pub start_byte: usize,
    pub end_byte: usize,
    /// 1-based, inclusive; for the Rust attribute adapter the range starts at the
    /// first attribute above the item, as an index item's range does.
    pub start_line: u32,
    pub end_line: u32,
    /// The syntax kind of the matched node.
    pub kind: String,
    /// The first line of the matched text, trimmed.
    pub head: String,
    /// The named item (function, class, rule set) the match is or lies in, where the language has one.
    pub item: Option<Enclosing>,
}

impl Match {
    /// What identifies the match across edits that only move it: the item it is
    /// in when it has a name, else its kind and first line of text.
    pub fn key(&self) -> String {
        match &self.item {
            Some(Enclosing { kind, name: Some(n), .. }) => format!("{}:{kind}:{n}", self.path),
            _ => format!("{}:{}:{}", self.path, self.kind, self.head),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct Hits {
    /// The language as ast-grep names it.
    pub language: String,
    /// By path, then position.
    pub matches: Vec<Match>,
    /// Repo-relative files holding at least one match, sorted.
    pub files: Vec<String>,
    /// Tracked files whose extension belongs to the language.
    pub candidates: usize,
    /// Candidates ruled out by the literal prefilter without being parsed.
    pub prefiltered_out: usize,
    /// Candidates parsed and matched.
    pub parsed: usize,
    /// Parsed files where tree-sitter recovered from a syntax error, so a match
    /// inside the broken region may be missing or wrong.
    pub with_syntax_errors: Vec<String>,
    /// Candidates not parsed at all, and why. Each is a finding.
    pub skipped: Vec<Skipped>,
    /// Candidates were required to contain every text of at least one of these lists; empty when no filter applies.
    pub prefilter: Vec<Vec<String>>,
    pub millis: u128,
}

impl Hits {
    pub fn count(&self) -> usize {
        self.matches.len()
    }

    /// The matches in one file, in position order.
    pub fn in_file<'a>(&'a self, path: &'a str) -> impl Iterator<Item = &'a Match> + 'a {
        let lo = self.matches.partition_point(|m| m.path.as_str() < path);
        self.matches[lo..].iter().take_while(move |m| m.path == path)
    }
}

/// Why a selector's language or pattern was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    UnknownLanguage(String),
    Unparsable(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::UnknownLanguage(s) | Failure::Unparsable(s) => f.write_str(s),
        }
    }
}

/// The languages a pattern may name, as the selector spells them.
pub fn languages() -> Vec<String> {
    SupportLang::all_langs().iter().map(|l| l.to_string().to_lowercase()).collect()
}

pub fn language(name: &str) -> Result<SupportLang, Failure> {
    SupportLang::from_str(name).map_err(|_| {
        Failure::UnknownLanguage(format!(
            "language \"{name}\" is not one ast-grep has a grammar for here; the supported languages are {}. \
             Fix the language in the selector, or own the files with a path selector",
            languages().join(", ")
        ))
    })
}

enum Shape {
    /// No pattern: the matcher is a node kind (see `Parsed::kind_matches`).
    Kind,
    /// Alternatives: the pattern as written, and the same pattern read as an expression or
    /// statement inside a function body (see `in_function`). A node matching either matches.
    One(Vec<Pattern>),
    /// Rust: attribute patterns that must all sit directly above an item matching the last.
    Decorated { attrs: Vec<Pattern>, item: Pattern },
}

pub struct Compiled {
    lang: SupportLang,
    shape: Shape,
    /// A file matched by the pattern contains at least one of these. Empty: no filter.
    prefilter: Vec<Vec<String>>,
}

/// The first syntax error ast-grep's parser recovered from in `src`, if any,
/// as `line:column near <text>`. A *missing* token is not one: a fragment such as
/// `malloc($$$A)` is a statement without its `;`, and ast-grep matches it as written.
fn first_syntax_error(src: &str, lang: SupportLang) -> Option<String> {
    let doc = StrDoc::try_new(src, lang).ok()?;
    let root = AstGrep::doc(doc);
    let bad = root.root().dfs().find(|n| n.is_error())?;
    let at = bad.start_pos();
    let text: String = bad.text().chars().take(40).collect();
    Some(format!("{}:{} near `{}`", at.line() + 1, at.column(&bad) + 1, text.replace('\n', " ")))
}

fn build(src: &str, lang: SupportLang) -> Result<Pattern, String> {
    let p = Pattern::try_new(src, lang).map_err(|e| e.to_string())?;
    // tree-sitter recovers from errors with ERROR nodes instead of failing, so
    // a pattern that is not code in the language would otherwise match garbage.
    if let Some(at) = first_syntax_error(&lang.pre_process_pattern(src), lang) {
        return Err(format!("the pattern has a syntax error at {at}"));
    }
    Ok(p)
}

/// Where an expression or statement pattern can be read: tree-sitter parses a file's top level
/// as declarations, so `Utc::now()` is a syntax error in Rust and `malloc($A)` is a function
/// declaration in C. The pattern is placed inside a function body to read it as the call it is.
fn function_body(lang: SupportLang) -> Option<(&'static str, &'static str)> {
    use SupportLang as L;
    Some(match lang {
        L::Rust => ("fn __keel__() {\n", "\n}"),
        L::C => ("void __keel__(void) {\n", ";\n}"),
        L::Cpp => ("void __keel__() {\n", ";\n}"),
        L::Go => ("package __keel__\nfunc __keel__() {\n", "\n}"),
        L::Java => ("class __Keel__ { void f() {\n", ";\n} }"),
        L::CSharp => ("class __Keel__ { void F() {\n", ";\n} }"),
        _ => return None,
    })
}

/// The pattern read inside a function body, when that reads as one expression or statement.
fn in_function(src: &str, lang: SupportLang) -> Option<Pattern> {
    let (head, tail) = function_body(lang)?;
    let pre_pat = lang.pre_process_pattern(src).into_owned();
    let context = format!("{head}{pre_pat}{tail}");
    let doc = StrDoc::try_new(&context, lang).ok()?;
    let root = AstGrep::doc(doc);
    if root.root().dfs().any(|n| n.is_error()) {
        return None;
    }
    let span = head.len()..head.len() + pre_pat.len();
    // The outermost node inside the pattern's text is the one the pattern means.
    let node = root.root().dfs().find(|n| n.is_named() && span.contains(&n.range().start) && n.range().end <= span.end)?;
    let kind = node.kind();
    let expressionish = kind.ends_with("_expression")
        || kind.ends_with("_statement")
        || matches!(kind.as_ref(), "identifier" | "macro_invocation" | "scoped_identifier" | "invocation_expression" | "method_invocation");
    expressionish.then(|| Pattern::from(node))
}

/// Leading attribute items and the one item after them, as separate pattern sources.
fn split_decorated(src: &str, lang: SupportLang) -> Option<(Vec<String>, String)> {
    let pre = lang.pre_process_pattern(src).into_owned();
    let doc = StrDoc::try_new(&pre, lang).ok()?;
    let root = AstGrep::doc(doc);
    let kids: Vec<Node<'_, _>> = root.root().children().filter(|n| !n.is_extra()).collect();
    let (item, attrs) = kids.split_last()?;
    if attrs.is_empty() || item.kind() == "attribute_item" || !attrs.iter().all(|a| a.kind() == "attribute_item") {
        return None;
    }
    Some((attrs.iter().map(|a| a.text().into_owned()).collect(), item.text().into_owned()))
}

/// The texts that must occur verbatim in any file the pattern matches.
///
/// A named leaf of the pattern matches a candidate leaf only if their texts are
/// equal (ast-grep's `match_terminal`), and no strictness ast-grep applies here
/// lets a pattern leaf be skipped, so each such text is a substring of every
/// matching file. Unnamed leaves (keywords, punctuation) are matched by node
/// kind, and a grammar may give an unnamed node a kind that differs from its
/// text, so they are never used. Metavariable placeholders (and so anything
/// holding the language's expando character) are not literals.
fn literals(node: &PatternNode, expando: char, out: &mut Vec<String>) {
    match node {
        PatternNode::Terminal { text, is_named: true, .. } => {
            if !text.is_empty() && !text.contains(['$', expando]) {
                out.push(text.clone());
            }
        }
        PatternNode::Internal { children, .. } => children.iter().for_each(|c| literals(c, expando, out)),
        _ => {}
    }
}

pub fn compile(language_name: &str, pattern: &str) -> Result<Compiled, Failure> {
    let lang = language(language_name)?;
    let failed = |why: String| {
        Failure::Unparsable(format!(
            "pattern \"{pattern}\" does not parse as {lang}: {why}. Write the pattern as code in that language, \
             with $NAME for one node and $$$ARGS for several"
        ))
    };
    let shape = match build(pattern, lang) {
        Ok(p) => Shape::One(std::iter::once(p).chain(in_function(pattern, lang)).collect()),
        Err(_) if in_function(pattern, lang).is_some() => Shape::One(in_function(pattern, lang).into_iter().collect()),
        Err(first) => {
            let split = (lang == SupportLang::Rust && first.starts_with("Multiple AST nodes"))
                .then(|| split_decorated(pattern, lang))
                .flatten();
            match split {
                Some((attrs, item)) => Shape::Decorated {
                    attrs: attrs.iter().map(|a| build(a, lang)).collect::<Result<_, _>>().map_err(failed)?,
                    item: build(&item, lang).map_err(failed)?,
                },
                None if first.starts_with("Multiple AST nodes") && lang == SupportLang::Rust => {
                    return Err(failed(format!(
                        "{first} (a Rust pattern may be leading attributes followed by one item, such as `#[tool] async fn $N($$$A) {{ $$$B }}`, \
                         and nothing else with more than one root)"
                    )));
                }
                None => return Err(failed(first)),
            }
        }
    };
    // Every named leaf of an alternative must occur, so a file passes if it holds all the
    // literals of at least one alternative. Few and long literals are the useful ones.
    let literals_of = |pats: &[&Pattern]| -> Vec<String> {
        let mut lits = Vec::new();
        pats.iter().for_each(|p| literals(&p.node, lang.expando_char(), &mut lits));
        lits.sort_by_key(|l| std::cmp::Reverse(l.len()));
        lits.dedup();
        lits.truncate(6);
        lits.sort();
        lits
    };
    let prefilter: Vec<Vec<String>> = match &shape {
        Shape::Kind => Vec::new(),
        Shape::One(alts) => {
            let mut each: Vec<Vec<String>> = alts.iter().map(|p| literals_of(&[p])).collect();
            // An alternative with no literal passes every file, so there is no filter.
            if each.iter().any(Vec::is_empty) {
                Vec::new()
            } else {
                each.sort();
                each.dedup();
                each
            }
        }
        Shape::Decorated { attrs, item } => {
            let all: Vec<&Pattern> = attrs.iter().chain([item]).collect();
            Some(literals_of(&all)).filter(|l| !l.is_empty()).into_iter().collect()
        }
    };
    Ok(Compiled { lang, shape, prefilter })
}

/// Whether `bytes` holds, for some alternative, every literal of it. Empty `dnf` passes everything.
pub fn passes(dnf: &[Vec<String>], bytes: &[u8]) -> bool {
    dnf.is_empty() || dnf.iter().any(|alt| alt.iter().all(|l| memmem::find(bytes, l.as_bytes()).is_some()))
}

impl Compiled {
    /// A file with a match holds every text of at least one of these lists; empty means no filter applies.
    pub fn prefilter(&self) -> &[Vec<String>] {
        &self.prefilter
    }

    pub fn language(&self) -> String {
        self.lang.to_string().to_lowercase()
    }
}

/// Node kinds that are a named item in the language: what a match "is in".
fn item_kinds(lang: SupportLang) -> &'static [&'static str] {
    use SupportLang as L;
    match lang {
        L::Rust => &[
            "function_item", "impl_item", "trait_item", "struct_item", "enum_item", "union_item", "mod_item",
            "macro_definition", "const_item", "static_item", "type_item",
        ],
        L::C => &["function_definition", "struct_specifier", "enum_specifier", "union_specifier", "type_definition"],
        L::Cpp => &[
            "function_definition", "class_specifier", "struct_specifier", "enum_specifier", "namespace_definition",
            "union_specifier", "type_definition",
        ],
        L::JavaScript | L::TypeScript | L::Tsx => &[
            "function_declaration", "generator_function_declaration", "method_definition", "class_declaration",
            "abstract_class_declaration", "interface_declaration", "enum_declaration", "type_alias_declaration",
        ],
        L::Python => &["function_definition", "class_definition"],
        L::Go => &["function_declaration", "method_declaration", "type_spec"],
        L::Java => &[
            "method_declaration", "constructor_declaration", "class_declaration", "interface_declaration",
            "enum_declaration", "record_declaration",
        ],
        L::CSharp => &[
            "method_declaration", "constructor_declaration", "class_declaration", "struct_declaration",
            "interface_declaration", "enum_declaration", "record_declaration", "namespace_declaration",
        ],
        L::Css => &["rule_set", "keyframes_statement", "media_statement"],
        L::Bash => &["function_definition"],
        L::Ruby => &["method", "singleton_method", "class", "module"],
        L::Swift => &["function_declaration", "class_declaration", "protocol_declaration"],
        _ => &[],
    }
}

fn name_of<D: ast_grep_core::Doc>(node: &Node<'_, D>) -> Option<String> {
    let text = |n: Node<'_, D>| Some(n.text().lines().next().unwrap_or("").trim().to_owned()).filter(|s| !s.is_empty());
    // C and C++ name a function through its declarator chain (`*name(args)`); their `type` is the return type.
    if let Some(mut d) = node.field("declarator") {
        while let Some(inner) = d.field("declarator") {
            d = inner;
        }
        return text(d);
    }
    // `impl Trait for Type` is named by its type.
    node.field("name").or_else(|| node.field("type")).and_then(text)
}

fn enclosing<D: ast_grep_core::Doc>(node: &Node<'_, D>, lang: SupportLang) -> Option<Enclosing> {
    let kinds = item_kinds(lang);
    std::iter::once(node.clone()).chain(node.ancestors()).find(|n| kinds.contains(&n.kind().as_ref())).map(|n| {
        let (start, end) = lines(&n);
        Enclosing { kind: n.kind().into_owned(), name: name_of(&n), start_line: start, end_line: end }
    })
}

/// 1-based inclusive lines of a node. A node whose end sits at column 0 ended on
/// the previous line's newline, so that line is its last.
fn lines<D: ast_grep_core::Doc>(n: &Node<'_, D>) -> (u32, u32) {
    let start = n.start_pos().line() as u32 + 1;
    let (row, col) = n.end_pos().byte_point();
    let r = n.range();
    let end = if col == 0 && r.end > r.start { row as u32 } else { row as u32 + 1 };
    (start, end.max(start))
}

struct FileResult {
    matches: Vec<Match>,
    syntax_error: bool,
}

fn record<D: ast_grep_core::Doc>(out: &mut Vec<Match>, c: &Compiled, path: &str, node: &Node<'_, D>, from_byte: usize, from_line: u32) {
    let (start_line, end_line) = lines(node);
    out.push(Match {
        path: path.to_owned(),
        start_byte: from_byte,
        end_byte: node.range().end,
        start_line: from_line.min(start_line),
        end_line,
        kind: node.kind().into_owned(),
        head: node.text().lines().next().unwrap_or("").trim().chars().take(120).collect(),
        item: enclosing(node, c.lang),
    });
}

/// A parsed file, for callers that run several matchers over one parse.
pub struct Parsed {
    lang: SupportLang,
    root: AstGrep<StrDoc<SupportLang>>,
    pub syntax_error: bool,
}

pub fn parse(language_name: &str, src: &str) -> Result<Parsed, String> {
    let lang = language(language_name).map_err(|e| e.to_string())?;
    let doc = StrDoc::try_new(src, lang)?;
    let syntax_error = doc.tree.root_node().has_error();
    Ok(Parsed { lang, root: AstGrep::doc(doc), syntax_error })
}

type TreeNode<'r> = Node<'r, StrDoc<SupportLang>>;

impl Parsed {
    /// Every node of `kind` that `keep` accepts, as matches.
    pub fn kind_matches(&self, path: &str, kind: &str, keep: impl Fn(&Match) -> bool) -> Vec<Match> {
        let Ok(k) = ast_grep_core::matcher::KindMatcher::try_new(kind, self.lang) else { return Vec::new() };
        let mut out = Vec::new();
        for n in self.root.root().find_all(k) {
            let mut v = Vec::new();
            record(&mut v, &Compiled { lang: self.lang, shape: Shape::Kind, prefilter: Vec::new() }, path, &*n, n.range().start, lines(&n).0);
            out.extend(v.into_iter().filter(|m| keep(m)));
        }
        out
    }

    /// Byte ranges of the nodes of the given kinds that carry an attribute `is_attr` accepts.
    pub fn attributed_ranges(&self, kinds: &[&str], is_attr: impl Fn(&str) -> bool) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for kind in kinds {
            let Ok(k) = ast_grep_core::matcher::KindMatcher::try_new(kind, self.lang) else { continue };
            for n in self.root.root().find_all(k) {
                let mut cur = n.prev();
                while let Some(p) = cur {
                    if p.kind() == "attribute_item" && is_attr(&p.text()) {
                        out.push((n.range().start, n.range().end));
                        break;
                    }
                    if p.kind() != "attribute_item" && !p.is_extra() {
                        break;
                    }
                    cur = p.prev();
                }
            }
        }
        out
    }

    /// Byte ranges of every node of `kind`.
    pub fn ranges_of(&self, kind: &str) -> Vec<(usize, usize)> {
        let Ok(k) = ast_grep_core::matcher::KindMatcher::try_new(kind, self.lang) else { return Vec::new() };
        self.root.root().find_all(k).map(|n| (n.range().start, n.range().end)).collect()
    }
}

impl Compiled {
    /// The matches of this pattern in a parsed file.
    pub fn find_in(&self, parsed: &Parsed, path: &str) -> Vec<Match> {
        let root = &parsed.root;
        let mut matches = Vec::new();
        match &self.shape {
            Shape::Kind => {}
            Shape::One(alts) => {
                for p in alts {
                    for m in root.root().find_all(p) {
                        record(&mut matches, self, path, &*m, m.range().start, lines(&m).0);
                    }
                }
                // Alternatives can find the same node.
                matches.sort_by_key(|m| (m.start_byte, m.end_byte));
                matches.dedup_by_key(|m| (m.start_byte, m.end_byte));
            }
            Shape::Decorated { attrs, item } => {
                for m in root.root().find_all(item) {
                    // The attributes directly above the item, nearest first; comments between are skipped.
                    let mut above: Vec<TreeNode<'_>> = Vec::new();
                    let mut cur = m.prev();
                    while let Some(n) = cur {
                        if n.kind() == "attribute_item" {
                            above.push(n.clone());
                        } else if !n.is_extra() {
                            break;
                        }
                        cur = n.prev();
                    }
                    if attrs.iter().all(|a| above.iter().any(|n| n.matches(a))) {
                        let first = above.last().unwrap_or(&*m);
                        record(&mut matches, self, path, &*m, first.range().start, lines(first).0);
                    }
                }
            }
        }
        matches
    }
}

fn scan(c: &Compiled, path: &str, src: &str) -> Result<FileResult, String> {
    let parsed = parse(&c.language(), src)?;
    Ok(FileResult { matches: c.find_in(&parsed, path), syntax_error: parsed.syntax_error })
}

enum Outcome {
    Skipped(String),
    Filtered,
    Parsed(FileResult),
}

fn visit(c: &Compiled, root: &Path, path: &str) -> Outcome {
    let full = root.join(path);
    let meta = match std::fs::symlink_metadata(&full) {
        Ok(m) => m,
        Err(e) => return Outcome::Skipped(format!("unreadable: {e}")),
    };
    if meta.file_type().is_symlink() {
        return Outcome::Skipped("a symbolic link; its target is matched under its own path if tracked".to_owned());
    }
    if !meta.is_file() {
        return Outcome::Skipped("not a regular file (a submodule or directory)".to_owned());
    }
    if meta.len() > MAX_FILE_BYTES {
        return Outcome::Skipped(format!("{} bytes, over the {MAX_FILE_BYTES}-byte limit", meta.len()));
    }
    let bytes = match std::fs::read(&full) {
        Ok(b) => b,
        Err(e) => return Outcome::Skipped(format!("unreadable: {e}")),
    };
    if !passes(&c.prefilter, &bytes) {
        return Outcome::Filtered;
    }
    let Ok(src) = std::str::from_utf8(&bytes) else {
        return Outcome::Skipped("not valid UTF-8, which the parser needs".to_owned());
    };
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan(c, path, src))) {
        Ok(Ok(r)) => Outcome::Parsed(r),
        Ok(Err(e)) => Outcome::Skipped(format!("the parser gave up: {e}")),
        Err(_) => Outcome::Skipped("the parser panicked on this file".to_owned()),
    }
}

/// Deep trees recurse in the matcher, so workers get the same large stack the
/// index's parser pool does.
pub(crate) fn pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .stack_size(64 << 20)
            .build()
            .expect("the pattern worker pool starts")
    })
}

/// Matches `pattern` against the tracked files of `language_name`.
pub fn find(root: &Path, tracked: &[String], language_name: &str, pattern: &str) -> Result<Hits, Failure> {
    find_with(root, tracked, language_name, pattern, true)
}

/// `find`, with the prefilter switchable so a test can show it drops nothing.
pub fn find_with(root: &Path, tracked: &[String], language_name: &str, pattern: &str, prefilter: bool) -> Result<Hits, Failure> {
    let mut c = compile(language_name, pattern)?;
    if !prefilter {
        c.prefilter.clear();
    }
    let started = Instant::now();
    let types = c.lang.file_types();
    let candidates: Vec<&String> = tracked.iter().filter(|p| types.matched(p, false).is_whitelist()).collect();
    let outcomes: Vec<Outcome> = pool().install(|| {
        candidates.par_iter().map(|p| visit(&c, root, p)).collect()
    });
    let mut hits = Hits {
        language: c.language(),
        matches: Vec::new(),
        files: Vec::new(),
        candidates: candidates.len(),
        prefiltered_out: 0,
        parsed: 0,
        with_syntax_errors: Vec::new(),
        skipped: Vec::new(),
        prefilter: c.prefilter.clone(),
        millis: 0,
    };
    for (path, outcome) in candidates.iter().zip(outcomes) {
        match outcome {
            Outcome::Filtered => hits.prefiltered_out += 1,
            Outcome::Skipped(reason) => hits.skipped.push(Skipped { path: (*path).clone(), reason }),
            Outcome::Parsed(r) => {
                hits.parsed += 1;
                if r.syntax_error {
                    hits.with_syntax_errors.push((*path).clone());
                }
                hits.matches.extend(r.matches);
            }
        }
    }
    hits.matches.sort_by(|a, b| (&a.path, a.start_byte, a.end_byte).cmp(&(&b.path, b.start_byte, b.end_byte)));
    hits.files = hits.matches.iter().map(|m| m.path.clone()).collect();
    hits.files.dedup();
    hits.millis = started.elapsed().as_millis();
    Ok(hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracked(root: &Path) -> Vec<String> {
        let out = std::process::Command::new("git").arg("-C").arg(root).args(["ls-files", "-z"]).output().expect("git runs");
        out.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
    }

    fn same_with_and_without(root: &Path, cases: &[(&str, &str)]) {
        let files = tracked(root);
        for (lang, pat) in cases {
            let on = find_with(root, &files, lang, pat, true).unwrap();
            let off = find_with(root, &files, lang, pat, false).unwrap();
            let spans = |h: &Hits| h.matches.iter().map(|m| (m.path.clone(), m.start_byte, m.end_byte)).collect::<Vec<_>>();
            assert_eq!(spans(&on), spans(&off), "the prefilter {:?} changed what `{pat}` finds", on.prefilter);
            assert_eq!(off.prefiltered_out, 0);
        }
    }

    #[test]
    fn the_prefilter_changes_nothing_on_this_repository() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        same_with_and_without(
            &root,
            &[
                ("rust", "#[test] fn $N() { $$$B }"),
                ("rust", "Command::new($$$A)"),
                ("rust", "std::env::var($A)"),
                ("rust", "Utc::now()"),
                ("rust", "println!($$$A)"),
                ("nix", "pkgs.$N"),
                ("json", "{}"),
            ],
        );
    }

    /// Run by hand against a large tree: `KEEL_PREFILTER_ROOT=/path/to/repo cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn the_prefilter_changes_nothing_on_a_large_tree() {
        let root = std::env::var("KEEL_PREFILTER_ROOT").expect("KEEL_PREFILTER_ROOT names a git checkout");
        same_with_and_without(
            Path::new(&root),
            &[
                ("rust", "#[tool($$$M)] pub async fn $N($$$A) -> $R { $$$B }"),
                ("rust", "Command::new($$$A)"),
                ("c", "free($A)"),
                ("typescript", "console.log($$$A)"),
                ("python", "print($$$A)"),
            ],
        );
    }

    /// Matches one in-memory source, with and without the prefilter.
    fn run(lang: &str, pattern: &str, src: &str) -> (Vec<Match>, Vec<Vec<String>>) {
        let c = compile(lang, pattern).unwrap_or_else(|e| panic!("{e}"));
        let with = scan(&c, "f", src).unwrap().matches;
        let kept = passes(&c.prefilter, src.as_bytes());
        // The prefilter may only drop a file that has no match.
        assert!(kept || with.is_empty(), "prefilter {:?} dropped a real match of {pattern}", c.prefilter);
        (with, c.prefilter)
    }

    #[test]
    fn the_attribute_pattern_keeps_the_old_semantics_through_ast_grep() {
        let src = "struct S; #[router] impl S { #[tool(name = \"a\")] async fn a(&self) {} #[tool] async fn b(&self) {} #[tool] fn sync(&self) {} } #[tool] async fn free() {}";
        // `#[tool]` names the attribute whatever its arguments, as the old matcher did.
        let (m, _) = run("rust", "#[tool] async fn $N($$$A) { $$$B }", src);
        assert_eq!(m.len(), 3);
        // `#[tool($$$M)]` is ast-grep's own reading: the attribute with an argument list.
        let (m, _) = run("rust", "#[tool($$$M)] async fn $N($$$A) { $$$B }", src);
        assert_eq!(m.len(), 1);
        let (m, _) = run("rust", "#[tool] fn $N($$$A) { $$$B }", src);
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn a_decorated_match_starts_at_its_first_attribute() {
        let src = "#[a]\n/// doc\n#[tool]\nasync fn f() {}\n";
        let (m, _) = run("rust", "#[tool] async fn $N() {}", src);
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].start_line, m[0].end_line), (1, 4));
        assert_eq!(m[0].item.as_ref().and_then(|i| i.name.as_deref()), Some("f"));
    }

    #[test]
    fn unknown_languages_and_unparsable_patterns_are_refused_with_a_reason() {
        let Err(Failure::UnknownLanguage(e)) = compile("cobol", "x") else { panic!() };
        assert!(e.contains("cobol") && e.contains("rust") && e.contains("typescript"), "{e}");
        let Err(Failure::Unparsable(e)) = compile("rust", "fn free(") else { panic!() };
        assert!(e.contains("syntax error"), "{e}");
        let Err(Failure::Unparsable(e)) = compile("rust", "fn a() {} fn b() {}") else { panic!() };
        assert!(e.contains("Multiple AST nodes"), "{e}");
    }

    #[test]
    fn prefilter_uses_only_named_leaves_and_never_drops_a_match() {
        let (_, pre) = run("rust", "#[tool] async fn $N($$$A) { $$$B }", "#[tool] async fn f() {}");
        assert_eq!(pre, [vec!["tool".to_owned()]]);
        // Keywords alone give no literal, so every file is parsed.
        let (m, pre) = run("rust", "async fn $N($$$A) { $$$B }", "async fn f() {}");
        assert_eq!((m.len(), pre.len()), (1, 0));
        let (m, pre) = run("python", "def $F($$$A): $$$B", "def f(x):\n    return x\n");
        assert_eq!((m.len(), pre.len()), (1, 0));
        // Go parses a bare call at file level as a type, so `($$$A)` would not match; two arguments do.
        let (m, pre) = run("go", "http.ListenAndServe($$$A)", "package main\nfunc main() { http.ListenAndServe(\":80\", nil) }");
        assert_eq!(m.len(), 1);
        assert_eq!(pre, [vec!["ListenAndServe".to_owned(), "http".to_owned()]]);
    }

    #[test]
    fn enclosing_items_are_named_per_language() {
        let (m, _) = run("c", "malloc($A)", "int main(void) {\n  char *p = malloc(4);\n  return 0;\n}\n");
        let i = m[0].item.as_ref().unwrap();
        assert_eq!((i.kind.as_str(), i.name.as_deref(), i.start_line, i.end_line), ("function_definition", Some("main"), 1, 4));
        let (m, _) = run("python", "print($$$A)", "class C:\n    def m(self):\n        print(1)\n");
        assert_eq!(m[0].item.as_ref().unwrap().name.as_deref(), Some("m"));
        let (m, _) = run("json", "{\"a\": 1}", "{\"a\": 1}");
        assert_eq!(m.len(), 1);
        assert!(m[0].item.is_none());
    }
}
