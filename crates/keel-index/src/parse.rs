//! Per-file scan: one `syn` parse, one walk, no compiler.
//!
//! The result depends only on the file's bytes (never on its path), which is
//! what lets the cache key it by content hash and lets `diff` scan blobs that
//! were never checked out.
//!
//! Hashing works on token trees, not on `to_string()` output: the text form
//! allocates per item. Spans never reach the hash, so moving a function or reflowing
//! whitespace leaves it unchanged; a doc comment is part of an item's tokens (a doctest is code).

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::io::Write;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    AttrStyle, Attribute, BinOp, Block, Expr, ExprBinary, ExprForLoop, ExprIf, ExprLoop, ExprMatch,
    ExprTry, ExprWhile, ImplItem, Item, Lit, Meta, Token, TraitItem, Type,
};

/// Bump when anything in this file changes what a scan returns; cached scans
/// with another version are ignored rather than trusted.
pub const SCAN_VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawItem {
    pub path: String,
    pub start_line: u32,
    pub end_line: u32,
    #[serde(with = "crate::hex32")]
    pub tokens: [u8; 32],
    #[serde(with = "crate::hex32")]
    pub signature: [u8; 32],
    pub branches: u32,
    pub is_test: bool,
    pub ignored: bool,
    /// Inside a `#[cfg(test)]` item of this file. File-level test-ness
    /// (integration tests, `#[cfg(test)] mod tests;` in another file) is
    /// decided by the builder, which can see the other files.
    pub cfg_test: bool,
}

/// An out-of-line `mod name;`, recorded so the builder can find the file it
/// names and propagate `#[cfg(test)]` and the target kind into it.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ModDecl {
    pub inline: Vec<String>,
    pub name: String,
    pub path_attr: Option<String>,
    pub cfg_test: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileScan {
    pub version: u32,
    pub parse_error: Option<String>,
    pub items: Vec<RawItem>,
    pub mods: Vec<ModDecl>,
    /// Hash of the file's token stream with every fn item removed (module,
    /// impl and trait shells stay). `diff` compares it to see whether anything
    /// outside functions changed.
    #[serde(with = "crate::hex32")]
    pub outside: [u8; 32],
}

/// Scans UTF-8 source text. Never panics: a parser panic on a pathological
/// file is reported as that file's parse error so one bad file cannot take the
/// whole index down.
pub fn scan_source(src: &str) -> FileScan {
    let attempt = std::panic::catch_unwind(|| scan_inner(src));
    match attempt {
        Ok(scan) => scan,
        Err(_) => failed("the parser panicked on this file; it is skipped (report the file to the keel-index owners)".into()),
    }
}

pub fn scan_bytes(bytes: &[u8]) -> FileScan {
    match std::str::from_utf8(bytes) {
        Ok(s) => scan_source(s),
        Err(e) => failed(format!(
            "not valid UTF-8 (first bad byte at offset {}); rustc would refuse it too",
            e.valid_up_to()
        )),
    }
}

fn failed(msg: String) -> FileScan {
    FileScan {
        version: SCAN_VERSION,
        parse_error: Some(msg),
        items: Vec::new(),
        mods: Vec::new(),
        outside: [0; 32],
    }
}

fn scan_inner(src: &str) -> FileScan {
    let file = match syn::parse_file(src) {
        Ok(f) => f,
        Err(e) => {
            let at = e.span().start();
            return failed(format!("{}:{}: {}", at.line, at.column + 1, e));
        }
    };
    let mut w = Walker::default();
    for a in file
        .attrs
        .iter()
        .filter(|a| matches!(a.style, AttrStyle::Inner(_)))
    {
        w.skel_put(a);
    }
    w.items(&file.items, false);
    let mut items = w.items;
    items.sort_by_key(|i| (i.start_line, i.end_line));
    FileScan {
        version: SCAN_VERSION,
        parse_error: None,
        items,
        mods: w.mods,
        outside: *blake3::hash(&w.skel).as_bytes(),
    }
}

// ---------------------------------------------------------------- hashing

/// True if `toks[i..]` starts a `#[doc = ...]` / `#![doc = ...]` attribute;
/// returns how many token trees it spans. `#[doc(hidden)]` is deliberately
/// not matched: it changes what rustdoc shows but also what tools may read,
/// and it is rare enough that treating it as code is the safe side.
fn doc_attr_len(toks: &[TokenTree], i: usize) -> Option<usize> {
    let TokenTree::Punct(p) = &toks[i] else {
        return None;
    };
    if p.as_char() != '#' {
        return None;
    }
    let mut j = i + 1;
    if let Some(TokenTree::Punct(bang)) = toks.get(j)
        && bang.as_char() == '!'
    {
        j += 1;
    }
    let Some(TokenTree::Group(g)) = toks.get(j) else {
        return None;
    };
    if g.delimiter() != Delimiter::Bracket {
        return None;
    }
    let mut inner = g.stream().into_iter();
    match (inner.next(), inner.next()) {
        (Some(TokenTree::Ident(id)), Some(TokenTree::Punct(eq)))
            if id == "doc" && eq.as_char() == '=' =>
        {
            Some(j + 1 - i)
        }
        _ => None,
    }
}

/// Writes the stream. `docs` says whether `#[doc = ..]` attributes (which is what `///` and `//!`
/// comments are) are part of it: they are in an item's `tokens`, because rustdoc compiles the code
/// in them as a test and a change there can fail one, and out of its `signature`, because a
/// reworded comment does not change what callers can write.
fn put_stream(buf: &mut Vec<u8>, ts: TokenStream, docs: bool) {
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut i = 0;
    while i < toks.len() {
        if !docs && let Some(n) = doc_attr_len(&toks, i) {
            i += n;
            continue;
        }
        put_tree(buf, &toks[i], docs);
        i += 1;
    }
}

fn put_tree(buf: &mut Vec<u8>, t: &TokenTree, docs: bool) {
    // Writes to a Vec cannot fail.
    match t {
        TokenTree::Ident(id) => {
            buf.push(1);
            let _ = write!(buf, "{id}");
            buf.push(0);
        }
        TokenTree::Punct(p) => {
            buf.push(2);
            let _ = write!(buf, "{}", p.as_char());
            buf.push(if p.spacing() == Spacing::Joint {
                b'j'
            } else {
                b'a'
            });
        }
        TokenTree::Literal(l) => {
            buf.push(3);
            let _ = write!(buf, "{l}");
            buf.push(0);
        }
        TokenTree::Group(g) => {
            buf.push(match g.delimiter() {
                Delimiter::Parenthesis => 4,
                Delimiter::Brace => 5,
                Delimiter::Bracket => 6,
                Delimiter::None => 7,
            });
            put_stream(buf, g.stream(), docs);
            buf.push(8);
        }
    }
}

fn put(buf: &mut Vec<u8>, x: &impl ToTokens) {
    put_stream(buf, x.to_token_stream(), true);
}

// ---------------------------------------------------------------- attributes

fn is_test_attr(a: &Attribute) -> bool {
    a.path().segments.last().is_some_and(|s| {
        matches!(
            s.ident.to_string().as_str(),
            "test" | "rstest" | "test_case" | "proptest" | "quickcheck" | "wasm_bindgen_test"
        )
    })
}

fn cfg_pred_is_test(m: &Meta) -> bool {
    match m {
        Meta::Path(p) => p.is_ident("test"),
        Meta::List(l) => {
            let args = l.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated);
            let Ok(args) = args else { return false };
            if l.path.is_ident("all") {
                args.iter().any(cfg_pred_is_test)
            } else if l.path.is_ident("any") {
                // `any(test, feature = "x")` is also true outside tests.
                !args.is_empty() && args.iter().all(cfg_pred_is_test)
            } else {
                false // `not(test)` and unknown predicates
            }
        }
        Meta::NameValue(_) => false,
    }
}

fn is_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        a.path().is_ident("cfg")
            && match &a.meta {
                Meta::List(l) => l
                    .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                    .is_ok_and(|args| args.iter().any(cfg_pred_is_test)),
                _ => false,
            }
    })
}

fn path_attr(attrs: &[Attribute]) -> Option<String> {
    attrs.iter().find_map(|a| match &a.meta {
        Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
            Expr::Lit(l) => match &l.lit {
                Lit::Str(s) => Some(s.value()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    })
}

// ---------------------------------------------------------------- branches

/// Counts decision points. Nested fns and closures are visited on purpose:
/// they are part of the enclosing item. Macro bodies are opaque.
struct Branches(u32);

impl<'ast> Visit<'ast> for Branches {
    fn visit_expr_if(&mut self, i: &'ast ExprIf) {
        self.0 += 1;
        visit::visit_expr_if(self, i);
    }
    fn visit_expr_match(&mut self, m: &'ast ExprMatch) {
        self.0 += m.arms.len().saturating_sub(1) as u32;
        visit::visit_expr_match(self, m);
    }
    fn visit_expr_while(&mut self, w: &'ast ExprWhile) {
        self.0 += 1;
        visit::visit_expr_while(self, w);
    }
    fn visit_expr_for_loop(&mut self, f: &'ast ExprForLoop) {
        self.0 += 1;
        visit::visit_expr_for_loop(self, f);
    }
    fn visit_expr_loop(&mut self, l: &'ast ExprLoop) {
        self.0 += 1;
        visit::visit_expr_loop(self, l);
    }
    fn visit_expr_try(&mut self, t: &'ast ExprTry) {
        self.0 += 1;
        visit::visit_expr_try(self, t);
    }
    fn visit_expr_binary(&mut self, b: &'ast ExprBinary) {
        if matches!(b.op, BinOp::And(_) | BinOp::Or(_)) {
            self.0 += 1;
        }
        visit::visit_expr_binary(self, b);
    }
}

fn count_branches(b: &Block) -> u32 {
    let mut v = Branches(0);
    v.visit_block(b);
    v.0
}

// ---------------------------------------------------------------- walker

#[derive(Default)]
struct Walker {
    items: Vec<RawItem>,
    mods: Vec<ModDecl>,
    stack: Vec<String>,
    skel: Vec<u8>,
}

/// The pieces of one function, however it was declared.
struct FnParts<'a> {
    name: String,
    attrs: &'a [Attribute],
    /// Outer attributes, visibility and signature, in source order.
    head: TokenStream,
    body: &'a Block,
    in_cfg_test: bool,
}

impl Walker {
    fn skel_put(&mut self, x: &impl ToTokens) {
        put(&mut self.skel, x);
    }

    fn skel_attrs(&mut self, attrs: &[Attribute]) {
        for a in attrs {
            put(&mut self.skel, a);
        }
    }

    fn prefix(&self, owner: Option<&str>, name: &str) -> String {
        let mut p = String::new();
        for m in &self.stack {
            p.push_str(m);
            p.push_str("::");
        }
        if let Some(o) = owner {
            p.push_str(o);
            p.push_str("::");
        }
        p.push_str(name);
        p
    }

    fn items(&mut self, items: &[Item], in_cfg_test: bool) {
        for item in items {
            match item {
                Item::Fn(f) => {
                    let mut head = TokenStream::new();
                    outer_attrs(&f.attrs).for_each(|a| a.to_tokens(&mut head));
                    f.vis.to_tokens(&mut head);
                    f.sig.to_tokens(&mut head);
                    let cfg = in_cfg_test || is_cfg_test(&f.attrs);
                    self.function(FnParts {
                        name: self.prefix(None, &f.sig.ident.to_string()),
                        attrs: &f.attrs,
                        head,
                        body: &f.block,
                        in_cfg_test: cfg,
                    });
                }
                Item::Mod(m) => {
                    let cfg = in_cfg_test || is_cfg_test(&m.attrs);
                    match &m.content {
                        Some((_, inner)) => {
                            // The shell stays in the "outside" hash so renaming or
                            // re-attributing a module is seen as a non-fn change.
                            self.skel_attrs(&m.attrs);
                            self.skel_put(&m.vis);
                            self.skel_put(&m.ident);
                            self.skel.push(b'{');
                            self.stack.push(m.ident.to_string());
                            self.items(inner, cfg);
                            self.stack.pop();
                            self.skel.push(b'}');
                        }
                        None => {
                            self.mods.push(ModDecl {
                                inline: self.stack.clone(),
                                name: m.ident.to_string(),
                                path_attr: path_attr(&m.attrs),
                                cfg_test: cfg,
                            });
                            self.skel_put(m);
                        }
                    }
                }
                Item::Impl(i) => {
                    let cfg = in_cfg_test || is_cfg_test(&i.attrs);
                    // Inherent: `Type::fn`. Trait impl: `<Type as Trait>::fn`, because
                    // `fmt`/`from`/`eq` repeat across impls of one type and the path
                    // is the identity `diff` matches on.
                    let ty = type_name(&i.self_ty);
                    let owner = match &i.trait_ {
                        Some((_, p, _)) => format!(
                            "<{ty} as {}>",
                            p.segments
                                .last()
                                .map(|s| s.ident.to_string())
                                .unwrap_or_default()
                        ),
                        None => ty,
                    };
                    self.skel_attrs(&i.attrs);
                    self.skel_put(&i.defaultness);
                    self.skel_put(&i.unsafety);
                    self.skel_put(&i.generics);
                    self.skel_put(&i.generics.where_clause);
                    if let Some((neg, p, _)) = &i.trait_ {
                        self.skel_put(neg);
                        self.skel_put(p);
                    }
                    self.skel_put(&i.self_ty);
                    self.skel.push(b'{');
                    for it in &i.items {
                        match it {
                            ImplItem::Fn(f) => {
                                let mut head = TokenStream::new();
                                outer_attrs(&f.attrs).for_each(|a| a.to_tokens(&mut head));
                                f.vis.to_tokens(&mut head);
                                f.defaultness.to_tokens(&mut head);
                                f.sig.to_tokens(&mut head);
                                self.function(FnParts {
                                    name: self.prefix(Some(&owner), &f.sig.ident.to_string()),
                                    attrs: &f.attrs,
                                    head,
                                    body: &f.block,
                                    in_cfg_test: cfg || is_cfg_test(&f.attrs),
                                });
                            }
                            other => self.skel_put(other),
                        }
                    }
                    self.skel.push(b'}');
                }
                Item::Trait(t) => {
                    let cfg = in_cfg_test || is_cfg_test(&t.attrs);
                    let owner = t.ident.to_string();
                    self.skel_attrs(&t.attrs);
                    self.skel_put(&t.vis);
                    self.skel_put(&t.unsafety);
                    self.skel_put(&t.ident);
                    self.skel_put(&t.generics);
                    self.skel_put(&t.generics.where_clause);
                    self.skel_put(&t.supertraits);
                    self.skel.push(b'{');
                    for it in &t.items {
                        match it {
                            // Required methods have no body to index; they stay in the shell.
                            TraitItem::Fn(f) if f.default.is_some() => {
                                let mut head = TokenStream::new();
                                outer_attrs(&f.attrs).for_each(|a| a.to_tokens(&mut head));
                                f.sig.to_tokens(&mut head);
                                if let Some(body) = &f.default {
                                    self.function(FnParts {
                                        name: self.prefix(Some(&owner), &f.sig.ident.to_string()),
                                        attrs: &f.attrs,
                                        head,
                                        body,
                                        in_cfg_test: cfg || is_cfg_test(&f.attrs),
                                    });
                                }
                            }
                            other => self.skel_put(other),
                        }
                    }
                    self.skel.push(b'}');
                }
                Item::Macro(m) => {
                    let cfg = in_cfg_test || is_cfg_test(&m.attrs);
                    let is_proptest = m
                        .mac
                        .path
                        .segments
                        .last()
                        .is_some_and(|s| s.ident == "proptest");
                    if !(is_proptest && self.proptest(m.mac.tokens.clone(), cfg)) {
                        self.skel_put(m);
                    }
                }
                other => self.skel_put(other),
            }
        }
    }

    fn function(&mut self, f: FnParts<'_>) {
        let start_line = f
            .head
            .clone()
            .into_iter()
            .next()
            .map_or(1, |t| t.span().start().line as u32);
        let end_line = f.body.brace_token.span.close().end().line as u32;
        let mut body = TokenStream::new();
        // Inner attributes (`#![allow(..)]` at the top of the body) live in
        // `attrs` in syn's model but belong textually to the body.
        f.attrs
            .iter()
            .filter(|a| matches!(a.style, AttrStyle::Inner(_)))
            .for_each(|a| a.to_tokens(&mut body));
        f.body.to_tokens(&mut body);
        let branches = count_branches(f.body);
        self.emit(
            f.name,
            f.attrs,
            f.head,
            body,
            start_line,
            end_line,
            branches,
            f.in_cfg_test,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        path: String,
        attrs: &[Attribute],
        head: TokenStream,
        body: TokenStream,
        start_line: u32,
        end_line: u32,
        branches: u32,
        cfg_test: bool,
    ) {
        let mut sig = Vec::new();
        put_stream(&mut sig, head.clone(), false);
        let mut with_body = Vec::new();
        put_stream(&mut with_body, head, true);
        with_body.push(0xFF);
        put_stream(&mut with_body, body, true);
        sig.extend_from_slice(&[0xFF, 5, 8]); // the same bytes as an empty `{}` group
        self.items.push(RawItem {
            path,
            start_line,
            end_line,
            tokens: *blake3::hash(&with_body).as_bytes(),
            signature: *blake3::hash(&sig).as_bytes(),
            branches,
            is_test: attrs.iter().any(is_test_attr),
            ignored: attrs.iter().any(|a| a.path().is_ident("ignore")),
            cfg_test,
        });
    }

    /// `proptest! { #[test] fn name(x in 0..9) { .. } }` is not valid Rust
    /// item syntax (`x in 0..9` is not a parameter), so `syn` cannot parse it
    /// as items. Walk the token trees by hand for the regular shape
    /// `attrs* [pub] fn name (..) [-> T] { .. }` and give up on the whole
    /// macro (returning false, so it stays opaque) on anything else: a partial
    /// read would report some tests and silently drop the rest.
    fn proptest(&mut self, tokens: TokenStream, cfg: bool) -> bool {
        let toks: Vec<TokenTree> = tokens.into_iter().collect();
        let mut found: Vec<RawItem> = Vec::new();
        let mut i = 0;
        let owner_prefix = self.prefix(None, "");
        while i < toks.len() {
            let mut attrs_ts = TokenStream::new();
            // Attributes: `#[..]`; inner `#![..]` (proptest_config) is skipped.
            while let Some(TokenTree::Punct(p)) = toks.get(i) {
                if p.as_char() != '#' {
                    break;
                }
                let mut j = i + 1;
                let inner = matches!(toks.get(j), Some(TokenTree::Punct(b)) if b.as_char() == '!');
                if inner {
                    j += 1;
                }
                let Some(TokenTree::Group(g)) = toks.get(j) else {
                    return false;
                };
                if g.delimiter() != Delimiter::Bracket {
                    return false;
                }
                if !inner {
                    attrs_ts.extend(toks[i..=j].iter().cloned());
                }
                i = j + 1;
            }
            if i >= toks.len() {
                break;
            }
            let mut head = attrs_ts.clone();
            if matches!(&toks[i], TokenTree::Ident(id) if id == "pub") {
                head.extend([toks[i].clone()]);
                i += 1;
                if let Some(TokenTree::Group(g)) = toks.get(i)
                    && g.delimiter() == Delimiter::Parenthesis
                {
                    head.extend([toks[i].clone()]);
                    i += 1;
                }
            }
            if !matches!(toks.get(i), Some(TokenTree::Ident(id)) if id == "fn") {
                return false;
            }
            head.extend([toks[i].clone()]);
            i += 1;
            let Some(TokenTree::Ident(name)) = toks.get(i) else {
                return false;
            };
            let name = name.to_string();
            head.extend([toks[i].clone()]);
            i += 1;
            // Parameters and any return type, up to the body brace group.
            let body = loop {
                match toks.get(i) {
                    Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Brace => {
                        break g.clone();
                    }
                    Some(t) => head.extend([t.clone()]),
                    None => return false,
                }
                i += 1;
            };
            i += 1;
            let Ok(attrs) = syn::parse::Parser::parse2(Attribute::parse_outer, attrs_ts) else {
                return false;
            };
            let Ok(block) = syn::parse2::<Block>(TokenStream::from(TokenTree::Group(body.clone())))
            else {
                return false;
            };
            let mut shell = Walker::default();
            shell.emit(
                format!("{owner_prefix}{name}"),
                &attrs,
                head,
                body.stream(),
                0,
                0,
                count_branches(&block),
                cfg || is_cfg_test(&attrs),
            );
            let mut item = shell.items.pop().expect("emit pushes exactly one item");
            item.start_line = start_of(&toks, &attrs, &name);
            item.end_line = body.span_close().end().line as u32;
            found.push(item);
        }
        self.items.extend(found);
        true
    }
}

/// First line of a proptest item: its first attribute, else its `fn` token.
fn start_of(toks: &[TokenTree], attrs: &[Attribute], name: &str) -> u32 {
    if let Some(a) = attrs.first() {
        return a.pound_token.span.start().line as u32;
    }
    toks.iter()
        .find_map(|t| match t {
            TokenTree::Ident(id) if id == name => Some(id.span().start().line as u32),
            _ => None,
        })
        .unwrap_or(1)
}

fn outer_attrs(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
    attrs.iter().filter(|a| matches!(a.style, AttrStyle::Outer))
}

fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(p) => p
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default(),
        Type::Reference(r) => format!("&{}", type_name(&r.elem)),
        Type::Paren(p) => type_name(&p.elem),
        Type::Group(g) => type_name(&g.elem),
        other => other.to_token_stream().to_string().replace(' ', ""),
    }
}
