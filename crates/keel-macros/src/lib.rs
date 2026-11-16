//! `#[stands_on(..)]` and `#[joins(..)]`: declare a test's edges in source.
//!
//! Each attribute writes a record into the `.keel` link section of the binary
//! that contains the test (layout and validation live in `keel-decl`, shared
//! with the reader). The only runtime effect is one address load per test call.
//!
//! ```ignore
//! #[test]
//! #[stands_on("unit(backend-store)", "integration(backend-flow)")]
//! #[joins(backend_store, backend_flow)]
//! fn replays_torn_tail() { .. }
//! ```
//!
//! Each record is kept alive twice over: `#[used]` for the compiler, and a
//! `black_box(addr_of!(RECORD))` at the top of the function body for the linker
//! (see `README.md` in `keel-decl`). Both attributes on one function produce one
//! record. The outer attribute
//! expands first, so it looks for its partner among the item's remaining
//! attributes, removes it and emits the merged record; the removed attribute
//! never expands. Everything else on the function is passed through untouched.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::ext::IdentExt;
use syn::parse::{ParseStream, Parser};
use syn::{Attribute, Ident, ItemFn, LitStr, Token};

/// Declares which groups or nodes this test stands on.
///
/// Entries are string literals: `"unit(<crate>)"`, `"integration(<crate>)"`,
/// or a node id containing `::`.
#[proc_macro_attribute]
pub fn stands_on(args: TokenStream, item: TokenStream) -> TokenStream {
    expand(Kind::StandsOn, args.into(), item.into()).into()
}

/// Declares which crates' interaction this test covers.
///
/// Entries are identifiers (`backend_store` becomes `backend-store`) or
/// string literals taken as written.
#[proc_macro_attribute]
pub fn joins(args: TokenStream, item: TokenStream) -> TokenStream {
    expand(Kind::Joins, args.into(), item.into()).into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    StandsOn,
    Joins,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::StandsOn => "stands_on",
            Kind::Joins => "joins",
        }
    }

    fn other(self) -> Kind {
        match self {
            Kind::StandsOn => Kind::Joins,
            Kind::Joins => Kind::StandsOn,
        }
    }

    fn example(self) -> &'static str {
        match self {
            Kind::StandsOn => r#"#[stands_on("unit(backend-store)", "integration(backend-flow)")]"#,
            Kind::Joins => r#"#[joins(backend_store, "backend-flow")]"#,
        }
    }
}

struct Entry {
    value: String,
    span: Span,
}

fn expand(kind: Kind, args: TokenStream2, item: TokenStream2) -> TokenStream2 {
    match try_expand(kind, args, item.clone()) {
        Ok(out) => out,
        // Emit the item as it was so one mistake does not also hide the
        // function from the compiler and bury the real error under
        // "cannot find function" noise.
        Err(err) => {
            let err = err.to_compile_error();
            quote!(#err #item)
        }
    }
}

fn try_expand(kind: Kind, args: TokenStream2, item: TokenStream2) -> syn::Result<TokenStream2> {
    let mut func: ItemFn = syn::parse2(item).map_err(|e| {
        syn::Error::new(
            e.span(),
            format!(
                "#[{}] applies to a test `fn` only, but this item is not one ({e})",
                kind.name()
            ),
        )
    })?;

    let own = parse_entries(kind, args)?;

    for attr in &func.attrs {
        if is_keel_attr(attr, kind) {
            return Err(syn::Error::new_spanned(
                attr,
                format!(
                    "#[{0}] appears twice on this function; put every entry in one attribute, \
                     for example {1}",
                    kind.name(),
                    kind.example()
                ),
            ));
        }
    }

    let partner = take_partner(&mut func, kind.other())?;
    let (stands_on, joins) = match (kind, partner) {
        (Kind::StandsOn, p) => (own, p.unwrap_or_default()),
        (Kind::Joins, p) => (p.unwrap_or_default(), own),
    };

    let stands_on: Vec<String> = stands_on.into_iter().map(|e| e.value).collect();
    let joins: Vec<String> = joins.into_iter().map(|e| e.value).collect();
    let tail = keel_decl::encode_tail(&stands_on, &joins);

    let name = func.sig.ident.unraw().to_string();
    let rec = format_ident!("__KEEL_REC_{}", name);
    let stat = format_ident!("__KEEL_DECL_{}", name);

    // Section retention must not depend on the linker: a reference from the test
    // function (itself reachable from the harness table) to the static is a
    // relocation that keeps the static's section under any section GC. addr_of!
    // avoids creating a reference; black_box forces the address to be
    // materialised so the optimiser cannot drop the relocation.
    let keep: syn::Stmt = syn::parse_quote! {
        let _ = ::core::hint::black_box(::core::ptr::addr_of!(#stat));
    };
    func.block.stmts.insert(0, keep);

    Ok(quote! {
        #func

        // The names derive from the fn name so two tests in one module cannot
        // collide; they are not for use by code.
        #[allow(non_upper_case_globals, dead_code)]
        const #rec: &str = ::core::concat!(::core::module_path!(), "::", #name, #tail);

        // Mach-O wants "segment,section"; ELF and PE/COFF want a bare name.
        #[used]
        #[allow(non_upper_case_globals, dead_code, unsafe_code)]
        #[cfg_attr(
            any(target_os = "macos", target_os = "ios", target_os = "tvos",
                target_os = "watchos", target_os = "visionos"),
            unsafe(link_section = "__DATA,__keel")
        )]
        #[cfg_attr(
            not(any(target_os = "macos", target_os = "ios", target_os = "tvos",
                    target_os = "watchos", target_os = "visionos")),
            unsafe(link_section = ".keel")
        )]
        static #stat: [u8; #rec.len()] =
            *#rec.as_bytes().first_chunk::<{ #rec.len() }>().unwrap();
    })
}

/// Removes the other keel attribute from the item and returns its entries.
fn take_partner(func: &mut ItemFn, kind: Kind) -> syn::Result<Option<Vec<Entry>>> {
    let positions: Vec<usize> = func
        .attrs
        .iter()
        .enumerate()
        .filter(|(_, a)| is_keel_attr(a, kind))
        .map(|(i, _)| i)
        .collect();
    let Some(&first) = positions.first() else {
        return Ok(None);
    };
    if let Some(&second) = positions.get(1) {
        return Err(syn::Error::new_spanned(
            &func.attrs[second],
            format!(
                "#[{0}] appears twice on this function; put every entry in one attribute, for \
                 example {1}",
                kind.name(),
                kind.example()
            ),
        ));
    }
    let attr = func.attrs.remove(first);
    let args = match &attr.meta {
        syn::Meta::List(list) => list.tokens.clone(),
        _ => {
            return Err(syn::Error::new_spanned(
                &attr,
                format!(
                    "#[{}] needs entries, for example {}",
                    kind.name(),
                    kind.example()
                ),
            ));
        }
    };
    parse_entries(kind, args).map(Some)
}

/// `#[stands_on]`, `#[joins]`, or the same behind `keel::` / `keel_macros::`.
fn is_keel_attr(attr: &Attribute, kind: Kind) -> bool {
    let segs = &attr.path().segments;
    let last_matches = segs.last().is_some_and(|s| s.ident == kind.name());
    let prefix_ok = segs.len() == 1
        || (segs.len() == 2
            && matches!(segs[0].ident.to_string().as_str(), "keel" | "keel_macros"));
    last_matches && prefix_ok
}

fn parse_entries(kind: Kind, args: TokenStream2) -> syn::Result<Vec<Entry>> {
    let parser = |input: ParseStream| -> syn::Result<Vec<Entry>> {
        let mut out: Vec<Entry> = Vec::new();
        while !input.is_empty() {
            let entry = parse_entry(kind, input)?;
            if out.iter().any(|p| p.value == entry.value) {
                return Err(syn::Error::new(
                    entry.span,
                    format!("`{}` is listed twice in #[{}]", entry.value, kind.name()),
                ));
            }
            out.push(entry);
            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }
        Ok(out)
    };
    let entries = parser.parse2(args)?;
    if entries.is_empty() {
        return Err(syn::Error::new(
            Span::call_site(),
            format!(
                "#[{}] needs at least one entry, for example {}",
                kind.name(),
                kind.example()
            ),
        ));
    }
    Ok(entries)
}

fn parse_entry(kind: Kind, input: ParseStream) -> syn::Result<Entry> {
    let lookahead = input.lookahead1();
    let (value, span) = if lookahead.peek(LitStr) {
        let lit: LitStr = input.parse()?;
        (lit.value(), lit.span())
    } else if kind == Kind::Joins && lookahead.peek(Ident::peek_any) {
        let ident = Ident::parse_any(input)?;
        (ident.unraw().to_string().replace('_', "-"), ident.span())
    } else {
        let want = match kind {
            Kind::StandsOn => "a string literal such as \"unit(backend-store)\"",
            Kind::Joins => "a crate name as an identifier (backend_store) or a string literal",
        };
        return Err(syn::Error::new(
            input.span(),
            format!("#[{}] entries must be {want}", kind.name()),
        ));
    };

    let checked = match kind {
        Kind::StandsOn => keel_decl::validate_stands_on(&value),
        Kind::Joins => keel_decl::validate_join(&value),
    };
    checked.map_err(|msg| syn::Error::new(span, msg))?;
    Ok(Entry { value, span })
}
