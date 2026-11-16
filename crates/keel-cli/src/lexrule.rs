//! Stage 0 rule: a modified `.rs` file is junk iff its token stream is
//! unchanged and every surviving token keeps its (line, column).
//!
//! Why positions and not just tokens. `panic!`, `assert!`, `line!()`,
//! `column!()` and `#[track_caller]` bake `file:line:col` into the binary, and
//! a test can observe it (a message comparison, a snapshot, `Location::caller`).
//! Rustc attaches no other source-position-dependent value to code that a test
//! can see, so tokens plus positions determine the compiled program exactly.
//!
//! What is deliberately NOT dropped, because rustc turns it into a token:
//! doc comments. `/// text` is `#[doc = "text"]`, and a derive macro such as
//! clap's reads it at compile time, so editing one is a code change.
//!
//! Both sides are normalised the way rustc normalises a source file before it
//! lexes (BOM removed, CRLF to LF), so CRLF conversion alone is junk. A lone
//! CR survives that normalisation and rustc's line table treats it
//! differently from us; a file containing one is refused rather than guessed at.

use ra_ap_rustc_lexer::{FrontmatterAllowed, TokenKind, strip_shebang, tokenize};

/// A kept token: its exact text and where it starts (1-based line, 1-based
/// column counted in chars, which is what `Location::column` reports).
#[derive(Debug, PartialEq, Eq)]
struct Tok<'a> {
    text: &'a str,
    line: u32,
    col: u32,
}

fn normalise(bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "the file is not valid UTF-8, which rustc would also refuse".to_owned())?;
    let text = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .replace("\r\n", "\n");
    if text.contains('\r') {
        return Err(
            "the file has a bare carriage return, whose line numbering this rule does not model"
                .into(),
        );
    }
    Ok(text)
}

fn tokens(src: &str) -> Result<Vec<Tok<'_>>, String> {
    let mut out = Vec::new();
    let (mut line, mut col) = (1u32, 1u32);
    let advance = |text: &str, line: &mut u32, col: &mut u32| {
        for c in text.chars() {
            if c == '\n' {
                *line += 1;
                *col = 1;
            } else {
                *col += 1;
            }
        }
    };
    let mut pos = 0;
    if let Some(n) = strip_shebang(src) {
        out.push(Tok {
            text: &src[..n],
            line,
            col,
        });
        advance(&src[..n], &mut line, &mut col);
        pos = n;
    }
    for t in tokenize(&src[pos..], FrontmatterAllowed::Yes) {
        let text = &src[pos..pos + t.len as usize];
        pos += t.len as usize;
        let trivia = match t.kind {
            TokenKind::Whitespace => true,
            TokenKind::LineComment { doc_style } => doc_style.is_none(),
            TokenKind::BlockComment {
                doc_style,
                terminated,
            } => {
                if !terminated {
                    return Err(format!(
                        "an unterminated block comment starts at line {line}, column {col}; it would swallow the rest of the file"
                    ));
                }
                doc_style.is_none()
            }
            _ => false,
        };
        if !trivia {
            out.push(Tok { text, line, col });
        }
        advance(text, &mut line, &mut col);
    }
    Ok(out)
}

/// `Ok(())` iff replacing `old` by `new` cannot change the compiled program.
/// The error says which token differs or moved, so the Stage 1 reason is actionable.
pub fn position_preserving(old: &[u8], new: &[u8]) -> Result<(), String> {
    let (old, new) = (normalise(old)?, normalise(new)?);
    let (a, b) = (tokens(&old)?, tokens(&new)?);
    for (i, (x, y)) in a.iter().zip(&b).enumerate() {
        if x.text != y.text {
            return Err(format!(
                "token {} differs: `{}` at {}:{} became `{}` at {}:{}",
                i + 1,
                clip(x.text),
                x.line,
                x.col,
                clip(y.text),
                y.line,
                y.col
            ));
        }
        if (x.line, x.col) != (y.line, y.col) {
            return Err(format!(
                "token `{}` moved from {}:{} to {}:{}, which changes the location panics and `line!()` report",
                clip(x.text),
                x.line,
                x.col,
                y.line,
                y.col
            ));
        }
    }
    if a.len() != b.len() {
        return Err(format!(
            "the token count changed from {} to {}",
            a.len(),
            b.len()
        ));
    }
    Ok(())
}

fn clip(s: &str) -> String {
    let one: String = s.chars().take(24).collect();
    if one.len() < s.len() {
        format!("{one}...")
    } else {
        one
    }
}

/// Every string literal token in `src`, quotes included; callers only look for a
/// file name inside them.
pub fn string_literals(src: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut pos = 0;
    for t in tokenize(src, FrontmatterAllowed::No) {
        let text = &src[pos..pos + t.len as usize];
        pos += t.len as usize;
        if matches!(t.kind, TokenKind::Literal { kind, .. } if matches!(kind,
            ra_ap_rustc_lexer::LiteralKind::Str { .. }
            | ra_ap_rustc_lexer::LiteralKind::ByteStr { .. }
            | ra_ap_rustc_lexer::LiteralKind::RawStr { .. }
            | ra_ap_rustc_lexer::LiteralKind::RawByteStr { .. }
            | ra_ap_rustc_lexer::LiteralKind::CStr { .. }
            | ra_ap_rustc_lexer::LiteralKind::RawCStr { .. }))
        {
            out.push(text);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "fn main() {\n    // say hello\n    let s = \"hi\";\n    assert_eq!(s, \"hi\"); // check\n}\n";

    fn check(new: &str) -> Result<(), String> {
        position_preserving(BASE.as_bytes(), new.as_bytes())
    }

    #[test]
    fn comment_text_edited_in_place_is_accepted() {
        assert_eq!(check(&BASE.replace("say hello", "say howdy")), Ok(()));
        // Shorter comment text on a line that has nothing after it.
        assert_eq!(check(&BASE.replace("// check", "// ok")), Ok(()));
        assert_eq!(check(&BASE.replace("say hello", "")), Ok(()));
    }

    #[test]
    fn trailing_whitespace_and_crlf_are_accepted() {
        assert_eq!(check(&BASE.replace("{\n", "{   \n")), Ok(()));
        assert_eq!(check(&BASE.replace('\n', "\r\n")), Ok(()));
        assert_eq!(check(&format!("{BASE}\n\n")), Ok(()));
        assert_eq!(check(&format!("\u{feff}{BASE}")), Ok(()));
    }

    #[test]
    fn inserting_a_comment_line_is_refused() {
        let err = check(&BASE.replace("    let s", "    // new line\n    let s")).unwrap_err();
        assert!(err.contains("`let` moved from 3:5 to 4:5"), "{err}");
    }

    #[test]
    fn reflowing_a_line_is_refused() {
        let err =
            check(&BASE.replace("assert_eq!(s, \"hi\");", "assert_eq!(s,\n \"hi\");")).unwrap_err();
        assert!(err.contains("moved"), "{err}");
        // Same line count, one token moved right by a space.
        let err = check(&BASE.replace("let s = \"hi\"", "let s  = \"hi\"")).unwrap_err();
        assert!(err.contains("moved"), "{err}");
    }

    #[test]
    fn a_comment_that_widens_a_line_before_a_token_is_refused() {
        let src = "fn f() { /* a */ g() }\n";
        let longer = "fn f() { /* abc */ g() }\n";
        assert!(position_preserving(src.as_bytes(), longer.as_bytes()).is_err());
        let same = "fn f() { /* b */ g() }\n";
        assert_eq!(position_preserving(src.as_bytes(), same.as_bytes()), Ok(()));
    }

    #[test]
    fn string_literal_content_is_a_token() {
        let err = check(&BASE.replace("let s = \"hi\"", "let s = \"ho\"")).unwrap_err();
        assert!(
            err.contains("`\"hi\"`") && err.contains("`\"ho\"`"),
            "{err}"
        );
    }

    #[test]
    fn doc_comments_are_tokens_even_when_edited_in_place() {
        // clap-style derives read these at compile time.
        let a = "/// Print help.\nstruct A;\n";
        let b = "/// Print halp.\nstruct A;\n";
        assert!(position_preserving(a.as_bytes(), b.as_bytes()).is_err());
        let c = "//! crate doc\nfn f() {}\n";
        let d = "//! crate dox\nfn f() {}\n";
        assert!(position_preserving(c.as_bytes(), d.as_bytes()).is_err());
        // `////` is an ordinary comment, not a doc comment.
        let e = "//// banner\nfn f() {}\n";
        let f = "//// bunner\nfn f() {}\n";
        assert_eq!(position_preserving(e.as_bytes(), f.as_bytes()), Ok(()));
    }

    #[test]
    fn removing_a_token_is_refused_and_so_is_unterminated_comment() {
        assert!(check(&BASE.replace("assert_eq!(s, \"hi\"); // check\n", "")).is_err());
        let err = check(&format!("{BASE}/* open")).unwrap_err();
        assert!(err.contains("unterminated"), "{err}");
    }

    #[test]
    fn multibyte_comment_text_keeps_columns_counted_in_chars() {
        let a = "fn f() { /* é */ g() }\n";
        let b = "fn f() { /* e */ g() }\n";
        assert_eq!(position_preserving(a.as_bytes(), b.as_bytes()), Ok(()));
    }

    #[test]
    fn non_utf8_and_bare_cr_are_refused() {
        assert!(position_preserving(b"fn f() {}\n", b"fn f() {} \xff\n").is_err());
        assert!(position_preserving(b"fn f() {}\n", b"fn f() {}\r\n\r").is_err());
    }

    #[test]
    fn finds_string_literals() {
        let v = string_literals("include_str!(\"../data/x.rs\"); let r = r#\"y.rs\"#; let n = 3;");
        assert_eq!(v.len(), 2);
        assert!(v[0].contains("x.rs"));
    }
}
