//! The input key of DESIGN.md §3:
//! `key(N) = blake3(schema ‖ code ‖ files ‖ env ‖ tools ‖ consumes ‖ platform)`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::frame::Framer;
use crate::node::{FilesInput, Inputs};

/// The key schema this build of the crate writes. Bumping it empties every
/// cache (§4 item 10).
pub const KEY_SCHEMA: u32 = 1;

/// Whether the test sandbox cuts the network (§4 item 4). Part of the key so
/// the two are never confused.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    /// Loopback only.
    Isolated,
    /// The host network.
    Open,
}

/// The platform half of a key (§3.7) and the `platform` object of both
/// documents of §8.
///
/// `cpu`, `kernel` and `libc` are filled only for nodes that declared
/// `sensitive = [...]` or whose reach contains feature detection; the caller
/// decides, this type only refuses to hash what it was not given. `extra` is
/// the open map the protocol allows (host names, runner labels): it is carried
/// through reads and writes but is **not** part of the key, so labelling a
/// runner never invalidates a cache.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Platform {
    /// Target triple.
    pub triple: String,
    /// `rustc -vV` text or its hash; hashed as given.
    pub toolchain: String,
    /// Emulator identity for emulated lanes.
    #[serde(default)]
    pub emulator: Option<String>,
    /// Network isolation of the run.
    pub net: NetMode,
    /// CPU feature mask, when the node can observe it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    /// Kernel release, when the node declared `sensitive = ["kernel"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    /// libc version, when the node declared `sensitive = ["kernel"]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub libc: Option<String>,
    /// Unkeyed, open-ended facts.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Platform {
    /// A platform with only the always-keyed fields set.
    pub fn new(triple: impl Into<String>, toolchain: impl Into<String>, net: NetMode) -> Self {
        Platform {
            triple: triple.into(),
            toolchain: toolchain.into(),
            emulator: None,
            net,
            cpu: None,
            kernel: None,
            libc: None,
            extra: BTreeMap::new(),
        }
    }
}

mod tag {
    pub const SCHEMA: u8 = 1;
    pub const CODE: u8 = 2;
    pub const CODE_KIND: u8 = 3;
    pub const FILES_HASH: u8 = 4;
    pub const ENV: u8 = 6;
    pub const TOOLS: u8 = 7;
    pub const CONSUMES: u8 = 8;
    pub const DRV: u8 = 9;
    pub const TRIPLE: u8 = 10;
    pub const TOOLCHAIN: u8 = 11;
    pub const EMULATOR: u8 = 12;
    pub const NET: u8 = 13;
    pub const CPU: u8 = 14;
    pub const KERNEL: u8 = 15;
    pub const LIBC: u8 = 16;
}

/// Why a key cannot be computed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// `inputs.files` still holds globs. A glob list is a declaration, not
    /// content: keying it would let a changed fixture go unnoticed.
    #[error(
        "inputs.files is still a list of globs ({}); resolve them to a content hash with `files_key` before computing the key, because a key over the patterns alone would not change when a matching file does",
        globs.join(", ")
    )]
    UnresolvedFiles {
        /// The unresolved patterns.
        globs: Vec<String>,
    },
}

/// Computes the input key.
///
/// One blake3 hasher is fed tagged, length-prefixed fields, so moving bytes
/// between neighbouring fields or between an absent and an empty value always
/// changes the key. `consumes` is hashed as a set (sorted) because its order carries no
/// meaning. Optional platform fields are
/// omitted entirely when `None`, which is what keeps a node that never
/// declared `sensitive` from re-running after a kernel upgrade (§3.7).
///
/// # Errors
///
/// [`KeyError::UnresolvedFiles`] when `inputs.files` holds globs. `None` (no
/// runtime files) is a valid, keyed state.
pub fn key(schema: u32, inputs: &Inputs, platform: &Platform) -> Result<Digest, KeyError> {
    let mut f = Framer::new("keel/key");
    f.field(tag::SCHEMA, &schema.to_le_bytes());
    f.opt_digest(tag::CODE, inputs.code.as_ref());
    f.opt_str(tag::CODE_KIND, inputs.code_kind.map(|k| k.as_str()));
    match &inputs.files {
        None => f.field(tag::FILES_HASH, &[0]),
        Some(FilesInput::Hash(d)) => f.opt_digest(tag::FILES_HASH, Some(d)),
        Some(FilesInput::Globs(globs)) => {
            return Err(KeyError::UnresolvedFiles {
                globs: globs.clone(),
            });
        }
    };
    f.opt_digest(tag::ENV, inputs.env.as_ref());
    f.opt_digest(tag::TOOLS, inputs.tools.as_ref());
    let mut consumes: Vec<&str> = inputs.consumes.iter().map(|n| n.as_str()).collect();
    consumes.sort_unstable();
    f.strings(tag::CONSUMES, consumes);
    f.opt_str(tag::DRV, inputs.drv.as_deref());

    f.field(tag::TRIPLE, platform.triple.as_bytes());
    f.field(tag::TOOLCHAIN, platform.toolchain.as_bytes());
    f.opt_str(tag::EMULATOR, platform.emulator.as_deref());
    f.field(tag::NET, &[platform.net as u8]);
    for (t, v) in [
        (tag::CPU, &platform.cpu),
        (tag::KERNEL, &platform.kernel),
        (tag::LIBC, &platform.libc),
    ] {
        if let Some(v) = v {
            f.field(t, v.as_bytes());
        }
    }
    Ok(f.finish())
}

/// A hash domain: the string that starts every framed hash of one kind of key.
/// It ends in a version (`keel/runner/1`), so changing what a key covers
/// orphans old records instead of reinterpreting them (design/keys.md K3).
pub trait Domain {
    /// The domain string, ending in `/<version>`.
    const NAME: &'static str;
}

/// A 32-byte blake3 digest in a named domain (design/keys.md §2.1).
///
/// There is no zero or empty value and no way to build one from raw bytes
/// outside this crate: the only constructor is [`Key::seal`], on a framed
/// hash begun in the domain's own name. A `Key<Runner>` therefore cannot be
/// confused with a `Key<SandboxProfile>` or with bytes someone made up, and
/// "absent" is an `Option`, never a sentinel.
pub struct Key<D: Domain>([u8; 32], std::marker::PhantomData<fn() -> D>);

impl<D: Domain> Key<D> {
    /// Finishes a hash that was started in this domain.
    pub(crate) fn seal(f: &Framer) -> Self {
        Key(*f.finish().as_bytes(), std::marker::PhantomData)
    }

    /// Starts the framed hash of a key in this domain.
    pub(crate) fn begin() -> Framer {
        Framer::new(D::NAME)
    }

    /// The key as a plain digest, for storage and display.
    pub fn digest(&self) -> Digest {
        Digest::Blake3(self.0)
    }
}

impl<D: Domain> Clone for Key<D> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<D: Domain> Copy for Key<D> {}
impl<D: Domain> PartialEq for Key<D> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<D: Domain> Eq for Key<D> {}
impl<D: Domain> std::hash::Hash for Key<D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl<D: Domain> std::fmt::Debug for Key<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key<{}>({})", D::NAME, self.digest())
    }
}
impl<D: Domain> std::fmt::Display for Key<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.digest().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::node::{CodeKind, NodeId};

    fn digest() -> impl Strategy<Value = Digest> {
        (any::<[u8; 32]>(), any::<bool>()).prop_map(|(b, s)| {
            if s {
                Digest::Sha256(b)
            } else {
                Digest::Blake3(b)
            }
        })
    }

    fn word() -> impl Strategy<Value = String> {
        "[a-z0-9-]{0,8}"
    }

    fn inputs() -> impl Strategy<Value = Inputs> {
        let files = prop_oneof![Just(None), digest().prop_map(|d| Some(FilesInput::Hash(d))),];
        (
            prop::option::of(digest()),
            prop::option::of(prop_oneof![
                Just(CodeKind::Reach),
                Just(CodeKind::Executable)
            ]),
            files,
            prop::option::of(digest()),
            prop::option::of(digest()),
            prop::collection::vec(word().prop_map(NodeId::new), 0..3),
            prop::option::of(word()),
        )
            .prop_map(
                |(code, code_kind, files, env, tools, consumes, drv)| Inputs {
                    code,
                    code_kind,
                    files,
                    env,
                    tools,
                    consumes,
                    drv,
                },
            )
    }

    fn platform() -> impl Strategy<Value = Platform> {
        (
            word(),
            word(),
            prop::option::of(word()),
            prop_oneof![Just(NetMode::Isolated), Just(NetMode::Open)],
            prop::option::of(word()),
            prop::option::of(word()),
            prop::option::of(word()),
        )
            .prop_map(
                |(triple, toolchain, emulator, net, cpu, kernel, libc)| Platform {
                    triple,
                    toolchain,
                    emulator,
                    net,
                    cpu,
                    kernel,
                    libc,
                    extra: BTreeMap::new(),
                },
            )
    }

    fn flip(d: &Digest) -> Digest {
        let mut b = *d.as_bytes();
        b[0] ^= 1;
        match d {
            Digest::Blake3(_) => Digest::Blake3(b),
            Digest::Sha256(_) => Digest::Sha256(b),
        }
    }

    fn toggle(o: &mut Option<String>) {
        *o = match o.take() {
            None => Some(String::new()),
            Some(_) => None,
        };
    }

    fn k(schema: u32, i: &Inputs, p: &Platform) -> Digest {
        key(schema, i, p).unwrap()
    }

    const FIELDS: usize = 19;

    /// Changes exactly one field so that the value is certainly different.
    /// Generated words never contain `!` or upper case, so appending either
    /// cannot land on another generated value.
    fn mutate(i: usize, schema: &mut u32, inp: &mut Inputs, p: &mut Platform) {
        match i {
            0 => *schema = schema.wrapping_add(1),
            1 => inp.code = Some(inp.code.as_ref().map_or(Digest::Blake3([0; 32]), flip)),
            2 => {
                inp.code_kind = match inp.code_kind {
                    None => Some(CodeKind::Reach),
                    Some(CodeKind::Reach) => Some(CodeKind::Executable),
                    Some(CodeKind::Executable) => None,
                }
            }
            3 => {
                inp.files = match inp.files.take() {
                    None => Some(FilesInput::Hash(Digest::Blake3([0; 32]))),
                    Some(FilesInput::Hash(d)) => Some(FilesInput::Hash(flip(&d))),
                    Some(FilesInput::Globs(_)) => unreachable!("never generated"),
                }
            }
            4 => inp.env = Some(inp.env.as_ref().map_or(Digest::Blake3([0; 32]), flip)),
            5 => inp.tools = Some(inp.tools.as_ref().map_or(Digest::Blake3([0; 32]), flip)),
            6 => inp.consumes.push(NodeId::new("Z")),
            7 => toggle(&mut inp.drv),
            8 => p.triple.push('!'),
            9 => p.toolchain.push('!'),
            10 => toggle(&mut p.emulator),
            11 => {
                p.net = match p.net {
                    NetMode::Isolated => NetMode::Open,
                    NetMode::Open => NetMode::Isolated,
                }
            }
            12 => toggle(&mut p.cpu),
            13 => toggle(&mut p.kernel),
            14 => toggle(&mut p.libc),
            // Same digest bytes under the other algorithm.
            15 => {
                if let Some(d) = inp.code.as_mut() {
                    *d = match *d {
                        Digest::Blake3(b) => Digest::Sha256(b),
                        Digest::Sha256(b) => Digest::Blake3(b),
                    };
                } else {
                    inp.code = Some(Digest::Sha256([0; 32]));
                }
            }
            // drv present before and after, with different text.
            16 => inp.drv = Some(inp.drv.take().map_or("Z".into(), |d| d + "!")),
            17 => p.cpu = Some(p.cpu.take().map_or("Z".into(), |c| c + "!")),
            _ => p.kernel = Some(p.kernel.take().map_or("Z".into(), |c| c + "!")),
        }
    }

    proptest! {
        #[test]
        fn equal_inputs_give_equal_keys(schema in any::<u32>(), i in inputs(), p in platform()) {
            prop_assert_eq!(k(schema, &i, &p), k(schema, &i.clone(), &p.clone()));
        }

        #[test]
        fn changing_any_one_field_changes_the_key(
            schema in any::<u32>(), i in inputs(), p in platform(), field in 0..FIELDS,
        ) {
            let before = k(schema, &i, &p);
            let (mut s2, mut i2, mut p2) = (schema, i.clone(), p.clone());
            mutate(field, &mut s2, &mut i2, &mut p2);
            prop_assert_ne!(before, k(s2, &i2, &p2), "field {}", field);
        }
    }

    #[test]
    fn unresolved_globs_are_refused_not_keyed() {
        let p = Platform::new("t", "r", NetMode::Isolated);
        let globs = Inputs {
            files: Some(FilesInput::Globs(vec!["fixtures/**".into()])),
            ..Inputs::default()
        };
        let err = key(1, &globs, &p).unwrap_err();
        assert_eq!(
            err,
            KeyError::UnresolvedFiles {
                globs: vec!["fixtures/**".into()]
            }
        );
        let text = err.to_string();
        assert!(
            text.contains("fixtures/**") && text.contains("files_key"),
            "{text}"
        );
        // No runtime files at all is a keyed state, not an error.
        assert!(key(1, &Inputs::default(), &p).is_ok());
    }

    #[test]
    fn consumes_is_a_set() {
        let p = Platform::new("t", "r", NetMode::Isolated);
        let a = Inputs {
            consumes: vec!["a".into(), "b".into()],
            ..Inputs::default()
        };
        let b = Inputs {
            consumes: vec!["b".into(), "a".into()],
            ..Inputs::default()
        };
        assert_eq!(k(1, &a, &p), k(1, &b, &p));
    }

    #[test]
    fn extra_platform_labels_are_not_keyed() {
        let mut p = Platform::new("t", "r", NetMode::Isolated);
        let before = k(1, &Inputs::default(), &p);
        p.extra.insert("host".into(), "ilo".into());
        assert_eq!(before, k(1, &Inputs::default(), &p));
    }

    #[test]
    fn unspecified_sensitivity_is_absent_not_empty() {
        let mut p = Platform::new("t", "r", NetMode::Isolated);
        let none = k(1, &Inputs::default(), &p);
        p.cpu = Some(String::new());
        assert_ne!(none, k(1, &Inputs::default(), &p));
    }

    #[test]
    fn platform_keeps_unknown_fields_in_extra() {
        let p: Platform = serde_json::from_str(
            r#"{"triple":"x","toolchain":"r","emulator":null,"net":"open","host":"ilo"}"#,
        )
        .unwrap();
        assert_eq!(p.extra["host"], "ilo");
        assert_eq!(p.net, NetMode::Open);
    }
}
