//! `keel interactions`: DESIGN §2.7. Read the registries of things that must
//! be exercised together and count the nodes that exercise each pair. Making
//! an untested interaction visible is the whole job; writing the test is not.

use std::collections::{BTreeSet, HashSet};

use anyhow::{Context, Result, bail};
use keel::{Interaction, Manifest, PartId, PartKind, Report};
use serde_json::Value;

/// A registered interaction. A node covers it when its `joins` hold the pair
/// and every `extra` part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    pub pair: [PartId; 2],
    /// Parts attached to the pair (the fleet's `edge:<name>`).
    pub extra: Vec<PartId>,
    pub source: String,
    /// The negative control's definition, printed beside the interaction.
    pub wrong: Option<String>,
}

fn svc(name: &str) -> PartId {
    PartId::new(PartKind::Service, name)
}

/// Every workspace dependency edge, `crate:A` to `crate:B`, deduplicated.
pub fn from_cargo_metadata(v: &Value) -> Result<Vec<Registered>> {
    let packages = v["packages"].as_array().context("cargo metadata has no `packages` array; pass the output of `cargo metadata --format-version 1`")?;
    let members: HashSet<&str> = v["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let member_pkgs: Vec<&Value> = packages
        .iter()
        .filter(|p| p["id"].as_str().is_some_and(|i| members.contains(i)))
        .collect();
    let names: HashSet<&str> = member_pkgs
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for p in member_pkgs {
        let Some(from) = p["name"].as_str() else {
            continue;
        };
        for d in p["dependencies"].as_array().into_iter().flatten() {
            let Some(to) = d["name"]
                .as_str()
                .filter(|n| names.contains(n) && *n != from)
            else {
                continue;
            };
            if seen.insert((from.to_owned(), to.to_owned())) {
                out.push(Registered {
                    pair: [
                        PartId::new(PartKind::Crate, from),
                        PartId::new(PartKind::Crate, to),
                    ],
                    extra: vec![],
                    source: "cargo".into(),
                    wrong: None,
                });
            }
        }
    }
    Ok(out)
}

fn fleet(v: &Value) -> Result<Vec<Registered>> {
    let edges = if v["edges"].is_object() {
        &v["edges"]
    } else {
        &v["derived"]["edges"]
    };
    let mut out = Vec::new();
    for (name, e) in edges.as_object().into_iter().flatten() {
        let (Some(from), Some(to)) = (e["from"]["service"].as_str(), e["to"]["service"].as_str())
        else {
            bail!("fleet edge `{name}` has no from.service and to.service; fix fleet.lock.json");
        };
        let w = &e["call"]["wrong"];
        let wrong = w["change"].as_str().map(|c| {
            format!(
                "{c} -> expect {}",
                w["expect"].as_str().unwrap_or("failure")
            )
        });
        out.push(Registered {
            pair: [svc(from), svc(to)],
            extra: vec![PartId::new(PartKind::Edge, name.as_str())],
            source: "fleet.lock.json".into(),
            wrong,
        });
    }
    Ok(out)
}

/// `https://api.example.test/v1/x` is `("https", "api.example.test")`.
fn origin_of(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| (scheme.to_owned(), host.to_owned()))
}

/// The keel `PartKind` has no `site` namespace, so a site is the `service:`
/// of its host: the pair stays distinguishable and parseable in a report.
fn serving(v: &Value) -> Vec<Registered> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for section in ["landing", "dashboard"] {
        let Some(own) = v[section]["origin"].as_str().and_then(origin_of) else {
            continue;
        };
        for page in v[section]["pages"].as_array().into_iter().flatten() {
            for link in page["links"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if let Some(other) = origin_of(link).filter(|o| *o != own)
                    && seen.insert((own.1.clone(), other.1.clone()))
                {
                    out.push(Registered {
                        pair: [svc(&own.1), svc(&other.1)],
                        extra: vec![],
                        source: "serving.json".into(),
                        wrong: None,
                    });
                }
            }
        }
    }
    out
}

fn auth_env(v: &Value) -> Result<Vec<Registered>> {
    let service = v["service"]
        .as_str()
        .context("env.json has no `service`; pass a contract environment file")?;
    let mut out = Vec::new();
    for r in v["routes"].as_array().into_iter().flatten() {
        let Some(path) = r["path"].as_str() else {
            continue;
        };
        // A route with no method answers every method.
        let route = format!("{} {path}", r["method"].as_str().unwrap_or("ANY"));
        out.push(Registered {
            pair: [svc(service), PartId::new(PartKind::Route, route)],
            extra: vec![],
            source: "env.json".into(),
            wrong: None,
        });
    }
    Ok(out)
}

fn generic(v: &Value) -> Result<Vec<Registered>> {
    let mut out = Vec::new();
    for (i, item) in v.as_array().into_iter().flatten().enumerate() {
        let pair = item["interaction"]
            .as_array()
            .filter(|a| a.len() == 2)
            .with_context(|| format!("registry entry {i} needs `interaction: [part, part]`"))?;
        let part = |j: usize| -> Result<PartId> {
            pair[j]
                .as_str()
                .unwrap_or_default()
                .parse::<PartId>()
                .map_err(Into::into)
        };
        out.push(Registered {
            pair: [part(0)?, part(1)?],
            extra: vec![],
            source: item["source"].as_str().unwrap_or("registry").to_owned(),
            wrong: None,
        });
    }
    Ok(out)
}

/// Recognises a registry by its shape; the file name is only used in errors.
pub fn from_registry(v: &Value, file: &str) -> Result<Vec<Registered>> {
    if v.is_array() {
        generic(v).with_context(|| format!("in generic registry {file}"))
    } else if v["edges"].is_object() || v["derived"]["edges"].is_object() {
        fleet(v).with_context(|| format!("in {file}"))
    } else if v["routes"].is_array() {
        auth_env(v).with_context(|| format!("in {file}"))
    } else if v["landing"]["pages"].is_array() || v["dashboard"]["pages"].is_array() {
        Ok(serving(v))
    } else {
        bail!(
            "{file} is not a known registry; use cargo metadata (--cargo-metadata), fleet.lock.json, serving.json, env.json, or a JSON list of {{\"interaction\": [part, part], \"source\": \"...\"}}"
        )
    }
}

pub struct Row {
    pub reg: Registered,
    pub nodes: u64,
}

/// Counts covering nodes. With a report, only nodes that passed (or were
/// cached) count, because a failed node exercised nothing; without one every
/// manifest node counts.
pub fn cover(regs: Vec<Registered>, manifest: &Manifest, report: Option<&Report>) -> Vec<Row> {
    let live: Option<HashSet<&str>> = report.map(|r| {
        r.nodes
            .iter()
            .filter(|n| n.status.gates_as_pass())
            .map(|n| n.id.as_str())
            .collect()
    });
    let nodes: Vec<&keel::Node> = manifest
        .nodes
        .iter()
        .filter(|n| live.as_ref().is_none_or(|l| l.contains(n.id.as_str())))
        .collect();
    regs.into_iter()
        .map(|reg| {
            let n = nodes
                .iter()
                .filter(|n| {
                    reg.pair
                        .iter()
                        .chain(&reg.extra)
                        .all(|p| n.joins.contains(p))
                })
                .count() as u64;
            Row { reg, nodes: n }
        })
        .collect()
}

/// Zero rows first, then by pair.
pub fn sorted(mut rows: Vec<Row>) -> Vec<Row> {
    rows.sort_by(|a, b| {
        (a.nodes != 0, &a.reg.pair, &a.reg.extra).cmp(&(b.nodes != 0, &b.reg.pair, &b.reg.extra))
    });
    rows
}

pub fn to_json(rows: &[Row]) -> Vec<Interaction> {
    rows.iter()
        .map(|r| Interaction {
            interaction: r.reg.pair.clone(),
            source: r.reg.source.clone(),
            nodes: r.nodes,
        })
        .collect()
}

pub fn render(rows: &[Row], color: bool) -> String {
    let (red, off) = if color {
        ("\x1b[31m", "\x1b[0m")
    } else {
        ("", "")
    };
    let mut out = String::new();
    for r in rows {
        let extra: String = r.reg.extra.iter().map(|e| format!("  {e}")).collect();
        let line = format!(
            "{:>5}  {} -> {}{extra}  [{}]",
            r.nodes, r.reg.pair[0], r.reg.pair[1], r.reg.source
        );
        if r.nodes == 0 {
            out.push_str(&format!("{red}{line}{off}\n"));
        } else {
            out.push_str(&line);
            out.push('\n');
        }
        if let Some(w) = &r.reg.wrong {
            out.push_str(&format!("         negative control: {w}\n"));
        }
    }
    let zero = rows.iter().filter(|r| r.nodes == 0).count();
    out.push_str(&format!(
        "{} interactions, {zero} with no covering node\n",
        rows.len()
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLEET: &str = include_str!("../tests/fixtures/fleet.lock.excerpt.json");
    const SERVING: &str = include_str!("../tests/fixtures/serving.excerpt.json");
    const ENV: &str = include_str!("../tests/fixtures/env.excerpt.json");
    const META: &str = include_str!("../tests/fixtures/cargo-metadata.excerpt.json");
    const MANIFEST: &str = include_str!("../../keel/tests/fixtures/manifest.json");

    fn load(text: &str, name: &str) -> Vec<Registered> {
        from_registry(&serde_json::from_str(text).unwrap(), name).unwrap()
    }

    #[test]
    fn fleet_edges_become_service_pairs_with_the_edge_attached_and_the_control() {
        let regs = load(FLEET, "fleet.lock.json");
        let oidc = regs
            .iter()
            .find(|r| r.extra[0].name() == "auth-to-identity-discovery")
            .unwrap();
        assert_eq!(oidc.pair[0].to_string(), "service:auth");
        assert_eq!(oidc.pair[1].to_string(), "service:server");
        assert_eq!(oidc.source, "fleet.lock.json");
        assert!(
            oidc.wrong
                .as_deref()
                .unwrap()
                .contains("wrong-vhost.invalid")
        );
        assert!(regs.iter().all(|r| r.wrong.is_some()));
    }

    #[test]
    fn serving_links_to_another_origin_only() {
        let regs = load(SERVING, "serving.json");
        let pairs: Vec<String> = regs
            .iter()
            .map(|r| format!("{}>{}", r.pair[0].name(), r.pair[1].name()))
            .collect();
        assert!(
            pairs.contains(&"example.test>api.example.test".to_owned()),
            "{pairs:?}"
        );
        assert!(pairs.contains(&"example.test>dashboard.example.test".to_owned()));
        assert!(pairs.contains(&"dashboard.example.test>example.test".to_owned()));
        assert!(!pairs.iter().any(|p| p == "example.test>example.test"));
        assert_eq!(
            pairs.len(),
            BTreeSet::from_iter(pairs.iter()).len(),
            "deduplicated"
        );
    }

    #[test]
    fn auth_routes_become_route_parts() {
        let regs = load(ENV, "env.json");
        let names: Vec<String> = regs.iter().map(|r| r.pair[1].to_string()).collect();
        assert!(names.contains(&"route:GET /v1/me".to_owned()));
        assert!(names.contains(&"route:ANY /auth/".to_owned()));
        assert!(
            regs.iter()
                .all(|r| r.pair[0].to_string() == "service:example-auth")
        );
    }

    #[test]
    fn cargo_metadata_gives_workspace_edges_once() {
        let regs = from_cargo_metadata(&serde_json::from_str(META).unwrap()).unwrap();
        let pairs: Vec<String> = regs
            .iter()
            .map(|r| format!("{} {}", r.pair[0], r.pair[1]))
            .collect();
        assert_eq!(
            pairs,
            ["crate:store crate:version", "crate:flow crate:store"],
            "dev+normal edges deduplicated, external deps dropped"
        );
    }

    #[test]
    fn generic_registry_and_unknown_shapes() {
        let regs = load(
            r#"[{"interaction":["crate:a","service:b"],"source":"mine"}]"#,
            "x.json",
        );
        assert_eq!(regs[0].source, "mine");
        let bad: Value = serde_json::from_str(r#"[{"interaction":["a","b"]}]"#).unwrap();
        assert!(from_registry(&bad, "x.json").is_err());
        let unknown: Value = serde_json::from_str(r#"{"hello": 1}"#).unwrap();
        assert!(
            from_registry(&unknown, "odd.json")
                .unwrap_err()
                .to_string()
                .contains("odd.json")
        );
    }

    #[test]
    fn coverage_counts_only_covering_nodes_and_lists_zero_first() {
        // The manifest example has one node joining crate:backend-store and one
        // joining service:nudox-backend + edge:mcp-to-locald (and the control twin
        // joins service:nudox-backend only).
        let manifest: Manifest = serde_json::from_str(MANIFEST).unwrap();
        let regs = vec![
            Registered {
                pair: [
                    "crate:backend-store".parse().unwrap(),
                    "crate:backend-store".parse().unwrap(),
                ],
                extra: vec![],
                source: "t".into(),
                wrong: None,
            },
            Registered {
                pair: [
                    "service:nudox-backend".parse().unwrap(),
                    "service:nudox-backend".parse().unwrap(),
                ],
                extra: vec!["edge:mcp-to-locald".parse().unwrap()],
                source: "t".into(),
                wrong: None,
            },
            Registered {
                pair: [
                    "service:nudox-backend".parse().unwrap(),
                    "service:nudox-backend".parse().unwrap(),
                ],
                extra: vec!["edge:nope".parse().unwrap()],
                source: "t".into(),
                wrong: None,
            },
        ];
        let rows = sorted(cover(regs.clone(), &manifest, None));
        assert_eq!(rows.iter().map(|r| r.nodes).collect::<Vec<_>>(), [0, 1, 1]);
        assert!(render(&rows, true).starts_with("\x1b[31m"));
        assert!(render(&rows, false).ends_with("3 interactions, 1 with no covering node\n"));
        // A failed node covers nothing.
        let mut report: Report =
            serde_json::from_str(include_str!("../../keel/tests/fixtures/report.json")).unwrap();
        report.nodes.clear();
        let none = cover(regs, &manifest, Some(&report));
        assert!(none.iter().all(|r| r.nodes == 0));
        assert_eq!(to_json(&rows).len(), 3);
    }
}
