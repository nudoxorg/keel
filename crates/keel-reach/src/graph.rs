//! The relocation graph: Tarjan's strongly connected components and the
//! Merkle hash over them. Independent of object formats so it can be tested
//! on hand-built graphs.

use crate::model::Hash;

/// Nodes carry a content hash; edges are relocation targets in relocation
/// (offset) order. Offsets, kinds and addends are already inside `content`.
pub struct Graph {
    pub content: Vec<Hash>,
    first: Vec<u32>,
    targets: Vec<u32>,
    /// Nodes whose edge order carries no meaning (a linker-synthesised section set).
    unordered: Vec<bool>,
}

impl Graph {
    pub fn from_adj(content: Vec<Hash>, adj: Vec<Vec<u32>>, unordered: Vec<bool>) -> Graph {
        let mut first = Vec::with_capacity(adj.len() + 1);
        let mut targets = Vec::new();
        for a in &adj {
            first.push(targets.len() as u32);
            targets.extend_from_slice(a);
        }
        first.push(targets.len() as u32);
        Graph {
            content,
            first,
            targets,
            unordered,
        }
    }

    pub fn len(&self) -> usize {
        self.content.len()
    }

    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    pub fn succ(&self, n: u32) -> &[u32] {
        &self.targets[self.first[n as usize] as usize..self.first[n as usize + 1] as usize]
    }

    pub fn edge_count(&self) -> usize {
        self.targets.len()
    }
}

/// Components in the order Tarjan completes them: every component comes after
/// all components reachable from it, so hashes can be computed front to back.
pub struct Condensation {
    pub scc_of: Vec<u32>,
    start: Vec<u32>,
    nodes: Vec<u32>,
}

impl Condensation {
    pub fn count(&self) -> usize {
        self.start.len() - 1
    }

    pub fn members(&self, s: u32) -> &[u32] {
        &self.nodes[self.start[s as usize] as usize..self.start[s as usize + 1] as usize]
    }
}

/// Iterative Tarjan: the graphs reach hundreds of thousands of nodes and call
/// chains deep enough to overflow a recursive one.
pub fn tarjan(g: &Graph) -> Condensation {
    const UNSEEN: u32 = u32::MAX;
    let n = g.len();
    let mut index = vec![UNSEEN; n];
    let mut low = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut scc_of = vec![UNSEEN; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut work: Vec<(u32, u32)> = Vec::new();
    let (mut start, mut nodes) = (vec![0u32], Vec::with_capacity(n));
    let mut counter = 0u32;
    for root in 0..n as u32 {
        if index[root as usize] != UNSEEN {
            continue;
        }
        work.push((root, 0));
        while let Some(&mut (v, ref mut ei)) = work.last_mut() {
            let vi = v as usize;
            if *ei == 0 && index[vi] == UNSEEN {
                index[vi] = counter;
                low[vi] = counter;
                counter += 1;
                stack.push(v);
                on_stack[vi] = true;
            }
            let succ = g.succ(v);
            if let Some(&w) = succ.get(*ei as usize) {
                *ei += 1;
                let wi = w as usize;
                if index[wi] == UNSEEN {
                    work.push((w, 0));
                } else if on_stack[wi] {
                    low[vi] = low[vi].min(index[wi]);
                }
                continue;
            }
            work.pop();
            if let Some(&(parent, _)) = work.last() {
                low[parent as usize] = low[parent as usize].min(low[vi]);
            }
            if low[vi] == index[vi] {
                let id = (start.len() - 1) as u32;
                loop {
                    let w = stack.pop().expect("component root is on the stack");
                    on_stack[w as usize] = false;
                    scc_of[w as usize] = id;
                    nodes.push(w);
                    if w == v {
                        break;
                    }
                }
                start.push(nodes.len() as u32);
            }
        }
    }
    Condensation {
        scc_of,
        start,
        nodes,
    }
}

pub struct Merkle {
    pub scc_hash: Vec<Hash>,
    /// Rank of a node's refined colour within its component; 0 for singletons.
    pub label: Vec<u32>,
}

fn h(parts: &[&[u8]]) -> Hash {
    let mut x = blake3::Hasher::new();
    for p in parts {
        x.update(p);
    }
    *x.finalize().as_bytes()
}

/// `hash(atom) = blake3(tag | content | for each relocation: hash of the target)`
/// where an out-of-component target contributes its component's hash (plus the
/// target's rank inside it, so calling `f` is not the same as calling `g` when
/// both sit in one cycle) and an in-component target contributes
/// `scc-local:<rank>`. Ranks come from colour refinement over the component's
/// own edges, so they depend on structure and content, never on node order.
pub fn merkle(g: &Graph, c: &Condensation) -> Merkle {
    let n = g.len();
    let mut scc_hash: Vec<Hash> = Vec::with_capacity(c.count());
    let mut label = vec![0u32; n];
    let mut pos = vec![u32::MAX; n];
    let ext = |t: u32, scc_hash: &[Hash], label: &[u32]| -> Hash {
        let s = c.scc_of[t as usize];
        if c.members(s).len() == 1 {
            scc_hash[s as usize]
        } else {
            h(&[
                b"scc-member",
                &scc_hash[s as usize],
                &label[t as usize].to_le_bytes(),
            ])
        }
    };
    for s in 0..c.count() as u32 {
        let members = c.members(s);
        // External parts of each member's hash do not change during refinement.
        let mut base: Vec<Hash> = Vec::with_capacity(members.len());
        for (i, &m) in members.iter().enumerate() {
            pos[m as usize] = i as u32;
        }
        for &m in members {
            let mut x = blake3::Hasher::new();
            x.update(b"keel-reach/colour/1");
            x.update(&g.content[m as usize]);
            for &t in g.succ(m) {
                if c.scc_of[t as usize] == s {
                    x.update(b"L");
                } else {
                    x.update(b"E");
                    x.update(&ext(t, &scc_hash, &label));
                }
            }
            base.push(*x.finalize().as_bytes());
        }
        let mut col = base;
        if members.len() > 1 {
            let classes = |col: &[Hash]| {
                let mut v = col.to_vec();
                v.sort_unstable();
                v.dedup();
                v.len()
            };
            let mut k = classes(&col);
            // At most one new class per round, so `len` rounds reach the fixed point;
            // the cap bounds pathological symmetric components.
            for _ in 0..members.len().min(64) {
                let next: Vec<Hash> = members
                    .iter()
                    .enumerate()
                    .map(|(i, &m)| {
                        let mut x = blake3::Hasher::new();
                        x.update(&col[i]);
                        let mut loc: Vec<&Hash> = g
                            .succ(m)
                            .iter()
                            .filter(|&&t| c.scc_of[t as usize] == s)
                            .map(|&t| &col[pos[t as usize] as usize])
                            .collect();
                        if g.unordered[m as usize] {
                            loc.sort_unstable();
                        }
                        for l in loc {
                            x.update(l);
                        }
                        *x.finalize().as_bytes()
                    })
                    .collect();
                let nk = classes(&next);
                col = next;
                if nk == k {
                    break;
                }
                k = nk;
            }
            let mut ranks = col.clone();
            ranks.sort_unstable();
            ranks.dedup();
            for (i, &m) in members.iter().enumerate() {
                label[m as usize] = ranks
                    .binary_search(&col[i])
                    .expect("colour is in its own rank table")
                    as u32;
            }
        }
        let mut atom_hashes: Vec<Hash> = Vec::with_capacity(members.len());
        for &m in members {
            let mut x = blake3::Hasher::new();
            x.update(b"keel-reach/atom/1");
            x.update(&g.content[m as usize]);
            let mut ts: Vec<Hash> = g
                .succ(m)
                .iter()
                .map(|&t| {
                    if c.scc_of[t as usize] == s {
                        h(&[b"scc-local:", &label[t as usize].to_le_bytes()])
                    } else {
                        ext(t, &scc_hash, &label)
                    }
                })
                .collect();
            if g.unordered[m as usize] {
                ts.sort_unstable();
            }
            for t in &ts {
                x.update(t);
            }
            atom_hashes.push(*x.finalize().as_bytes());
        }
        atom_hashes.sort_unstable();
        let mut x = blake3::Hasher::new();
        x.update(b"keel-reach/scc/1");
        x.update(&(members.len() as u64).to_le_bytes());
        for a in &atom_hashes {
            x.update(a);
        }
        scc_hash.push(*x.finalize().as_bytes());
        for &m in members {
            pos[m as usize] = u32::MAX;
        }
    }
    Merkle { scc_hash, label }
}

impl Merkle {
    /// The hash by which a reference to `node` is committed to: its component's hash, plus the
    /// node's rank inside the component when that has several members (so a reference to `f`
    /// differs from one to `g` in the same cycle). Because a component's hash is built from
    /// its members' bytes and from the hashes of every component they point at, this one
    /// hash covers everything reachable from `node`, cycles included.
    pub fn node_hash(&self, c: &Condensation, node: u32) -> Hash {
        let s = c.scc_of[node as usize];
        if c.members(s).len() == 1 {
            self.scc_hash[s as usize]
        } else {
            h(&[
                b"scc-member",
                &self.scc_hash[s as usize],
                &self.label[node as usize].to_le_bytes(),
            ])
        }
    }
}

impl Condensation {
    /// Add every component reachable from `roots` that `seen` does not yet mark.
    pub fn close(&self, g: &Graph, roots: &[u32], seen: &mut [bool], out: &mut Vec<u32>) {
        let mut work: Vec<u32> = Vec::new();
        for &r in roots {
            let s = self.scc_of[r as usize];
            if !std::mem::replace(&mut seen[s as usize], true) {
                work.push(s);
                out.push(s);
            }
        }
        while let Some(s) = work.pop() {
            for &m in self.members(s) {
                for &t in g.succ(m) {
                    let ts = self.scc_of[t as usize];
                    if !std::mem::replace(&mut seen[ts as usize], true) {
                        work.push(ts);
                        out.push(ts);
                    }
                }
            }
        }
    }
}

/// The key of a test: the harness, and the roots the test starts from, each by the hash that
/// commits to everything it reaches. O(roots), where hashing every reachable component
/// (`closure_key`) is O(reach). `groups` are the labelled root sets (entries, descriptors,
/// extra roots); within a group order does not matter.
pub fn root_key(harness_key: &Hash, groups: &[(&str, Vec<Hash>)]) -> Hash {
    let mut x = blake3::Hasher::new();
    x.update(b"keel-reach/key/2");
    x.update(harness_key);
    for (label, hashes) in groups {
        let mut v = hashes.clone();
        v.sort_unstable();
        x.update(&(label.len() as u64).to_le_bytes());
        x.update(label.as_bytes());
        x.update(&(v.len() as u64).to_le_bytes());
        for e in &v {
            x.update(e);
        }
    }
    *x.finalize().as_bytes()
}

/// `blake3(schema | count | sorted component hashes)`. Duplicates are kept: two
/// identical functions in a reach are two functions. The key before `root_key`; kept to
/// compare against it (`Options::closure_key`).
pub fn key_of(scc_hashes: impl Iterator<Item = Hash>) -> Hash {
    let mut v: Vec<Hash> = scc_hashes.collect();
    v.sort_unstable();
    let mut x = blake3::Hasher::new();
    x.update(b"keel-reach/key/1");
    x.update(&(v.len() as u64).to_le_bytes());
    for e in &v {
        x.update(e);
    }
    *x.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(tag: &str) -> Hash {
        *blake3::hash(tag.as_bytes()).as_bytes()
    }

    fn graph(spec: &[(&str, &[u32])]) -> Graph {
        Graph::from_adj(
            spec.iter().map(|(t, _)| leaf(t)).collect(),
            spec.iter().map(|(_, a)| a.to_vec()).collect(),
            vec![false; spec.len()],
        )
    }

    fn analyse(g: &Graph) -> (Condensation, Merkle) {
        let c = tarjan(g);
        let m = merkle(g, &c);
        (c, m)
    }

    #[test]
    fn tarjan_finds_cycles_and_orders_callees_first() {
        // 0 -> 1 -> 2 -> 1, 2 -> 3, 4 -> 4
        let g = graph(&[
            ("a", &[1]),
            ("b", &[2]),
            ("c", &[1, 3]),
            ("d", &[]),
            ("e", &[4]),
        ]);
        let c = tarjan(&g);
        assert_eq!(c.count(), 4);
        assert_eq!(c.scc_of[1], c.scc_of[2]);
        assert_ne!(c.scc_of[0], c.scc_of[1]);
        assert!(
            c.scc_of[3] < c.scc_of[1] && c.scc_of[1] < c.scc_of[0],
            "callees complete first"
        );
        assert_eq!(c.members(c.scc_of[4]), [4]);
    }

    #[test]
    fn tarjan_survives_a_very_deep_chain() {
        let n = 200_000u32;
        let adj: Vec<Vec<u32>> = (0..n)
            .map(|i| if i + 1 < n { vec![i + 1] } else { vec![] })
            .collect();
        let g = Graph::from_adj(
            (0..n).map(|i| leaf(&i.to_string())).collect(),
            adj,
            vec![false; n as usize],
        );
        assert_eq!(tarjan(&g).count(), n as usize);
    }

    #[test]
    fn tarjan_big_ring_is_one_component() {
        let n = 5000u32;
        let adj: Vec<Vec<u32>> = (0..n).map(|i| vec![(i + 1) % n]).collect();
        let g = Graph::from_adj(
            (0..n).map(|i| leaf(&i.to_string())).collect(),
            adj,
            vec![false; n as usize],
        );
        assert_eq!(tarjan(&g).count(), 1);
    }

    #[test]
    fn mutual_recursion_hash_is_defined_and_stable_under_reordering() {
        // f <-> g, both call h; main calls f.
        let a = graph(&[("main", &[1]), ("f", &[2, 3]), ("g", &[1, 3]), ("h", &[])]);
        // Same program with nodes numbered differently.
        let b = graph(&[("h", &[]), ("g", &[2, 0]), ("f", &[1, 0]), ("main", &[2])]);
        let (ca, ma) = analyse(&a);
        let (cb, mb) = analyse(&b);
        let ha = ma.scc_hash[ca.scc_of[0] as usize];
        let hb = mb.scc_hash[cb.scc_of[3] as usize];
        assert_eq!(ha, hb, "root hash does not depend on node numbering");
        assert_eq!(
            ma.scc_hash[ca.scc_of[1] as usize],
            mb.scc_hash[cb.scc_of[2] as usize]
        );
        // Defined twice over the same input: identical.
        let (ca2, ma2) = analyse(&a);
        assert_eq!(ma2.scc_hash[ca2.scc_of[0] as usize], ha);
    }

    #[test]
    fn changing_one_member_of_a_cycle_changes_every_dependent() {
        let a = graph(&[("main", &[1]), ("f", &[2]), ("g", &[1])]);
        let b = graph(&[("main", &[1]), ("f", &[2]), ("g!", &[1])]);
        let (ca, ma) = analyse(&a);
        let (cb, mb) = analyse(&b);
        assert_ne!(
            ma.scc_hash[ca.scc_of[0] as usize],
            mb.scc_hash[cb.scc_of[0] as usize]
        );
    }

    #[test]
    fn calling_f_differs_from_calling_g_when_both_are_in_one_cycle() {
        // Same cycle contents; the caller picks a different member.
        let a = graph(&[("main", &[1]), ("f", &[2]), ("g", &[1])]);
        let b = graph(&[("main", &[2]), ("f", &[2]), ("g", &[1])]);
        let (ca, ma) = analyse(&a);
        let (cb, mb) = analyse(&b);
        assert_eq!(
            ma.scc_hash[ca.scc_of[1] as usize],
            mb.scc_hash[cb.scc_of[1] as usize]
        );
        assert_ne!(
            ma.scc_hash[ca.scc_of[0] as usize],
            mb.scc_hash[cb.scc_of[0] as usize]
        );
    }

    #[test]
    fn a_root_hash_covers_everything_reachable_cycles_included() {
        // main -> f <-> g -> h: a change anywhere below main, including inside the cycle
        // and below it, changes the hash of f, of g and of the key built from them.
        let base = graph(&[("main", &[1]), ("f", &[2]), ("g", &[1, 3]), ("h", &[])]);
        let deep = graph(&[("main", &[1]), ("f", &[2]), ("g", &[1, 3]), ("h!", &[])]);
        let in_cycle = graph(&[("main", &[1]), ("f", &[2]), ("g!", &[1, 3]), ("h", &[])]);
        let hash = |gr: &Graph, node: u32| {
            let (c, m) = analyse(gr);
            m.node_hash(&c, node)
        };
        let key = |gr: &Graph, root: u32| {
            let (c, m) = analyse(gr);
            root_key(&[0; 32], &[("entries", vec![m.node_hash(&c, root)])])
        };
        for (what, changed) in [("below the cycle", &deep), ("inside the cycle", &in_cycle)] {
            for node in [0, 1, 2] {
                assert_ne!(hash(&base, node), hash(changed, node), "{what}: node {node}");
            }
            assert_ne!(key(&base, 0), key(changed, 0), "{what}");
        }
        // Two members of one cycle are different roots.
        assert_ne!(hash(&base, 1), hash(&base, 2));
        assert_ne!(key(&base, 1), key(&base, 2));
        // Nothing that main does not reach moves main's hash: an unreferenced extra node.
        let extra = graph(&[("main", &[1]), ("f", &[2]), ("g", &[1, 3]), ("h", &[]), ("unused", &[3])]);
        assert_eq!(hash(&base, 0), hash(&extra, 0));
    }

    #[test]
    fn self_recursion_is_local() {
        let a = graph(&[("f", &[0])]);
        let b = graph(&[("f", &[])]);
        let (ca, ma) = analyse(&a);
        let (cb, mb) = analyse(&b);
        assert_ne!(
            ma.scc_hash[ca.scc_of[0] as usize],
            mb.scc_hash[cb.scc_of[0] as usize]
        );
    }

    #[test]
    fn closure_and_key() {
        let g = graph(&[("a", &[1]), ("b", &[2]), ("c", &[]), ("d", &[2])]);
        let (c, m) = analyse(&g);
        let mut seen = vec![false; c.count()];
        let mut out = Vec::new();
        c.close(&g, &[0], &mut seen, &mut out);
        assert_eq!(out.len(), 3, "a reaches b and c but not d");
        let k1 = key_of(out.iter().map(|&s| m.scc_hash[s as usize]));
        let mut seen2 = vec![false; c.count()];
        let mut out2 = Vec::new();
        c.close(&g, &[3], &mut seen2, &mut out2);
        assert_ne!(k1, key_of(out2.iter().map(|&s| m.scc_hash[s as usize])));
    }
}
