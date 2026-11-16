//! The plan graph (DESIGN.md §2.3, §2.5, §2.6) as pure functions over a
//! manifest's nodes.
//!
//! Nothing here knows how a node runs or what reach analysis is; reach and
//! exercised-code sets arrive as plain data in [`ReachInfo`].

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;

use crate::node::{GroupId, Node, NodeId, Upstream};

/// An opaque symbol identity from reach analysis.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SymbolId(pub u64);

/// What reach analysis learned about the nodes of a plan. A node absent from
/// either map has no reach information (a foreign node, or a binary whose
/// reach could not be verified) and is handled by the group rule.
#[derive(Clone, Debug, Default)]
pub struct ReachInfo {
    /// `reach(T)`: every symbol the test can reach.
    pub reach: BTreeMap<NodeId, BTreeSet<SymbolId>>,
    /// `exercised(F) = reach(F) ∩ symbols(package(F))`.
    pub exercised: BTreeMap<NodeId, BTreeSet<SymbolId>>,
}

/// Why a plan could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// Two nodes share an id.
    #[error(
        "node id `{0}` appears twice in the manifest; ids must be unique, so fix the runner that emitted both or merge the manifests first"
    )]
    DuplicateId(NodeId),
    /// `stands_on` edges form a cycle. Each id stands on the next, and the
    /// last on the first.
    #[error("`stands_on` cycle: {}; remove one of these edges (a declaration usually closes the loop)", cycle_text(.0))]
    Cycle(Vec<NodeId>),
}

fn cycle_text(ids: &[NodeId]) -> String {
    let mut parts: Vec<&str> = ids.iter().map(NodeId::as_str).collect();
    parts.extend(ids.first().map(NodeId::as_str));
    parts.join(" -> ")
}

/// A validated, acyclic hierarchy of nodes.
///
/// Group upstreams are expanded to member sets. A node never stands on
/// itself through a group it belongs to; an explicit self edge is a cycle.
pub struct Plan {
    ids: Vec<NodeId>,
    index: HashMap<NodeId, usize>,
    /// Resolved upstream indices per node, sorted and unique.
    up: Vec<Vec<usize>>,
    down: Vec<Vec<usize>>,
    level: Vec<u32>,
    members: BTreeMap<GroupId, Vec<usize>>,
    unresolved: Vec<(NodeId, Upstream)>,
}

impl Plan {
    /// Indexes `nodes`, resolves groups, rejects duplicate ids and cycles and
    /// computes topological levels.
    ///
    /// An upstream that names no node or group in `nodes` is not an error:
    /// cross-repo edges are resolved by the conductor after merging. Such
    /// edges are listed by [`unresolved`](Self::unresolved), do not gate and do
    /// not count toward levels.
    pub fn new(nodes: &[Node]) -> Result<Plan, PlanError> {
        let mut index = HashMap::with_capacity(nodes.len());
        let mut members: BTreeMap<GroupId, Vec<usize>> = BTreeMap::new();
        for (i, n) in nodes.iter().enumerate() {
            if index.insert(n.id.clone(), i).is_some() {
                return Err(PlanError::DuplicateId(n.id.clone()));
            }
            members.entry(n.group.clone()).or_default().push(i);
        }

        let mut up = vec![Vec::new(); nodes.len()];
        let mut unresolved = Vec::new();
        for (i, n) in nodes.iter().enumerate() {
            for u in &n.stands_on {
                match u {
                    Upstream::Node(id) => match index.get(id) {
                        Some(&j) => up[i].push(j),
                        None => unresolved.push((n.id.clone(), u.clone())),
                    },
                    Upstream::Group(g) => match members.get(g) {
                        Some(ms) => up[i].extend(ms.iter().copied().filter(|&j| j != i)),
                        None => unresolved.push((n.id.clone(), u.clone())),
                    },
                }
            }
            up[i].sort_unstable();
            up[i].dedup();
        }
        let mut down = vec![Vec::new(); nodes.len()];
        for (i, ups) in up.iter().enumerate() {
            for &j in ups {
                down[j].push(i);
            }
        }

        let ids: Vec<NodeId> = nodes.iter().map(|n| n.id.clone()).collect();
        if let Some(cycle) = find_cycle(&up, &ids) {
            return Err(PlanError::Cycle(
                cycle.into_iter().map(|i| ids[i].clone()).collect(),
            ));
        }
        let level = levels(&up, &down);
        Ok(Plan {
            ids,
            index,
            up,
            down,
            level,
            members,
            unresolved,
        })
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    /// Whether the plan has no nodes.
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Topological level: 0 with nothing to stand on, else one more than the
    /// highest level it stands on.
    pub fn level(&self, id: &NodeId) -> Option<u32> {
        self.index.get(id).map(|&i| self.level[i])
    }

    /// Node ids in scheduling order: by level, then by id.
    pub fn order(&self) -> Vec<&NodeId> {
        let mut v: Vec<usize> = (0..self.ids.len()).collect();
        v.sort_by(|&a, &b| (self.level[a], &self.ids[a]).cmp(&(self.level[b], &self.ids[b])));
        v.into_iter().map(|i| &self.ids[i]).collect()
    }

    /// The nodes `id` directly stands on, after group expansion.
    pub fn upstream(&self, id: &NodeId) -> Option<Vec<&NodeId>> {
        self.index
            .get(id)
            .map(|&i| self.up[i].iter().map(|&j| &self.ids[j]).collect())
    }

    /// The members of a group.
    pub fn members(&self, group: &GroupId) -> Vec<&NodeId> {
        self.members
            .get(group)
            .map_or_else(Vec::new, |m| m.iter().map(|&i| &self.ids[i]).collect())
    }

    /// Edges whose target is not in this manifest.
    pub fn unresolved(&self) -> &[(NodeId, Upstream)] {
        &self.unresolved
    }

    /// For each node blocked by one of `failed_roots`, the roots that block it
    /// (sorted by id). Nodes that are not blocked have no entry.
    ///
    /// `failed_roots` are the roots of [`crate::status::roots`], that is nodes
    /// with status `fail`, `timeout` or `error` and no failed upstream of their
    /// own. The result only ever names members of that slice, never an
    /// intermediate failure. Roots not in the plan are ignored. A node is never
    /// blocked by itself, and nothing here removes a root from the result's keys
    /// (which keeps the result monotone in the root set), so do not pass a node
    /// as a root if it stands on another root.
    ///
    /// The rule is decided per pair (root F, node T):
    ///
    /// - If `reach` is given and holds both `exercised(F)` and `reach(T)`, T is
    ///   blocked iff the two sets intersect (§2.5). This is consulted for every
    ///   node in the plan, not only for transitive dependents of F: a node with
    ///   reach information that does not stand on F at all is still blocked if
    ///   it can reach the code F exercised, and a node that does stand on F is
    ///   not blocked if it cannot. `stands_on` edges therefore gate scheduling
    ///   but never decide blocking for such a pair.
    /// - For every other pair (no `reach`, or either side has no reach
    ///   information: foreign nodes, unverifiable binaries) the group rule
    ///   applies: T is blocked iff it stands on F, directly, through a group,
    ///   or through other nodes. For a failing unit test that is "T stands on
    ///   `unit(package(F))`"; a test standing only on a package's *unit* group is
    ///   not blocked by a failing *integration* test of the same package.
    pub fn blocked_by(
        &self,
        failed_roots: &[NodeId],
        reach: Option<&ReachInfo>,
    ) -> BTreeMap<NodeId, Vec<NodeId>> {
        let mut out: BTreeMap<NodeId, BTreeSet<&NodeId>> = BTreeMap::new();
        for root in failed_roots {
            let Some(&f) = self.index.get(root) else {
                continue;
            };
            let stands_on_f = self.dependents(f);
            let exercised = reach.and_then(|r| r.exercised.get(root));
            for (t, &downstream) in stands_on_f.iter().enumerate() {
                if t == f {
                    continue;
                }
                let blocked = match (exercised, reach.and_then(|r| r.reach.get(&self.ids[t]))) {
                    (Some(ex), Some(rt)) => !ex.is_disjoint(rt),
                    _ => downstream,
                };
                if blocked {
                    out.entry(self.ids[t].clone())
                        .or_default()
                        .insert(&self.ids[f]);
                }
            }
        }
        out.into_iter()
            .map(|(k, v)| (k, v.into_iter().cloned().collect()))
            .collect()
    }

    /// Indicator vector of the nodes that transitively stand on `f`.
    fn dependents(&self, f: usize) -> Vec<bool> {
        let mut seen = vec![false; self.ids.len()];
        let mut queue = VecDeque::from([f]);
        while let Some(n) = queue.pop_front() {
            for &d in &self.down[n] {
                if !seen[d] {
                    seen[d] = true;
                    queue.push_back(d);
                }
            }
        }
        seen
    }
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plan({} nodes)", self.ids.len())
    }
}

struct Tarjan {
    index: Vec<usize>,
    low: Vec<usize>,
    on_stack: Vec<bool>,
    stack: Vec<usize>,
    counter: usize,
    /// (node, next edge to look at): an explicit call stack, so a
    /// ten-thousand-deep `stands_on` chain cannot overflow the real one.
    call: Vec<(usize, usize)>,
}

impl Tarjan {
    const NONE: usize = usize::MAX;

    fn enter(&mut self, v: usize) {
        self.index[v] = self.counter;
        self.low[v] = self.counter;
        self.counter += 1;
        self.stack.push(v);
        self.on_stack[v] = true;
        self.call.push((v, 0));
    }
}

/// Strongly connected components by Tarjan's algorithm.
fn tarjan(up: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = up.len();
    let mut t = Tarjan {
        index: vec![Tarjan::NONE; n],
        low: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        counter: 0,
        call: Vec::new(),
    };
    let mut components = Vec::new();
    for start in 0..n {
        if t.index[start] != Tarjan::NONE {
            continue;
        }
        t.enter(start);
        while let Some(&(v, edge)) = t.call.last() {
            if let Some(&w) = up[v].get(edge) {
                t.call.last_mut().expect("non-empty").1 += 1;
                if t.index[w] == Tarjan::NONE {
                    t.enter(w);
                } else if t.on_stack[w] {
                    t.low[v] = t.low[v].min(t.index[w]);
                }
                continue;
            }
            t.call.pop();
            if let Some(&(parent, _)) = t.call.last() {
                t.low[parent] = t.low[parent].min(t.low[v]);
            }
            if t.low[v] == t.index[v] {
                let mut component = Vec::new();
                loop {
                    let w = t.stack.pop().expect("v is on the stack");
                    t.on_stack[w] = false;
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                components.push(component);
            }
        }
    }
    components
}

/// The shortest cycle through the smallest-id node of the cyclic component
/// that contains the smallest id, as indices in "stands on the next" order.
fn find_cycle(up: &[Vec<usize>], ids: &[NodeId]) -> Option<Vec<usize>> {
    let cyclic = tarjan(up)
        .into_iter()
        .filter(|c| c.len() > 1 || up[c[0]].contains(&c[0]));
    let component = cyclic.min_by_key(|c| c.iter().map(|&i| &ids[i]).min().cloned())?;
    let start = *component.iter().min_by_key(|&&i| &ids[i])?;
    let inside: BTreeSet<usize> = component.into_iter().collect();

    // Breadth-first from `start` along `up`, until an edge returns to it.
    let mut parent: HashMap<usize, usize> = HashMap::new();
    let mut queue = VecDeque::from([start]);
    while let Some(v) = queue.pop_front() {
        for &w in up[v].iter().filter(|w| inside.contains(w)) {
            if w == start {
                let mut path = vec![v];
                while let Some(&p) = parent.get(path.last().expect("non-empty")) {
                    path.push(p);
                }
                path.reverse();
                return Some(path);
            }
            if w != start && !parent.contains_key(&w) {
                parent.insert(w, v);
                queue.push_back(w);
            }
        }
    }
    None
}

/// Longest-path levels by Kahn's algorithm; `up` must be acyclic.
fn levels(up: &[Vec<usize>], down: &[Vec<usize>]) -> Vec<u32> {
    let mut remaining: Vec<usize> = up.iter().map(Vec::len).collect();
    let mut level = vec![0u32; up.len()];
    let mut queue: VecDeque<usize> = (0..up.len()).filter(|&i| remaining[i] == 0).collect();
    while let Some(n) = queue.pop_front() {
        for &d in &down[n] {
            level[d] = level[d].max(level[n] + 1);
            remaining[d] -= 1;
            if remaining[d] == 0 {
                queue.push_back(d);
            }
        }
    }
    level
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::digest::Digest;
    use crate::node::{Inputs, Kind, Policy};

    fn node(id: &str, group: GroupId, stands_on: Vec<Upstream>) -> Node {
        Node {
            id: NodeId::new(id),
            kind: Kind::RustTest,
            group,
            stands_on,
            joins: vec![],
            inputs: Inputs::default(),
            produces: vec![],
            via: None,
            key: Digest::Blake3([0; 32]),
            policy: Policy::default(),
        }
    }

    fn on(id: &str) -> Upstream {
        Upstream::Node(NodeId::new(id))
    }

    fn ids(v: &[&str]) -> Vec<NodeId> {
        v.iter().map(|s| NodeId::new(*s)).collect()
    }

    #[test]
    fn levels_follow_the_longest_chain_and_groups_expand() {
        let nodes = [
            node("a", GroupId::unit("p"), vec![]),
            node("b", GroupId::unit("p"), vec![]),
            node(
                "c",
                GroupId::integration("p"),
                vec![Upstream::Group(GroupId::unit("p"))],
            ),
            node("d", GroupId::scenario("s"), vec![on("c"), on("a")]),
        ];
        let plan = Plan::new(&nodes).unwrap();
        let lv: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .map(|i| plan.level(&NodeId::new(*i)).unwrap())
            .collect();
        assert_eq!(lv, [0, 0, 1, 2]);
        assert_eq!(
            plan.upstream(&"c".into()).unwrap(),
            ids(&["a", "b"]).iter().collect::<Vec<_>>()
        );
        let order: Vec<_> = plan.order().into_iter().map(NodeId::as_str).collect();
        assert_eq!(order, ["a", "b", "c", "d"]);
    }

    #[test]
    fn a_member_does_not_stand_on_its_own_group() {
        let nodes = [
            node(
                "a",
                GroupId::unit("p"),
                vec![Upstream::Group(GroupId::unit("p"))],
            ),
            node("b", GroupId::unit("p"), vec![]),
        ];
        let plan = Plan::new(&nodes).unwrap();
        assert_eq!(plan.upstream(&"a".into()).unwrap(), vec![&NodeId::new("b")]);
    }

    #[test]
    fn cycles_are_reported_as_an_ordered_list() {
        let g = GroupId::unit("p");
        let nodes = [
            node("z", g.clone(), vec![on("a")]),
            node("a", g.clone(), vec![on("b")]),
            node("b", g.clone(), vec![on("c")]),
            node("c", g.clone(), vec![on("a")]),
            node("free", g, vec![]),
        ];
        match Plan::new(&nodes) {
            Err(PlanError::Cycle(c)) => {
                assert_eq!(c, ids(&["a", "b", "c"]));
                let text = PlanError::Cycle(c).to_string();
                assert!(text.contains("a -> b -> c -> a"), "{text}");
            }
            other => panic!("expected a cycle, got {other:?}"),
        }
    }

    #[test]
    fn cycle_through_a_group_and_self_edge_are_cycles() {
        let g = GroupId::unit("p");
        let two = [
            node(
                "a",
                g.clone(),
                vec![Upstream::Group(GroupId::integration("q"))],
            ),
            node("b", GroupId::integration("q"), vec![on("a")]),
        ];
        assert!(matches!(Plan::new(&two), Err(PlanError::Cycle(c)) if c == ids(&["a", "b"])));
        let own = [node("a", g, vec![on("a")])];
        assert!(matches!(Plan::new(&own), Err(PlanError::Cycle(c)) if c == ids(&["a"])));
    }

    #[test]
    fn duplicate_ids_and_unresolved_edges() {
        let g = GroupId::unit("p");
        let dup = [node("a", g.clone(), vec![]), node("a", g.clone(), vec![])];
        assert!(matches!(Plan::new(&dup), Err(PlanError::DuplicateId(_))));
        let nodes = [node(
            "a",
            g,
            vec![on("other-repo"), Upstream::Group(GroupId::unit("missing"))],
        )];
        let plan = Plan::new(&nodes).unwrap();
        assert_eq!(plan.unresolved().len(), 2);
        assert_eq!(plan.level(&"a".into()), Some(0));
    }

    #[test]
    fn deep_chains_do_not_overflow_the_stack() {
        let g = GroupId::unit("p");
        let nodes: Vec<Node> = (0..20_000)
            .map(|i| {
                node(
                    &format!("n{i:06}"),
                    g.clone(),
                    if i == 0 {
                        vec![]
                    } else {
                        vec![on(&format!("n{:06}", i - 1))]
                    },
                )
            })
            .collect();
        let plan = Plan::new(&nodes).unwrap();
        assert_eq!(plan.level(&"n019999".into()), Some(19_999));
    }

    fn symbols(v: &[u64]) -> BTreeSet<SymbolId> {
        v.iter().map(|&s| SymbolId(s)).collect()
    }

    #[test]
    fn reach_intersection_blocks_only_what_can_reach_the_exercised_code() {
        // Both flow tests stand on unit(store) but only one reaches the
        // failing helper (symbol 1).
        let store = GroupId::unit("store");
        let flow = GroupId::unit("flow");
        let nodes = [
            node("store::bad", store.clone(), vec![]),
            node(
                "flow::uses_helper",
                flow.clone(),
                vec![Upstream::Group(store.clone())],
            ),
            node("flow::unrelated", flow, vec![Upstream::Group(store)]),
        ];
        let plan = Plan::new(&nodes).unwrap();
        let roots = ids(&["store::bad"]);

        let group_rule = plan.blocked_by(&roots, None);
        assert_eq!(group_rule.len(), 2);

        let mut r = ReachInfo::default();
        r.exercised.insert("store::bad".into(), symbols(&[1, 2]));
        r.reach.insert("flow::uses_helper".into(), symbols(&[1, 9]));
        r.reach.insert("flow::unrelated".into(), symbols(&[7, 9]));
        let sharp = plan.blocked_by(&roots, Some(&r));
        assert_eq!(
            sharp.keys().map(NodeId::as_str).collect::<Vec<_>>(),
            ["flow::uses_helper"]
        );
        assert_eq!(sharp[&NodeId::new("flow::uses_helper")], roots);
    }

    #[test]
    fn reach_blocks_a_node_that_does_not_stand_on_the_root() {
        // `sideways` has no edge to `store::bad` at all, but can reach the
        // symbol that `store::bad` exercised.
        let nodes = [
            node("store::bad", GroupId::unit("store"), vec![]),
            node("sideways", GroupId::unit("other"), vec![]),
            node("far", GroupId::unit("other"), vec![]),
        ];
        let plan = Plan::new(&nodes).unwrap();
        let roots = ids(&["store::bad"]);
        assert!(plan.blocked_by(&roots, None).is_empty());

        let mut r = ReachInfo::default();
        r.exercised.insert("store::bad".into(), symbols(&[5]));
        r.reach.insert("sideways".into(), symbols(&[5, 6]));
        r.reach.insert("far".into(), symbols(&[6]));
        let blocked = plan.blocked_by(&roots, Some(&r));
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[&NodeId::new("sideways")], roots);
    }

    #[test]
    fn nodes_without_reach_info_fall_back_to_the_group_rule() {
        let store = GroupId::unit("store");
        let nodes = [
            node("store::bad", store.clone(), vec![]),
            node(
                "go::journey",
                GroupId::scenario("s"),
                vec![Upstream::Group(store)],
            ),
            node("rust::elsewhere", GroupId::unit("x"), vec![]),
        ];
        let plan = Plan::new(&nodes).unwrap();
        let mut r = ReachInfo::default();
        r.exercised.insert("store::bad".into(), symbols(&[1]));
        r.reach.insert("rust::elsewhere".into(), symbols(&[2]));
        let blocked = plan.blocked_by(&ids(&["store::bad"]), Some(&r));
        assert_eq!(
            blocked.keys().map(NodeId::as_str).collect::<Vec<_>>(),
            ["go::journey"]
        );
    }

    #[test]
    fn transitive_dependents_name_the_root_not_the_middle() {
        let g = GroupId::unit("p");
        let nodes = [
            node("root", g.clone(), vec![]),
            node("mid", g.clone(), vec![on("root")]),
            node("top", g.clone(), vec![on("mid")]),
            node("island", g, vec![]),
        ];
        let blocked = Plan::new(&nodes).unwrap().blocked_by(&ids(&["root"]), None);
        assert_eq!(blocked[&NodeId::new("mid")], ids(&["root"]));
        assert_eq!(blocked[&NodeId::new("top")], ids(&["root"]));
        assert!(!blocked.contains_key(&NodeId::new("island")));
        assert!(!blocked.contains_key(&NodeId::new("root")));
    }

    /// Random hierarchies that are acyclic by construction: node `i` may stand
    /// on any earlier node, or on a group made only of strictly earlier nodes
    /// (groups are blocks of three consecutive indices).
    #[derive(Debug, Clone)]
    struct Shape {
        edges: Vec<Vec<(bool, usize)>>,
    }

    fn shape() -> impl Strategy<Value = Shape> {
        (1usize..24).prop_flat_map(|n| {
            let per_node: Vec<_> = (0..n)
                .map(|i| {
                    prop::collection::vec((any::<bool>(), any::<prop::sample::Index>()), 0..4)
                        .prop_map(move |picks| {
                            picks
                                .into_iter()
                                .filter_map(|(is_group, ix)| {
                                    if is_group {
                                        let blocks = i / 3;
                                        (blocks > 0).then(|| (true, ix.index(blocks)))
                                    } else {
                                        (i > 0).then(|| (false, ix.index(i)))
                                    }
                                })
                                .collect::<Vec<_>>()
                        })
                })
                .collect();
            per_node.prop_map(|edges| Shape { edges })
        })
    }

    fn build(s: &Shape) -> Vec<Node> {
        s.edges
            .iter()
            .enumerate()
            .map(|(i, es)| {
                let ups = es
                    .iter()
                    .map(|&(g, j)| {
                        if g {
                            Upstream::Group(GroupId::unit(format!("p{j}")))
                        } else {
                            on(&format!("n{j:02}"))
                        }
                    })
                    .collect();
                node(
                    &format!("n{i:02}"),
                    GroupId::unit(format!("p{}", i / 3)),
                    ups,
                )
            })
            .collect()
    }

    /// Independent oracle: transitive upstream set straight from the nodes.
    fn stands_on_closure(nodes: &[Node], start: usize) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut todo = vec![start];
        while let Some(i) = todo.pop() {
            for u in &nodes[i].stands_on {
                let targets: Vec<usize> = match u {
                    Upstream::Node(id) => {
                        nodes.iter().position(|n| &n.id == id).into_iter().collect()
                    }
                    Upstream::Group(g) => nodes
                        .iter()
                        .enumerate()
                        .filter(|(_, n)| &n.group == g)
                        .map(|(j, _)| j)
                        .collect(),
                };
                for j in targets {
                    if seen.insert(nodes[j].id.as_str().to_owned()) {
                        todo.push(j);
                    }
                }
            }
        }
        seen
    }

    proptest! {
        #[test]
        fn a_dag_never_reports_a_cycle_and_levels_respect_edges(s in shape()) {
            let nodes = build(&s);
            let plan = Plan::new(&nodes).unwrap();
            for n in &nodes {
                let lv = plan.level(&n.id).unwrap();
                for u in plan.upstream(&n.id).unwrap() {
                    prop_assert!(plan.level(u).unwrap() < lv);
                }
            }
        }

        #[test]
        fn a_back_edge_is_reported_as_a_real_cycle(s in shape(), from in any::<prop::sample::Index>(), to in any::<prop::sample::Index>()) {
            let mut nodes = build(&s);
            let (a, b) = (from.index(nodes.len()), to.index(nodes.len()));
            // `a` stands on `b`; if `b` already (transitively) stands on `a`, or a == b, that closes a loop.
            nodes[a].stands_on.push(on(&format!("n{b:02}")));
            let closes = a == b || stands_on_closure(&nodes, b).contains(nodes[a].id.as_str());
            match Plan::new(&nodes) {
                Ok(_) => prop_assert!(!closes),
                Err(PlanError::Cycle(c)) => {
                    prop_assert!(closes);
                    // Each id stands on the next, the last on the first.
                    for w in 0..c.len() {
                        let me = nodes.iter().position(|n| n.id == c[w]).unwrap();
                        let next = &c[(w + 1) % c.len()];
                        prop_assert!(stands_on_closure(&nodes, me).contains(next.as_str()));
                    }
                }
                Err(e) => prop_assert!(false, "{e}"),
            }
        }

        #[test]
        fn blocking_is_monotone_names_only_roots_and_follows_standing_on(
            s in shape(),
            picks in prop::collection::vec(any::<prop::sample::Index>(), 0..6),
            extra in any::<prop::sample::Index>(),
        ) {
            let nodes = build(&s);
            let plan = Plan::new(&nodes).unwrap();
            let pick = |ix: &prop::sample::Index| nodes[ix.index(nodes.len())].id.clone();
            let small: Vec<NodeId> = picks.iter().map(pick).collect();
            let mut large = small.clone();
            large.push(pick(&extra));

            let (b_small, b_large) = (plan.blocked_by(&small, None), plan.blocked_by(&large, None));
            for (t, roots) in &b_small {
                let bigger = b_large.get(t).expect("monotone: key stays");
                prop_assert!(roots.iter().all(|r| bigger.contains(r)));
            }
            for (t, roots) in &b_large {
                let ti = nodes.iter().position(|n| &n.id == t).unwrap();
                let closure = stands_on_closure(&nodes, ti);
                for r in roots {
                    prop_assert!(large.contains(r), "{r} is not a root");
                    prop_assert!(closure.contains(r.as_str()), "{t} does not stand on {r}");
                    prop_assert_ne!(r, t);
                }
            }
        }

        #[test]
        fn reach_mode_is_monotone_and_only_names_roots(
            s in shape(),
            picks in prop::collection::vec(any::<prop::sample::Index>(), 1..5),
            sym in prop::collection::vec(prop::collection::btree_set(0u64..6, 0..4), 24),
        ) {
            let nodes = build(&s);
            let plan = Plan::new(&nodes).unwrap();
            let mut r = ReachInfo::default();
            for (n, set) in nodes.iter().zip(&sym) {
                r.reach.insert(n.id.clone(), set.iter().map(|&x| SymbolId(x)).collect());
                r.exercised.insert(n.id.clone(), set.iter().take(2).map(|&x| SymbolId(x)).collect());
            }
            let roots: Vec<NodeId> = picks.iter().map(|ix| nodes[ix.index(nodes.len())].id.clone()).collect();
            let all = plan.blocked_by(&roots, Some(&r));
            let first = plan.blocked_by(&roots[..1], Some(&r));
            for (t, rs) in &first {
                prop_assert!(rs.iter().all(|x| all[t].contains(x)));
            }
            for (t, rs) in &all {
                prop_assert!(rs.iter().all(|x| roots.contains(x) && x != t));
            }
        }
    }
}
