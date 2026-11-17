# NuDox observations for harness order

`keel-judge guidance --manifest manifest.json --inputs inputs.json -o order.json`
produces the full case inventory in an order accepted by the harness. It never
selects, caches, or passes a case. This interface does not establish that a
change is unrelated to a test; every case remains necessary.

The inputs file is schema 1:

```json
{"schema":1,"changes":["src/example.rs"],"observations":[{
  "case":"case-id", "coordinate":"<exact coordinate from NuDox>",
  "before":"before.json", "graph":"graph.json", "source":"source.json",
  "after":"after.json"
}]}
```

Paths to captures are relative to inputs.json. Capture `backend.status` at
`detail=full` immediately before and after `backend.graph` and
`backend.source`, retaining the exact structured JSON responses. `graph` is
optional: its absence or incomplete coverage leaves legacy graph facts unknown
but does not invalidate separately source-bound related observations. Graph pages
with a continuation are currently unknown; do not discard a continuation and
claim completeness. Changes must be normalized project-relative paths for the
same indexed project. Each observed case must be bound by the caller to a
relevant coordinate; the adapter cannot verify that association or prove that
status captures bracket a graph returned from the same owner. The raw captures'
BLAKE3 hashes are in the output for audit. Capture freshness against the actual
working tree and change list is the caller's responsibility.

A matching changed graph path moves a case earlier, then the count of distinct
changed declaration coordinates breaks ties. This counts returned declaration
rows, not graph edges. `dependency_complexity` and `blast_radius` are null:
`backend.graph`'s rows do not identify edge endpoints or directions. The NuDox
implementation explicitly says completed graph pagination does not certify
relation coverage (`crates/present/drive.rs`, `graph_page_records`). Even an
untruncated page therefore cannot establish callers, SCCs, reach, complexity,
or blast radius. `backend.references` can carry typed source sites and relation
kinds (`crates/present/product.rs`, `reference_row`), but the observed response
does not carry a machine-readable view root or completeness; it cannot be safely
joined across snapshots by this adapter. These are product evidence gaps, not
zero values. Coverage and confidence remain unmeasured. Missing,
partial, stale-looking, unbound and nonmatching observations are unknown. An
unavailable/malformed capture fails guidance generation; the harness can run
its entire inventory without an order. No empirical claim of speedup or
improvement over another fuzzer follows from this ordering.

A case observation may additionally list `related` JSON capture paths. These
must be full, unwithheld single-page `backend.related` responses with the
`related_basis` and endpoint IDs introduced by backend commit bfd1c27d94.
All pages must share the full source basis and semantic revision, match the
bracketing status view root and source object, and contain the requested case
coordinate and exact selected source ID as a center. Paged results are unknown until continuation verification is supported.
Malformed or mismatched related evidence makes that case unknown. Captures are
hashed in the evidence list after the four original responses.

Only compiler-confidence `calls` and `method-call` relations participate.
Distinct edges, direct callers, and reverse reachable callers are lower bounds
on that captured relation set. SCC count and maximum reverse shortest depth
describe the **observed subgraph only**: adding edges can change either in both
directions. The adapter orders cases with observed forward paths to changed
declarations first. The source seed is attributed by its source response; other
endpoints count as changed only when their records match a same-page owner-issued
attribution in project, selected ID, coordinate, path, view, semantic revision,
and source/workspace scope. The adapter checks visible consistency only; it
cannot verify the owner's seal or source membership offline. Missing project attribution is
reported as `unattributed_related_nodes`, never inferred from opaque coordinate
text. This is a scheduling hint; an absent path proves nothing,
case-to-coordinate bindings remain caller supplied, and global complexity,
blast radius, coverage and confidence remain unknown. The graph analysis has a
512-node / 10,000-edge bound and refuses larger captures.

The CLI tests include independently authored synthetic protocol controls and
sanitized, status-bracketed responses from an official 189f backend fanout run.
See the fixture README for provenance. The run does not establish complete
relation coverage or predict scheduling performance.

For a paginated capture, an observation may provide `related_chains` in addition
to single-page `related` inputs. Each chain names a trusted driver report,
passing case step IDs for the bracketing status responses, source response and
page call, and an ordered array of raw JSON-RPC request and reply paths:

```json
{"report":"report.json","before_step":"status-before","source_step":"source",
 "step":"related-pages","after_step":"status-after",
 "pages":[{"request":"page-0.request.json","reply":"page-0.json"},
          {"request":"page-1.request.json","reply":"page-1.json"}]}
```

The report must bind the exact manifest and raw status/source bytes, and its
ordered page receipts must bind each raw request and reply by SHA-256, request ID
and one process ID. The adapter checks each next request against the preceding
continuation, requires a terminal page, preserves each neighborhood root, and
rejects conflicting repeated rows or claims and repeated chain edges. Source,
view, semantic and project scopes must stay stable. A forged or modified
unsigned report can forge these links: the local driver receipt and owner
transport are trust inputs, not signatures or offline proof of source membership.
Incomplete or unverified chains remain unknown.
An observation cannot mix `related` and `related_chains`. Each capture is
limited to 16 MiB, and the combined chain reads for one observation are limited
to 64 MiB. Each nonterminal page must add a typed edge.
