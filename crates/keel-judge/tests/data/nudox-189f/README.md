These sanitized structured responses were captured during one Rust fanout
fixture run against the official 189f backend on 2026-11-16. The before and
after status responses and intervening graph, source and typed-related pages
come from the same run. The project path was replaced consistently with
`/workspace/example`. The original unsanitized captures remain in the v4
harness run evidence. Relation coverage is unknown.

Original artifacts in the v4 run, relative to `evidence/rust-fanout-and-diamond/`;
SHA-256 values cover the original bytes before extracting structured content or
sanitizing paths:

| Artifact | SHA-256 |
| --- | --- |
| `012-guidance-status-before.json` | `ea42130217e8931a6e9dff9c31886ea912300f093f521d7f83d3c261f3ed522f` |
| `013-guidance-graph.json` | `c3ae6b15a87be61abeac5365faaee4dc99fd2e8bbfbbf72b8961f77ed44f49ac` |
| `014-guidance-source.json` | `2ca74a24cc22f047b996c6993eee8765567576e6e6ff6784ac375816684ff541` |
| `015-typed-related-call-edges.page-0.json` | `db1681f0e2a3d9d496396172deeb8829438ecd3c64d8d6973fb3cb718b377d4b` |
| `016-guidance-status-after.json` | `ea42130217e8931a6e9dff9c31886ea912300f093f521d7f83d3c261f3ed522f` |
