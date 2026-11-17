# Related page aggregation

A `pages` step for `backend.related` preserves each request and reply and
records their SHA-256 digests, request ID and MCP process ID in `page_receipts`.
The hashes cover the bytes actually written to the evidence files; they are
local driver receipts, not an offline authentication or owner-seal proof.
Named MCP initialization and calls likewise record hashes of their persisted
request and reply files.

The aggregate retains the first and last structured pages, all structured
`page_results`, and the page-specific `neighborhood_roots`. It joins identical
selected-symbol context rows and identical project claims, rejects conflicting
reuse of an ID, and requires unique typed edges with endpoint IDs and
coordinates resolving to the aggregated rows. All other basis fields and the
presence and value of project scope remain stable. A continuation must make
new edge progress, preserve the exact opaque cursor and agree with `more`.
These checks describe the delivered pages; they do not assert a complete call
graph or authenticate the owner's claims. Other tools retain their ordinary
record-duplicate rule.
