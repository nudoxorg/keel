# Source byte pages

`pages` can opt into `page_format = "source-range"` for `backend.source`
with `arguments.byte_range = true`. It follows the exact copied MCP
continuations in one process. Each page must start where the prior page ended,
contain at most 4096 UTF-8 bytes, make progress, retain the same source identity,
scope, total and owner extent, and have an opaque cursor exactly when more
bytes remain. The aggregate retains every structured page and source-policy
value, first and last pages, exact concatenated text and byte count. Its scope
is the extent the owner named, not a claim that a declaration or file is whole.

An optional `cli` argument vector beginning with `source` and including
`--byte-range` independently drains the CLI's cursors; its reconstructed text,
identity, scope and owner extent must agree with MCP. Cursor strings are never
compared between transports. Both transports preserve page evidence and file
hash receipts. `bind` reads from the completed aggregate for both source and
ordinary `pages` steps. The hashes identify locally retained, redacted bytes;
they are not an independent owner seal verification.

A continuation must retain the requested coordinate, selected symbol, detail,
and byte-range opt-in. The first continuation may add canonical defaults; all
non-cursor arguments are then fixed for subsequent continuations. The aggregate
reports `cli_pages` separately and retains the first and last CLI pages when CLI
pagination was requested; MCP and CLI are free to use different page boundaries.

Each page also retains a canonical outer revision and selected-symbol identity,
optional coordinate, and the transport's verified-at-read marker. These values
must stay stable through a sequence, and CLI and MCP identities must agree.
An explicitly requested coordinate must match the returned coordinate. If
an initial selected-symbol ID was supplied, its exact canonical bytes must
match the returned identity; a legacy 32-byte array is accepted without
substituting a coordinate-derived ID. These are consistency checks on the
owner response, not independent authentication of the owner.
