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
