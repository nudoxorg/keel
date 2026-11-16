# Persistent MCP session steps

`mcp-start` opens a named MCP process, performs one initialize exchange and
sends initialized. `session` is a short alphanumeric, hyphen or underscore
identifier. A case may own at most eight live sessions and must explicitly
stop each; invalid lifecycles fail manifest admission before any process runs.
Each successful start and stop receipt includes the process ID and containment
mode. A stop closes stdin, checks clean termination, reaps the process and its
contained descendants, and records `reaped: true`.

`mcp-call` uses the named session. Provide either `tool` and `arguments`, or
`call` with an exact copied `{name, arguments}` object (including a typed
`${binding}` referring to a prior `continuation_call`). Request IDs advance
monotonically within that process. `expect.json` and `bind` refer to the tool's
`structuredContent`; `expect.exit` is 0 because the process remains open.
Set `mcp_error: true` for an expected typed tool refusal. JSON-RPC errors,
missing structured content, unexpected `isError`, timeouts, and expectation
failures fail the step. A refusal is never converted into an empty success.

Each start retains initialization request, response, notification and raw
process streams; each call retains its exact JSON-RPC request, reply and
structured result. Every call/start/stop has a finite `timeout_seconds` (1–600).
On a failed step, all live sessions are explicitly cleaned up and any cleanup
failure fails the case. A case can write files and invoke other processes
between calls without replacing the named MCP process.
