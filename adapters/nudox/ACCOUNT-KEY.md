# Private account key input

For an execution requiring account access, set `KEEL_NUDOX_API_KEY_FILE` to
an absolute path. The final directory must be owned by the effective user and
mode 0700; the regular file must be owned by that user and mode 0600. The
path must contain no symlink components. A nonempty ASCII key using letters,
numbers, `_`, `-`, and `.` is accepted, with at most one trailing newline and
a 4096-byte key limit. The file is read once. `--list` and `--inventory` do
not read it or contact an account.

Only CLI and MCP subprocesses receive `NUDOX_API_KEY`. The key is separate
from the recorded authority environment. Reports record only presence and the
source basename. Process output, MCP replies, and owner logs are redacted for
the exact key before capture or parsing, including across read chunks. The
redaction is not a general secret scanner: encoded, transformed, or partial
copies are outside its scope. Product responses containing the exact key are
changed before assertions and may therefore fail their contracts.

If the harness reaches a capture size limit, it also withholds any trailing
bytes that could be the beginning of the key, so truncation itself does not
persist a credential prefix. Oversized output still fails the step.
