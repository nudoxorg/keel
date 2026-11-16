# keel-store

The Keel result store (DESIGN.md §6): an HTTP service over the filesystem
content-addressed store that `keel::store::LocalStore` defines, a blocking
client that implements `keel::store::ResultStore`, the conductor skeleton that
starts jobs, and the small subcommands and library functions the CI host's
systemd units and conductor use. A directory written by the service is readable
by the local tooling (`~/.cache/keel/store` on a developer machine) and the
other way round.

```text
keel-store serve --dir /ci/keel/store [--listen ADDR:PORT]
keel-store conduct --listen ADDR:PORT --jobs-dir D --out-dir D --token-file F
                   --pipeline-tokens-file F --repo OWNER/NAME... --program phase=/nix/store/… ...
keel-store gc --dir D [--keep-pass 30d] [--keep-fail 90d] [--reserve-gib 80] [--blob-grace 1d] [--dry-run]
keel-store validate-job NAME [--env-file PATH]
```

## Store endpoints

JSON unless noted. Every `PUT` needs the **writer token**; every `GET` except
`/v1/health` needs the **read token** (the writer token also works).

| Endpoint | |
|---|---|
| `GET /v1/health` | Open. `{schema, version, records, blobs, bytes}`; counts are approximate (files on disk, cached 30 s). |
| `GET /v1/pass/{key}` | The newest stored `pass` for a `blake3:` or `sha256:` key (`keel::store::StoredPass`), 404 if none. |
| `GET /v1/blob/{digest}` | Raw bytes; the service re-hashes before serving, a corrupt file is a 500 naming it. |
| `PUT /v1/blob` | Raw bytes (64 MiB max) to `{digest}`. |
| `PUT /v1/record` | A `StoredRecord` (16 MiB max). Append only: nothing over HTTP deletes. |
| `PUT`/`GET /v1/manifest/{revision}` | Stage-0 manifest (DESIGN §5.2), validated, stored as a blob, indexed by revision. |
| `PUT`/`GET /v1/report/{run_id}` | Run report (§8.2), likewise. |

A missing or wrong token is 401 and the body names the header, never the token.
Bodies over a limit are 413 and say which limit.

## Tokens and environment variables

- `KEEL_STORE_TOKEN_FILE`: file holding the writer token (at least 16
  characters). `KEEL_STORE_READ_TOKEN_FILE`: file holding the read token, which
  pipelines get instead of the writer token: reads open to the whole bridge
  would let a task running PR code in another pipeline read every stored
  stdout and stderr. `serve` refuses to start without both. Only file names
  travel in the environment, never a token, so nothing leaks into `ps` or
  logs. A token file readable by everyone draws a warning; on the CI host the
  files are group `keel-token`, mode 0440.
- `KEEL_STORE_PORT` is read only when `--listen` is absent: the service binds
  `127.0.0.1:$KEEL_STORE_PORT` (port 0 if unset). On the CI host the module
  passes `--listen <bridge>:<port>` and the port comes from the fleet model;
  no port is built into the binary.

Client: `keel_store::client::Client::new(base_url, Some(writer_token))`, then
`.with_read_token(read_token)` for reads (without it, reads carry the writer
token). Connect timeout 5 s, read timeout 60 s, one retry on a connection
error; as a `ResultStore` every failure is `StoreError::Remote` (a damaged
entry the service reports stays `Corrupt`).

## Trust domains and job units (DESIGN §6.1, §6.2)

Four users: `keel-store` (the service), `keel-conduct` (the conductor, the
only writer), `keel-canon` (canonical jobs, the only writer of the shared
compiler cache) and `keel-build` (PR jobs). Each phase of a job is a systemd
unit of its own:

| Unit | Runs | Network |
|---|---|---|
| `keel-fetch@<job>` | the pinned cargo's `cargo fetch --locked`, no PR code | yes, minus every private range and the fleet's addresses |
| `keel-build@<job>` | `cargo build --offline`, PR code executes | none (`PrivateNetwork`) |
| `keel-test@<job>` | the tests | none (`PrivateNetwork`, a fresh loopback) |
| `keel-audit@<job>` | like test, plus ptrace, for `keel audit` | none |

`keel-canon-{fetch,build,test}@<job>` are the same units as `keel-canon`, with
`/ci/keel/canon/<job>` and a read-write compiler cache; PR units get the cache
read-only. All of them sit in `keel.slice`, which carries the budget for the
whole of Keel. `nix/keel-host.nix` has the rationale for every setting and
`nix/keel-host-test.nix` a VM test case that fails without each.

### The job env file and the command interface

The conductor writes `/ci/keel/jobs/<job>.env` (mode 0640, group `keel-jobs`)
before each phase, holding exactly two variables, **both chosen by the
conductor**:

- `KEEL_PROGRAM`: a Nix store path, the phase's entry in `--program`. It is
  the one word executed.
- `KEEL_ARGS`: words separated by single spaces: the phase, the job id, a repo
  name from the conductor's fixed allow-list, the revision as 40 hex
  characters, the slot number.

**Branch names, commit messages, PR titles and anything else from the forge
never enter the file.** The unit runs `keel-store validate-job %i` and
`keel-store validate-job %i --env-file …` before anything else: the job name
must match `^[a-z0-9][a-z0-9._-]{0,63}$` with no `..`; the file may hold only
the two keys, each once, `KEEL_PROGRAM` a `/nix/store/<hash>-<name>[/…]` path
of `[A-Za-z0-9._+-]` components, `KEEL_ARGS` 1 to 16 words of `[A-Za-z0-9._/-]`
that start with a letter or digit (never a flag) and contain no `..`. The repo
allow-list is the conductor's; the check enforces shape only. Then systemd runs
`env -- ${KEEL_PROGRAM} $KEEL_ARGS`, no shell. The unit uses the escaped
instance name `%i`, never `%I`: systemd unescapes `-` to `/` in `%I`, which
would let a name spell a path.

A test that needs `AF_UNIX` sockets declares `sockets = ["unix"]`; the
conductor would turn that into a per-job drop-in lifting
`RestrictAddressFamilies=none` for that job. The drop-in is not implemented.

### The conductor

`keel-store conduct` is an HTTP skeleton: it starts jobs, it does not clone or
run cargo. Pipelines authenticate with a per-pipeline bearer token; the
`--pipeline-tokens-file` maps `blake3(token)` to `{"repo": …, "kinds": […]}`.

| Endpoint | |
|---|---|
| `POST /v1/jobs` | `{repo, revision, kind: "pr"\|"canonical", pr}`. The repo must be on the allow-list and be the token's repo, the kind one the token permits, the revision 40 lowercase hex; a PR needs `pr`. Unknown fields are rejected (there is nowhere for forge text to ride). 202 with `{id, units}`; the fetch, build, test sequence runs in the background, each phase an env-file write and a `systemctl start`. |
| `GET /v1/jobs/{id}` | Stage, whether finished, and the **outcome as systemd reports it** (`keel_store::job::job_outcome`). A token for another repo gets 404. |
| `GET /v1/jobs/{id}/log` | The job's journal (`journalctl -u … -f`) as the body, ending shortly after the job does. |

A PR pipeline's token therefore cannot start a canonical job or a job for
another repo. The conductor's user is in group `systemd-journal` to follow the
log, which gives it read access to the whole system journal.

### Outcomes and outputs

A job's outcome is what systemd says: `systemctl show --property=Result,
ExecMainStatus,ExecMainCode,ActiveState`, parsed by `job_outcome(unit)`, never
a file the job user can write. Outputs in `/ci/keel/out/<job>` are
**attacker-controlled input**: `keel_store::ingest::ingest_outputs(dir, &Caps)`
opens each entry relative to the directory's descriptor with `openat2`
(`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`; elsewhere
`O_NOFOLLOW` after a name check), accepts regular files only, and caps the
count (64), each file (16 MiB) and the total (256 MiB) before reading a byte.
A symlink to the token, a FIFO, a sparse 10 GiB file or a `..` is an error,
never a read.

## Failure modes

- **Conductor dies mid-run.** Job units carry `TimeoutStartSec` (the module
  option `jobTimeout`; `RuntimeMaxSec` has no effect on oneshot units), so they
  end on their own with `Result=timeout`. The next conductor start asks
  systemd about the units it knows of. No result record can be written by
  anything but a live conductor holding the writer token, so a dead conductor
  leaves no partial truth in the store.
- **Store down.** Clients get `StoreError::Remote` naming the endpoint; the
  service restarts on failure and keeps retrying a bind to a bridge address that
  does not exist yet.
- **Disk full.** Writes answer 507; `gc` runs daily, refuses to run if it cannot
  stat the filesystem, and exits 2 when free space stays under the reserve.
- **Corrupt entry.** A blob that does not hash to its name is a 500 naming the
  file and is never served; delete the file and the entry is recomputed.
- **gc race.** A blob that no record names yet is kept for `--blob-grace`
  (default 1 d). A blob stored, then unreferenced for longer than that, then
  referenced again by a new record can be removed in between; the cost is old
  logs, not a wrong result.
