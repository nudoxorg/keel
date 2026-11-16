#!/usr/bin/env bash
# Exercise the restored fork through actual Cargo, test and report processes.
set -euo pipefail

binary=${1:?pass the absolute cargo-nextest binary path}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/project/src" "$scratch/project/.config"
cat > "$scratch/project/Cargo.toml" <<'TOML'
[package]
name = "keel-nextest-smoke"
version = "0.1.0"
edition = "2021"
TOML
printf 'schema = 1\n' > "$scratch/project/.config/keel.toml"
printf '#[test]\nfn addition() { assert_eq!(2 + 2, 4); }\n' > "$scratch/project/src/lib.rs"
export CARGO_TARGET_DIR="$scratch/fixture-target"
export CARGO_INCREMENTAL=0
run() {
  "$binary" nextest run --keel --color=never --no-input-handler \
    --manifest-path "$scratch/project/Cargo.toml" --keel-store "$scratch/store" \
    --keel-report "$scratch/report-$1.json"
}
run 1
run 2
printf '#[test]\nfn addition() { assert_eq!(2 + 2, 5); }\n' > "$scratch/project/src/lib.rs"
set +e
run 3
status=$?
set -e
if [ "$status" -ne 100 ]; then
  echo "expected nextest test-failure exit 100, got $status" >&2
  exit 1
fi
python3 - "$scratch" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
reports = [json.loads((root / f"report-{n}.json").read_text()) for n in (1, 2, 3)]
assert [r["verdict"] for r in reports] == ["pass", "pass", "fail"]
assert reports[0]["counts"]["pass"] == 1 and reports[0]["counts"]["cached"] == 0
assert reports[1]["counts"]["cached"] == 1
assert reports[2]["counts"]["fail"] == 1 and reports[2]["counts"]["cached"] == 0
assert reports[0]["stages"]["first_test_ms"] is not None
assert reports[0]["stages"]["cargo_exit_ms"] is not None
PY
