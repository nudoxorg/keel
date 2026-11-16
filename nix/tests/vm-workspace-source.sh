#!/usr/bin/env bash
# Check the actual source filter used by both NixOS VM builds. Run after
# Cargo's registry cache is populated; this intentionally needs no network.
set -euo pipefail
cd "$(dirname "$0")/../.."
source_path=$(nix eval --impure --raw --expr '
  let lib = (builtins.getFlake (toString ./.)).inputs.nixpkgs.lib;
  in toString (import ./nix/vm-workspace-source.nix { inherit lib; })
')
cargo metadata --manifest-path "$source_path/Cargo.toml" --locked --offline --no-deps --format-version 1 |
  jq -e '. as $workspace | any(.packages[]; .name == "backend-keel-harness" and (.id as $id | $workspace.workspace_members | index($id) != null))' >/dev/null
printf 'VM workspace source resolves every Cargo member, including backend-keel-harness\n'
