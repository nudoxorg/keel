# Cargo resolves every workspace member even when building only one package.
# Keep this source shared by both VM tests so their filtered workspace remains
# complete as members are added. Build outputs and unrelated repository files
# stay outside the VM source closure.
{ lib }:
lib.fileset.toSource {
  root = ../.;
  fileset = lib.fileset.unions [
    ../Cargo.toml
    ../Cargo.lock
    ../crates
    ../bench
    ../adapters
  ];
}
