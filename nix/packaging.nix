# Standalone Rust binaries share Keel's lockfile and do not depend on the
# repository that consumes the Nudox adapter.
{
  pkgs,
  rust,
  src,
}:
let
  rustPlatform = pkgs.makeRustPlatform {
    cargo = rust;
    rustc = rust;
  };
  packageSource = pkgs.lib.fileset.toSource {
    root = src;
    fileset = pkgs.lib.fileset.unions [
      (src + "/Cargo.toml")
      (src + "/Cargo.lock")
      (src + "/crates")
      (src + "/adapters")
      (src + "/bench")
    ];
  };
  build =
    package:
    rustPlatform.buildRustPackage {
      pname = package;
      version = "0.1.0";
      src = packageSource;
      cargoLock.lockFile = src + "/Cargo.lock";
      cargoBuildFlags = [
        "--package"
        package
      ];
      # CI runs the workspace tests separately. Some integration tests require
      # external services or host-specific tools that are unavailable in a sandbox.
      doCheck = false;
    };

in
rec {
  keel = build "keel-cli";
  default = keel;
  keel-tree = build "keel-tree";
  keel-index = build "keel-index";
  keel-reach = build "keel-reach";
  keel-conduct = build "keel-conduct";
  keel-store = build "keel-store";
  keel-settle = build "keel-settle";
  keel-judge = build "keel-judge";
  keel-nudox-harness = build "backend-keel-harness";
}
