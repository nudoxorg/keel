{
  description = "Keel: reproducible test selection and execution";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/0bb7ec54c8483066ec9d7720e780a5caa71f8612";
    fenix = {
      url = "github:nix-community/fenix/8d20dd64ad45ed4b5179a37cec75fff9f732e78d";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      fenix,
      ...
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      lib = (import ./nix/keel/lib.nix) // {
        models.backend = ./models/backend/keel.nix;
      };
      nixosModules = {
        keel-host = ./nix/keel-host.nix;
        keel-judge = ./nix/keel-judge.nix;
      };
      packages = eachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          rust =
            (fenix.packages.${system}.toolchainOf {
              channel = "1.97.1";
              sha256 = "sha256-A1abGIbOtcBSdrUMhDGrER3pRM1hQP4fp9gh3Y4PKc8=";
            }).withComponents
              [
                "cargo"
                "rustc"
              ];
        in
        import ./nix/packaging.nix {
          inherit pkgs rust;
          src = ./.;
        }
      );
      checks = eachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          libraryTests = import ./nix/keel/tests.nix;
        in
        {
          model-library = pkgs.runCommand "keel-model-library-tests" { } ''
            echo ${toString libraryTests.passed} > "$out"
          '';
          cli = self.packages.${system}.keel;
          nudox-harness = self.packages.${system}.keel-nudox-harness;
        }
      );
    };
}
