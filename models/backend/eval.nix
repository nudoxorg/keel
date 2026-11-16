# Entry point for `nix-instantiate --eval --strict --json`.
import ./keel.nix {
  keel = import ../../nix/keel/lib.nix;
  root = ../../backend;
}
