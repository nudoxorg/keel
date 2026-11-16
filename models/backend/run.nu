#!/usr/bin/env nu
# Regenerates models/backend/out/ from the model and the backend clone, so
# every captured output can be reproduced with one command.
def capture [file: string, cmd: list<string>] {
  let r = (do { ^($cmd | first) ...($cmd | skip 1) } | complete)
  $r.stdout + $r.stderr | save -f $file
  print $"($file): exit ($r.exit_code)"
}

def main [--bin: string = "target/release/keel-tree"] {
  let k = [$bin "--root" backend "--model" models/backend/eval.nix]
  let out = "models/backend/out"
  mkdir $out
  capture $"($out)/check.txt" ($k ++ [check "--lock" $"($out)/keel.lock.json"])
  capture $"($out)/tree.txt" ($k ++ [tree])
  for node in [search desktop] { capture $"($out)/tree-($node).txt" ($k ++ [tree $node]) }
  for head in [b4dad662e df3404463 ffdd71557 a6391886e 87c88b39a 24a238ebc] {
    capture $"($out)/plan-($head).txt" ($k ++ [plan "--base" $"($head)^" "--head" $head "--statuses" $"($out)/status-plan-($head).json" "--comment" $"($out)/comment-plan-($head).md"])
  }
  # Every place the product meets code or state it does not control, per owning node: a lower bound.
  capture $"($out)/boundaries.txt" ($k ++ [boundaries])
  capture $"($out)/explain.txt" ($k ++ [explain "--failures" bench/data/deep-linux-14.status-lines.txt "--failures-only"])
  # The same run on the feature trees: roots, what stands on them, one commit status per feature,
  # and the PR comment CI posts (the roots first, the trees folded under them).
  capture $"($out)/tree-results-deep14.txt" ($k ++ [tree "--results" bench/data/deep-linux-14.status-lines.txt "--failures-only" "--statuses" $"($out)/statuses-deep14.json" "--comment" $"($out)/comment-deep14.md"])
}
