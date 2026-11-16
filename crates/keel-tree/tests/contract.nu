#!/usr/bin/env nu
# The contract between nix/keel/lib.nix and keel-tree's model reader.
#
#   nu contract.nu <keel-tree binary> <lib.nix> <contract/model.nix>
#
# 1. Evaluates the contract model, which uses every constructor the library exports.
# 2. Checks that the model really does use them all: every selector kind, fault kind, test-set
#    operator, `during` verdict, census source, world field, node field and policy field the
#    library defines appears in the JSON. The lists are read from the library's own text, so a
#    constructor added to the library fails here until contract/model.nix uses it.
# 3. Feeds the JSON to `keel-tree read-model`, which fails if any key or variant in it has no
#    typed field in the reader. A field added to the library fails here until the engine reads it.

# The quoted words, one per line, of the Nix list that starts at `start` (`name = [`).
def listed [lib: string, start: string]: nothing -> list<string> {
  let i = ($lib | str index-of $start)
  if $i < 0 { error make { msg: $"the library no longer has `($start)`; update tests/contract.nu" } }
  $lib | str substring $i.. | split row "];" | first | lines | each { str trim } | where { $in =~ '^"[^"]+"$' } | each { str trim -c '"' }
}

# Every value found under `key` anywhere in the JSON.
def under [key: string]: any -> list<any> {
  let v = $in
  let t = ($v | describe)
  if ($t | str starts-with "record") {
    $v | transpose k val | each {|r| (if $r.k == $key { [ $r.val ] } else { [] }) ++ ($r.val | under $key) } | flatten
  } else if ($t | str starts-with "list") or ($t | str starts-with "table") {
    $v | each {|x| $x | under $key } | flatten
  } else { [] }
}

def missing [what: string, wanted: list<string>, found: list<string>]: nothing -> list<string> {
  $wanted | where { $in not-in $found } | each {|w| $"($what) `($w)` is defined by the library and the contract model does not use it" }
}

def main [bin: string, lib_path: string, model_path: string] {
  let lib = (open --raw $lib_path)
  let json_path = ($nu.temp-dir | path join $"keel-contract-(random uuid).json")
  let eval = (^nix-instantiate --eval --strict --json $model_path | complete)
  if $eval.exit_code != 0 {
    error make { msg: $"the contract model does not evaluate; the library refused it:\n($eval.stderr)" }
  }
  $eval.stdout | save -f $json_path
  let j = ($eval.stdout | from json)

  mut problems: list<string> = []

  # 2. Every constructor is used.
  let select_at = ($lib | str index-of "  select = {")
  let select_block = ($lib | str substring $select_at.. | split row "literalPrefix =" | first)
  let selector_kinds = ($select_block | parse --regex 'by = "(?<k>\w+)"' | get k | uniq)
  let tests_ops = ($lib | parse --regex 'testSet "(?<k>\w+)"' | get k | uniq)
  let fault_kinds = (listed $lib "faultKinds = [")
  let world_fields = (listed $lib "worldFields = [")
  let node_fields = (listed $lib "nodeFields = [" | where { $in != "_keel" })
  let policy_fields = (listed $lib "policyFields = [")
  let top_fields = (listed $lib "reserved = [")

  $problems = $problems ++ (missing "selector kind" $selector_kinds ($j | under "by" | where { ($in | describe) == "string" }))
  $problems = $problems ++ (missing "test-set operator" $tests_ops ($j | under "op"))
  let faults = ($j.checks | transpose g v | each { $in.v.checks } | flatten | get faults | flatten)
  $problems = $problems ++ (missing "fault kind" $fault_kinds ($faults | get kind))
  let verdicts = ($faults | get during | each { columns } | flatten)
  $problems = $problems ++ (missing "`during` verdict" [ "holds" "down" "degradesTo" "refuses" ] $verdicts)
  let world_keys = ($j.worlds | each { $in | transpose k v | where { $in.v != null and $in.v != [] and $in.v != {} and $in.v != false } | get k } | flatten | uniq)
  $problems = $problems ++ (missing "world field" $world_fields $world_keys)
  let node_keys = ($j.nodes | each { $in | transpose k v | where { $in.v != null and $in.v != [] } | get k } | flatten | uniq)
  $problems = $problems ++ (missing "node field" $node_fields $node_keys)
  $problems = $problems ++ (missing "policy field" $policy_fields ($j.policy | columns))
  $problems = $problems ++ (missing "top-level section" ($top_fields | where { $in in [ "axes" "place" "checks" "worlds" "policy" "census" "nodesFromCrates" ] }) ($j | columns))
  let cells = ($j.checks | transpose g v | each { $in.v.checks } | flatten)
  let breaks = ($cells | get breaks | where { $in != null } | each { columns } | flatten)
  $problems = $problems ++ (missing "breaks form" [ "node" "edge" ] $breaks)
  if ($cells | where { $in.together != null } | is-empty) { $problems = $problems | append "`together` is never used by the contract model" }
  if ($cells | where { $in.control != null } | is-empty) { $problems = $problems | append "no control twin in the contract model" }
  if ($j.axisDefaults | is-empty) { $problems = $problems | append "no axis default in the contract model" }
  if ($j.census | where { $in.result == null } | is-empty) { $problems = $problems | append "no census observed by a command (result null) in the contract model" }
  if ($j.census | where { $in.result != null } | is-empty) { $problems = $problems | append "no census observed as a value in the contract model" }
  let ships = ($j.nodes | get ship | uniq)
  $problems = $problems ++ (missing "ship policy" [ "required" "may-lag" ] ($ships | where { $in != null }))

  if ($problems | is-not-empty) {
    print ($problems | str join "\n")
    error make { msg: $"the contract model leaves ($problems | length) constructors of the library unused; add them to crates/keel-tree/tests/contract/model.nix" }
  }

  # 3. The reader reads every key.
  let r = (^$bin read-model $json_path | complete)
  rm -f $json_path
  print $r.stdout
  if $r.exit_code != 0 {
    error make { msg: $"keel-tree does not read every key of the contract model (see `unread:` lines above); add typed fields to crates/keel-tree/src/model.rs\n($r.stderr)" }
  }
  print $"contract ok: ($selector_kinds | length) selector kinds, ($tests_ops | length) test-set operators, ($fault_kinds | length) fault kinds, ($world_fields | length) world fields, all read"
}
