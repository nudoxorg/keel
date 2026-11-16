#!/usr/bin/env nu
# Checks the Keel dashboards and alert rules before they are copied into
# MachineConfigurations. Grafana shows a panel on a misspelt metric as an
# empty graph and a vmalert rule on one as a rule that never fires; neither
# says anything at provisioning time. So this evaluates the Nix, takes every
# keel_judge_* name out of every query, and requires each to exist in a real
# keel-judge textfile. It also checks what a provisioning mistake would hide:
# duplicate panel ids, panels off the 24-column grid, empty queries.
#
#   nu nix/grafana/check.nu <file.prom>
#
# Exits non-zero, naming every problem, if anything is wrong.

const dashboards = ["keel-fuzz.nix" "keel-ci.nix"]
const rules = "../alerts/keel-judge.nix"

def eval-nix [file: path]: nothing -> any {
  let r = (^nix-instantiate --eval --strict --json $file | complete)
  if $r.exit_code != 0 {
    print -e $"nix-instantiate failed on ($file):\n($r.stderr)"
    exit 1
  }
  $r.stdout | from json
}

# Every query: where it is, and its text.
def dashboard-queries [d: record, file: string]: nothing -> table {
  $d.panels | each {|p|
    ($p.targets? | default []) | each {|t|
      {where: $"($file): panel ($p.id) \"($p.title)\"", expr: ($t.expr? | default "")}
    }
  } | flatten
}

# The names a prom file defines: from # TYPE lines and from samples.
def prom-names [file: path]: nothing -> list<string> {
  let lines = (open --raw $file | lines | str trim | where {|l| $l != ""})
  let typed = ($lines | where {|l| $l =~ '^# TYPE '} | each {|l| $l | split row " " | get 2})
  let sampled = ($lines | where {|l| not ($l | str starts-with "#")} | each {|l| $l | parse --regex '^(?P<n>[a-zA-Z_:][a-zA-Z0-9_:]*)' | get 0.n})
  $typed | append $sampled | uniq
}

# Grid, id and query checks for one dashboard; returns problem strings.
def dashboard-problems [d: record, file: string]: nothing -> list<string> {
  let ids = ($d.panels | get id)
  let dup_ids = ($ids | uniq --repeated | each {|i| $"($file): panel id ($i) is used twice"})
  let grid = ($d.panels | each {|p|
    let g = ($p.gridPos? | default null)
    if $g == null {
      [$"($file): panel ($p.id) \"($p.title)\" has no gridPos"]
    } else {
      let missing = (["x" "y" "w" "h"] | where {|k| ($g | get -o $k) == null})
      if ($missing | is-not-empty) {
        [$"($file): panel ($p.id) \"($p.title)\" gridPos lacks ($missing | str join ', ')"]
      } else if ($g.x + $g.w) > 24 {
        [$"($file): panel ($p.id) \"($p.title)\" runs off the grid: x ($g.x) + w ($g.w) > 24"]
      } else if $g.w < 1 or $g.h < 1 {
        [$"($file): panel ($p.id) \"($p.title)\" has no size"]
      } else { [] }
    }
  } | flatten)
  let empty = ($d.panels | each {|p|
    let ts = ($p.targets? | default [])
    let blank = ($ts | enumerate | where {|t| ($t.item.expr? | default "" | str trim) == ""}
      | each {|t| $"($file): panel ($p.id) \"($p.title)\" query ($t.index + 1) has an empty expr"})
    let refs = ($ts | each {|t| $t.refId? | default ""})
    let dup_refs = ($refs | uniq --repeated | each {|r| $"($file): panel ($p.id) \"($p.title)\" uses refId '($r)' twice"})
    let none = if ($ts | is-empty) and $p.type != "row" { [$"($file): panel ($p.id) \"($p.title)\" has no queries"] } else { [] }
    $blank | append $dup_refs | append $none
  } | flatten)
  $dup_ids | append $grid | append $empty
}

def rule-problems [g: record]: nothing -> list<string> {
  let names = ($g.rules | get alert)
  let dups = ($names | uniq --repeated | each {|n| $"rules: alert ($n) is defined twice"})
  let incomplete = ($g.rules | each {|r|
    let need = [
      [expr ($r.expr? | default "")]
      [severity ($r.labels?.severity? | default "")]
      [summary ($r.annotations?.summary? | default "")]
      [description ($r.annotations?.description? | default "")]
    ] | where {|kv| ($kv.1 | str trim) == ""} | each {|kv| $kv.0}
    if ($need | is-empty) { [] } else { [$"rules: ($r.alert) lacks ($need | str join ', ')"] }
  } | flatten)
  $dups | append $incomplete
}

def main [prom: path] {
  let dir = $env.FILE_PWD
  let defined = (prom-names $prom)

  mut problems: list<string> = []
  mut queries: table = []
  mut uids: list<string> = []

  for f in $dashboards {
    let d = (eval-nix ($dir | path join $f))
    $problems = ($problems | append (dashboard-problems $d $f))
    $queries = ($queries | append (dashboard-queries $d $f))
    $uids = ($uids | append $d.uid)
  }

  let group = (eval-nix ($dir | path join $rules))
  $problems = ($problems | append (rule-problems $group))
  $queries = ($queries | append ($group.rules | each {|r| {where: $"keel-judge.nix: alert ($r.alert)", expr: ($r.expr? | default "")}}))

  let dup_uids = ($uids | uniq --repeated | each {|u| $"dashboard uid ($u) is used twice"})
  $problems = ($problems | append $dup_uids)

  let used = ($queries | each {|q|
    $q.expr | parse --regex '(?P<metric>keel_judge_[a-z_]+)' | each {|m| {metric: $m.metric, where: $q.where}}
  } | flatten)
  let missing = ($used | where {|u| $u.metric not-in $defined}
    | each {|u| $"($u.where): metric ($u.metric) is not in ($prom | path basename)"})
  $problems = ($problems | append $missing)

  if ($problems | is-not-empty) {
    print -e ($problems | uniq | each {|p| $"FAIL ($p)"} | str join "\n")
    exit 1
  }
  let names = ($used | get metric | uniq | length)
  print $"ok: ($dashboards | length) dashboards and ($group.rules | length) alerts, ($names) distinct keel_judge metrics, all in ($prom | path basename)"
}
