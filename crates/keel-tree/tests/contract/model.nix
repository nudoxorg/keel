# The contract model: it uses every constructor nix/keel/lib.nix exports, every fault kind with
# a valid target, every `during` verdict and every source of a census, so that the JSON it
# evaluates to carries every key and variant the library can emit. tests/contract.nu feeds that
# JSON to keel-tree's model reader and fails if any key is not read by a typed field.
#
# It describes this crate, which is why every path below exists under `root`. Nothing here is a
# claim about the product; when the library gains a field or a constructor, add a use of it here.
let
  keel = import ../../../../nix/keel/lib.nix;
in
keel.model (
  m:
  with keel;
  let
    # A world with every field: kept as machines, built from nothing, with every selector kind
    # in its inputs, text and selectors in its environment, tools, a network, a time limit.
    base = world {
      name = "base";
      about = "Every field a world has.";
      step = [ "probe" "world" "empty" ];
      keep = "machine";
      inputs = [
        (crate "keel-tree")
        (path "Cargo.toml")
        (module "keel-tree::model")
        (pattern "rust" "fn main() {}")
        (option "services.probe.enable")
        (drv "pkgs.hello")
        (within (path "src") "lib.rs")
        (within (drv "pkgs.jdk") "bin/javac")
      ];
      maxAgeMinutes = 60;
      machines = [ "ilo" "ilo-prod" ];
      env = {
        LANG = "C.UTF-8";
        JAVAC = within (drv "pkgs.jdk") "bin/javac";
        PROBE = within (crate "keel-tree") "src/main.rs";
        SOCK = state "owner.sock";
      };
      tools = [
        (drv "pkgs.go")
        (crate "keel-tree")
        (within (drv "pkgs.jdk") "bin/javac")
      ];
      network = true;
      readyWithin = 30;
    };
    # A fork: it inherits and restates.
    leaf = world {
      name = "leaf";
      from = base;
      step = [ "probe" "world" "indexed" ];
      keep = "service";
      inputs = [ (path "tests/contract/**") ];
      env.EXTRA = "1";
      tools = [ (drv "pkgs.git") ];
      network = false;
    };
    census-world = world {
      name = "census-world";
      step = [ "probe" "world" "census" ];
      inputs = [ (path "Cargo.toml") ];
    };
    place-world = world {
      name = "place-world";
      step = [ "probe" "world" "placed" ];
      inputs = [ (path "Cargo.toml") ];
    };

    # One fault of every kind, each with a target its kind accepts.
    unit = { host = "ilo"; service = "locald"; };
    link = extra: { host = "ilo"; port = 443; proto = "tcp"; direction = "in"; } // extra;
    fault =
      name: kind: target: during: extra:
      {
        inherit name kind target during;
        hold = 20;
        recoverWithin = 60;
      }
      // extra;
    holds = { holds = true; };
    degrades = { degradesTo = { expect = { degraded = true; }; within = 5; }; };
    refuses = { refuses = { expect = { refused = "unavailable"; }; within = 5; }; };
    faults = [
      (fault "stop-unit" "stop" unit holds { breaks = m.core; })
      (fault "kill-unit" "kill" { host = "ilo"; unit = "locald.service"; } refuses { breaks = { edge = [ m.app m.core ]; }; })
      (fault "pause-unit" "pause" unit degrades { })
      (fault "restart-unit" "restart" unit holds { after = { settled = true; }; })
      (fault "oom-unit" "oom-kill" unit holds { })
      (fault "reboot-host" "reboot" { host = "ilo"; } { down = true; } { })
      (fault "power-loss-host" "power-loss" { host = "ilo"; path = "/var/lib/keel"; } { down = true; } { })
      (fault "boot-order-host" "boot-order" { host = "ilo"; first = [ "a.service" "b.service" ]; } holds { })
      (fault "partition-hosts" "partition" { between = [ "ilo" "ilo-prod" ]; } refuses { })
      (fault "drop-link" "drop" (link { percent = 10; }) degrades { })
      (fault "corrupt-link" "corrupt" (link { percent = 5; }) refuses { })
      (fault "delay-link" "delay" (link { milliseconds = 200; }) degrades { })
      (fault "dns-nxdomain-name" "dns-nxdomain" { host = "ilo"; name = "example.org"; } refuses { })
      (fault "dns-wrong-name" "dns-wrong" { host = "ilo"; name = "example.org"; answer = "10.0.0.1"; } refuses { })
      (fault "clock-skew-host" "clock-skew" { host = "ilo"; seconds = 3600; } holds { })
      (fault "disk-full-host" "disk-full" { host = "ilo"; path = "/var"; } degrades { })
      (fault "cert-expired" "certificate-expired" { host = "ilo"; name = "api"; } refuses { })
      (fault "cert-rotated" "certificate-rotated" { host = "ilo"; name = "api"; } holds { })
      (fault "credential-rotated" "credential-rotated" { host = "ilo"; secret = "token"; } holds { })
      (fault "credential-revoked" "credential-revoked" { host = "ilo"; secret = "token"; } refuses { })
      (fault "dependency-slow" "dependency-slow" { host = "ilo"; service = "db"; milliseconds = 500; } degrades { })
      (fault "dependency-error" "dependency-error" { host = "ilo"; service = "db"; status = 503; } degrades { })
      (fault "custom-fault" "custom" { } holds { at = "ilo"; inject = [ "probe" "inject" ]; heal = [ "probe" "heal" ]; })
    ];
  in
  {
    root = ../..;

    # ── Nodes: every field, a child, both ship policies ───────────────
    core = node {
      about = "Selectors of every kind a node may own.";
      code = [
        (crate "keel-tree")
        (path "src/**")
        (module "keel-tree::model")
        (pattern "rust" "fn main() {}")
        (option "services.probe.enable")
        (drv "pkgs.hello")
      ];
      entry = [ (path "Cargo.toml") ];
      source = "tests/contract/model.nix";
      movedBy = [ "src/lib.rs" ];
      unmovedBy = [ "Cargo.toml" ];
      child = node { code = [ (path "src/main.rs") ]; };
    } // required;
    app = node {
      code = [ (path "tests/**") ];
      on = [ m.core ];
      never = [ m.other ];
    };
    other = node { code = [ (crate "elsewhere") ]; };
    mirror = node {
      code = [ (crate "mirror") ];
      of = [ m.core ];
    };
    lagging = node {
      code = [ (path "tests/contract.rs") ];
      movedBy = [ "tests/contract.rs" ];
      unmovedBy = [ "Cargo.toml" ];
    } // mayLag { atMostMinutes = 120; confidence = 0.95; };

    # One node for each of this workspace's packages that no node above claims.
    nodesFromCrates = { strip = "keel-"; under = [ "src/**" ]; };

    axes = {
      tier = { values = [ "unit" "law" ]; default = "unit"; };
      language = [ "rust" "nix" ];
    };

    # ── Placement: every test-set operator that a rule may use ─────────
    place = [
      { tests = tests.all; tier = "unit"; }
      { tests = tests.under "src/**"; tier = "law"; world = place-world; }
      { tests = tests.inPackage "keel-tree"; language = "rust"; }
      { tests = tests.reaching (crate "keel-tree"); language = "nix"; }
      { tests = tests.on m.core; tier = "law"; }
      { tests = tests.only m.app; tier = "unit"; }
      { tests = tests.union [ (tests.under "src/**") (tests.under "tests/**") ]; tier = "law"; }
      { tests = tests.both [ (tests.under "src/**") (tests.inPackage "keel-tree") ]; tier = "unit"; }
      { tests = tests.minus (tests.under "tests/**") (tests.under "tests/contract/**"); tier = "unit"; }
      { tests = tests.named "*contract*"; world = place-world; }
    ];

    # ── Checks: a matrix with every field, controls, and every fault ───
    checks.contract = matrix {
      over = { p = [ "one" "two" ]; };
      when = cell: true;
      world = cell: leaf;
      run = cell: [ "probe" cell.p ];
      expect = { ok = true; };
      on = cell: [ m.core m.app ];
      at = "ilo";
      as = "operator";
      coordinates = cell: { tier = "law"; };
      inputs = [ (crate "keel-tree") (path "tests/contract/**") (within (path "src") "main.rs") ];
      together = cell: "batch";
      controls = [
        {
          name = "wrong-node";
          alter = cell: cell // { p = "${cell.p}-wrong"; };
          expect = { refused = true; };
          breaks = m.core;
        }
        {
          name = "wrong-edge";
          alter = cell: cell // { p = "${cell.p}-bad"; };
          expect = { refused = "edge"; };
          breaks = { edge = [ m.app m.core ]; };
        }
      ];
      inherit faults;
    };

    # ── Census: both sources ───────────────────────────────────────────
    census.observed-here = {
      about = "Records known when the model is evaluated.";
      key = [ "name" "port" ];
      observed = [
        { name = "web"; port = 80; }
        { name = "db"; port = 5432; }
        { name = "stray"; port = 9; host = "ilo"; }
      ];
      declared = [
        { name = "web"; port = 80; }
        { name = "gone"; port = 1; }
      ];
      ignore = [ { match = { name = "db"; }; reason = "a dependency of the probe, not the product"; } ];
      extra = "report";
      missing = "fail";
      axes = { tier = "name"; };
      on = [ m.core ];
      inputs = [ (path "Cargo.toml") ];
    };
    census.boundary-process-spawn = {
      about = "Files that start other programs, found by the engine in the source.";
      boundary = "process-spawn";
      key = [ "file" "node" ];
      declared = [ { file = "src/main.rs"; node = "app"; } ];
      extra = "report";
      inputs = [ (path "src/**") ];
    };
    census.observed-live = {
      about = "Records a command prints when the driver runs it in a world.";
      world = census-world;
      key = [ "file" ];
      observe = [ "probe" "sites" "--record" "file" ];
      declared = [ { file = "src/main.rs"; } ];
      inputs = [ (crate "keel-tree") (path "src/**") ];
    };

    policy = {
      deployGate = tests.minus tests.all (tests.only m.app);
      idle = {
        mutate = tests.under "src/**";
        recheckOneIn = 50;
      };
      uncovered = "report";
      joins = [ [ m.core m.app ] ];
      inert = [ (inert "tests/contract/**" "the contract model describes this crate and is built from nothing") ];
      faults = "report";
      unfaulted = [ { from = m.app; to = m.core; reason = "the contract model does not exercise it"; } ];
    };
  }
)
