# NixOS VM test for nix/keel-judge.nix: the real supervisor, run by the real
# unit, against a fake bundle whose targets are `keel-judge-test-target`. It
# proves the wiring (the targets file is built from the bundle, the unit's user
# and sandbox let the children write /durable/fuzz, SIGTERM leaves a closed
# record and a restart keeps everything) and the scheduling the fake targets can
# show (a cold start for each target, a starved one, a retired crasher). It
# proves nothing about the real fuzz binaries: they are not run here.
# Build with
#   nix-build nix/keel-judge-test.nix            (needs a Linux builder with KVM)
# The scheduling is not asserted in Python. It is a list of expectations about
# the metrics file (`bundleExpectations`, each with its why) merged with the
# module's own, and one `keel-judge expect` evaluates them; the same list works
# against a local soak or the live host. The testScript keeps only what metrics
# cannot say: the unit's settings, the wrapper contract and the stop/start
# records. It is Python because that is the only driver NixOS has; it is test
# data here, not repository code.
#
# Unexecuted so far: the author's machine has no Linux builder, so this file is
# only known to evaluate (`nix-instantiate`) to a derivation. Expect to fix
# small things the first time it runs (record field names, timing).
{
  pkgs ? import <nixpkgs> { system = "x86_64-linux"; },
}:
let
  inherit (pkgs) lib;

  # Both binaries (`keel-judge` and the fake libFuzzer target) come from the
  # workspace. The crate reuses crates/keel-fuzz/src/dedup.rs by path, so the
  # whole of crates/ stays in the source, as in keel-host-test.nix.
  keelJudge = pkgs.rustPlatform.buildRustPackage {
    pname = "keel-judge";
    version = "0.1.0";
    src = import ./vm-workspace-source.nix { inherit lib; };
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [
      "--package"
      "keel-judge"
    ];
    doCheck = false; # the workspace tests run under cargo; the VM needs the binaries
  };

  # The scheduled rows. rank is complexity.score * gap.score * blast.score,
  # which is what the consumer rules (continuous-fuzzing.md) say to recompute;
  # the numbers make the order alpha > crashy > zero, and zero's gap of 0 gives
  # rank 0 with schedule still true.
  row =
    {
      id,
      loc,
      gap,
      startOrder,
    }:
    let
      complexity = loc + 2 + 2;
      blast = 5;
    in
    {
      inherit id;
      kind = "fuzz";
      name = id;
      engine = "libfuzzer";
      bin = "packages.\${system}.continuous-fuzz.bins.${id}";
      corpus = "packages.\${system}.continuous-fuzz.corpora.${id}";
      committed_corpus = "tests/fuzz/targets/${id}/corpus";
      warmVault = {
        name = id;
        corporaAttr = "packages.\${system}.continuous-fuzz.corpora.${id}";
      };
      durableMount = "/durable/fuzz/${id}/corpus";
      dictionary = "tests/fuzz/targets/${id}/dictionary.txt";
      max_input_bytes = 4096;
      schedule = true;
      rank = complexity * gap * blast;
      start_order = startOrder;
      reason = null;
      complexity = {
        score = complexity;
        inherit loc;
        error_variants = 2;
        discriminants = 2;
        method = "measured";
      };
      gap = {
        score = gap;
        method = "classified";
        llvm_cov_percent = null;
      };
      blast = {
        score = blast;
        method = "classified";
      };
    };

  # A sibling row the supervisor must skip: not scheduled, nothing to run.
  propertyRow = {
    id = "laws";
    kind = "property";
    name = "laws";
    engine = "property";
    bin = null;
    corpus = null;
    committed_corpus = null;
    warmVault = null;
    durableMount = null;
    dictionary = null;
    max_input_bytes = null;
    schedule = false;
    rank = null;
    start_order = null;
    reason = null;
    complexity = {
      score = null;
      method = "unscored";
    };
    gap = {
      score = 2;
      method = "classified";
      llvm_cov_percent = null;
    };
    blast = {
      score = 5;
      method = "classified";
    };
  };

  metadata = pkgs.writeText "metadata.json" (
    builtins.toJSON {
      schema = "nudox.continuous-fuzz.v1";
      latticeKind = "continuous-fuzz";
      kinds = [
        "fuzz"
        "property"
      ];
      formula = "complexity.score * gap.score * blast.score";
      targets = [
        (row {
          id = "alpha";
          loc = 896; # 900 * 2 * 5 = 9000
          gap = 2;
          startOrder = 1;
        })
        (row {
          id = "zero";
          loc = 496; # gap 0, so rank 0
          gap = 0;
          startOrder = 2;
        })
        (row {
          id = "crashy";
          loc = 6; # 10 * 2 * 5 = 100
          gap = 2;
          startOrder = 3;
        })
        propertyRow
      ];
    }
  );

  # The backend wrapper's contract (continuous-fuzzing.md): exit 2 unless
  # argv[1] is exactly the durable mount, refuse -max_total_time, create the
  # corpus and the sibling artifacts directory, then exec the engine. The
  # engine here is the fake target, with the rate (and for crashy the crash)
  # that makes the test deterministic.
  wrapper =
    id: flags:
    pkgs.writeShellScript "fuzz-${id}" ''
      set -eu
      mount=/durable/fuzz/${id}/corpus
      if [ "$#" -lt 1 ] || [ "$1" != "$mount" ]; then
        echo "refusing to start: argv[1] must be $mount" >&2
        exit 2
      fi
      corpus=$1
      shift
      for arg in "$@"; do
        case "$arg" in
          -max_total_time*)
            echo "refusing -max_total_time; the supervisor owns campaign lifetime" >&2
            exit 2
            ;;
        esac
      done
      mkdir -p "$corpus" "$(dirname "$corpus")/artifacts"
      exec ${keelJudge}/bin/keel-judge-test-target "$corpus" "$@" ${flags}
    '';

  bundle = pkgs.runCommand "continuous-fuzz-fake" { } ''
    mkdir -p "$out/bin"
    cp ${metadata} "$out/metadata.json"
    ln -s ${wrapper "alpha" "-keel_test_rate=20"} "$out/bin/fuzz-alpha"
    ln -s ${wrapper "zero" "-keel_test_rate=1"} "$out/bin/fuzz-zero"
    ln -s ${wrapper "crashy" "-keel_test_crash_after=1"} "$out/bin/fuzz-crashy"
  '';

  # Node exporter's directory on the node and the link the module puts in it.
  metricsLink = "/var/lib/node-exporter-textfile/keel_judge.prom";

  # What this bundle must show, beyond what every healthy service shows
  # (`nudox.services.keel-judge.expectations`). Each is a series of the metrics
  # file, so the same list can be checked against a local soak or the live host
  # (`keel-judge expect --metrics`), and a failed one prints its own why.
  bundleExpectations = [
    {
      name = "eight-quanta";
      metric = "keel_judge_quanta_total";
      op = ">=";
      value = 8;
      why = "the run is long enough for every case below to have happened; a unit that has not recorded eight 3 s quanta by now did not start, or its children cannot run (read journalctl -u keel-judge)";
    }
    {
      name = "property-row-never-runs";
      metric = "keel_judge_target_quanta_total";
      labels.target = "laws";
      op = "absent";
      why = "the property row 'laws' has schedule = false, and the supervisor must skip unscheduled rows; check the targets file the unit wrote to /var/lib/keel-judge/targets.json";
    }
    {
      name = "zero-starved";
      metric = "keel_judge_target_chosen_total";
      labels = {
        target = "zero";
        chosen_by = "starved";
      };
      op = ">=";
      value = 1;
      why = "'zero' has rank 0, so only the starve turn (every tenth pick, to the least recently served target) ever runs it after its cold start; with one worker that is deterministic";
    }
    {
      name = "crashy-one-finding";
      metric = "keel_judge_findings";
      labels.target = "crashy";
      op = "==";
      value = 1;
      why = "the fake crashes once, in its first quantum; more than one finding means the supervisor re-ran a target that already crashed, or did not deduplicate";
    }
    {
      name = "crashy-one-quantum";
      metric = "keel_judge_target_quanta_total";
      labels.target = "crashy";
      op = "==";
      value = 1;
      why = "the quantum that found the crash must be crashy's last: a target with a finding must not be scheduled again";
    }
    {
      name = "crashy-blocked";
      metric = "keel_judge_target_blocked";
      labels.target = "crashy";
      op = "==";
      value = 1;
      why = "a finding against the current binary holds the target back until a new build; if this is 0 the finding was not recorded against the binary that ran";
    }
    {
      name = "alpha-corpus-grows";
      metric = "keel_judge_target_corpus_files";
      labels.target = "alpha";
      op = ">";
      value = 0;
      why = "the children run as keel-fuzz and must be able to write /durable/fuzz/alpha/corpus; no files there means the sandbox (ReadWritePaths) or the directory's owner is wrong";
    }
  ]
  # Every scheduled row gets a cold quantum, even at rank 0.
  ++
    map
      (id: {
        name = "cold-start-${id}";
        metric = "keel_judge_target_chosen_total";
        labels = {
          target = id;
          chosen_by = "cold";
        };
        op = ">=";
        value = 1;
        why = "every scheduled row of the bundle must get a cold quantum, '${id}' included; check the targets file the unit wrote to /var/lib/keel-judge/targets.json";
      })
      [
        "alpha"
        "zero"
        "crashy"
      ];

  # The module's expectations come from the node's own configuration, so the
  # test checks what a host that enables the module would check.
  expectSpec =
    nodes:
    pkgs.writeText "keel-judge-test-expect.json" (
      builtins.toJSON {
        schema = "keel.judge.expect.v1";
        expectations = nodes.judge.nudox.services.keel-judge.expectations ++ bundleExpectations;
      }
    );
in
pkgs.testers.runNixOSTest {
  name = "keel-judge";

  nodes.judge =
    { ... }:
    {
      imports = [ ./keel-judge.nix ];

      virtualisation = {
        cores = 2;
        memorySize = 2048;
        # --min-free-gib 1 below needs a gibibyte free on the root disk, which
        # the default 1 GiB image does not have.
        diskSize = 4096;
      };

      nudox.services.keel-judge = {
        enable = true;
        package = keelJudge;
        inherit bundle;
        # One worker, so the starve turn (every tenth pick) lands on whichever target was
        # served least recently, and that is `zero` once `alpha` holds the index. With two
        # workers and two eligible targets each worker keeps one target, and which of them
        # gets the starve turn depends on timing. tests/run.rs covers two workers.
        workers = 1;
        # Short, so the whole run fits in minutes. The crash is at 1 s, inside it.
        quantum = "3s";
        minFreeGib = 1;
        # Stands in for node exporter's directory, which this node does not run.
        metrics.textfileDirectory = "/var/lib/node-exporter-textfile";
      };

      systemd.tmpfiles.rules = [ "d /var/lib/node-exporter-textfile 0755 root root - -" ];
    };

  testScript =
    { nodes, ... }:
    ''
      import json

      state = "/var/lib/keel-judge"
      bundle = "${bundle}"

      # Only newline-terminated lines count: a reader can catch the supervisor
      # in the middle of an append, and a half line is not yet a record.
      def raw(name):
          return judge.execute(f"cat {state}/{name}.jsonl 2>/dev/null")[1]

      start_all()
      judge.wait_for_unit("keel-judge.service")

      # --- What the metrics can say: scheduling, findings, the file itself -----

      # One checker, one spec (the module's own expectations plus this bundle's).
      # It reads the file through the symlink in the collector's directory and as
      # a user that is not keel-fuzz and not in its group, which is what node
      # exporter is. A failing expectation prints its FAIL line into this log.
      judge.succeed(
          "runuser -u nobody -- ${keelJudge}/bin/keel-judge expect --spec ${expectSpec nodes} "
          "--metrics ${metricsLink} --within 300s"
      )

      # --- What they cannot: the unit's own settings ----------------------------

      props = dict(
          line.split("=", 1)
          for line in judge.succeed(
              "systemctl show keel-judge.service -p User -p PrivateNetwork -p CPUWeight -p Nice -p Type -p NotifyAccess -p OOMPolicy"
          ).split("\n")
          if line
      )
      # systemd stores CPUWeight=idle as the weight 0, and `systemctl show` may print either.
      if props.get("CPUWeight") == "0":
          props["CPUWeight"] = "idle"
      expected = {
          "User": "keel-fuzz",
          "PrivateNetwork": "yes",
          "CPUWeight": "idle",
          "Nice": "19",
          # READY and the watchdog heartbeat come from the supervisor's own process.
          "Type": "notify",
          "NotifyAccess": "main",
          # One fuzz child killed by the OOM killer must not stop the unit.
          "OOMPolicy": "continue",
      }
      assert props == expected, (
          f"keel-judge.service has {props}, expected {expected}; one of the unit's sandbox or "
          "priority settings is missing or was changed in nix/keel-judge.nix."
      )

      status = judge.succeed("keel-judge-status")
      missing = [t for t in ("alpha", "zero", "crashy") if t not in status]
      assert not missing, (
          f"keel-judge-status does not name {missing}; its output was:\n{status}\n"
          "It reads /var/lib/keel-judge/targets.json and quanta.jsonl; check both exist."
      )

      # The wrapper contract, as the unit's user would meet it: the fake follows
      # the backend's, so this is a check of the test's own fidelity as much as
      # of anything else.
      for args in ("/tmp/not-the-mount", "/durable/fuzz/zero/corpus", ""):
          code = judge.execute(f"runuser -u keel-fuzz -- {bundle}/bin/fuzz-alpha {args}")[0]
          assert code == 2, (
              f"fuzz-alpha called with {args!r} exited {code}, expected 2: the wrapper must refuse "
              "any argv[1] but /durable/fuzz/alpha/corpus. The fake in keel-judge-test.nix no longer "
              "follows the backend wrapper's contract (continuous-fuzzing.md)."
          )

      # --- Stop and start: SIGTERM closes the records, nothing is lost ---------

      judge.succeed("systemctl stop keel-judge.service")
      result = judge.succeed("systemctl show keel-judge.service -p Result --value").strip()
      assert result == "success", (
          f"keel-judge.service stopped with Result={result!r}, expected success: the supervisor "
          "must exit 0 on SIGTERM within TimeoutStopSec, after stopping its children."
      )
      before = raw("quanta")
      assert before.endswith("\n"), (
          "quanta.jsonl ends in a partial line after a clean stop; the supervisor must append whole "
          f"records before it exits. Tail: {before[-200:]!r}"
      )
      last = json.loads(before.split("\n")[-2])
      assert last["stopped_by"] == "supervisor", (
          f"the last quantum record has stopped_by={last['stopped_by']!r}, expected 'supervisor': "
          f"on SIGTERM the supervisor appends its children's records. Record: {last!r}"
      )

      judge.succeed("systemctl start keel-judge.service")
      count = before.count("\n")
      # Two more records than before the stop: the restart rebuilt its state and carried on.
      judge.wait_until_succeeds(f"test $(wc -l < {state}/quanta.jsonl) -ge {count + 2}")
      after = raw("quanta")
      assert after.startswith(before), (
          "quanta.jsonl after the restart does not begin with the records from before it: state "
          "is append-only and a restart must rebuild from it, not rewrite it."
      )
    '';
}
