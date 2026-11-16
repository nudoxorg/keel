# NixOS module `nudox.services.keel-judge`: the always-on fuzz supervisor
# (design/doubt.md §5.6). It runs the backend's `continuous-fuzz` bundle in
# short quanta, a few targets at a time, at the lowest CPU priority, so the
# machine fuzzes whatever the rest of the fleet leaves idle.
#
# One user, `keel-fuzz`, and it is its own trust domain: it executes fuzz
# inputs against product code, so it holds no token, no network and nothing
# another unit trusts. It shares no group with keel-store, keel-conduct,
# keel-canon or keel-build (nix/keel-host.nix), and no unit of theirs shares one
# with it. What it writes is a corpus and crash artifacts; both are inputs to a
# human, never to a unit that acts on them.
#
# This module opens no port and starts nothing but the supervisor. The VM test
# is nix/keel-judge-test.nix; it runs the real supervisor against a fake
# target, so it proves the unit's wiring and sandbox, not the real binaries.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.nudox.services.keel-judge;

  # Fixed paths, so constants and not options: a reviewer reads one path per
  # purpose, everywhere.
  #
  # The backend's wrapper (`bins.<id>`, continuous-fuzzing.md) exits 2 for any
  # corpus path other than /durable/fuzz/<id>/corpus, so this root cannot move
  # without changing the backend first.
  durableRoot = "/durable/fuzz"; # keel-fuzz:keel-fuzz 0750, <id>/{corpus,artifacts} inside
  stateDir = "/var/lib/keel-judge"; # keel-fuzz:keel-fuzz 0750, append-only records
  targetsFile = "${stateDir}/targets.json"; # rewritten from the bundle at every start

  keelJudge = "${cfg.package}/bin/keel-judge";

  # The quantum is a humantime string for the supervisor, but the watchdog
  # needs seconds; only the forms the assertion below allows are read. A bad
  # value yields 60 here so evaluation reaches the assertion, which says why.
  quantumForm = builtins.match "([0-9]+)(s|m|h)" cfg.quantum;
  quantumSeconds =
    if quantumForm == null then
      60
    else
      lib.toInt (builtins.elemAt quantumForm 0)
      * {
        s = 1;
        m = 60;
        h = 3600;
      }
      .${builtins.elemAt quantumForm 1};

  # The supervisor stops sending WATCHDOG=1 once a worker has been inside one
  # quantum for longer than the quantum + 15 s (the SIGINT grace in
  # quantum.rs) + 60 s (STALL_MARGIN in run.rs): that is a child in
  # uninterruptible sleep, which never lets wait() return. WatchdogSec is
  # twice that, so it is always past the point where the supervisor gives up
  # itself and a heartbeat that is merely late is never a kill; a stuck service
  # is restarted within WatchdogSec of its last good heartbeat.
  watchdogSec = 2 * (quantumSeconds + 15 + 60);

  # Separate from stateDir because that is 0750 keel-fuzz, which node
  # exporter's user cannot traverse; this one holds only the metrics file.
  metricsDir = "/var/lib/keel-judge-metrics";
  metricsFile = "${metricsDir}/keel_judge.prom";
  withMetrics = cfg.metrics.textfileDirectory != null;

  # What every healthy running service shows in its own metrics file, as data for
  # `keel-judge expect` (schema keel.judge.expect.v1). Written here, next to the unit
  # that produces the metrics, so the VM test, a local soak and the live host
  # evaluate one definition and none keeps a parser for the logs of its own. They
  # read the metrics file, so there are none without one.
  healthyExpectations = lib.optionals withMetrics [
    {
      name = "metrics-fresh";
      metric = "keel_judge_metrics_written_timestamp_seconds";
      op = "age_below";
      value = 180;
      # The supervisor rewrites the file at least every 60 s (WRITE_EVERY in
      # metrics.rs) even while every target is blocked, so three missed writes
      # is a stalled or dead supervisor, not an idle one.
      why = "the supervisor rewrites its metrics file at least every 60 s, so a file older than 180 s means it has stalled or stopped; see journalctl -u keel-judge";
    }
    {
      name = "quanta-increase";
      metric = "keel_judge_quanta_total";
      op = "increases";
      why = "a healthy supervisor finishes a quantum (${cfg.quantum}) every so often, so the count must rise while this check reads; it needs a check that runs for more than one quantum, and fails when every target is blocked by a finding or the disk is below minFreeGib";
    }
    {
      name = "state-undamaged";
      metric = "keel_judge_state_damaged_lines";
      op = "==";
      value = 0;
      why = "a log line that is not a record was moved aside at start, so the history is incomplete; read the quanta.jsonl.damaged-* file in ${stateDir} and the journal for how it got damaged";
    }
    {
      name = "no-target-faulted";
      metric = "keel_judge_target_faulted";
      op = "==";
      value = 0;
      why = "a target is backed off because it cannot fuzz (a corpus or artifacts directory it cannot use, or quanta that end in error), so it gets no fuzz time; the journal names the target and why";
    }
  ];

  # Two quanta and a minute: long enough for `quanta-increase` to see one finish
  # even when the check starts right after a quantum ended.
  selftestWithin = 2 * quantumSeconds + 60;

  expectSpec = pkgs.writeText "keel-judge-expect.json" (
    builtins.toJSON {
      schema = "keel.judge.expect.v1";
      expectations = healthyExpectations;
    }
  );

  # The state directory is 0750 keel-fuzz, so a reader needs root or that
  # group. The unit rewrites the targets file at every start, so the script
  # always asks about the targets the running supervisor was given. Extra
  # arguments (`--json`) pass through.
  statusScript = pkgs.writeShellScriptBin "keel-judge-status" ''
    exec ${keelJudge} status --state ${stateDir} --targets ${targetsFile} "$@"
  '';
in
{
  options.nudox.services.keel-judge = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to run the always-on fuzz supervisor `keel-judge`. It runs
        each scheduled target of the backend's `continuous-fuzz` bundle in
        quanta, picks the next target from the records it keeps in
        `/var/lib/keel-judge`, and stops each child with SIGINT at its
        deadline. Corpora and crash artifacts live in `/durable/fuzz/<id>/`.

        Read the state with `keel-judge-status` as root or as a member of
        group `keel-fuzz`.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      description = "The package providing `bin/keel-judge` (crates/keel-judge). Pinned by the host configuration, not taken from a PR.";
    };

    bundle = lib.mkOption {
      type = lib.types.package;
      description = ''
        The backend's `packages.<system>.continuous-fuzz`: `bin/fuzz-<id>`
        wrappers and `metadata.json`. The unit reads `metadata.json` at every
        start, so a new bundle takes effect on restart and the corpora under
        `/durable/fuzz` carry over (the wrapper resumes from the same
        directory).
      '';
    };

    workers = lib.mkOption {
      type = lib.types.int;
      default = 2;
      description = "How many targets run at once. They run at idle CPU weight, so they take only CPU that nothing else wants.";
    };

    quantum = lib.mkOption {
      type = lib.types.str;
      default = "60s";
      description = ''
        How long one target runs before it is stopped and the next is chosen
        (design/doubt.md §5.6). continuous-fuzzing.md measured `INITED` in
        under 1 s on these targets, so a 60 s quantum loses about 1% to
        start-up.
      '';
    };

    memoryMax = lib.mkOption {
      type = lib.types.str;
      default = "16G";
      description = "Hard memory limit for the whole unit, all workers together. Each target is also capped by the backend wrapper at `-rss_limit_mb=4096`.";
    };

    minFreeGib = lib.mkOption {
      type = lib.types.ints.unsigned;
      default = 20;
      description = "Free space in GiB below which the supervisor stops starting new quanta on `/durable/fuzz`, so a growing corpus cannot fill the disk the rest of the host lives on.";
    };

    metrics.textfileDirectory = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/var/lib/node-exporter-textfile";
      description = ''
        Node exporter's `--collector.textfile.directory`. When set, the
        supervisor writes its Prometheus metrics to
        `${metricsFile}` (the unit has no network, so it
        cannot serve them) and this directory gets a symlink
        `keel_judge.prom` to that file. The directory itself must already
        exist; the host's node exporter configuration creates it.
      '';
    };

    expectations = lib.mkOption {
      type = lib.types.listOf (lib.types.attrsOf lib.types.anything);
      readOnly = true;
      default = healthyExpectations;
      description = ''
        What every healthy running service shows in its metrics file, as a
        list of keel.judge.expect.v1 expectations (`name`, `metric`, `labels`,
        `op`, `value`, `why`; `keel-judge expect` evaluates them). Empty
        unless `metrics.textfileDirectory` is set, because they read the
        metrics file. Read-only: a test of a particular deployment appends
        its own to this list (nix/keel-judge-test.nix does) instead of
        changing it.
      '';
    };

    selftest = lib.mkOption {
      type = lib.types.nullOr (
        lib.types.submodule {
          options = {
            run = lib.mkOption { type = lib.types.str; };
            expected = lib.mkOption { type = lib.types.str; };
          };
        }
      );
      readOnly = true;
      default =
        if withMetrics then
          {
            run = "${keelJudge} expect --spec ${expectSpec} --metrics ${metricsFile} --within ${toString selftestWithin}s --every 5s";
            expected = "every line printed is `ok`: the metrics file was written in the last 180 s, a quantum finished while the check read it, no state log line is damaged and no target is faulted";
          }
        else
          null;
      description = ''
        The service's self-check: a shell command and what its passing means,
        in the shape of MachineConfigurations' `nudox.testing.checks.<id>.probe.command`
        (`run`, `expected`; nix/selftest/check-type.nix there), so its runner can
        run it on the live host and in its scenario VM tests. It is `keel-judge
        expect` over `expectations`, reading for two quanta and a minute so
        it sees a quantum finish. Null unless `metrics.textfileDirectory` is
        set. Setting `nudox.testing.checks.keel-judge.probe.command` from it
        is the host configuration's job, in MachineConfigurations
        (`system/testing.nix`); this module does not reach into that option.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.workers >= 1;
        message = "nudox.services.keel-judge.workers is ${toString cfg.workers}; with no worker nothing fuzzes. Set it to 1 or more.";
      }
      {
        assertion = quantumForm != null;
        message = "nudox.services.keel-judge.quantum is \"${cfg.quantum}\"; the unit's watchdog is computed from it, so write whole seconds, minutes or hours, like \"60s\", \"2m\" or \"1h\".";
      }
    ];

    users.groups.keel-fuzz = { };
    users.users.keel-fuzz = {
      isSystemUser = true;
      group = "keel-fuzz";
      home = stateDir;
      shell = "${pkgs.shadow}/bin/nologin";
      description = "Keel fuzz supervisor (runs fuzz inputs against product code; no token, no network)";
    };

    systemd.tmpfiles.rules = [
      "d /durable 0755 root root - -"
      "d ${durableRoot} 0750 keel-fuzz keel-fuzz - -"
    ]
    ++ lib.optionals withMetrics [
      "d ${metricsDir} 0755 keel-fuzz keel-fuzz - -"
      # Node exporter's textfile collector opens each *.prom with os.Open, which
      # follows symlinks, so a link is enough and the unit needs no write
      # access to the host's directory. That is read from the collector's
      # source, not observed: unverified on the host until the first scrape
      # shows keel_judge_* series.
      "L+ ${cfg.metrics.textfileDirectory}/keel_judge.prom - - - - ${metricsFile}"
    ];

    systemd.services.keel-judge = {
      description = "Keel fuzz supervisor";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig = {
        # ReadWritePaths below fails the whole namespace set-up if the path is
        # missing, which would look like a sandbox bug. Say what is needed.
        RequiresMountsFor = [ durableRoot ];
      };

      serviceConfig = {
        User = "keel-fuzz";
        Group = "keel-fuzz";
        StateDirectory = "keel-judge";
        StateDirectoryMode = "0750";

        # The targets file is rebuilt from the bundle at every start, so a
        # new bundle needs only a restart. `run` reads it, nothing else does.
        ExecStartPre = "${keelJudge} targets --bundle ${cfg.bundle} --durable-root ${durableRoot} -o ${targetsFile}";
        ExecStart = lib.concatStringsSep " " (
          [
            "${keelJudge} run"
            "--targets ${targetsFile}"
            "--state ${stateDir}"
            "--workers ${toString cfg.workers}"
            "--quantum ${cfg.quantum}"
            "--min-free-gib ${toString cfg.minFreeGib}"
          ]
          ++ lib.optional withMetrics "--metrics ${metricsFile}"
        );
        # The supervisor says READY=1 once its state is loaded and its workers
        # start, and WATCHDOG=1 while no worker is stuck in a quantum. Only the
        # main process talks to systemd; the children have no use for the socket.
        # A missed watchdog makes systemd abort and restart the service.
        Type = "notify";
        NotifyAccess = "main";
        WatchdogSec = watchdogSec;
        Restart = "always";
        RestartSec = 30;

        # systemd's default (`stop`) stops the whole unit when the kernel
        # OOM-kills any process in its cgroup, so one fuzz child reaching
        # MemoryMax took every worker down with it. With `continue` the
        # supervisor sees that child die by SIGKILL, records an `oom` quantum
        # and the other workers go on.
        OOMPolicy = "continue";

        # SIGTERM goes to the supervisor first: it stops its children with
        # SIGINT, appends their records (`stopped_by: supervisor`) and exits 0.
        # `mixed` leaves SIGTERM to the supervisor alone and sends SIGKILL to
        # whatever is left in the group once it exits or the timeout passes, so
        # a child that ignores SIGINT cannot outlive the unit.
        # The timeout covers one libFuzzer shutdown per worker, with room.
        KillMode = "mixed";
        KillSignal = "SIGTERM";
        TimeoutStopSec = 90;

        # Fuzzing takes only what is idle. The weight and the nice value are
        # inherited by every child; I/O the same, because a corpus that
        # grows writes a lot of small files.
        CPUWeight = "idle";
        Nice = 19;
        IOSchedulingClass = "idle";
        MemoryMax = cfg.memoryMax;
        TasksMax = 4096;

        # No network at all: a fuzz target that phones out would be an escape
        # from the rule that this user holds nothing worth stealing.
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];

        ProtectSystem = "strict";
        ReadWritePaths = [ durableRoot ] ++ lib.optionals withMetrics [ metricsDir ];
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        LockPersonality = true;
        # MemoryDenyWriteExecute is deliberately not set. Sanitizer runtimes
        # and libFuzzer builds are not known to work under it, and the real
        # bins have not been run under it; the VM test uses the fake target,
        # so a passing test would prove nothing about them. Set it only after
        # a real `fuzz-<id>` has run for a full quantum under the flag.
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictNamespaces = true;
        RestrictSUIDSGID = true;
        RemoveIPC = true;
        SystemCallArchitectures = "native";
        UMask = "0027";
      };
    };

    environment.systemPackages = [ statusScript ];
  };
}
