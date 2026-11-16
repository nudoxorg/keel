# NixOS module `nudox.services.keel`: the Keel result store, the conductor and
# the sandboxed job units on the CI host (DESIGN.md §6.1, §6.2).
#
# Four users, each a trust domain: `keel-store` serves the store, `keel-conduct`
# is the only writer (it holds the writer token and starts jobs), `keel-canon`
# runs canonical jobs and is the only writer of the shared compiler cache, and
# `keel-build` runs PR-controlled code with no network, no token, no store and
# no way to write anything another job or the conductor will trust. Groups
# exist only for one-directional hand-offs (token, env files, outputs, cache),
# never between keel-build and a secret holder. Every rule below has a case in
# nix/keel-host-test.nix that fails without it.
#
# This module opens no firewall port: the fleet model does that. It only adds
# the reject rule that keeps keel-build away from the store port.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.nudox.services.keel;

  # Fixed by DESIGN §6, so constants and not options: a reviewer reads one
  # path per purpose, everywhere.
  storeDir = "/ci/keel/store"; # keel-store:keel-store 0750
  workRoot = "/ci/keel/work"; # keel-build:keel-build 0750, <job> dirs inside
  canonRoot = "/ci/keel/canon"; # keel-canon:keel-canon 0750, <job> dirs inside
  jobsDir = "/ci/keel/jobs"; # keel-conduct:keel-jobs 2750, <job>.env 0640
  outDir = "/ci/keel/out"; # keel-build:keel-out 2750, <job> dirs inside
  cacheDir = "/ci/keel/cache"; # keel-canon:keel-cache 2750, shared compiler cache

  keelStore = "${cfg.package}/bin/keel-store";

  # `--listen` wants brackets around an IPv6 literal.
  listenOn =
    port:
    (if lib.hasInfix ":" cfg.bridgeAddress then "[${cfg.bridgeAddress}]" else cfg.bridgeAddress)
    + ":${toString port}";

  secretFiles = lib.filter (f: f != null) [
    cfg.tokenFile
    cfg.readTokenFile
    cfg.pipelineTokensFile
  ];

  # What the long-running services share. The store process serves bytes it
  # never executes: no capabilities, no W+X memory, a system-service syscall
  # set, no kernel knobs, no other processes visible.
  hardening = {
    DynamicUser = false; # the fixed uid owns /ci/keel/store
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    PrivateDevices = true;
    NoNewPrivileges = true;
    ReadWritePaths = [ storeDir ];
    CapabilityBoundingSet = "";
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectProc = "invisible";
    SystemCallFilter = [ "@system-service" ];
    SystemCallArchitectures = "native";
    UMask = "0027";
  };

  # The store and the conductor talk to the bridge and to themselves, nothing
  # else; a compromise cannot phone out.
  bridgeOnly = {
    IPAddressDeny = "any";
    IPAddressAllow = [
      cfg.bridgeCidr
      "localhost"
    ];
  };

  # Ranges the fetch unit may never reach. Its cargo reads PR data (a
  # `.cargo/config.toml` or a git dependency can aim it at any URL), so
  # everything inside the host and the fleet is denied by destination.
  fetchDeny = [
    "localhost"
    "link-local"
    "multicast"
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "100.64.0.0/10"
    "fc00::/7"
  ]
  ++ cfg.fleetAddresses;

  # One job unit. `phase` is fetch, build, test or audit; `canon` selects the
  # canonical trust domain (own user, own work root, read-write cache).
  #
  # fetch  runs only the pinned cargo's `cargo fetch --locked`: no PR code
  #        executes in it. It is the only unit with network, because
  #        dependencies are not vendored today.
  # build  `cargo build --offline`: PR code (build scripts, proc macros)
  #        executes, in a private network namespace.
  # test   runs the tests, in a private network namespace: it has a fresh
  #        loopback of its own, so the store port on the host's loopback is
  #        unreachable from here by construction, not by a rule that could be
  #        edited away.
  # audit  PR only; test plus ptrace, for `keel audit`.
  #
  # The command comes from the env file the conductor writes to
  # ${jobsDir}/<job>.env, which holds exactly two variables, both chosen by
  # the conductor:
  #   KEEL_PROGRAM  a Nix store path (the program for this phase).
  #   KEEL_ARGS     words: the phase, the job id, a repo name from the
  #                 conductor's fixed allow-list, the revision as 40 hex
  #                 characters, the slot number.
  # Branch names, commit messages, PR titles and anything else from the forge
  # never enter the file. `validate-job` re-checks the instance name and the
  # file before ExecStart. systemd passes `${KEEL_PROGRAM}` as one word and
  # splits `$KEEL_ARGS` on whitespace (no shell); an empty program is an empty
  # word, so a missing entry fails with 127 instead of `env` printing its
  # environment and succeeding.
  #
  # Instance name: `%i` is the escaped instance string exactly as it appears
  # in the unit name; `%I` would unescape it, turning `-` into `/`, and a
  # name could then spell a path. Only `%i` is used, here and in the Rust
  # check.
  # Creates one job's work and output directories on the host, as root, after
  # the name is known to be safe. Nothing can start it directly: polkit lets
  # the conductor start job units only, and this comes in as their dependency.
  prepare =
    canon:
    let
      user = if canon then "keel-canon" else "keel-build";
      root = if canon then canonRoot else workRoot;
      install = "${pkgs.coreutils}/bin/install";
    in
    {
      description = "Keel ${if canon then "canonical " else ""}job directories for %i";
      unitConfig.RequiresMountsFor = [
        root
        outDir
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = [
          "${keelStore} validate-job %i"
          "${install} -d -o ${user} -g ${user} -m 0750 ${root}/%i"
          "${install} -d -o ${user} -g keel-out -m 2750 ${outDir}/%i"
        ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        NoNewPrivileges = true;
        ReadWritePaths = [
          root
          outDir
        ];
        # chown to the job user, and write into roots root does not own.
        CapabilityBoundingSet = "CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID";
        RestrictAddressFamilies = [ "AF_UNIX" ];
      };
    };

  job =
    {
      phase,
      canon ? false,
    }:
    let
      user = if canon then "keel-canon" else "keel-build";
      root = if canon then canonRoot else workRoot;
      work = "${root}/%i";
      out = "${outDir}/%i";
      env = "${jobsDir}/%i.env";
      fetch = phase == "fetch";
      audit = phase == "audit";
      prepareUnit = if canon then "keel-canon-prepare" else "keel-prepare";
    in
    {
      description = "Keel ${if canon then "canonical " else ""}${phase} job %i";
      unitConfig = {
        RequiresMountsFor = [
          root
          jobsDir
          outDir
          cacheDir
        ];
        # The job's directories are made by a separate root unit. An
        # ExecStartPre with `+` still runs inside this unit's mount namespace,
        # where the work root is a private tmpfs: the directory it made was
        # never on the host (found by the VM test, run 974473).
        Requires = [ "${prepareUnit}@%i.service" ];
        After = [ "${prepareUnit}@%i.service" ];
      };
      serviceConfig = {
        Type = "oneshot";
        User = user;
        Group = user;
        # All job units are in one slice that carries the budget for the
        # whole of Keel; the per-instance caps below are sanity only.
        Slice = "keel.slice";
        WorkingDirectory = work;
        Environment = [
          "HOME=${work}"
          # Builds do not talk to the Nix daemon: /nix/var is inaccessible
          # below, the conductor realises the toolchain closure beforehand and
          # passes store paths.
          "NIX_REMOTE="
        ]
        ++ lib.optional fetch "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt";
        EnvironmentFile = env;
        ExecStartPre = [
          "${keelStore} validate-job %i"
          "${keelStore} validate-job %i --env-file ${env}"
        ];
        ExecStart = "${pkgs.coreutils}/bin/env -- \${KEEL_PROGRAM} $KEEL_ARGS";

        # Oneshot units ignore RuntimeMaxSec; TimeoutStartSec is what ends a
        # hung job. If the conductor dies, the job still ends by itself, and
        # its outcome is whatever `systemctl show` reports (Result,
        # ExecMainStatus), never a file the job could have written.
        TimeoutStartSec = cfg.jobTimeout;
        TimeoutStopSec = "30s";
        KillMode = "control-group";
        SendSIGKILL = true;
        # Sanity caps per instance; the slice is the budget.
        MemoryMax = "40G";
        TasksMax = 4096;

        # Filesystem: an allow-list, not a deny-list. Everything that is not
        # mounted back below is an empty tmpfs.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        TemporaryFileSystem = [
          "/var"
          "/run"
          "/srv"
          "/mnt"
          "/ci"
          "/home"
          "/root"
          "/etc"
        ];
        BindPaths = [
          work
          out
        ]
        ++ lib.optional canon cacheDir;
        BindReadOnlyPaths = [
          env
          "/nix/store"
          "/etc/passwd"
          "/etc/group"
        ]
        ++ lib.optionals fetch [
          "/etc/resolv.conf"
          "/etc/ssl/certs"
        ]
        # PR jobs read the shared compiler cache and never write it; their own
        # incremental state lives in their work directory (DESIGN §6.1).
        ++ lib.optional (!canon) cacheDir;
        ReadWritePaths = [
          work
          out
        ]
        ++ lib.optional canon cacheDir;
        # The Nix daemon socket lives under /nix/var. An untrusted user can
        # ask the daemon to build a fixed-output derivation, which runs as
        # nixbld* in the host's network namespace: an escape from every
        # network rule here. NIX_REMOTE= alone stops nothing.
        InaccessiblePaths = [ "/nix/var" ];

        # Process and kernel surface.
        ProtectProc = "invisible";
        ProcSubset = "pid";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        RemoveIPC = true;
        KeyringMode = "private";
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        SystemCallArchitectures = "native";
        # ptrace is in @debug: only the audit unit may use it.
        SystemCallFilter =
          if audit then
            [
              "@system-service"
              "ptrace"
            ]
          else
            [
              "@system-service"
              "~@debug"
            ];
        UMask = "0027";

        # Network. Build and test have none at all (PrivateNetwork) and no
        # socket families; nextest talks to its children over pipes. A test
        # that needs AF_UNIX declares `sockets = ["unix"]` and the conductor
        # turns that into a per-job drop-in (not implemented here). Fetch
        # reaches the internet through IP sockets only.
        RestrictAddressFamilies =
          if fetch then
            [
              "AF_INET"
              "AF_INET6"
            ]
          else
            "none";
      }
      // lib.optionalAttrs fetch { IPAddressDeny = lib.concatStringsSep " " fetchDeny; }
      // lib.optionalAttrs (!fetch) {
        PrivateNetwork = true;
        # Not evaluated on a real system yet (no Linux builder here): if the
        # VM test shows PrivateUsers conflicting with the bind mounts, remove
        # this line and say why here.
        PrivateUsers = true;
      };
    };
in
{
  options.nudox.services.keel = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether to run the Keel result store and conductor and provide the
        sandboxed job unit templates `keel-{fetch,build,test,audit}@<job>` and
        `keel-canon-{fetch,build,test}@<job>`.

        A job is started only by the conductor (`POST /v1/jobs`). For each
        phase it writes `/ci/keel/jobs/<job>.env` and starts the unit. The
        file holds exactly two variables, both written by the conductor and
        never derived from forge data (branch names, commit messages, PR
        titles):

        `KEEL_PROGRAM`: a Nix store path chosen by the conductor (the phase's
        entry in `programs`); it is the one word executed.

        `KEEL_ARGS`: words chosen by the conductor, separated by single
        spaces: the phase, the job id, a repo name from `repos`, the revision
        as 40 hex characters, the slot number.

        The unit checks the job name and the file with
        `keel-store validate-job` before running anything. See
        `crates/keel-store/README.md`.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      description = "The package providing `bin/keel-store` (crates/keel-store). Pinned by the host configuration, not taken from a PR. The services and the job units call it.";
    };

    port = lib.mkOption {
      type = lib.types.nullOr lib.types.port;
      default = null;
      description = ''
        TCP port the store listens on. No default on purpose: the port is
        allocated in the fleet model and passed in from it, never baked into
        this module (DESIGN §6). Evaluation fails while it is unset. The module
        does not open this port; the fleet model's firewall exposure does.
      '';
    };

    conductPort = lib.mkOption {
      type = lib.types.nullOr lib.types.port;
      default = null;
      description = "TCP port the conductor listens on, on `bridgeAddress`. No default; allocated in the fleet model like `port`, and opened by it.";
    };

    bridgeAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = "Address the store and conductor bind. Defaults to loopback; set it to a reachable bridge gateway for remote tasks.";
    };

    bridgeCidr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.0/8";
      description = "Network allowed to reach the store and conductor; set it with `bridgeAddress` when using a remote task bridge.";
    };

    fleetAddresses = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      example = [ ];
      description = ''
        The fleet hosts' own public addresses, denied to the fetch units (a
        fetch must not be able to reach the forge, the mail server or the
        host's own public services even though they are not in a private
        range). No default: fill it from the fleet model, or set `[ ]`
        deliberately.
      '';
    };

    tokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/keel-store-token";
      description = ''
        File holding the writer token (at least 16 characters). It is read by
        `keel-store` (to verify) and by `keel-conduct` (to write) through the
        group `keel-token`: set group `keel-token`, mode 0440 in the host's
        secrets mechanism (for example sops-nix). The services are given only
        this path, in `KEEL_STORE_TOKEN_FILE` / `--token-file`, never the
        token. It must not be a Nix store path, which is world-readable.
      '';
    };

    readTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/keel-store-read-token";
      description = ''
        File holding the read token (`KEEL_STORE_READ_TOKEN_FILE`): every GET
        on the store except `/v1/health` needs it (the writer token also
        works). Group `keel-token`, mode 0440. Pipelines get this token, not
        the writer token. Must differ from the writer token.
      '';
    };

    pipelineTokensFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/keel-pipeline-tokens";
      description = ''
        JSON file mapping the blake3 hash of each pipeline's bearer token to
        `{"repo": "<owner/name>", "kinds": ["pr"]}` (PR pipelines list only
        `pr`). Read by `keel-conduct` only: owner `keel-conduct`, mode 0400.
      '';
    };

    repos = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      example = [ "Nudox/Backend" ];
      description = "The allow-list of repos the conductor starts jobs for. Names may contain letters, digits and `._/-` only. No default.";
    };

    programs = lib.mkOption {
      type = lib.types.submodule {
        options = lib.genAttrs [ "fetch" "build" "test" ] (
          phase:
          lib.mkOption {
            type = lib.types.str;
            description = "Nix store path of the program run for the ${phase} phase, as `KEEL_PROGRAM`. It is called with `<phase> <job> <repo> <revision> <slot>` and is responsible for running the pinned toolchain with fixed flags (`cargo fetch --locked`, `cargo build --offline`, the test runner).";
          }
        );
      };
      description = "The programs the conductor puts in each phase's env file. Chosen by the host configuration, never by a request.";
    };

    slots = lib.mkOption {
      type = lib.types.ints.positive;
      default = 3;
      description = "PR slots per lane. The conductor's slot choice is a placeholder (PR number modulo this); real assignment is future work.";
    };

    keepPass = lib.mkOption {
      type = lib.types.str;
      default = "30d";
      description = "How long `pass` records are kept, by `recorded_at` (`keel-store gc --keep-pass`).";
    };

    keepFail = lib.mkOption {
      type = lib.types.str;
      default = "90d";
      description = "How long failures, flakes and every other non-pass record are kept (`--keep-fail`).";
    };

    reserveGiB = lib.mkOption {
      type = lib.types.ints.positive;
      default = 80;
      description = "Free space in GiB that must remain on the store disk after pruning. The gc unit fails, and shows up in `systemctl --failed`, when pruning cannot reach it.";
    };

    gcSchedule = lib.mkOption {
      type = lib.types.str;
      default = "daily";
      description = "systemd `OnCalendar` expression for the gc timer.";
    };

    jobTimeout = lib.mkOption {
      type = lib.types.str;
      default = "2h";
      description = "Hard wall-clock limit for one job unit instance (`TimeoutStartSec`; `RuntimeMaxSec` is ignored for oneshot units). It is what ends a job whose conductor died; its `Result` is then `timeout` in `systemctl show`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      let
        required = name: value: {
          assertion = value != null;
          message = "nudox.services.keel.${name} must be set; there is deliberately no default.";
        };
        notInStore = name: file: {
          assertion = file == null || !(lib.hasPrefix builtins.storeDir (toString file));
          message = "nudox.services.keel.${name} is in the Nix store, which every user can read; point it at a runtime secret such as /run/secrets/…";
        };
        trusted = config.nix.settings.trusted-users or [ ];
        allowed = config.nix.settings.allowed-users or [ ];
        users = [
          "keel-build"
          "keel-canon"
        ];
        named = list: lib.any (n: builtins.elem n list || builtins.elem "@${n}" list) users;
      in
      [
        (required "port" cfg.port)
        (required "conductPort" cfg.conductPort)
        (required "tokenFile" cfg.tokenFile)
        (required "readTokenFile" cfg.readTokenFile)
        (required "pipelineTokensFile" cfg.pipelineTokensFile)
        (notInStore "tokenFile" cfg.tokenFile)
        (notInStore "readTokenFile" cfg.readTokenFile)
        (notInStore "pipelineTokensFile" cfg.pipelineTokensFile)
        {
          assertion = cfg.repos != [ ];
          message = "nudox.services.keel.repos is empty; the conductor starts jobs only for repos on this allow-list.";
        }
        {
          assertion = config.networking.firewall.enable;
          message = "nudox.services.keel needs networking.firewall.enable: the rule that keeps keel-build away from the store port lives in the firewall.";
        }
        {
          assertion = !config.networking.nftables.enable;
          message = "nudox.services.keel writes its owner-match rule with iptables (the style of this repo's other firewall rules); it does not apply under networking.nftables.enable.";
        }
        {
          # A trusted user can ask the Nix daemon to build or import arbitrary
          # things, and an allowed user to build at all; PR and canonical job
          # users must have neither, even with /nix/var inaccessible to them.
          assertion = !(named trusted) && !(named allowed);
          message = "keel-build and keel-canon must not be in nix.settings.trusted-users or nix.settings.allowed-users: job code could use the Nix daemon through them.";
        }
        {
          assertion = config.security.polkit.enable;
          message = "nudox.services.keel needs security.polkit.enable: keel-conduct starts the job units through a polkit rule.";
        }
      ];

    # `allowed-users = [ "*" ]` is the NixOS default and lets every user,
    # including the job users, talk to the daemon. The inaccessible /nix/var in
    # the job units is what keeps them out; narrowing the list is stronger.
    warnings = lib.optional (builtins.elem "*" (config.nix.settings.allowed-users or [ ])) ''
      nudox.services.keel: nix.settings.allowed-users contains "*", so keel-build and keel-canon are allowed to use the Nix daemon. The job units make /nix/var inaccessible, which blocks the socket; restricting allowed-users is defence in depth.
    '';

    users.groups = {
      keel-store = { };
      keel-conduct = { };
      keel-canon = { };
      keel-build = { };
      # One-directional hand-offs, each with one writer.
      keel-token = { }; # the tokens: keel-store, keel-conduct (read)
      keel-jobs = { }; # jobs dir: the job users read what keel-conduct writes
      keel-out = { }; # out dir: keel-conduct reads what the job users leave
      keel-cache = { }; # cache: keel-build reads what keel-canon writes
    };
    users.users = {
      keel-store = {
        isSystemUser = true;
        group = "keel-store";
        extraGroups = [ "keel-token" ];
        home = storeDir;
        description = "Keel result-store service (verifies the writer token)";
      };
      keel-conduct = {
        isSystemUser = true;
        group = "keel-conduct";
        extraGroups = [
          "keel-token"
          "keel-out"
          # The job log endpoint follows the journal of the job units, which
          # needs read access to the system journal (all of it, not only the
          # job units).
          "systemd-journal"
        ];
        description = "Keel conductor (the only writer, holds the writer token, starts jobs)";
      };
      keel-canon = {
        isSystemUser = true;
        group = "keel-canon";
        extraGroups = [ "keel-jobs" ];
        home = canonRoot;
        description = "Keel canonical jobs (merged code, writes the compiler cache)";
      };
      keel-build = {
        isSystemUser = true;
        group = "keel-build";
        extraGroups = [
          "keel-jobs"
          "keel-cache"
        ];
        home = workRoot;
        description = "Keel PR jobs (PR-controlled code, no network, no store or token access)";
      };
    };

    systemd.tmpfiles.rules = [
      "d /ci/keel 0755 root root - -"
      "d ${storeDir} 0750 keel-store keel-store - -"
      "d ${workRoot} 0750 keel-build keel-build - -"
      "d ${canonRoot} 0750 keel-canon keel-canon - -"
      # setgid, so files the conductor drops in jobs/, files the job users
      # leave in out/ and files keel-canon writes in cache/ carry the shared
      # group without anyone chgrp-ing them.
      "d ${jobsDir} 2750 keel-conduct keel-jobs - -"
      "d ${outDir} 2750 keel-build keel-out - -"
      "d ${cacheDir} 2750 keel-canon keel-cache - -"
    ];

    security.polkit.enable = lib.mkDefault true;
    # keel-conduct may start, stop and restart the job templates' instances and
    # nothing else: the unit name is matched in full, so keel-store.service,
    # sshd and every other unit stay out of reach.
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.freedesktop.systemd1.manage-units" &&
            subject.user == "keel-conduct" &&
            /^keel-(canon-)?(fetch|build|test|audit)@[A-Za-z0-9._-]+\.service$/.test(action.lookup("unit")) &&
            ["start", "stop", "restart"].indexOf(action.lookup("verb")) >= 0) {
          return polkit.Result.YES;
        }
      });
    '';

    # One slice carries the budget for the whole of Keel, so two concurrent
    # jobs share it instead of each getting it.
    systemd.slices.keel = {
      description = "Keel jobs";
      sliceConfig = {
        # 14 of the host's 20 threads; Forgejo, Stalwart, Concourse and the
        # observability stack keep the other 6.
        CPUQuota = "1400%";
        # Throttle before the OOM killer: 36G of 64G is where reclaim starts,
        # 40G is the wall. The deep lane measured 25 GB container limits as
        # sufficient.
        MemoryHigh = "36G";
        MemoryMax = "40G";
        # Half the default weight (100), so the forge stays responsive while a
        # compile writes gigabytes.
        IOWeight = 50;
        # cargo, rustc and nextest's one process per test, for all jobs.
        TasksMax = 8192;
      };
    };

    systemd.services = {
      keel-store = {
        description = "Keel result store";
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [ "network-online.target" ];
        unitConfig = {
          RequiresMountsFor = [ storeDir ];
          # The bridge address may appear after boot; keep retrying the bind.
          StartLimitIntervalSec = 0;
        };
        environment = lib.mkIf (cfg.tokenFile != null && cfg.readTokenFile != null) {
          KEEL_STORE_TOKEN_FILE = toString cfg.tokenFile;
          KEEL_STORE_READ_TOKEN_FILE = toString cfg.readTokenFile;
        };
        serviceConfig =
          hardening
          // bridgeOnly
          // {
            User = "keel-store";
            Group = "keel-store";
            ExecStart = "${keelStore} serve --dir ${storeDir} --listen ${listenOn cfg.port}";
            Restart = "on-failure";
            RestartSec = 5;
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_INET6"
              "AF_UNIX"
            ];
          };
      };

      # The conductor: writes env files and starts job units through polkit.
      # It never clones or runs cargo.
      keel-conduct = {
        description = "Keel conductor";
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [
          "network-online.target"
          "keel-store.service"
        ];
        unitConfig = {
          RequiresMountsFor = [
            jobsDir
            outDir
          ];
          StartLimitIntervalSec = 0;
        };
        # systemctl and journalctl.
        path = [ config.systemd.package ];
        serviceConfig =
          hardening
          // bridgeOnly
          // {
            User = "keel-conduct";
            Group = "keel-conduct";
            ReadWritePaths = [ jobsDir ];
            ExecStart = lib.concatStringsSep " " (
              [
                "${keelStore} conduct"
                "--listen ${listenOn cfg.conductPort}"
                "--jobs-dir ${jobsDir}"
                "--out-dir ${outDir}"
                "--token-file ${toString cfg.tokenFile}"
                "--pipeline-tokens-file ${toString cfg.pipelineTokensFile}"
                "--slots ${toString cfg.slots}"
              ]
              ++ map (r: "--repo ${lib.escapeShellArg r}") cfg.repos
              ++ lib.mapAttrsToList (phase: p: "--program ${phase}=${p}") (
                lib.filterAttrs (n: _: n != "_module") cfg.programs
              )
            );
            Restart = "on-failure";
            RestartSec = 5;
            # Local sockets for the system bus; IP for the bridge.
            RestrictAddressFamilies = [
              "AF_INET"
              "AF_INET6"
              "AF_UNIX"
            ];
          };
      };

      keel-gc = {
        description = "Keel result-store retention";
        serviceConfig = hardening // {
          Type = "oneshot";
          User = "keel-store";
          Group = "keel-store";
          ExecStart = "${keelStore} gc --dir ${storeDir} --keep-pass ${cfg.keepPass} --keep-fail ${cfg.keepFail} --reserve-gib ${toString cfg.reserveGiB}";
          # gc never talks to anyone.
          PrivateNetwork = true;
          RestrictAddressFamilies = [ "AF_UNIX" ];
        };
      };

      "keel-prepare@" = prepare false;
      "keel-canon-prepare@" = prepare true;
      "keel-fetch@" = job { phase = "fetch"; };
      "keel-build@" = job { phase = "build"; };
      "keel-test@" = job { phase = "test"; };
      "keel-audit@" = job { phase = "audit"; };
      "keel-canon-fetch@" = job {
        phase = "fetch";
        canon = true;
      };
      "keel-canon-build@" = job {
        phase = "build";
        canon = true;
      };
      "keel-canon-test@" = job {
        phase = "test";
        canon = true;
      };
    };

    systemd.timers.keel-gc = {
      description = "Daily Keel result-store retention";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.gcSchedule;
        Persistent = true;
        RandomizedDelaySec = "30m";
      };
    };

    # Only the reject for keel-build; opening the ports is the fleet model's
    # job. Connections *from* keel-build to the store port are refused,
    # loopback and bridge address alike: both leave through OUTPUT, where the
    # owner match works. A private chain keeps the rule idempotent across
    # firewall reloads (nixos-fw is flushed on every start, OUTPUT is not).
    networking.firewall = lib.mkIf (cfg.port != null) {
      # A direct OUTPUT rule, not a user chain: iptables-nft rejects an owner
      # match inside a chain that is not yet attached to a hook (EINVAL on
      # ilo, VM run 973436), which took the whole firewall down. The comment
      # tags the rule so the VM test can read its packet counter.
      extraCommands = ''
        ip46tables -D OUTPUT -p tcp --dport ${toString cfg.port} -m owner --uid-owner keel-build -m comment --comment keel-store-guard -j REJECT --reject-with tcp-reset 2>/dev/null || true
        ip46tables -I OUTPUT -p tcp --dport ${toString cfg.port} -m owner --uid-owner keel-build -m comment --comment keel-store-guard -j REJECT --reject-with tcp-reset
      '';
      extraStopCommands = ''
        ip46tables -D OUTPUT -p tcp --dport ${toString cfg.port} -m owner --uid-owner keel-build -m comment --comment keel-store-guard -j REJECT --reject-with tcp-reset 2>/dev/null || true
      '';
    };
  };
}
