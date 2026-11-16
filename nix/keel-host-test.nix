# NixOS VM test for nix/keel-host.nix: every rule of DESIGN §6.2 has a case
# here that fails when the rule is removed (named in the comment above it).
# Build with
#   nix-build nix/keel-host-test.nix            (needs a Linux builder with KVM)
# The testScript is Python because that is the only driver NixOS has; it is
# test data here, not repository code.
#
# Unexecuted so far: the author's machine has no Linux builder, so this file is
# only known to evaluate (`nix-instantiate`) to a derivation. Expect to fix
# small things the first time it runs (quoting, timing, nsenter details).
{
  pkgs ? import <nixpkgs> { system = "x86_64-linux"; },
}:
let
  inherit (pkgs) lib;

  # The binary the VM runs, built from this workspace. Only keel-store is
  # needed; the other crates are in the source tree because the workspace
  # manifest names them.
  keelStore = pkgs.rustPlatform.buildRustPackage {
    pname = "keel-store";
    version = "0.1.0";
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
        ../bench
      ];
    };
    cargoLock.lockFile = ../Cargo.lock;
    cargoBuildFlags = [
      "--package"
      "keel-store"
    ];
    doCheck = false; # the workspace tests run under cargo; the VM needs the binary
  };

  port = 4817;
  conductPort = 4818;
  # The host gets 192.168.1.1 on eth1 from the test driver. It stands in for
  # the CI bridge address: a local address, reached through the loopback
  # path exactly as on the CI host. 203.0.113.0/24 (eth2) is "the internet":
  # outside every range the fetch unit denies, except the host's own address,
  # which the test lists in fleetAddresses as the fleet model would.
  bridge = "192.168.1.1";
  hostPublic = "203.0.113.1";
  outsideAddr = "203.0.113.10";
  secrets = "/run/secrets/keel";
  writerToken = "writer-token-0123456789abcdef";
  readToken = "read-token-0123456789abcdef";
  revision = "7ab31d07ab31d07ab31d07ab31d07ab31d07ab31";

  # A job env file: exactly the two variables the conductor writes.
  env =
    name: program: args:
    pkgs.writeText "${name}.env" ''
      KEEL_PROGRAM=${program}
      KEEL_ARGS=${args}
    '';
  coreutils = "${pkgs.coreutils}/bin";
  # The timeout lives in the probe, not in KEEL_ARGS: the validator refuses
  # argument words that start with a dash, which is the behaviour under test.
  nc = pkgs.writeShellScript "keel-probe" ''
    exec ${pkgs.busybox}/bin/nc -w 2 "$@"
  '';

  envs = {
    smoke = env "smoke" "${coreutils}/true" "run smoke Nudox/Backend ${revision} 0";
    broken = env "broken" "${coreutils}/false" "run broken";
    # A key the validator must refuse.
    bad = pkgs.writeText "bad.env" ''
      KEEL_PROGRAM=${coreutils}/true
      KEEL_ARGS=run bad
      LD_PRELOAD=/nix/store/evil.so
    '';
    sleeper = env "sleeper" "${coreutils}/sleep" "600";
    sleeper2 = env "sleeper2" "${coreutils}/sleep" "600";
    nix = env "nix" "${pkgs.nix}/bin/nix-build" "fod.nix";
    toOutside = env "to-outside" nc "${outsideAddr} 8080";
    toHost = env "to-host" nc "${hostPublic} 8080";
    toStore = env "to-store" nc "${bridge} ${toString port}";
  };

  # A fixed-output derivation: building it needs the Nix daemon, which a job
  # must not be able to reach.
  fod = pkgs.writeText "fod.nix" ''
    derivation {
      name = "fod";
      system = "x86_64-linux";
      builder = "${pkgs.busybox}/bin/sh";
      args = [ "-c" "echo -n > $out" ];
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      outputHash = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    }
  '';

  record = pkgs.writeText "record.json" (
    builtins.toJSON {
      key = "blake3:${lib.strings.replicate 64 "a"}";
      id = "rust:a::b";
      status = "pass";
      run_id = "smoke-run";
      recorded_at = "2026-11-14T08:12:03Z";
      platform = {
        triple = "x86_64-unknown-linux-gnu";
        toolchain = "rustc 1.97.1";
        net = "isolated";
      };
    }
  );

  # A listener that accepts and hangs up at once (systemd socket activation
  # with Accept=yes), so `nc <addr> <port>` exits 0 when it can connect.
  probe =
    { pkgs, ... }:
    {
      systemd.sockets.probe = {
        wantedBy = [ "sockets.target" ];
        listenStreams = [ "8080" ];
        socketConfig.Accept = true;
      };
      systemd.services."probe@".serviceConfig = {
        ExecStart = "${pkgs.coreutils}/bin/true";
        StandardInput = "socket";
      };
    };

  programs = lib.genAttrs [ "fetch" "build" "test" ] (_: "${coreutils}/echo");
in
pkgs.testers.runNixOSTest {
  name = "keel-host";

  nodes.host =
    { pkgs, lib, ... }:
    {
      imports = [
        ./keel-host.nix
        probe
      ];
      virtualisation.vlans = [
        1
        2
      ];
      networking.interfaces.eth2.ipv4.addresses = lib.mkForce [
        {
          address = hostPublic;
          prefixLength = 24;
        }
      ];

      nudox.services.keel = {
        enable = true;
        package = keelStore;
        inherit port conductPort programs;
        bridgeAddress = bridge;
        bridgeCidr = "192.168.1.0/24";
        tokenFile = "${secrets}/writer";
        readTokenFile = "${secrets}/read";
        pipelineTokensFile = "${secrets}/pipelines";
        repos = [
          "Nudox/Backend"
          "Nudox/Other"
        ];
        fleetAddresses = [ hostPublic ];
        # B4: short, so a sleeper past it is killed within the test.
        jobTimeout = "5s";
      };

      # The module's reject rule is iptables.
      networking.nftables.enable = false;
      environment.systemPackages = [
        pkgs.curl
        pkgs.b3sum
        pkgs.util-linux
      ];

      # Stand-in for the host's secrets mechanism (R7: the module does not
      # touch these files). Tokens in group keel-token, 0440, as documented.
      systemd.tmpfiles.rules = [
        "d /run/secrets 0755 root root - -"
        "d ${secrets} 0755 root root - -"
        "f ${secrets}/writer 0440 root keel-token - ${writerToken}"
        "f ${secrets}/read 0440 root keel-token - ${readToken}"
        # keel-conduct refuses to start without its grants file; the R5 subtest
        # rewrites it with real tokens and restarts the unit.
        "f ${secrets}/pipelines 0400 keel-conduct keel-conduct - {}"
      ];
    };

  nodes.outside =
    { lib, ... }:
    {
      imports = [ probe ];
      virtualisation.vlans = [
        1
        2
      ];
      networking.interfaces.eth2.ipv4.addresses = lib.mkForce [
        {
          address = outsideAddr;
          prefixLength = 24;
        }
      ];
      networking.firewall.enable = false;
    };

  testScript = ''
    import json

    start_all()
    host.wait_for_unit("firewall.service")
    host.wait_for_unit("keel-store.service")
    host.wait_for_unit("keel-conduct.service")
    host.wait_for_open_port(${toString port}, "${bridge}")
    outside.wait_for_open_port(8080, "${outsideAddr}")
    host.wait_for_open_port(8080, "${hostPublic}")
    url = "http://${bridge}:${toString port}"
    cond = "http://${bridge}:${toString conductPort}"

    # Every round trip through the CI host is minutes, so one run must answer
    # everything: a failed subtest is recorded and the run fails once, at the end.
    import contextlib
    import traceback
    failures: list[tuple[str, str]] = []

    @contextlib.contextmanager
    def check(name):
        try:
            with subtest(name):
                yield
        except Exception:
            failures.append((name, traceback.format_exc()))
            print(f"SUBTEST FAILED: {name}\n{traceback.format_exc()}")

    def put_env(name, store_path):
        host.succeed(f"runuser -u keel-conduct -- install -m 0640 {store_path} /ci/keel/jobs/{name}.env")

    def start(unit, name):
        return host.execute(f"runuser -u keel-conduct -- systemctl start {unit}@{name}.service")[0]

    def prop(unit, name, p):
        return host.succeed(f"systemctl show -p {p} --value {unit}@{name}.service").strip()

    def curl_code(args):
        return host.succeed(f"curl -s -o /dev/null -w '%{{http_code}}' {args}").strip()

    # Long-running jobs get a drop-in that lifts the 5 s test timeout.
    def long_lived(unit, name):
        host.succeed(
            f"mkdir -p /run/systemd/system/{unit}@{name}.service.d && "
            f"printf '[Service]\\nTimeoutStartSec=600\\n' > /run/systemd/system/{unit}@{name}.service.d/t.conf && "
            "systemctl daemon-reload"
        )

    # --- The store itself ---------------------------------------------------

    with check("health is open, every other read needs the read token (R6)"):
        host.succeed(f"curl -sf {url}/v1/health | grep -q '\"schema\":1'")
        assert curl_code(f"{url}/v1/pass/blake3:${lib.strings.replicate 64 "a"}") == "401"
        assert curl_code(f"-H 'Authorization: Bearer ${readToken}' {url}/v1/pass/blake3:${lib.strings.replicate 64 "a"}") == "404"
        assert curl_code(f"-X PUT -H 'Authorization: Bearer ${readToken}' --data x {url}/v1/blob") == "401"

    with check("the store can only talk to the bridge and itself (R6: IPAddressDeny=any)"):
        host.succeed("systemctl show -p IPAddressDeny keel-store.service | grep -q '0.0.0.0/0'")

    with check("keel-build cannot read the tokens or touch the store"):
        host.fail("runuser -u keel-build -- cat ${secrets}/writer")
        host.fail("runuser -u keel-build -- ls /ci/keel/store")
        host.fail("runuser -u keel-build -- touch /ci/keel/store/pwned")

    with check("keel-build cannot connect to the store port on the bridge address"):
        host.fail(f"runuser -u keel-build -- curl -sS --max-time 5 {url}/v1/health")

    with check("... nor on loopback (a second store listens there so the rule, not a closed port, is what refuses)"):
        host.succeed(
            "systemd-run --unit=keel-lo-probe -p User=keel-store -p SupplementaryGroups=keel-token "
            "-p StateDirectory=keel-lo -p Environment=KEEL_STORE_TOKEN_FILE=${secrets}/writer "
            "-p Environment=KEEL_STORE_READ_TOKEN_FILE=${secrets}/read "
            "${keelStore}/bin/keel-store serve --dir /var/lib/keel-lo --listen 127.0.0.1:${toString port}"
        )
        host.wait_for_open_port(${toString port}, "127.0.0.1")
        host.succeed("runuser -u keel-conduct -- curl -sf http://127.0.0.1:${toString port}/v1/health")
        host.fail("runuser -u keel-build -- curl -sS --max-time 5 http://127.0.0.1:${toString port}/v1/health")
        rules = host.succeed("iptables -nvxL OUTPUT | grep keel-store-guard")
        assert int(rules.split()[0]) > 0, "the owner-match rule never matched:\n" + rules
        host.succeed("systemctl stop keel-lo-probe")

    with check("keel-conduct can write a record with the token; nobody else can"):
        host.succeed(
            """runuser -u keel-conduct -- sh -c 'curl -sf -X PUT -H "Authorization: Bearer $(cat ${secrets}/writer)" --data-binary @${record} """
            + url + """/v1/record'"""
        )
        host.succeed(f"curl -sf -H 'Authorization: Bearer ${readToken}' {url}/v1/pass/blake3:${lib.strings.replicate 64 "a"} | grep -q '\"run_id\":\"smoke-run\"'")
        assert curl_code(f"-X PUT --data-binary @${record} {url}/v1/record") == "401"

    # --- Job units: identity, outcome, timeout ------------------------------

    with check("a validated job runs and its outcome is systemd's (R3), with no marker file"):
        put_env("smoke", "${envs.smoke}")
        assert start("keel-build", "smoke") == 0
        assert prop("keel-build", "smoke", "Result") == "success"
        host.succeed("test ! -e /ci/keel/out/smoke/stopped")
        put_env("broken", "${envs.broken}")
        assert start("keel-build", "broken") != 0
        assert prop("keel-build", "broken", "Result") == "exit-code"
        assert prop("keel-build", "broken", "ExecMainStatus") == "1"

    with check("the unit itself refuses a bad env file and a bad name"):
        host.succeed("runuser -u keel-conduct -- install -m 0640 ${envs.bad} /ci/keel/jobs/bad.env")
        assert start("keel-build", "bad") != 0
        put_env("Upper", "${envs.smoke}")
        assert start("keel-build", "Upper") != 0
        host.succeed("journalctl -u keel-prepare@Upper.service -u keel-build@Upper.service | grep -q 'job name'")

    with check("polkit lets keel-conduct manage job units and nothing else"):
        host.fail("runuser -u keel-conduct -- systemctl stop keel-store.service")
        host.fail("runuser -u keel-build -- systemctl start keel-build@smoke.service")

    # B4: RuntimeMaxSec is ignored for Type=oneshot; TimeoutStartSec is not.
    with check("a job that outlives the limit is killed with Result=timeout (B4)"):
        put_env("slow", "${envs.sleeper}")
        assert start("keel-build", "slow") != 0
        assert prop("keel-build", "slow", "Result") == "timeout"

    # --- The sandbox, seen from inside a running job (R1, B3) --------------

    with check("inside a job: no /dev/kvm, no /var/lib, own processes only, no machine-id (R1)"):
        put_env("sleeper", "${envs.sleeper}")
        long_lived("keel-build", "sleeper")
        host.succeed("runuser -u keel-conduct -- systemctl start --no-block keel-build@sleeper.service")
        host.wait_until_succeeds("test \"$(systemctl show -p MainPID --value keel-build@sleeper.service)\" != 0")
        pid = host.succeed("systemctl show -p MainPID --value keel-build@sleeper.service").strip()
        uid = host.succeed("id -u keel-build").strip()
        gid = host.succeed("id -g keel-build").strip()
        ns = f"nsenter --target {pid} --mount --setuid {uid} --setgid {gid} --"
        # The job really is in its own directory, and that directory is on the host.
        cwd = host.succeed(f"readlink /proc/{pid}/cwd").strip()
        assert cwd == "/ci/keel/work/sleeper", cwd
        assert host.succeed("stat -c %U:%G /ci/keel/work/sleeper").strip() == "keel-build:keel-build"
        ls = "${coreutils}/ls"
        host.fail(f"{ns} {ls} /dev/kvm")
        # The module promises /var is a fresh tmpfs: host state is absent, not
        # merely empty, so a job cannot even learn which services keep state.
        host.fail(f"{ns} {ls} -d /var/lib")
        host.fail(f"{ns} ${coreutils}/cat /etc/machine-id")
        procs = host.succeed(f"{ns} {ls} /proc").split()
        assert "1" not in procs, procs
        assert "cpuinfo" not in procs, procs
        # PR jobs see the compiler cache read-only.
        host.fail(f"{ns} ${coreutils}/touch /ci/keel/cache/pr-wrote-this")

    # B3: one slice carries the budget; two concurrent jobs share it.
    with check("two concurrent jobs sit in keel.slice, which holds the quota (B3)"):
        put_env("sleeper2", "${envs.sleeper2}")
        long_lived("keel-test", "sleeper2")
        host.succeed("runuser -u keel-conduct -- systemctl start --no-block keel-test@sleeper2.service")
        host.wait_until_succeeds("test \"$(systemctl show -p MainPID --value keel-test@sleeper2.service)\" != 0")
        for unit in ["keel-build@sleeper", "keel-test@sleeper2"]:
            assert host.succeed(f"systemctl show -p Slice --value {unit}.service").strip() == "keel.slice"
            assert "/keel.slice/" in host.succeed(f"systemctl show -p ControlGroup --value {unit}.service")
        props = dict(l.split("=", 1) for l in host.succeed(
            "systemctl show keel.slice -p CPUQuotaPerSecUSec -p MemoryHigh -p MemoryMax -p IOWeight -p TasksMax"
        ).split())
        assert props["CPUQuotaPerSecUSec"] == "14s", props
        assert props["MemoryHigh"] == str(36 * 1024**3), props
        assert props["MemoryMax"] == str(40 * 1024**3), props
        assert props["IOWeight"] == "50" and props["TasksMax"] == "8192", props
        assert host.succeed("cat /sys/fs/cgroup/keel.slice/cpu.max").split()[0] == "1400000"
        host.succeed("runuser -u keel-conduct -- systemctl stop keel-build@sleeper.service keel-test@sleeper2.service")

    # --- Nix daemon (B1) ----------------------------------------------------

    with check("a job cannot reach the Nix daemon: nix-build of a fixed-output derivation fails (B1)"):
        host.succeed("install -d -o keel-build -g keel-build -m 0750 /ci/keel/work/nixprobe")
        host.succeed("install -o keel-build -g keel-build -m 0644 ${fod} /ci/keel/work/nixprobe/fod.nix")
        put_env("nixprobe", "${envs.nix}")
        assert start("keel-build", "nixprobe") != 0
        host.succeed("journalctl -u keel-build@nixprobe.service | grep -q '/nix/var'")

    # --- Network (B2) -------------------------------------------------------

    with check("fetch reaches a server outside the denied ranges (B2)"):
        put_env("net-out", "${envs.toOutside}")
        assert start("keel-fetch", "net-out") == 0

    with check("fetch cannot reach the bridge or the host's own public address (B2)"):
        put_env("net-store", "${envs.toStore}")
        assert start("keel-fetch", "net-store") != 0
        put_env("net-host", "${envs.toHost}")
        assert start("keel-fetch", "net-host") != 0

    with check("build and test cannot reach the store port, the host, or the outside (B2)"):
        for unit in ["keel-build", "keel-test"]:
            for env_name, path in [("to-store", "${envs.toStore}"), ("to-host", "${envs.toHost}"), ("to-out", "${envs.toOutside}")]:
                put_env(f"{unit}-{env_name}", path)
                assert start(unit, f"{unit}-{env_name}") != 0, (unit, env_name)

    # --- Trust domains (R4) -------------------------------------------------

    with check("PR jobs cannot write the shared compiler cache; canonical can (R4)"):
        host.fail("runuser -u keel-build -- touch /ci/keel/cache/pr-wrote-this")
        host.succeed("runuser -u keel-build -- ls /ci/keel/cache")
        host.succeed("runuser -u keel-canon -- touch /ci/keel/cache/canon-wrote-this")
        host.fail("runuser -u keel-build -- ls /ci/keel/canon")
        host.fail("runuser -u keel-canon -- ls /ci/keel/work")
        pr_unit = host.succeed("systemctl cat keel-build@x.service")
        canon_unit = host.succeed("systemctl cat keel-canon-build@x.service")
        assert "BindReadOnlyPaths=/ci/keel/cache" in pr_unit and "BindPaths=/ci/keel/cache" not in pr_unit
        assert "BindPaths=/ci/keel/cache" in canon_unit and "User=keel-canon" in canon_unit

    with check("a canonical job runs as keel-canon in its own directory (R4)"):
        put_env("canon-smoke", "${envs.smoke}")
        assert start("keel-canon-build", "canon-smoke") == 0
        # Each claim separately, with the listing in the message, so a failure
        # says whether the directory is missing or wrongly owned.
        listing = host.execute("ls -la /ci/keel/canon /ci/keel/work 2>&1")[1]
        assert host.execute("test -d /ci/keel/canon/canon-smoke")[0] == 0, listing
        owner = host.succeed("stat -c %U:%G /ci/keel/canon/canon-smoke").strip()
        assert owner == "keel-canon:keel-canon", (owner, listing)

    with check("a running canonical job is keel-canon, in its own directory (R4)"):
        put_env("canon-sleeper", "${envs.sleeper}")
        long_lived("keel-canon-build", "canon-sleeper")
        host.succeed("runuser -u keel-conduct -- systemctl start --no-block keel-canon-build@canon-sleeper.service")
        host.wait_until_succeeds("test \"$(systemctl show -p MainPID --value keel-canon-build@canon-sleeper.service)\" != 0")
        cpid = host.succeed("systemctl show -p MainPID --value keel-canon-build@canon-sleeper.service").strip()
        assert host.succeed(f"stat -c %U /proc/{cpid}").strip() == "keel-canon"
        cwd = host.succeed(f"readlink /proc/{cpid}/cwd").strip()
        assert cwd == "/ci/keel/canon/canon-sleeper", cwd
        host.succeed("runuser -u keel-conduct -- systemctl stop keel-canon-build@canon-sleeper.service")

    # --- The conductor (R5) -------------------------------------------------

    with check("the conductor starts only what a pipeline token permits (R5)"):
        tokens = {}
        for token, repo, kinds in [("pr-token-a", "Nudox/Backend", ["pr"]), ("pr-token-b", "Nudox/Other", ["pr"])]:
            h = host.succeed(f"printf %s {token} | b3sum --no-names").strip()
            tokens[h] = {"repo": repo, "kinds": kinds}
        host.succeed(f"cat > ${secrets}/pipelines <<'EOF'\n{json.dumps(tokens)}\nEOF")
        host.succeed("chown keel-conduct ${secrets}/pipelines && chmod 0400 ${secrets}/pipelines")
        host.succeed("systemctl restart keel-conduct.service")
        host.wait_for_open_port(${toString conductPort}, "${bridge}")

        def post(token, body):
            return host.succeed(
                f"curl -s -w '\\n%{{http_code}}' -X POST -H 'Authorization: Bearer {token}' -d '{json.dumps(body)}' {cond}/v1/jobs"
            ).rsplit("\n", 1)

        pr = {"repo": "Nudox/Backend", "revision": "${revision}", "kind": "pr", "pr": 132}
        refused = [post("pr-token-a", {**pr, "kind": "canonical"}), post("pr-token-a", {**pr, "repo": "Nudox/Other"}), post("guess", pr)]
        assert [r[1] for r in refused] == ["403", "403", "401"], refused
        body, code = post("pr-token-a", pr)
        assert code == "202", body
        job_id = json.loads(body)["id"]
        # Wait on what a pipeline polls: the conductor's own status going
        # terminal. `systemctl show -p Result` says success for a unit that
        # has never run, so it cannot be the condition.
        poll = f"curl -sf -H 'Authorization: Bearer pr-token-a' {cond}/v1/jobs/{job_id}"
        host.wait_until_succeeds(f"{poll} | grep -q '\"finished\":true'", timeout=60)
        host.succeed(f"journalctl -u keel-fetch@{job_id}.service | grep -q 'fetch {job_id} Nudox/Backend'")
        status = json.loads(host.succeed(poll))
        assert status["stage"] == "done" and status["error"] is None, status
        # Proof that each phase ran is the conductor's own blocking start
        # returning success; systemd has already unloaded the finished units.
        assert status["result"] == "success" and status["completed"] == ["fetch", "build", "test"], status
        # The job is finished, so its log must end by itself: the response is
        # timed, not only read.
        took, job_log = host.succeed(f"curl -sf --max-time 5 -w '%{{time_total}}\\n' -o /tmp/job.log -H 'Authorization: Bearer pr-token-a' {cond}/v1/jobs/{job_id}/log && cat /tmp/job.log").split("\n", 1)
        assert float(took) < 3.0, took
        assert f"fetch {job_id}" in job_log, job_log
        # Another repo's token cannot even see the job.
        assert curl_code(f"-H 'Authorization: Bearer pr-token-b' {cond}/v1/jobs/{job_id}") == "404"

    for name, trace in failures:
        print(f"--- FAILED: {name}\n{trace}")
    assert not failures, f"{len(failures)} subtests failed: {[n for n, _ in failures]}"
  '';
}
