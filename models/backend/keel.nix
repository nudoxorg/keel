# The NuDox backend, as Keel sees it. This is the whole authored surface:
# no test is named here and no test file mentions Keel.
#
# Evaluate:  nix-instantiate --eval --strict --json models/backend/eval.nix
{ keel, root }:
keel.model (
  m:
  with keel;
  let
    # The languages that are both a frontend node and an axis value. The two
    # lists are not the same, and this keeps them as they were: the
    # frontend nodes add stylo (and sql, whose crate is named otherwise), the
    # axis adds css and sql, and the place rules take every one of these but
    # vue for both of their paths.
    languages = [
      "rust"
      "python"
      "typescript"
      "go"
      "java"
      "csharp"
      "clang"
      "vue"
    ];
  in
  {
    # Every path below is checked against this tree when the model is
    # evaluated; one that matches nothing is an error, not a quiet no-op.
    inherit root;

    # A workspace crate that no node below claims is a node of its own, named
    # by the package without its prefix: `backend-platform` is `platform`. A
    # node is written here only when it has more to say than its crate: an
    # `about`, several crates, parts, a law, or a place in a feature.
    #
    # Only the packages under crates/ and vendor/ are asked for. The packages
    # under tests/ are suites, not code anything stands on: made nodes, they
    # would "stand on" the engine only because they exercise it, and every
    # such edge is false. The packages under tools/ are dev tools nothing
    # ships. A directory that is not listed here makes no node, however many
    # packages it holds, so a new one is a choice made in this file.
    nodesFromCrates = {
      strip = "backend-";
      under = [
        "crates/**"
        "vendor/**"
      ];
    };

    # ── Foundations ─────────────────────────────────────────────────────
    # A node says which code it owns. What it stands on is not written: the
    # engine derives it from the code, pins it in keel.lock.json, and a PR
    # that changes the shape of the product shows that as a lock diff.
    version = node {
      about = "Stable keys, object versions, relation roots, exact deltas.";
      code = [ (crate "backend-version") ];
    };

    # Not written here, and nodes of their own: platform, compile, discovery,
    # runtime, execution and semantic. `keel-tree check` found that
    # with the first two inside `service` and `engine`, twenty-two nodes
    # stood on each other (the store and every adapter use the platform,
    # every frontend the compile contract), and in a second round that the
    # engine, the library and the adapters stand on the rest, so none of
    # them can be part of another node.

    store = node {
      about = "Durable objects and the intent journal.";
      code = [ (crate "backend-store") ];
      s3 = node { code = [ (crate "backend-store-s3") ]; };
    };

    flow = node {
      about = "Weighted batches, arrangements, joins, subscribers.";
      code = [ (crate "backend-flow") ];
    };

    engine = node {
      code = [
        (crate "backend-engine")
      ];
      # An architecture law. If engine code ever comes to stand on the
      # desktop, the plan fails before a test runs and names the path.
      never = [ m.desktop ];
    };

    # ── One node per language frontend, written once ────────────────────
    frontends = node (
      builtins.listToAttrs (
        map (language: {
          name = language;
          value = node { code = [ (crate "backend-frontend-${language}") ]; };
        }) (languages ++ [ "stylo" ])
      )
      // {
        sql = node {
          code = [
            # frontends/sqlite is kept out of the cargo workspace: no test
            # here can exercise it, so no node may claim to cover it.
            (crate "backend-sql-contract")
          ];
        };
      }
    );

    adapters = node {
      tantivy = node { code = [ (crate "backend-extension-tantivy") ]; };
      qdrant = node { code = [ (crate "backend-extension-qdrant") ]; };
      trustfall = node { code = [ (crate "backend-extension-trustfall") ]; };
      turso = node { code = [ (crate "backend-extension-turso") ]; };
    };

    cluster = node {
      code = [
        (crate "backend-cluster-transport")
        (crate "backend-replication")
      ];
    };
    # Written because it lives under apps/, which `nodesFromCrates.under` does
    # not list: the apps are the products, and each is named on purpose.
    worker = node { code = [ (crate "backend-worker") ]; };

    service = node {
      about = "The local owner every surface attaches to.";
      code = [
        (crate "backend-local-service")
        (crate "backend-locald")
        (crate "backend-client")
        (crate "backend-account")
      ];
    };

    library = node {
      about = "Package browsing, registries, advisories.";
      code = [
        (crate "backend-library")
        (crate "backend-advisory")
      ];
    };

    # ── Features: the trees people ask about ────────────────────────────
    # A feature is a node with a ship policy. Its tree is everything it
    # turns out to stand on. `movedBy` and `unmovedBy` are its adversarial
    # neighbours: one change that must reach it and one that must not.
    indexing =
      node {
        about = "Turning a project into admitted relations.";
        entry = [ (path "apps/cli/src/index_wait.rs") ];
        on = [
          m.engine
          m.frontends
        ];
        movedBy = [ "crates/store/src/lib.rs" ];
        unmovedBy = [ "apps/desktop/src/lib.rs" ];
      }
      // required;

    search =
      node {
        about = "Graph, text and semantic queries.";
        entry = [
          (path "apps/cli/src/invoke.rs")
          # The MCP tool table. `keel-tree check` refused the first
          # attempt, a `#[tool]` pattern: its nine matches lie in
          # workspace/nudox-engine, which this cargo workspace does not
          # build, so that entry guarded nothing.
          (path "apps/mcp/src/jsonrpc/tools.rs")
        ];
        movedBy = [ "extensions/tantivy/src/lib.rs" ];
        unmovedBy = [ "apps/desktop/src/lib.rs" ];
      }
      // required;

    cli =
      node {
        about = "Parsing, rendering, exit codes.";
        code = [
          (crate "backend-cli")
          (crate "backend-present")
        ];
        movedBy = [ "crates/present/lib.rs" ];
        unmovedBy = [ "apps/desktop/src/lib.rs" ];
      }
      // required;

    mcp =
      node {
        code = [ (crate "backend-mcp") ];
        movedBy = [ "apps/mcp/src/main.rs" ];
        unmovedBy = [ "apps/desktop/src/lib.rs" ];
      }
      // required;

    desktop =
      node {
        code = [
          (crate "backend-desktop")
          (crate "backend-facet")
        ];
        movedBy = [ "apps/desktop/src/lib.rs" ];
        unmovedBy = [ "apps/mcp/src/main.rs" ];
      }
      # Intent only: the engine holds this at `required` until its
      # predictions for desktop pass the calibration gate.
      // mayLag {
        atMostMinutes = 120;
        confidence = 0.95;
      };

    # ── Other ways to cut the same tests ────────────────────────────────
    # A test has one position on every axis. A failure is reported along
    # whichever axis describes it in the fewest words: "python is down" and
    # "mcp is down" are both one line, though no tree contains either.
    axes = {
      language = languages ++ [
        "css"
        "sql"
      ];
      transport = [
        "cli"
        "mcp"
        "desktop"
      ];
      tier = {
        values = [
          "unit"
          "law"
          "journey"
          "crash"
          "fleet"
        ];
        # Nearly every test is a unit test that sits in the crate it tests
        # (15,348 of 15,496 when the rules below were last counted), and the
        # other tiers are directories of their own. The rules name those
        # directories; what no rule places is a unit test.
        default = "unit";
      };
    };

    # Coordinates for the tests that exist, by rule. Eighteen thousand
    # tests, eleven lines.
    place = [
      {
        tests = tests.under "tests/laws/**";
        tier = "law";
      }
      {
        tests = tests.under "tests/journeys/**";
        tier = "journey";
        world = m.worlds.owner;
      }
      {
        tests = tests.under "tests/crash/**";
        tier = "crash";
      }
      {
        tests = tests.under "tests/fleet/**";
        tier = "fleet";
      }
    ]
    # A language's tests are its frontend's own, and the engine's
    # integration targets that carry its name as a file prefix. Reach is
    # no evidence here: every engine test links every frontend.
    ++
      builtins.concatMap
        (language: [
          {
            tests = tests.under "frontends/${language}/**";
            inherit language;
          }
          {
            tests = tests.under "crates/engine/tests/${language}_*.rs";
            inherit language;
          }
        ])
        # Every language but vue, which is placed by its directory alone (next rule).
        (builtins.filter (language: language != "vue") languages)
    ++ [
      {
        tests = tests.under "frontends/vue/**";
        language = "vue";
      }
      {
        tests = tests.under "apps/cli/**";
        transport = "cli";
      }
      {
        tests = tests.under "apps/mcp/**";
        transport = "mcp";
      }
      {
        tests = tests.under "apps/desktop/**";
        transport = "desktop";
      }
    ];

    # ── Start states ────────────────────────────────────────────────────
    # Built once, forked for every check that starts there.
    worlds = rec {
      owner = world {
        name = "owner";
        about = "One isolated local owner, workspace and credential.";
        step = [
          "backend-locald"
          "--isolated"
        ];
        keep = "service";
        inputs = [
          (crate "backend-locald")
          (crate "backend-local-service")
        ];
      };
      indexed =
        project:
        world {
          name = "indexed-${project}";
          from = owner;
          step = [
            "backend"
            "index"
            "--case"
            project
          ];
          keep = "directory";
          inputs = [
            (crate "backend-cli")
            (path "tests/surface/cases.json")
          ];
        };
    };

    # ── One law, many cells ─────────────────────────────────────────────
    # The surface suite, read from the cases file the repository already
    # keeps: every project, through every transport, for every query. Each
    # cell starts from the world where its project is already indexed, so a
    # project is indexed once however many cells ask about it.
    checks.surface =
      let
        cases = builtins.filter (c: c ? cli) (
          (builtins.fromJSON (builtins.readFile (root + "/tests/surface/cases.json"))).cases
        );
        queries = builtins.listToAttrs (
          map (c: {
            inherit (c) name;
            value = map (builtins.concatStringsSep " ") c.cli;
          }) cases
        );
      in
      matrix {
        over = {
          project = map (c: c.name) cases;
          transport = [
            "cli"
            "mcp"
          ];
          query = [
            0
            1
            2
            3
          ];
        };
        when = cell: cell.query < builtins.length queries.${cell.project};
        world = cell: m.worlds.indexed cell.project;
        run = cell: [
          "surface-probe"
          "--transport"
          cell.transport
          "--credential"
          (cell.credential or "own")
          "--"
          (builtins.elemAt queries.${cell.project} cell.query)
        ];
        expect = cell: {
          snapshot = "tests/surface/snapshots/${cell.project}.json";
        };
        on = cell: [ m.search ] ++ (if cell.transport == "mcp" then [ m.mcp ] else [ m.cli ]);
        # The harness and the cases it replays; editing either reruns all.
        inputs = [ (path "tests/surface/**") ];
        # Every cell gets this twin for free: the same call with another
        # workspace's credential must be refused, by name.
        controls = [
          {
            name = "foreign-credential";
            alter = cell: cell // { credential = "another-workspace"; };
            expect = {
              refused = "unauthorized";
            };
          }
        ];
      };

    policy = {
      # Should be "fail", and is not yet. `indexing` and `search` are
      # entry files, and the engine only knows which package a test
      # links, not which functions it reaches, so it sees no test pass
      # through them: 19 edges uncovered. Until reach is per function
      # that is the tool's blindness, not a finding about the backend.
      uncovered = "report";
      # No fault driver exists for the backend yet, so nothing has ever
      # taken a dependency away. Reported on every run until one does.
      faults = "report";
      # Sets, not lists: this stays right as tests come and go.
      deployGate = tests.minus tests.all (tests.only m.desktop);
      idle = {
        mutate = tests.all;
        recheckOneIn = 50;
      };
    };
  }
)
