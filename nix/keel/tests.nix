# The library's own negative controls: every model here is wrong in exactly
# one way and must fail to evaluate. `good` is the same model with nothing
# wrong, so a case cannot pass merely because the base is broken.
#
# Run:  nix-instantiate --eval -A passed nix/keel/tests.nix
# One:  nix-instantiate --eval --strict -A cases.<name> nix/keel/tests.nix
# Prints the names of the cases that evaluated when they should not have,
# and aborts if that list is not empty.
let
  keel = import ./lib.nix;
  inherit (keel)
    node
    world
    matrix
    tests
    required
    mayLag
    crate
    path
    ;
  root = ./probe;

  w =
    name: extra:
    world (
      {
        inherit name;
        step = [ "true" ];
      }
      // extra
    );
  grid =
    extra: m:
    matrix (
      {
        over.p = [
          "a"
          "b"
        ];
        run = cell: [
          "probe"
          cell.p
        ];
        expect = {
          ok = true;
        };
        on = _: [ m.a ];
        inputs = [ (crate "probe") ];
        controls = [
          {
            name = "wrong";
            alter = cell: cell // { p = "${cell.p}-wrong"; };
            expect = {
              refused = true;
            };
          }
        ];
      }
      // extra
    );
  base = m: {
    inherit root;
    a = node { code = [ (crate "a") ]; };
    b = node { code = [ (crate "b") ]; };
  };
  # Every case has a gate unless it sets its own policy fields, so that a
  # case fails for the one thing it gets wrong and not for lacking a gate.
  with' =
    extra:
    keel.model (
      m:
      base m
      // extra m
      // {
        policy = {
          deployGate = tests.all;
        }
        // ((extra m).policy or { });
      }
    );
  fails = value: !(builtins.tryEval (builtins.deepSeq value value)).success;

  good = with' (m: {
    checks.g = grid {
      world = cell: w "ix-${cell.p}" { machines = [ "h" ]; };
      faults = [
        {
          name = "dep-down";
          kind = "stop";
          target = {
            host = "h";
            unit = "b";
          };
          hold = 5;
          during = {
            refuses = {
              expect = {
                error = "unavailable";
              };
              within = 2;
            };
          };
          recoverWithin = 10;
        }
      ];
    } m;
    policy.deployGate = tests.minus tests.all (tests.only m.b);
    census.ports = {
      key = [
        "host"
        "port"
      ];
      inputs = [ (crate "probe") ];
      declared = [
        {
          host = "h";
          port = 25;
        }
        {
          host = "h";
          port = 443;
        }
      ];
      observed = [
        {
          host = "h";
          port = 25;
        }
        {
          host = "h";
          port = 9090;
        }
        {
          host = "h";
          port = 22;
        }
      ];
      ignore = [
        {
          match = {
            port = 22;
          };
          reason = "ssh is declared by the base system";
        }
      ];
    };
  });

  cases = {
    node-field-misspelt = with' (m: {
      c = node {
        code = [ (crate "c") ];
        nevr = [ m.b ];
      };
    });
    top-level-field-misspelt = with' (m: {
      polcy = { };
    });
    policy-field-misspelt = with' (m: {
      policy.deployGates = tests.all;
    });
    world-field-misspelt = with' (m: {
      checks.g = grid { world = _: w "x" { keeep = "run"; }; } m;
    });
    matrix-field-misspelt = with' (m: {
      checks.g = grid { wen = _: true; } m;
    });
    control-field-misspelt = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "wrong";
            alter = cell: cell // { p = "z"; };
            expect = { };
            expct = { };
          }
        ];
      } m;
    });
    world-named-twice = with' (m: {
      checks.g = grid { world = cell: w "same" { about = cell.p; }; } m;
    });
    world-kept-without-inputs = with' (m: {
      checks.g = grid { world = _: w "x" { keep = "directory"; }; } m;
    });
    control-changes-nothing = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "same";
            alter = cell: cell;
            expect = { };
          }
        ];
      } m;
    });
    control-is-another-cell = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "other";
            alter = cell: cell // { p = if cell.p == "a" then "b" else "a"; };
            expect = { };
          }
        ];
      } m;
    });
    cell-without-control = with' (m: {
      checks.g = grid { controls = [ ]; } m;
    });
    cell-value-with-separator = with' (m: {
      checks.g = grid { over.p = [ "a,b=c" ]; } m;
    });
    code-owned-twice = with' (m: {
      c = node { code = [ (crate "a") ]; };
    });
    witness-path-missing = with' (m: {
      c =
        node {
          code = [ (crate "c") ];
          movedBy = [ "src/lib.rs" ];
          unmovedBy = [ "src/absent.rs" ];
        }
        // required;
    });
    selector-path-missing = with' (m: {
      c = node { code = [ (path "absent/**") ]; };
    });
    placement-directory-missing = with' (m: {
      axes.tier = [ "law" ];
      place = [
        {
          tests = tests.under "absent/**";
          tier = "law";
        }
      ];
    });
    coordinates-from-a-name = with' (m: {
      axes.language = [ "go" ];
      place = [
        {
          tests = tests.named "*go_*";
          language = "go";
        }
      ];
    });
    gate-subtracts-by-reach = with' (m: {
      policy.deployGate = tests.minus tests.all (tests.on m.b);
    });
    may-lag-below-calibration-floor = with' (m: {
      c =
        node {
          code = [ (crate "c") ];
          movedBy = [ "src/lib.rs" ];
          unmovedBy = [ "src/lib.rs" ];
        }
        // mayLag {
          atMostMinutes = 60;
          confidence = 0.6;
        };
    });
    may-lag-duration-as-text = with' (m: {
      c =
        node { code = [ (crate "c") ]; }
        // mayLag {
          atMostMinutes = "2h";
          confidence = 0.95;
        };
    });
    matrix-without-inputs = with' (m: {
      checks.g = matrix {
        over.p = [ "a" ];
        run = cell: [ "probe" ];
        expect = { };
        on = _: [ m.a ];
        uncontrolled = "case under test";
      };
    });
    check-input-path-missing = with' (m: {
      checks.g = grid { inputs = [ (path "absent/**") ]; } m;
    });
    check-coordinate-undeclared = with' (m: {
      axes.host = [ "one" ];
      checks.g = grid { coordinates = _: { host = "two"; }; } m;
    });
    join-of-a-node-with-itself = with' (m: {
      policy.joins = [
        [
          m.a
          m.a
        ]
      ];
    });
    axis-value-with-separator = with' (m: {
      axes.host = [ "a=b" ];
    });
    instance-of-something-not-a-node = with' (m: {
      c = node {
        code = [ (crate "c") ];
        of = [ "a" ];
      };
    });
    inert-path-missing = with' (m: {
      policy.inert = [ (path "absent/**") ];
    });
    fault-kind-unknown = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "dep-down";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              during = {
                refuses = {
                  expect = {
                    error = "unavailable";
                  };
                  within = 2;
                };
              };
              recoverWithin = 10;
            }
            // {
              kind = "gremlin";
            }
          )
        ];
      } m;
    });
    fault-during-left-open = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "dep-down";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              during = {
                refuses = {
                  expect = {
                    error = "unavailable";
                  };
                  within = 2;
                };
              };
              recoverWithin = 10;
            }
            // {
              during = { };
            }
          )
        ];
      } m;
    });
    fault-during-says-two-things = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "dep-down";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              during = {
                refuses = {
                  expect = {
                    error = "unavailable";
                  };
                  within = 2;
                };
              };
              recoverWithin = 10;
            }
            // {
              during = {
                holds = true;
                refuses = {
                  x = 1;
                };
              };
            }
          )
        ];
      } m;
    });
    fault-without-recovery-bound = with' (m: {
      checks.g = grid {
        faults = [
          (removeAttrs {
            name = "dep-down";
            kind = "stop";
            target = {
              host = "h";
              unit = "b";
            };
            hold = 5;
            during = {
              refuses = {
                expect = {
                  error = "unavailable";
                };
                within = 2;
              };
            };
            recoverWithin = 10;
          } [ "recoverWithin" ])
        ];
      } m;
    });
    fault-custom-without-heal = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "dep-down";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              during = {
                refuses = {
                  expect = {
                    error = "unavailable";
                  };
                  within = 2;
                };
              };
              recoverWithin = 10;
            }
            // {
              kind = "custom";
              inject = [ "break" ];
            }
          )
        ];
      } m;
    });
    fault-field-misspelt = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "dep-down";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              during = {
                refuses = {
                  expect = {
                    error = "unavailable";
                  };
                  within = 2;
                };
              };
              recoverWithin = 10;
            }
            // {
              recoverWithn = 3;
            }
          )
        ];
      } m;
    });
    fault-named-twice = with' (m: {
      checks.g = grid {
        faults = [
          {
            name = "dep-down";
            kind = "stop";
            target = {
              host = "h";
              unit = "b";
            };
            hold = 5;
            during = {
              refuses = {
                expect = {
                  error = "unavailable";
                };
                within = 2;
              };
            };
            recoverWithin = 10;
          }
          {
            name = "dep-down";
            kind = "stop";
            target = {
              host = "h";
              unit = "b";
            };
            hold = 5;
            during = {
              refuses = {
                expect = {
                  error = "unavailable";
                };
                within = 2;
              };
            };
            recoverWithin = 10;
          }
        ];
      } m;
    });
    policy-unfaulted-without-reason = with' (m: {
      policy.unfaulted = [
        {
          from = m.a;
          to = m.b;
        }
      ];
    });
    policy-faults-misspelt-value = with' (m: {
      policy.faults = "ignore";
    });
    cells-share-an-id = with' (m: {
      checks.g = grid {
        over.p = [
          1
          "1"
        ];
        controls = [ ];
        uncontrolled = "case under test";
        run = cell: [ "probe" ];
      } m;
    });
    matrix-over-nothing = with' (m: {
      checks.g = grid { when = _: false; } m;
    });
    controls-share-a-name = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "w";
            alter = c: c // { p = "x"; };
            expect = { };
          }
          {
            name = "w";
            alter = c: c // { p = "y"; };
            expect = { };
          }
        ];
      } m;
    });
    node-name-with-a-dot = with' (m: {
      "c.d" = node { code = [ (crate "c") ]; };
    });
    node-named-like-a-section = with' (m: {
      worlds = node { code = [ (crate "c") ]; };
    });
    node-stands-on-itself = with' (m: {
      c = node {
        code = [ (crate "c") ];
        on = [ m.c ];
      };
    });
    ship-written-by-hand = with' (m: {
      c = node {
        code = [ (crate "c") ];
        ship = "requried";
        movedBy = [ "src/lib.rs" ];
        unmovedBy = [ "src/lib.rs" ];
      };
    });
    path-climbs-out-of-the-root = with' (m: {
      c = node { code = [ (path "../probe/src/**") ]; };
    });
    witness-path-absolute = with' (m: {
      c =
        node {
          code = [ (crate "c") ];
          movedBy = [ "/etc/hosts" ];
          unmovedBy = [ "src/lib.rs" ];
        }
        // required;
    });
    axis-with-a-repeated-value = with' (m: {
      axes.host = [
        "a"
        "a"
      ];
    });
    axis-empty = with' (m: {
      axes.host = [ ];
    });
    axis-set-without-values = with' (m: {
      axes.host = {
        default = "a";
      };
    });
    axis-set-with-a-misspelt-field = with' (m: {
      axes.host = {
        values = [
          "a"
          "b"
        ];
        defualt = "a";
      };
    });
    axis-default-is-not-one-of-the-values = with' (m: {
      axes.host = {
        values = [
          "a"
          "b"
        ];
        default = "c";
      };
    });
    axis-default-is-not-a-string = with' (m: {
      axes.host = {
        values = [
          "a"
          "b"
        ];
        default = 1;
      };
    });
    nodes-from-crates-is-not-a-set = with' (m: {
      nodesFromCrates = "backend-";
    });
    nodes-from-crates-with-a-misspelt-field = with' (m: {
      nodesFromCrates = {
        strip = "backend-";
        under = [ "src/**" ];
        strpi = "x";
      };
    });
    nodes-from-crates-strip-is-not-a-string = with' (m: {
      nodesFromCrates = {
        strip = 1;
        under = [ "src/**" ];
      };
    });
    nodes-from-crates-strip-is-empty = with' (m: {
      nodesFromCrates = {
        strip = "";
        under = [ "src/**" ];
      };
    });
    nodes-from-crates-without-under = with' (m: {
      nodesFromCrates = {
        strip = "backend-";
      };
    });
    nodes-from-crates-with-an-empty-under = with' (m: {
      nodesFromCrates = {
        under = [ ];
      };
    });
    nodes-from-crates-under-is-a-string = with' (m: {
      nodesFromCrates = {
        under = "src/**";
      };
    });
    nodes-from-crates-under-names-a-missing-directory = with' (m: {
      nodesFromCrates = {
        under = [
          "src/**"
          "vendor/**"
        ];
      };
    });
    nodes-from-crates-under-climbs-out = with' (m: {
      nodesFromCrates = {
        under = [ "../**" ];
      };
    });
    axis-default-on-an-empty-axis = with' (m: {
      axes.host = {
        values = [ ];
        default = "a";
      };
    });
    check-group-is-not-a-matrix = with' (m: {
      checks.g = {
        checks = [ ];
      };
    });
    placement-rule-that-does-nothing = with' (m: {
      place = [ { tests = tests.all; } ];
    });
    fault-target-names-service-and-unit = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              target = {
                host = "h";
                unit = "b";
                service = "b";
              };
            }
          )
        ];
      } m;
    });
    fault-target-without-host = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              target = {
                unit = "b";
              };
            }
          )
        ];
      } m;
    });
    fault-target-field-misspelt = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              target = {
                host = "h";
                unit = "b";
                hots = "h";
              };
            }
          )
        ];
      } m;
    });
    fault-partition-of-a-host-from-itself = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              kind = "partition";
              target = {
                between = [
                  "a"
                  "a"
                ];
              };
            }
          )
        ];
      } m;
    });
    fault-drop-above-a-hundred-percent = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              kind = "drop";
              target = {
                host = "h";
                port = 25;
                proto = "tcp";
                direction = "in";
                percent = 250;
              };
            }
          )
        ];
      } m;
    });
    fault-clock-skew-of-zero = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              kind = "clock-skew";
              target = {
                host = "h";
                seconds = 0;
              };
            }
          )
        ];
      } m;
    });
    fault-disk-full-on-a-relative-path = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              kind = "disk-full";
              target = {
                host = "h";
                path = "var/lib";
              };
            }
          )
        ];
      } m;
    });
    fault-verdict-without-a-deadline = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                };
              };
            }
          )
        ];
      } m;
    });
    fault-deadline-not-before-heal = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 5;
                };
              };
            }
          )
        ];
      } m;
    });
    fault-place-given-for-a-named-kind = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              at = "elsewhere";
            }
          )
        ];
      } m;
    });
    machine-world-without-machines = with' (m: {
      checks.g = grid {
        world =
          _:
          w "vm" {
            keep = "machine";
            inputs = [ (crate "a") ];
          };
      } m;
    });
    check-at-a-machine-the-world-lacks = with' (m: {
      checks.g = grid {
        world = _: w "vm" { machines = [ "h" ]; };
        at = "hh";
      } m;
    });
    fault-on-a-machine-the-world-lacks = with' (m: {
      checks.g = grid {
        world = _: w "vm" { machines = [ "other" ]; };
        faults = [
          {
            name = "f";
            kind = "stop";
            target = {
              host = "h";
              unit = "b";
            };
            hold = 5;
            recoverWithin = 10;
            during = {
              refuses = {
                expect = {
                  error = "x";
                };
                within = 2;
              };
            };
          }
        ];
      } m;
    });
    partition-with-a-machine-the-world-lacks = with' (m: {
      checks.g = grid {
        world =
          _:
          w "vm" {
            machines = [
              "a"
              "b"
            ];
          };
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              kind = "partition";
              target = {
                between = [
                  "a"
                  "c"
                ];
              };
            }
          )
        ];
      } m;
    });
    census-with-two-sources = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        observe = [ "ss" ];
      };
    });
    census-with-no-source = with' (m: {
      census.ports = removeAttrs {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      } [ "observed" ];
    });
    census-without-a-key = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        key = [ ];
      };
    });
    census-record-lacks-a-key-field = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        declared = [ { host = "h"; } ];
      };
    });
    census-declares-a-record-twice = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 25;
          }
        ];
      };
    });
    census-observes-nothing = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        observed = [ ];
      };
    });
    census-ignore-without-reason = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        ignore = [
          {
            match = {
              port = 22;
            };
          }
        ];
      };
    });
    census-ignore-that-matches-everything = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        ignore = [
          {
            match = { };
            reason = "all";
          }
        ];
      };
    });
    census-without-inputs = with' (m: {
      census.ports = removeAttrs {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      } [ "inputs" ];
    });
    census-field-misspelt = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        mising = "report";
      };
    });
    census-axis-undeclared = with' (m: {
      census.ports = {
        key = [
          "host"
          "port"
        ];
        inputs = [ (crate "probe") ];
        declared = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 443;
          }
        ];
        observed = [
          {
            host = "h";
            port = 25;
          }
          {
            host = "h";
            port = 9090;
          }
          {
            host = "h";
            port = 22;
          }
        ];
        ignore = [
          {
            match = {
              port = 22;
            };
            reason = "ssh is declared by the base system";
          }
        ];
      }
      // {
        axes = {
          host = "host";
        };
      };
    });
    # From the design review of the evaluated model (design/ir.md): wrong
    # models that still evaluated on 2026-11-14.
    lag-written-by-hand = with' (m: {
      c = node {
        code = [ (crate "c") ];
        ship = "may-lag";
        lag = {
          atMostMinutes = -5;
          confidence = 0.1;
        };
        movedBy = [ "src/lib.rs" ];
        unmovedBy = [ "src/main.rs" ];
      };
    });
    node-with-an-empty-code-list = with' (m: {
      c = node { code = [ ]; };
    });
    control-alters-a-field-nothing-reads = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "noop";
            alter = cell: cell // { ignored = "x"; };
            expect = {
              refused = true;
            };
          }
        ];
      } m;
    });
    control-and-fault-share-a-name = with' (m: {
      checks.g = grid {
        world = _: w "vm" { machines = [ "h" ]; };
        faults = [
          {
            name = "wrong";
            kind = "reboot";
            target = {
              host = "h";
            };
            hold = 5;
            during = {
              holds = true;
            };
            recoverWithin = 5;
          }
        ];
      } m;
    });
    dimension-value-with-white-space = with' (m: {
      checks.g = grid {
        over.p = [
          "a b"
          "c"
        ];
      } m;
    });
    check-on-something-that-is-not-a-node = with' (m: {
      checks.g = grid { on = _: [ { id = "no.such.node"; } ]; } m;
    });
    check-on-a-forged-node = with' (m: {
      checks.g = grid {
        on = _: [
          {
            _keel = "node";
            id = "no.such.node";
          }
        ];
      } m;
    });
    coordinates-contradict-a-dimension = with' (m: {
      axes.p = [
        "a"
        "b"
      ];
      checks.g = grid {
        coordinates = cell: { p = "b"; };
        controls = [ ];
        uncontrolled = "case under test";
      } m;
    });
    census-ignore-that-matches-nothing = with' (m: {
      census.ports = {
        key = [ "port" ];
        inputs = [ (crate "probe") ];
        declared = [ { port = 1; } ];
        observed = [ { port = 1; } ];
        ignore = [
          {
            match = {
              port = 99999;
            };
            reason = "long gone";
          }
        ];
      };
    });
    axis-named-like-a-derived-attribute = with' (m: {
      axes.target = [ "aarch64" ];
    });
    path-both-moves-and-does-not = with' (m: {
      c =
        node {
          code = [ (crate "c") ];
          movedBy = [ "src/lib.rs" ];
          unmovedBy = [ "src/lib.rs" ];
        }
        // required;
    });
    deploy-gate-that-is-not-a-test-set = with' (m: {
      policy.deployGate = "everything";
    });
    idle-recheck-as-text = with' (m: {
      policy.idle.recheckOneIn = "often";
    });
    twin-without-inputs = with' (m: {
      checks.g = grid {
        inputs = cell: if cell.p == "a" || cell.p == "b" then [ (crate "probe") ] else [ ];
      } m;
    });
    run-as-a-shell-string = with' (m: {
      checks.g = grid { run = cell: "rm -rf"; } m;
    });
    expectation-as-free-text = with' (m: {
      checks.g = grid { expect = "whatever"; } m;
    });
    world-env-name-with-a-dash = with' (m: {
      checks.g = grid {
        world =
          _:
          w "x" {
            env = {
              "NOT-A-NAME" = "1";
            };
          };
      } m;
    });
    world-env-value-that-is-a-number = with' (m: {
      checks.g = grid {
        world =
          _:
          w "x" {
            env = {
              JOBS = 4;
            };
          };
      } m;
    });
    world-tools-as-names = with' (m: {
      checks.g = grid { world = _: w "x" { tools = [ "clang" ]; }; } m;
    });
    world-network-as-text = with' (m: {
      checks.g = grid { world = _: w "x" { network = "yes"; }; } m;
    });
    cells-run-together-under-a-key-with-spaces = with' (m: {
      checks.g = grid { together = cell: "all of them"; } m;
    });
    path-inside-a-selector-that-climbs-out = with' (m: {
      checks.g = grid {
        world =
          _:
          w "x" {
            env = {
              JAVAC = keel.within (keel.drv "jdk") "../bin/javac";
            };
          };
      } m;
    });
    path-inside-nested-twice = with' (m: {
      checks.g = grid {
        world =
          _:
          w "x" {
            env = {
              X = keel.within (keel.within (keel.drv "jdk") "bin") "javac";
            };
          };
      } m;
    });
    world-state-as-an-input = with' (m: {
      checks.g = grid {
        world =
          _:
          w "x" {
            keep = "directory";
            inputs = [ (keel.state "owner.sock") ];
          };
      } m;
    });
    world-state-as-a-tool = with' (m: {
      checks.g = grid { world = _: w "x" { tools = [ (keel.state "bin/tool") ]; }; } m;
    });
    down-during-a-fault-that-is-not-an-outage = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              during = {
                down = true;
              };
            }
          )
        ];
      } m;
    });
    power-loss-on-a-relative-path = with' (m: {
      checks.g = grid {
        faults = [
          (
            {
              name = "f";
              kind = "stop";
              target = {
                host = "h";
                unit = "b";
              };
              hold = 5;
              recoverWithin = 10;
              during = {
                refuses = {
                  expect = {
                    error = "x";
                  };
                  within = 2;
                };
              };
            }
            // {
              kind = "power-loss";
              target = {
                host = "h";
                path = "var/lib";
              };
              during = {
                down = true;
              };
            }
          )
        ];
      } m;
    });
    control-breaks-a-node-the-check-is-not-on = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "w";
            alter = c: c // { p = "x"; };
            expect = {
              refused = true;
            };
            breaks = m.b;
          }
        ];
      } m;
    });
    control-breaks-something-that-is-no-node = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "w";
            alter = c: c // { p = "x"; };
            expect = {
              refused = true;
            };
            breaks = "a";
          }
        ];
      } m;
    });
    control-breaks-an-edge-to-a-node-the-check-is-not-on = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "w";
            alter = c: c // { p = "x"; };
            expect = {
              refused = true;
            };
            breaks = {
              edge = [
                m.a
                m.b
              ];
            };
          }
        ];
      } m;
    });
    control-breaks-an-edge-from-a-node-to-itself = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "w";
            alter = c: c // { p = "x"; };
            expect = {
              refused = true;
            };
            breaks = {
              edge = [
                m.a
                m.a
              ];
            };
          }
        ];
      } m;
    });
    # From the CI lead's consumer-side review: models that evaluated and
    # tested nothing.
    model-with-no-node = keel.model (m: {
      inherit root;
    });
    checks-without-a-deploy-gate = keel.model (m: base m // { checks.g = grid { } m; });
    world-entry-that-is-no-world = with' (m: {
      worlds.junk = 5;
    });
    world-declared-and-never-used = with' (m: {
      worlds.spare = w "spare" { };
    });
    check-at-a-machine-with-no-world = with' (m: {
      checks.g = grid { at = "ghost"; } m;
    });
    fault-host-in-a-world-without-machines = with' (m: {
      checks.g = grid {
        world = _: w "x" { };
        faults = [
          {
            name = "f";
            kind = "stop";
            target = {
              host = "h";
              unit = "b";
            };
            hold = 5;
            recoverWithin = 10;
            during = {
              refuses = {
                expect = {
                  error = "x";
                };
                within = 2;
              };
            };
          }
        ];
      } m;
    });
    inert-without-a-reason = with' (m: {
      policy.inert = [ (path "src/**") ];
    });
    inert-beginning-with-a-wildcard = with' (m: {
      policy.inert = [ (keel.inert "**" "everything") ];
    });
    census-over-nothing = with' (m: {
      census.ports = {
        key = [ "port" ];
        inputs = [ (crate "probe") ];
        declared = [ ];
        observed = [ ];
      };
    });
    control-expecting-what-the-check-expects = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "same";
            alter = c: c // { p = "x"; };
            expect = {
              ok = true;
            };
          }
        ];
      } m;
    });
    control-name-with-a-slash = with' (m: {
      checks.g = grid {
        controls = [
          {
            name = "wrong/../x";
            alter = c: c // { p = "x"; };
            expect = {
              refused = true;
            };
          }
        ];
      } m;
    });
    run-that-is-true = with' (m: {
      checks.g = grid {
        run = cell: [ "true" ];
        controls = [ ];
        uncontrolled = "case under test";
      } m;
    });
    run-with-an-empty-program = with' (m: {
      checks.g = grid {
        run = cell: [
          ""
          cell.p
        ];
      } m;
    });
    expectation-of-null = with' (m: {
      checks.g = grid {
        expect = {
          ok = null;
        };
      } m;
    });
    expectation-with-an-empty-key = with' (m: {
      checks.g = grid {
        expect = {
          "" = "x";
        };
      } m;
    });
    about-as-an-empty-string = with' (m: {
      c = node {
        code = [ (crate "c") ];
        about = "";
      };
    });
    uncontrolled-without-a-reason = with' (m: {
      checks.g = grid {
        controls = [ ];
        uncontrolled = "";
      } m;
    });
    path-inside-a-selector-as-code = with' (m: {
      c = node { code = [ (keel.within (path "src") "lib.rs") ]; };
    });
    world-ready-bound-of-zero = with' (m: {
      checks.g = grid { world = _: w "x" { readyWithin = 0; }; } m;
    });
    declared-edges-in-a-cycle = with' (m: {
      c = node {
        code = [ (crate "c") ];
        on = [ m.d ];
      };
      d = node {
        code = [ (crate "d") ];
        on = [ m.c ];
      };
    });
    node-required-and-forbidden-to-stand-on-another = with' (m: {
      c = node {
        code = [ (crate "c") ];
        on = [ m.b ];
        never = [ m.b ];
      };
    });
    node-standing-on-its-own-child = with' (m: {
      c = node {
        on = [ m.c.d ];
        d = node { code = [ (crate "d") ]; };
      };
    });
    gate-selected-by-a-directory-that-is-not-there = with' (m: {
      policy.deployGate = tests.under "absent/**";
    });
    census-of-an-unknown-boundary-class = with' (m: {
      census.spawns = {
        key = [ "file" ];
        inputs = [ (crate "a") ];
        declared = [ { file = "src/lib.rs"; } ];
        boundary = "process-spwan";
      };
    });
    census-of-a-boundary-in-a-world = with' (m: {
      census.spawns = {
        key = [ "file" ];
        inputs = [ (crate "a") ];
        declared = [ { file = "src/lib.rs"; } ];
        boundary = "process-spawn";
        world = w "x" { };
      };
    });
    census-of-a-boundary-and-a-command = with' (m: {
      census.spawns = {
        key = [ "file" ];
        inputs = [ (crate "a") ];
        declared = [ { file = "src/lib.rs"; } ];
        boundary = "process-spawn";
        observe = [ "ss" ];
      };
    });
    model-without-root = keel.model (m: removeAttrs (base m) [ "root" ]);
  };

  # The altered cell's world must exist, or the twin starts from nothing.
  twinWorlds = map (x: x.name) good.worlds;
  wrong =
    (if fails good then [ "good-model-does-not-evaluate" ] else [ ])
    ++ (if builtins.elem "ix-a-wrong" twinWorlds then [ ] else [ "twin-world-not-collected" ])
    # A fork inherits its parent's variables, overrides by name, adds tools.
    # A control that says what it takes away carries that node's id.
    ++ (
      let
        model = with' (m: {
          checks.g = grid {
            controls = [
              {
                name = "w";
                alter = c: c // { p = "x"; };
                expect = {
                  refused = true;
                };
                breaks = m.a;
              }
            ];
          } m;
        });
      in
      if
        map (c: c.breaks) model.checks.g.checks == [
          null
          { node = "a"; }
          null
          { node = "a"; }
        ]
      then
        [ ]
      else
        [ "breaks-not-emitted" ]
    )
    # A path inside a derivation, a path inside the world's state, and a
    # power loss with nothing answering while it lasts, all evaluate.
    ++ (
      if
        fails (
          with' (m: {
            checks.g = grid {
              world =
                _:
                w "x" {
                  machines = [ "h" ];
                  env = {
                    JAVAC = keel.within (keel.drv "jdk") "bin/javac";
                    SOCKET = keel.state "owner.sock";
                  };
                };
              faults = [
                (
                  {
                    name = "f";
                    kind = "stop";
                    target = {
                      host = "h";
                      unit = "b";
                    };
                    hold = 5;
                    recoverWithin = 10;
                    during = {
                      refuses = {
                        expect = {
                          error = "x";
                        };
                        within = 2;
                      };
                    };
                  }
                  // {
                    kind = "power-loss";
                    target = {
                      host = "h";
                      path = "/var/lib";
                    };
                    during = {
                      down = true;
                    };
                  }
                )
              ];
            } m;
          })
        )
      then
        [ "within-state-or-power-loss-refused" ]
      else
        [ ]
    )
    ++ (
      let
        parent = w "p" {
          env = {
            A = "1";
            B = "2";
          };
          tools = [ (crate "t1") ];
          network = true;
        };
        child = world {
          name = "c";
          from = parent;
          step = [ "true" ];
          env = {
            B = "3";
          };
          tools = [ (crate "t2") ];
        };
      in
      if
        child.env == {
          A = "1";
          B = "3";
        }
        && builtins.length child.tools == 2
        && child.network == true
      then
        [ ]
      else
        [ "world-inheritance-wrong" ]
    )
    # Two cells, each with its check, one twin and one fault check whose
    # recovery expectation defaults to the plain one.
    ++ (
      if
        builtins.length good.checks.g.checks == 6
        && builtins.any (
          c:
          c.faults != [ ]
          && (builtins.head c.faults).after == { ok = true; }
          && (builtins.head c.faults).at == "h"
        ) good.checks.g.checks
      then
        [ ]
      else
        [ "fault-check-not-emitted" ]
    )
    # Port 9090 is observed and undeclared, 443 declared and unobserved,
    # and 22 is ignored with a reason.
    ++ (
      let
        r = (builtins.head good.census).result;
      in
      if map (x: x.port) r.extra == [ 9090 ] && map (x: x.port) r.missing == [ 443 ] then
        [ ]
      else
        [ "census-difference-wrong" ]
    )
    # An axis written as a set is its list of values to everything that reads
    # axes, and its default is carried beside them; a plain list has none.
    ++ (
      let
        defaulted = with' (m: {
          axes.host = {
            values = [
              "a"
              "b"
            ];
            default = "b";
          };
          axes.plain = [ "x" ];
          place = [
            {
              tests = tests.all;
              host = "a";
            }
          ];
        });
      in
      if
        defaulted.axes == {
          host = [
            "a"
            "b"
          ];
          plain = [ "x" ];
        }
        &&
          defaulted.axisDefaults == {
            host = "b";
          }
        && good.axisDefaults == { }
      then
        [ ]
      else
        [ "axis-default-not-emitted" ]
    )
    # `nodesFromCrates` is passed on with its strip and the line that wrote it,
    # and a model without it says nothing of the kind.
    ++ (
      let
        derived = with' (m: {
          nodesFromCrates = {
            strip = "backend-";
            under = [ "src/**" ];
          };
        });
        bare = with' (m: {
          nodesFromCrates = {
            under = [ "src/**" ];
          };
        });
      in
      if
        derived.nodesFromCrates.strip == "backend-"
        && derived.nodesFromCrates.under == [ "src/**" ]
        && builtins.match ".*tests.nix:[0-9]+" derived.nodesFromCrates.at != null
        && bare.nodesFromCrates.strip == ""
        && !(good ? nodesFromCrates)
        && builtins.length derived.nodes == 2
      then
        [ ]
      else
        [ "nodes-from-crates-not-emitted" ]
    )
    ++ builtins.filter (name: !(fails cases.${name})) (builtins.attrNames cases);
in
if wrong == [ ] then
  {
    passed = builtins.length (builtins.attrNames cases) + 9;
    # Exposed so one case can be evaluated alone to read its message.
    inherit cases;
  }
else
  abort "keel library: these wrong models evaluated without error: ${builtins.concatStringsSep ", " wrong}"
