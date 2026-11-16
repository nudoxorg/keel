# The Keel model library: the product described once, as one evaluated value.
# Pure Nix with no nixpkgs, so evaluating a model costs milliseconds and can
# run before anything is built. Everything here produces data; the engine
# resolves selectors against the code index and reports back by `at`.
#
# The library is fail-closed: a field it does not know, a path that does not
# exist, a world named twice or a control that changes nothing is an error at
# evaluation. A model that evaluates says only what its author wrote.
let
  inherit (builtins)
    all
    any
    attrNames
    attrValues
    concatLists
    concatMap
    concatStringsSep
    elem
    filter
    foldl'
    head
    isAttrs
    isFloat
    isFunction
    isInt
    isList
    isString
    length
    listToAttrs
    map
    mapAttrs
    match
    pathExists
    unsafeGetAttrPos
    ;

  # One fail-closed gate, the same shape the backend's control plane uses:
  # the first false condition throws the context and its message.
  #
  # Rules are tried in order and nothing after the first failure is
  # evaluated. A later rule may therefore assume the earlier ones hold (that
  # a field exists, that a value is a list); without that, a wrong model
  # would die inside a rule with Nix's own error and not with ours.
  demand =
    context: rules: value:
    let
      failed = foldl' (
        found: rule:
        if found != null then
          found
        else if rule.cond then
          null
        else
          rule.message
      ) null rules;
    in
    if failed == null then value else throw "keel: ${context}: ${failed}";

  unique = foldl' (seen: x: if elem x seen then seen else seen ++ [ x ]) [ ];

  tagged = tag: value: isAttrs value && (value._keel or null) == tag;
  isNode = tagged "node";
  isWorld = tagged "world";
  isTests = tagged "tests";
  isSelector = value: isAttrs value && value ? by;

  where =
    attrs: name:
    let
      pos = unsafeGetAttrPos name attrs;
    in
    if pos == null then "unknown position" else "${pos.file}:${toString pos.line}";

  # A misspelt field must not evaluate to its default. `nevr = [ m.desktop ]`
  # would otherwise be an architecture law that silently says nothing.
  known =
    what: allowed: attrs:
    map (name: {
      cond = false;
      message = "unknown field `${name}` in ${what} (${where attrs name}). Known fields: ${concatStringsSep ", " allowed}.";
    }) (filter (name: !(elem name allowed)) (attrNames attrs));

  # ── Selectors: what code a node owns ──────────────────────────────────
  # Data only. `pattern` is an ast-grep style matcher over the syntax tree,
  # so "every #[tool] function" is one line and stays true as tools appear.
  # `option` and `drv` are how a NixOS fleet owns things: by option path and
  # by derivation output, whose store path is already an exact content key.
  select = {
    crate = name: {
      by = "crate";
      inherit name;
    };
    path = glob: {
      by = "path";
      inherit glob;
    };
    module = path: {
      by = "module";
      inherit path;
    };
    pattern = language: pattern: {
      by = "pattern";
      inherit language pattern;
    };
    option = path: {
      by = "option";
      inherit path;
    };
    drv = attr: {
      by = "drv";
      inherit attr;
    };
    # A path inside what another selector names: `within (drv "jdk")
    # "bin/javac"`. Keyed by the outer selector.
    within = of: path: {
      by = "within";
      inherit of path;
    };
    # A path inside a world's own state, which does not exist until the
    # world is built: `state "owner.sock"`. The driver puts the real path
    # in; it is no part of any key, because the world's key already covers
    # how that state came to be.
    state = path: {
      by = "state";
      inherit path;
    };
    # A file that can change no build and no test, and why. Only for
    # `policy.inert`.
    inert = glob: reason: {
      by = "path";
      inherit glob reason;
    };
  };

  # The part of a glob before its first wildcard, cut back to a directory.
  # If that does not exist, the glob can never match and says nothing.
  literalPrefix =
    glob:
    let
      cut = match "([^*?[{]*)/[^/]*[*?[{].*" glob;
      bare = match "[^*?[{]*" glob;
    in
    if bare != null then
      glob
    else if cut != null then
      head cut
    else
      "";

  # A path that is absolute or climbs out with `..` would be checked against
  # some other tree than the one the model describes.
  inside =
    glob:
    isString glob && glob != "" && match "/.*" glob == null && match "(.*/)?\\.\\.(/.*)?" glob == null;
  exists = root: glob: inside glob && pathExists (root + "/${literalPrefix glob}");

  # ── Test sets: an algebra, never a list ───────────────────────────────
  # Nobody enumerates tests. Policy, placement and quarantine all speak in
  # sets that the engine evaluates against whatever tests exist today.
  #
  # A test's parts are the nodes whose code it reaches. Its tops are the
  # parts no other of its parts stands on: what the test is about, as
  # opposed to what it merely passes through.
  #   on n    every test with a part at or under n. A search test is `on
  #           store`, because search stands on the store.
  #   only n  every test whose tops all lie at or under n. This is the set
  #           that is safe to subtract: nothing in it is also about
  #           something else.
  testSet =
    op: args:
    {
      _keel = "tests";
      inherit op;
    }
    // args;
  mentions =
    op: set:
    set.op == op
    || any (mentions op) (set.sets or [ ])
    || (set ? left && (mentions op set.left || mentions op set.right));
  # Every `under` glob a set mentions, however it is combined.
  underGlobs =
    set:
    (if set.op == "under" then [ set.glob ] else [ ])
    ++ concatMap underGlobs (set.sets or [ ])
    ++ (if set ? left then underGlobs set.left ++ underGlobs set.right else [ ]);
  tests = {
    all = testSet "all" { };
    under = glob: testSet "under" { inherit glob; };
    named = glob: testSet "named" { inherit glob; };
    inPackage = name: testSet "package" { inherit name; };
    reaching = selector: testSet "reaching" { inherit selector; };
    on = node: testSet "node" { node = node.id; };
    only = node: testSet "only" { node = node.id; };
    union = sets: testSet "union" { inherit sets; };
    both = sets: testSet "both" { inherit sets; };
    minus =
      left: right:
      demand "tests.minus"
        [
          {
            cond = !(mentions "node" right || mentions "reaching" right);
            message = "the subtracted set uses `on` or `reaching`, which would also remove every test that is about something else and merely passes through. Subtract `tests.only <node>`: the tests that are about that node and nothing beside it.";
          }
        ]
        (
          testSet "minus" {
            inherit left right;
          }
        );
  };

  # ── Ship policy ───────────────────────────────────────────────────────
  required = {
    ship = "required";
  };
  # A declaration of intent, not a licence. The engine treats a may-lag
  # node as required until its predictions pass the calibration gate, and
  # reads the policy from the base commit, never from the change under test.
  mayLag =
    spec:
    demand "mayLag"
      (
        known "mayLag" [ "atMostMinutes" "confidence" ] spec
        ++ [
          {
            cond = isInt (spec.atMostMinutes or null) && spec.atMostMinutes > 0;
            message = "`atMostMinutes` is a whole number of minutes, for example 120. It is how long the surface may stay unproven after merge before the merge is reverted.";
          }
          {
            cond = isFloat (spec.confidence or null) && spec.confidence >= 0.95 && spec.confidence < 1.0;
            message = "`confidence` must be at least 0.95 and below 1. Below that the calibration gate cannot tell a good estimate from a lucky one; use `required`.";
          }
        ]
      )
      {
        ship = "may-lag";
        lag = {
          inherit (spec) atMostMinutes confidence;
        };
      };

  node = spec: spec // { _keel = "node"; };

  # ── Worlds: start states, built once and forked ───────────────────────
  # `inputs` is what the kept state was computed from. The engine keys the
  # snapshot by them, by `step` and by the parent's key; a world kept
  # without inputs would be a snapshot nothing can ever invalidate.
  worldFields = [
    "name"
    "about"
    "from"
    "step"
    "keep"
    "inputs"
    "maxAgeMinutes"
    "machines"
    "env"
    "tools"
    "network"
    "readyWithin"
  ];
  world =
    spec:
    let
      keep = spec.keep or "run";
    in
    demand "world ${spec.name or "<unnamed>"} (${where spec "name"})"
      (
        known "world" worldFields spec
        ++ [
          {
            cond = spec ? name && isString spec.name && match "[a-z0-9][a-z0-9._-]*" spec.name != null;
            message = "a world needs a `name` of lower-case letters, digits, dots and dashes; it is how reports and cached snapshots refer to it.";
          }
          {
            cond = elem keep [
              "run"
              "directory"
              "service"
              "machine"
            ];
            message = "`keep` is one of run, directory, service, machine.";
          }
          {
            cond = isList (spec.step or null) && all isString spec.step && spec.step != [ ];
            message = "`step` is the command that turns the parent world into this one, as a list of strings.";
          }
          {
            cond = !(spec ? from) || isWorld spec.from;
            message = "`from` holds something that is not a world.";
          }
          {
            cond = keep == "run" || (isList (spec.inputs or null) && spec.inputs != [ ]);
            message = "a world that is kept (`keep = \"${keep}\"`) lists its `inputs`: the selectors and files its state was computed from, for example `inputs = [ (crate \"backend-locald\") (path \"tests/fixtures/**\") ]`. They are what makes a stale snapshot detectable.";
          }
          {
            cond = all isSelector (spec.inputs or [ ]);
            message = "`inputs` holds selectors: crate, path, module, pattern, option or drv.";
          }
          {
            cond =
              !(spec ? machines)
              || (
                isList spec.machines
                && spec.machines != [ ]
                && all (name: isString name && name != "") spec.machines
                && unique spec.machines == spec.machines
              );
            message = "`machines` is a non-empty list of distinct machine names.";
          }
          {
            # A process in a world sees these variables and no others. The
            # value is text, or a selector whose content then keys the world.
            cond =
              isAttrs (spec.env or { })
              && all (
                name:
                match "[A-Za-z_][A-Za-z0-9_]*" name != null
                && (isString spec.env.${name} || isSelector spec.env.${name})
              ) (attrNames (spec.env or { }));
            message = "`env` maps variable names to text or to a selector, for example `env = { NUDOX_CLANG = within (drv \"clang\") \"bin/clang\"; SOCKET = state \"owner.sock\"; }`. Whatever is not listed here does not exist for a process in this world.";
          }
          {
            cond = all (
              s:
              !(isSelector s)
              || !(elem s.by [
                "within"
                "state"
              ])
              || (
                inside s.path
                && (
                  s.by == "state"
                  || (
                    isSelector s.of
                    && !(elem s.of.by [
                      "within"
                      "state"
                    ])
                  )
                )
              )
            ) (attrValues (spec.env or { }) ++ (spec.tools or [ ]) ++ (spec.inputs or [ ]));
            message = "`within` takes a selector and a relative path inside it; `state` takes a relative path inside the world's state. Neither may be absolute, climb out with `..`, or nest.";
          }
          {
            # State is made by the world; it cannot also be what the world
            # was made from, nor a program found before the world exists.
            cond = all (s: !(isSelector s) || s.by != "state") ((spec.tools or [ ]) ++ (spec.inputs or [ ]));
            message = "`state` paths may appear in `env` only.";
          }
          {
            cond = isList (spec.tools or [ ]) && all isSelector (spec.tools or [ ]);
            message = "`tools` lists the programs a process in this world may find on its PATH, as selectors: `drv \"go\"`, or `crate \"backend-cli\"` for the binaries that crate builds.";
          }
          {
            cond = builtins.isBool (spec.network or false);
            message = "`network` is true or false. It is false unless the world says otherwise, and a check that reaches the network in a world without it fails.";
          }
          {
            # What the scheduler prices the world at before it has been
            # measured, and when the driver stops waiting and reports `hung`.
            cond = !(spec ? readyWithin) || positive spec.readyWithin;
            message = "`readyWithin` is whole seconds above zero: how long this world's step may take before it is given up as hung.";
          }
          {
            cond = (spec.about or "x") != "";
            message = "`about` is left out or says something.";
          }
          {
            # A check that runs `at` a machine, or a fault aimed at one, can
            # only be held to the world's machines if the world names them.
            cond =
              keep != "machine"
              || spec ? machines
              || (spec ? from && isWorld spec.from && spec.from.machines != null);
            message = "a world kept as machines says which: `machines = [ \"ilo\" \"ilo-prod\" ]`, here or on the world it is built from.";
          }
        ]
      )
      {
        _keel = "world";
        inherit (spec) name step;
        inherit keep;
        # Inherited: forking a world does not add or remove machines unless
        # the fork says so.
        machines = spec.machines or (if spec ? from && isWorld spec.from then spec.from.machines else null);
        # A fork sees what its parent saw unless it says otherwise: variables
        # are overridden by name, tools are added, the network is restated.
        env = (if spec ? from && isWorld spec.from then spec.from.env else { }) // (spec.env or { });
        tools = unique (
          (if spec ? from && isWorld spec.from then spec.from.tools else [ ]) ++ (spec.tools or [ ])
        );
        network = spec.network or (if spec ? from && isWorld spec.from then spec.from.network else false);
        readyWithin = spec.readyWithin or null;
        about = spec.about or null;
        inputs = spec.inputs or [ ];
        maxAgeMinutes = spec.maxAgeMinutes or null;
        at = where spec "name";
        parent = spec.from or null;
        from = if spec ? from then spec.from.name else null;
      };

  # ── Matrices: one law, many cells ─────────────────────────────────────
  # `over` names the dimensions; every combination that `when` admits is a
  # check. Controls are transformations of a cell, so each cell gets its
  # wrong-configuration twins without anyone writing them.
  cartesian =
    dims:
    foldl' (
      cells: name: concatMap (cell: map (value: cell // { ${name} = value; }) dims.${name}) cells
    ) [ { } ] (attrNames dims);

  # Cell names become check ids, so a value that contained the separators
  # could make two cells share one id.
  scalar = value: isInt value || (isString value && match "[A-Za-z0-9._:/@+-]+" value != null);
  cellName =
    cell: concatStringsSep "," (map (name: "${name}=${toString cell.${name}}") (attrNames cell));

  matrixFields = [
    "over"
    "when"
    "world"
    "run"
    "expect"
    "on"
    "at"
    "as"
    "coordinates"
    "inputs"
    "controls"
    "uncontrolled"
    "faults"
    "together"
  ];
  # ── Faults: the world is changed and the system must hold ────────────
  # A control changes the request and must be refused. A fault changes the
  # world under a correct request, and the check states what must stay
  # true while it lasts and how soon everything is true again afterwards.
  # Kinds are data so that a driver implements each exactly once.
  faultKinds = [
    "stop"
    "kill"
    "pause"
    "restart"
    "reboot"
    "oom-kill"
    "partition"
    "drop"
    "delay"
    "corrupt"
    "dns-wrong"
    "dns-nxdomain"
    "clock-skew"
    "disk-full"
    "certificate-expired"
    "certificate-rotated"
    "credential-rotated"
    "credential-revoked"
    "dependency-slow"
    "dependency-error"
    "boot-order"
    "power-loss"
    "custom"
  ];
  faultFields = [
    "name"
    "kind"
    "target"
    "at"
    "hold"
    "during"
    "after"
    "recoverWithin"
    "inject"
    "heal"
    "breaks"
  ];
  positive = value: isInt value && value > 0;
  # The program is named; `true` and the empty string run nothing.
  argv =
    value:
    isList value
    && value != [ ]
    && all isString value
    && !(elem (head value) [
      ""
      "true"
      ":"
    ]);
  # Every clause says something: no empty key, no null, no empty text.
  stated =
    value:
    isAttrs value
    && value != { }
    && all (name: name != "" && value.${name} != null && value.${name} != "") (attrNames value);
  # What each kind of fault needs to know to be injected. Checked here so a
  # driver never has to guess, and so two models cannot spell one fault two
  # ways.
  targetRules =
    let
      str = value: isString value && value != "";
      has = fields: target: all (name: target ? ${name}) fields;
      only = fields: target: all (name: elem name fields) (attrNames target);
      exactly = fields: target: has fields target && only fields target;
      oneOf = names: target: length (filter (name: target ? ${name}) names) == 1;
      unit = {
        shape = "`{ host; service; }` or `{ host; unit; }`, with exactly one of service and unit";
        ok =
          t:
          only [ "host" "service" "unit" ] t
          && str (t.host or null)
          && oneOf [ "service" "unit" ] t
          && str (t.service or t.unit or null);
      };
      link = extra: check: {
        shape = "`{ host; port; proto = \"tcp\" or \"udp\"; direction = \"in\", \"out\" or \"both\"; ${extra}; }`";
        ok =
          t:
          exactly [ "host" "port" "proto" "direction" extra ] t
          && str t.host
          && isInt t.port
          && t.port > 0
          && t.port < 65536
          && elem t.proto [
            "tcp"
            "udp"
          ]
          && elem t.direction [
            "in"
            "out"
            "both"
          ]
          && check t.${extra};
      };
      percent = value: isInt value && value > 0 && value <= 100;
      named = field: {
        shape = "`{ host; ${field}; }`";
        ok = t: exactly [ "host" field ] t && str t.host && str t.${field};
      };
    in
    {
      stop = unit;
      kill = unit;
      pause = unit;
      restart = unit;
      oom-kill = unit;
      reboot = {
        shape = "`{ host; }`";
        ok = t: exactly [ "host" ] t && str t.host;
      };
      # The machine loses power: what was written and not yet flushed is
      # gone. A process exit cannot show this, because the page cache
      # outlives the process. The driver records block writes under `path`
      # and replays every prefix up to each flush; `after` must hold for
      # each of them.
      power-loss = {
        shape = "`{ host; path; }`, path the absolute mount point whose writes are recorded";
        ok = t: exactly [ "host" "path" ] t && str t.host && isString t.path && match "/.*" t.path != null;
      };
      boot-order = {
        shape = "`{ host; first = [ units ]; }`";
        ok =
          t:
          exactly [ "host" "first" ] t && str t.host && isList t.first && t.first != [ ] && all str t.first;
      };
      partition = {
        shape = "`{ between = [ hostA hostB ]; }`, two different hosts";
        ok =
          t:
          exactly [ "between" ] t
          && isList t.between
          && length t.between == 2
          && all str t.between
          && head t.between != builtins.elemAt t.between 1;
      };
      drop = link "percent" percent;
      corrupt = link "percent" percent;
      delay = link "milliseconds" positive;
      dns-nxdomain = named "name";
      dns-wrong = {
        shape = "`{ host; name; answer; }`";
        ok = t: exactly [ "host" "name" "answer" ] t && str t.host && str t.name && str t.answer;
      };
      clock-skew = {
        shape = "`{ host; seconds; }`, seconds a non-zero whole number";
        ok = t: exactly [ "host" "seconds" ] t && str t.host && isInt t.seconds && t.seconds != 0;
      };
      disk-full = {
        shape = "`{ host; path; }`, path absolute";
        ok = t: exactly [ "host" "path" ] t && str t.host && isString t.path && match "/.*" t.path != null;
      };
      certificate-expired = named "name";
      certificate-rotated = named "name";
      credential-rotated = named "secret";
      credential-revoked = named "secret";
      dependency-slow = {
        shape = "`{ host; service; milliseconds; }`";
        ok =
          t:
          exactly [ "host" "service" "milliseconds" ] t
          && str t.host
          && str t.service
          && positive t.milliseconds;
      };
      dependency-error = {
        shape = "`{ host; service; status; }`, status an HTTP status from 400 to 599";
        ok =
          t:
          exactly [ "host" "service" "status" ] t
          && str t.host
          && str t.service
          && isInt t.status
          && t.status >= 400
          && t.status < 600;
      };
    };
  controlFields = [
    "name"
    "alter"
    "expect"
    "breaks"
  ];
  # What a control or a fault takes away. A check that lists two nodes in
  # `on` has shown nothing about the pair; it shows something when taking
  # one of them away makes it fail. `breaks` names that one, and it is what
  # lets a check count as evidence for a stands-on edge.
  brokenBy =
    what: on: cell: given:
    let
      value = if isFunction given then given cell else given;
      # A node is taken away (a unit stopped), or the path between two nodes
      # is (a partition, a name that no longer resolves): the second names
      # the pair and breaks neither end.
      pair = isAttrs value && attrNames value == [ "edge" ];
      nodes = if pair then value.edge else [ value ];
    in
    demand what [
      {
        cond = !pair || (isList value.edge && length value.edge == 2);
        message = "`breaks = { edge = [ m.a m.b ]; }` names exactly two nodes.";
      }
      {
        cond = all isNode nodes;
        message = "`breaks` holds a node, or `{ edge = [ m.a m.b ]; }`; something here is not a node.";
      }
      {
        cond = all (node: any (n: n.id == node.id) on) nodes;
        message = "`breaks` names ${
          concatStringsSep ", " (map (n: n.id) nodes)
        }, not all of which this cell is `on`. A control can only show a dependency on something the check says it stands on.";
      }
      {
        cond = !pair || (head nodes).id != (builtins.elemAt nodes 1).id;
        message = "an edge joins two different nodes.";
      }
    ] (if pair then { edge = map (n: n.id) nodes; } else { node = value.id; });

  matrix =
    spec:
    let
      cells = filter (spec.when or (_: true)) (cartesian spec.over);
      controlsOf =
        cell:
        let
          given = spec.controls or [ ];
        in
        if isFunction given then given cell else given;
      # `expect`, `at` and `as` may each be a plain value or depend on the cell.
      per = value: cell: if isFunction value then value cell else value;
      worldOf = cell: if spec ? world then spec.world cell else null;
      twin =
        cell: control:
        let
          altered = control.alter cell;
        in
        demand "control ${control.name or "<unnamed>"} on cell ${cellName cell}"
          (
            known "control" controlFields control
            ++ [
              {
                cond = control ? name && control ? alter && control ? expect;
                message = "a control has a `name`, an `alter` (cell to cell) and an `expect`.";
              }
              {
                cond = isString control.name && match "[a-z][a-z0-9-]*" control.name != null;
                message = "a control's name is lower-case words joined by dashes; it becomes part of the check's id.";
              }
              {
                cond = per control.expect cell != per spec.expect cell;
                message = "the control expects exactly what the check expects, so it cannot show the check able to fail.";
              }
              {
                cond = altered != cell;
                message = "`alter` returns the cell unchanged, so this twin is the check itself and proves nothing. Change the one thing that must make the check fail.";
              }
              {
                cond = !(admitted altered);
                message = "`alter` turns this cell into another cell of the same matrix, which is expected to pass. A control must leave the matrix.";
              }
              {
                # Altering a field nothing reads leaves the same command in
                # the same place: the check under another name.
                cond =
                  spec.run altered != spec.run cell
                  || worldOf altered != worldOf cell
                  || (spec ? at && per spec.at altered != per spec.at cell)
                  || (spec ? as && per spec.as altered != per spec.as cell);
                message = "the twin runs exactly what the check runs, in the same world and place: `alter` changed a field that `run`, `world`, `at` and `as` do not read.";
              }
              {
                cond =
                  argv (spec.run altered)
                  && (per spec.inputs altered) != [ ]
                  && all isSelector (per spec.inputs altered);
                message = "for the altered cell, `run` must still be a command (a list of strings) and `inputs` must still name what it reads.";
              }
              {
                cond = stated (per control.expect cell);
                message = "a control's `expect` is a non-empty attribute set saying how the refusal looks.";
              }
            ]
          )
          (
            instance cell control altered
            // {
              breaks =
                if control ? breaks then
                  brokenBy "control ${control.name} on cell ${cellName cell}" (spec.on cell) cell control.breaks
                else
                  null;
            }
          );
      # A name that is not one of the world's machines is a typo that
      # would otherwise reach the driver as a host that never answers.
      machinesOf =
        world:
        if world == null || world.machines == null then
          "it names none"
        else
          concatStringsSep ", " world.machines;
      absent =
        world: hosts:
        # No world, or a world that names no machines, has none: any
        # machine named against it is absent.
        filter (
          host: host != null && !(world != null && world.machines != null && elem host world.machines)
        ) hosts;
      instance =
        cell: control: actual:
        demand "check on cell ${cellName cell}" [
          {
            cond = absent (worldOf actual) [ (if spec ? at then per spec.at actual else null) ] == [ ];
            message = "`at` names ${
              toString (if spec ? at then per spec.at actual else null)
            }, which is not a machine of world ${(worldOf actual).name or ""} (${machinesOf (worldOf actual)}).";
          }
        ] (instanceOf cell control actual);
      instanceOf = cell: control: actual: {
        cell = cellName cell;
        dims = cell;
        control = if control == null then null else control.name;
        breaks = null;
        run = spec.run actual;
        expect = if control == null then per spec.expect cell else per control.expect cell;
        world = if worldOf actual == null then null else (worldOf actual).name;
        at = if spec ? at then per spec.at actual else null;
        as = if spec ? as then per spec.as actual else null;
        # A check that names one node twice stands on it once.
        on = unique (map (n: n.id) (spec.on cell));
        # Where the check sits on the model's axes; validated against the
        # declared axes when the model is assembled.
        coordinates = if spec ? coordinates then per spec.coordinates cell else { };
        # What the check's result is keyed by beyond its own text and its
        # world: the probe that runs it, the fixtures it reads.
        inputs = per spec.inputs actual;
        faults = [ ];
        # Cells with one key here are run by one invocation of the probe,
        # which reports each by its id: a table of six hundred rows is one
        # process, and still six hundred results, each keyed and reused alone.
        together = if spec ? together then toString (spec.together actual) else null;
      };
      uncontrolled = filter (cell: controlsOf cell == [ ]) cells;
      faultsOf =
        cell:
        let
          given = spec.faults or [ ];
        in
        if isFunction given then given cell else given;
      faulted =
        cell: fault:
        let
          kind = fault.kind or null;
          target = fault.target or { };
          during = fault.during or { };
          verdict = attrNames during;
          said = if length verdict == 1 then head verdict else null;
          bound =
            if
              elem said [
                "degradesTo"
                "refuses"
              ]
              && isAttrs during.${said}
            then
              during.${said}.within or null
            else
              null;
          rule = targetRules.${kind} or null;
        in
        demand "fault ${fault.name or "<unnamed>"} on cell ${cellName cell}"
          (
            known "fault" faultFields fault
            ++ [
              {
                cond = isString (fault.name or null) && match "[a-z][a-z0-9-]*" fault.name != null;
                message = "a fault needs a `name` of lower-case words joined by dashes.";
              }
              {
                cond = elem kind faultKinds;
                message = "`kind` is one of: ${concatStringsSep ", " faultKinds}. A kind the driver does not know cannot be injected; use `custom` with `inject` and `heal` commands if none fits.";
              }
              {
                cond = kind != "custom" || (argv (fault.inject or null) && argv (fault.heal or null));
                message = "a `custom` fault gives `inject` and `heal`, each a command as a list of strings. A fault that cannot be healed leaves the world broken for the checks after it.";
              }
              {
                cond = kind == "custom" || !(fault ? inject || fault ? heal || fault ? at);
                message = "`inject`, `heal` and `at` belong to `custom` faults only; a named kind is implemented by the driver and happens where its `target` says.";
              }
              {
                cond = rule == null || (isAttrs target && rule.ok target);
                message = "the target of a `${toString kind}` fault is ${rule.shape or ""}.";
              }
              {
                cond = positive (fault.hold or null) && positive (fault.recoverWithin or null);
                message = "`hold` and `recoverWithin` are whole seconds greater than zero: how long the fault lasts, and how long the system has to be right again after it is healed.";
              }
              {
                # "Anything may happen during the fault" is the tautology
                # this field exists to forbid.
                cond =
                  said == "holds" && during.holds == true
                  ||
                    said == "down"
                    && during.down == true
                    && elem kind [
                      "reboot"
                      "power-loss"
                    ]
                  ||
                    elem said [
                      "degradesTo"
                      "refuses"
                    ]
                    && isAttrs during.${said}
                    &&
                      attrNames during.${said} == [
                        "expect"
                        "within"
                      ]
                    && isAttrs during.${said}.expect
                    && during.${said}.expect != { };
                message = "`during` says exactly one thing: `{ holds = true; }` (the check keeps passing), or `{ degradesTo = { expect = …; within = <seconds>; }; }`, or `{ refuses = { expect = …; within = <seconds>; }; }`. For `reboot` and `power-loss` alone it may be `{ down = true; }`: nothing answers, and everything is said by `after`. It may not be left open.";
              }
              {
                # Without a deadline, a caller that hangs until the fault is
                # healed would count as having been refused.
                cond = bound == null || (positive bound && positive (fault.hold or null) && bound < fault.hold);
                message = "`within` is whole seconds, greater than zero and less than `hold`: the answer must come while the fault still lasts.";
              }
              {
                cond =
                  !(isAttrs target)
                  ||
                    absent (worldOf cell) (
                      (if target ? host then [ target.host ] else [ ])
                      ++ (if isList (target.between or null) then target.between else [ ])
                    ) == [ ];
                message = "the target names a host that is not a machine of world ${(worldOf cell).name or ""} (${machinesOf (worldOf cell)}).";
              }
            ]
          )
          (
            instance cell null cell
            // {
              # A fault forks the world for itself, so it never shares a run.
              together = null;
              breaks =
                if fault ? breaks then
                  brokenBy "fault ${fault.name} on cell ${cellName cell}" (spec.on cell) cell fault.breaks
                else
                  null;
              # A list, because faults compose (restarted while partitioned)
              # even though one check carries one today. The driver adds a
              # verdict the model cannot waive: a probe still running when
              # the fault is healed is `hung`, which is not a wrong answer.
              faults = [
                {
                  inherit (fault)
                    name
                    kind
                    hold
                    recoverWithin
                    during
                    ;
                  inherit target;
                  at = if kind == "custom" then fault.at or null else target.host or null;
                  # Unless said otherwise, healed means the plain check passes again.
                  after = fault.after or (per spec.expect cell);
                  inject = fault.inject or null;
                  heal = fault.heal or null;
                }
              ];
            }
          );
      names = map cellName cells;
      # Looked up by id: scanning the cell list for every twin made a
      # matrix of n cells cost n squared.
      byName = listToAttrs (
        map (name: {
          inherit name;
          value = true;
        }) names
      );
      admitted = cell: all (name: scalar cell.${name}) (attrNames cell) && byName ? ${cellName cell};
      # Sorted, so that a matrix of a hundred thousand cells is still checked.
      repeated =
        list:
        let
          sorted = builtins.sort builtins.lessThan list;
        in
        unique (
          concatLists (
            builtins.genList (
              i:
              if builtins.elemAt sorted i == builtins.elemAt sorted (i + 1) then
                [ (builtins.elemAt sorted i) ]
              else
                [ ]
            ) (if sorted == [ ] then 0 else length sorted - 1)
          )
        );
    in
    demand "matrix"
      (
        known "matrix" matrixFields spec
        ++ [
          {
            cond = spec ? over && spec ? run && spec ? expect && spec ? on;
            message = "a matrix needs `over`, `run`, `expect` and `on`.";
          }
          {
            cond = all (cell: argv (spec.run cell) && stated (per spec.expect cell)) cells;
            message = "`run` gives a command as a list of strings for every cell, and `expect` a non-empty attribute set. A shell string or a free-text expectation cannot be checked.";
          }
          {
            cond = all (cell: isList (spec.on cell) && spec.on cell != [ ] && all isNode (spec.on cell)) cells;
            message = "`on` gives, for every cell, a non-empty list of nodes of this model (`[ m.search m.cli ]`).";
          }
          {
            cond =
              spec ? inputs
              && all (cell: (per spec.inputs cell) != [ ] && all isSelector (per spec.inputs cell)) cells;
            message = "a matrix lists its `inputs`: selectors for the program that runs the check and the files it reads, for example `inputs = [ (crate \"surface-probe\") ]`. Without them, editing the probe would reuse every old result.";
          }
          {
            cond = all (name: all scalar spec.over.${name}) (attrNames (spec.over or { }));
            message = "dimension values are integers or strings of letters, digits and `. _ : / @ + -`, because they are joined into check ids and printed in reports.";
          }
          {
            cond = !(spec ? together) || all (cell: scalar (spec.together cell)) cells;
            message = "`together` gives, for a cell, the name of the run it shares: an integer or a string of letters, digits and `. _ : / @ + -`.";
          }
          {
            cond = cells != [ ];
            message = "no cell is admitted: a dimension is empty or `when` rejects everything. A law over nothing checks nothing.";
          }
          {
            # 1 and \"1\" print alike, and so would a value listed twice.
            cond = repeated names == [ ];
            message = "two cells share the id ${concatStringsSep ", " (repeated names)}. Dimension values must be distinct once printed.";
          }
          {
            cond = all (
              cell:
              repeated (map (c: c.name or "") (controlsOf cell) ++ map (f: f.name or "") (faultsOf cell)) == [ ]
            ) cells;
            message = "two controls or faults of one cell share a name; the name is part of the check's id, and a control and a fault may not share one either.";
          }
          {
            cond = uncontrolled == [ ] || (isString (spec.uncontrolled or null) && spec.uncontrolled != "");
            message = "${toString (length uncontrolled)} cells have no control (first: ${
              if uncontrolled == [ ] then "" else cellName (head uncontrolled)
            }). A check with no twin that must fail cannot show it is able to fail. Add `controls`, or say why not with `uncontrolled = \"<reason>\"`.";
          }
        ]
      )
      {
        _keel = "matrix";
        dimensions = mapAttrs (_: length) spec.over;
        uncontrolled = spec.uncontrolled or null;
        # Twins start somewhere too: a control that alters a dimension the
        # world depends on needs that world to exist.
        worlds = filter (w: w != null) (
          concatMap (cell: [ (worldOf cell) ] ++ map (c: worldOf (c.alter cell)) (controlsOf cell)) cells
        );
        checks = concatMap (
          cell:
          [ (instance cell null cell) ]
          ++ map (twin cell) (controlsOf cell)
          ++ map (faulted cell) (faultsOf cell)
        ) cells;
      };

  # ── The model: a fixed point, so nodes refer to each other as values ──
  # A reference to a node that does not exist is a Nix evaluation error at
  # the line that wrote it. Nothing can dangle by spelling.
  annotate =
    trail: parent: name: value:
    if isNode value then
      let
        id = concatStringsSep "." (trail ++ [ name ]);
      in
      mapAttrs (annotate (trail ++ [ name ]) value) value
      // {
        inherit id;
        _keel = "node";
        segment = name;
        at = where parent name;
        # Found here, where the author's own attribute set still carries
        # positions, and reported by `emit`.
        unknown = map (field: "`${field}` (${where value field})") (
          filter (field: !(elem field nodeFields) && !(isNode value.${field})) (attrNames value)
        );
      }
    else
      value;

  nodeFields = [
    "about"
    "code"
    "entry"
    "on"
    "never"
    "of"
    "ship"
    "lag"
    "movedBy"
    "unmovedBy"
    "source"
    "_keel"
  ];

  flatten =
    root: parent: value:
    concatLists (
      map (
        name:
        let
          child = value.${name};
        in
        if isNode child then [ (emit root parent child) ] ++ flatten root child.id child else [ ]
      ) (attrNames value)
    );

  refs =
    owner: field:
    unique (
      map (
        target:
        demand "${owner.id} (${owner.at})" [
          {
            cond = isNode target;
            message = "`${field}` holds something that is not a node. Write a node of this model, for example `m.store.wal`.";
          }
        ] target.id
      ) (owner.${field} or [ ])
    );

  missing = root: globs: filter (glob: !(exists root glob)) globs;

  emit =
    root: parent: n:
    let
      selectors = (n.code or [ ]) ++ (n.entry or [ ]);
      globs = map (s: s.glob) (filter (s: isSelector s && s.by == "path") selectors);
      witnesses = (n.movedBy or [ ]) ++ (n.unmovedBy or [ ]);
      gone = missing root (globs ++ witnesses);
    in
    demand "${n.id} (${n.at})"
      ([
        {
          cond = n.unknown == [ ];
          message = "unknown field ${concatStringsSep ", " n.unknown}. Known fields: ${concatStringsSep ", " nodeFields}, and child nodes.";
        }
        {
          # Checked per segment: an attribute named \"a.b\" would otherwise
          # be indistinguishable from the node b inside a.
          cond = match "[a-z][a-z0-9-]*" n.segment != null;
          message = "node names are lower-case words joined by dashes, because they become report lines and file names.";
        }
        {
          cond =
            elem (n.ship or null) [
              null
              "required"
              "may-lag"
            ]
            && ((n.ship or null) != "may-lag" || isAttrs (n.lag or null));
          message = "`ship` is set by merging `required` or `mayLag { … }` into the node, not written by hand.";
        }
        {
          cond = !(elem n.id (refs n "on" ++ refs n "never" ++ refs n "of"));
          message = "a node names itself in `on`, `never` or `of`.";
        }
        {
          cond = all (id: !(elem id (refs n "never"))) (refs n "on" ++ refs n "of");
          message = "a node is named in both `on` (or `of`) and `never`: it cannot be required to stand on something and forbidden to.";
        }
        {
          # A parent is its children taken together; it cannot also stand
          # on one of them.
          cond = all (id: match "${builtins.replaceStrings [ "." ] [ "\\." ] n.id}\\..*" id == null) (
            refs n "on" ++ refs n "of"
          );
          message = "a node names one of its own children in `on` or `of`.";
        }
        {
          cond = all inside (globs ++ witnesses);
          message = "paths are relative to the model's root and may not be absolute or contain `..`.";
        }
        {
          cond = (n.code or [ ]) != [ ] || (n.entry or [ ]) != [ ] || flatten root n.id n != [ ];
          message = "this node owns no code, starts nowhere and contains nothing. Give it `code`, `entry` or a child node, or delete it.";
        }
        {
          cond = all (
            s:
            isSelector s
            && elem s.by [
              "crate"
              "path"
              "module"
              "pattern"
              "option"
              "drv"
            ]
          ) selectors;
          message = "`code` and `entry` hold selectors: crate, path, module, pattern, option or drv. `within` and `state` are for a world's environment and inputs.";
        }
        {
          cond = (n.about or "x") != "" && (n.source or "x") != "";
          message = "`about` and `source` are left out or say something; an empty string is neither.";
        }
        {
          cond = !(n ? ship) || ((n.movedBy or [ ]) != [ ] && (n.unmovedBy or [ ]) != [ ]);
          message = "a node with a ship policy states one path that must move it and one that must not (`movedBy`, `unmovedBy`). Without both, nothing checks that the tree still means what its name says.";
        }
        {
          cond = all isString witnesses;
          message = "`movedBy` and `unmovedBy` hold file paths relative to the repository root.";
        }
        {
          cond = all (path: !(elem path (n.unmovedBy or [ ]))) (n.movedBy or [ ]);
          message = "a path is listed in both `movedBy` and `unmovedBy`; it cannot both move this node and not.";
        }
        {
          # `mayLag` checks these; a node that spells the fields out by
          # hand must not get round it.
          cond =
            (n.ship or null) != "may-lag"
            || (
              isAttrs (n.lag or null)
              && isInt (n.lag.atMostMinutes or null)
              && n.lag.atMostMinutes > 0
              && isFloat (n.lag.confidence or null)
              && n.lag.confidence >= 0.95
              && n.lag.confidence < 1.0
            );
          message = "`lag` must be what `mayLag` produces: whole minutes above zero and a confidence from 0.95 up to, not including, 1.";
        }
        {
          # A witness that names a missing file is satisfied for ever.
          cond = gone == [ ];
          message = "these paths do not exist under the model's root: ${concatStringsSep ", " gone}. A path that matches nothing checks nothing; correct it or delete it.";
        }
      ])
      {
        inherit (n) id at;
        inherit parent;
        # For generated nodes, whose position is one line of a `map`: where
        # a person would go to change this node.
        source = n.source or null;
        about = n.about or null;
        code = n.code or [ ];
        entry = n.entry or [ ];
        on = refs n "on";
        never = refs n "never";
        # Instance-of: this node is that code in one context (a service on
        # one host, of its module). It is moved by what it is an instance
        # of, keyed with it and blamed through it, but the pair is not an
        # interaction, so the coverage law does not ask for a test of it.
        of = refs n "of";
        ship = n.ship or null;
        lag = n.lag or null;
        movedBy = n.movedBy or [ ];
        unmovedBy = n.unmovedBy or [ ];
      };

  reserved = [
    "root"
    "axes"
    "place"
    "checks"
    "worlds"
    "policy"
    "census"
    "nodesFromCrates"
  ];

  policyFields = [
    "deployGate"
    "idle"
    "uncovered"
    "joins"
    "inert"
    "faults"
    "unfaulted"
  ];

  model =
    describe:
    let
      self = mapAttrs (annotate [ ] raw) raw;
      raw = describe self;
      root = raw.root;
      # An axis is its list of values, or `{ values = [ … ]; default = "…"; }` when the tests no
      # rule places are still somewhere: the engine reads the values as lists either way, and
      # the defaults beside them.
      declaredAxes = raw.axes or { };
      axes = mapAttrs (_: axis: if isAttrs axis then axis.values or null else axis) declaredAxes;
      axisDefaults = listToAttrs (
        concatMap (
          name:
          let
            axis = declaredAxes.${name};
          in
          if isAttrs axis && axis ? default then
            [
              {
                inherit name;
                value = axis.default;
              }
            ]
          else
            [ ]
        ) (attrNames declaredAxes)
      );
      nodes = flatten root null (removeAttrs self reserved);

      # `nodesFromCrates = { strip = "backend-"; };` asks the engine for one
      # node per workspace package that no node's `crate` claims, named by the
      # package with `strip` taken off the front. Packages are known to the
      # engine and not to this evaluation, so the library only checks the
      # request and passes it on, with the line that wrote it.
      fromCrates = raw.nodesFromCrates or null;
      fromCratesRules =
        if fromCrates == null then
          [ ]
        else
          [
            {
              cond = isAttrs fromCrates && !(isNode fromCrates);
              message = "`nodesFromCrates` is a set, for example `nodesFromCrates = { strip = \"backend-\"; };`.";
            }
          ]
          ++ (
            if isAttrs fromCrates then
              known "nodesFromCrates" [ "strip" "under" ] fromCrates
              ++ [
                {
                  cond = isString (fromCrates.strip or "") && (fromCrates.strip or "x") != "";
                  message = "`nodesFromCrates.strip` is the text to take off the front of each package name, for example \"backend-\"; leave `strip` out to keep the names whole.";
                }
                {
                  # An allow-list, so a directory that is added to the workspace tomorrow
                  # (a test suite, a dev tool) does not become nodes without anyone saying so.
                  cond =
                    isList (fromCrates.under or null)
                    && fromCrates.under != [ ]
                    && all inside (fromCrates.under or [ ]);
                  message = "`nodesFromCrates.under` is required: the directories, relative to the root, whose packages become nodes, for example `under = [ \"crates/**\" ];`. Packages elsewhere (tests, tools) stay out unless a node claims them.";
                }
                {
                  cond = missing root fromCrates.under == [ ];
                  message = "`nodesFromCrates.under` names a directory that does not exist under the model's root: ${concatStringsSep ", " (missing root fromCrates.under)}.";
                }
              ]
            else
              [ ]
          );

      placement =
        rule:
        let
          coordinates = removeAttrs rule [
            "tests"
            "world"
          ];
          globs =
            if isTests (rule.tests or null) && rule.tests.op == "under" then [ rule.tests.glob ] else [ ];
        in
        demand "place"
          (
            [
              {
                cond = coordinates != { } || rule ? world;
                message = "a placement rule that gives neither a coordinate nor a world does nothing; delete it or finish it.";
              }
              {
                cond = !(rule ? world) || isWorld rule.world;
                message = "`world` holds something that is not a world.";
              }
              {
                cond = isTests (rule.tests or null);
                message = "each placement rule starts from a test set: `tests = tests.under \"tests/journeys/**\"`.";
              }
              {
                # `*go_*` also matches cargo_, ergo_ and algo_, and a report
                # would then say "go is down" when cargo handling broke.
                cond = coordinates == { } || !(mentions "named" rule.tests);
                message = "a rule that selects tests by name may not give them coordinates; names are not evidence of what a test exercises. Use `tests.reaching (crate …)` or `tests.under \"<directory>/**\"`.";
              }
              {
                cond = missing root globs == [ ];
                message = "`tests.under \"${concatStringsSep ", " globs}\"` names a directory that does not exist under the model's root.";
              }
            ]
            ++ map (axis: {
              cond = axes ? ${axis} && elem coordinates.${axis} axes.${axis};
              message = "`${axis} = ${toString coordinates.${axis}}` is not a value of that axis. ${
                if axes ? ${axis} then
                  "Its values: ${concatStringsSep ", " axes.${axis}}."
                else
                  "Declared axes: ${concatStringsSep ", " (attrNames axes)}."
              }";
            }) (attrNames coordinates)
          )
          {
            inherit (rule) tests;
            inherit coordinates;
            world = if rule ? world then rule.world.name else null;
          };

      # A check sits on the axes like any test. A dimension that bears the
      # name of an axis is a coordinate already; `coordinates` adds the
      # ones that are properties of a cell rather than dimensions of it.
      # Each distinct input path is looked for on disk once, however many
      # cells name it.
      present = listToAttrs (
        concatMap (
          m:
          concatMap (
            check:
            map (s: {
              name = s.glob;
              value = exists root s.glob;
            }) (filter (s: s.by == "path") check.inputs)
          ) m.checks
        ) (attrValues (raw.checks or { }))
      );
      # Worlds written under `worlds`, however deeply grouped. A function
      # is a world not yet made and is judged where it is applied; anything
      # else that is no world is kept as null so that it can be refused.
      declaredWorlds =
        let
          walk =
            value:
            if isWorld value then
              [ value ]
            else if isFunction value then
              [ ]
            else if isAttrs value then
              concatMap walk (attrValues value)
            else
              [ null ];
        in
        walk (raw.worlds or { });
      unusedWorlds =
        let
          used = listToAttrs (
            map (w: {
              inherit (w) name;
              value = true;
            }) worlds
          );
        in
        filter (w: w != null && !(used ? ${w.name})) declaredWorlds;
      nodeIds = listToAttrs (
        map (n: {
          name = n.id;
          value = true;
        }) nodes
      );
      located =
        name: check:
        let
          coordinates =
            listToAttrs (
              map (axis: {
                name = axis;
                value = check.dims.${axis};
              }) (filter (axis: axes ? ${axis}) (attrNames check.dims))
            )
            // check.coordinates;
        in
        demand "checks.${name}, cell ${check.cell}" (
          [
            {
              cond = all (
                axis:
                !(check.dims ? ${axis}) || !(axes ? ${axis}) || check.coordinates.${axis} == check.dims.${axis}
              ) (attrNames check.coordinates);
              message = "`coordinates` contradicts a dimension that is itself an axis; the dimension's value is the coordinate.";
            }
            {
              cond = all (id: nodeIds ? ${id}) check.on;
              message = "`on` names a node that is not in this model.";
            }
            {
              cond = all (s: s.by != "path" || present.${s.glob}) check.inputs;
              message = "an input path does not exist under the model's root: ${
                concatStringsSep ", " (
                  map (s: s.glob) (filter (s: s.by == "path" && !present.${s.glob}) check.inputs)
                )
              }.";
            }
          ]
          ++ map (axis: {
            cond = axes ? ${axis} && elem coordinates.${axis} axes.${axis};
            message = "`${axis} = ${toString coordinates.${axis}}` is not a value of that axis. ${
              if axes ? ${axis} then
                "Its values: ${concatStringsSep ", " axes.${axis}}."
              else
                "Declared axes: ${concatStringsSep ", " (attrNames axes)}."
            }";
          }) (attrNames coordinates)
        ) (check // { inherit coordinates; });

      # Worlds are collected from wherever they are used, parents included,
      # so a parameterised world exists exactly for the cells that need it.
      worlds =
        let
          chain = w: if w == null then [ ] else [ w ] ++ chain w.parent;
          used =
            concatMap (m: m.worlds or [ ]) (attrValues (raw.checks or { }))
            ++ concatMap (rule: if rule ? world then [ rule.world ] else [ ]) (raw.place or [ ])
            ++ concatMap (c: if c ? world && isWorld c.world then [ c.world ] else [ ]) (
              attrValues (raw.census or { })
            );
          # One name, one start state. Two different worlds under one name
          # would share a snapshot.
          one =
            name: same:
            let
              first = head same;
              other = filter (w: w != first) same;
            in
            if other == [ ] then
              first
            else
              throw "keel: world ${name}: defined twice with different contents, at ${first.at} and ${(head other).at}. Give them different names, or make them the same world.";
        in
        map (
          w:
          removeAttrs w [
            "_keel"
            "parent"
          ]
        ) (attrValues (mapAttrs one (builtins.groupBy (w: w.name) (concatMap chain used))));

      # `on` and `of` are written by the author, so a cycle among them is a
      # mistake in the model, unlike a cycle the code turns out to have,
      # which the engine reports.
      declaredEdges = listToAttrs (
        map (n: {
          name = n.id;
          value = n.on ++ n.of;
        }) nodes
      );
      cyclic = filter (
        n:
        any (x: x.key == n.id) (
          builtins.genericClosure {
            startSet = map (id: { key = id; }) declaredEdges.${n.id};
            operator = item: map (id: { key = id; }) (declaredEdges.${item.key} or [ ]);
          }
        )
      ) nodes;

      # Two nodes owning the same code would make blame and placement depend
      # on the order nodes happen to be visited in.
      owners = foldl' (
        seen: n:
        foldl' (
          seen: s:
          let
            key = builtins.toJSON s;
          in
          if seen ? ${key} then
            throw "keel: ${n.id} (${n.at}): owns ${key}, which ${seen.${key}} already owns. Code has one owner; put the shared part in a node of its own that both stand on."
          else
            seen // { ${key} = n.id; }
        ) seen n.code
      ) { } nodes;

      # ── Censuses: what is declared against what exists ──────────────────
      # A matrix asks whether one thing behaves. A census asks whether the
      # model's list of things is the list of things: everything of a kind
      # is enumerated (listening sockets in a booted world, files in the
      # tree, foreign functions in the code), and a record on one side
      # with no partner on the other is a finding, in either direction.
      boundaryClasses = [
        "ffi-extern-block"
        "ffi-extern-fn"
        "ffi-no-mangle"
        "ffi-link-attr"
        "ffi-dynamic-load"
        "native-links-key"
        "native-build-script"
        "native-build-tool"
        "native-sys-member"
        "native-sys-dependency"
        "native-source"
        "process-spawn"
        "process-current-exe"
        "net-listen"
        "net-connect"
        "fs-env-path"
        "fs-dirs"
        "fs-tempfile"
        "nondet-time"
        "nondet-random"
        "compile-include"
        "compile-env"
      ];
      censusFields = [
        "about"
        "world"
        "observe"
        "observed"
        "boundary"
        "declared"
        "key"
        "extra"
        "missing"
        "ignore"
        "axes"
        "on"
        "inputs"
      ];
      census =
        name: spec:
        let
          key = spec.key or [ ];
          keyed = record: isAttrs record && all (field: record ? ${field} && scalar record.${field}) key;
          idOf = record: concatStringsSep "," (map (field: "${field}=${toString record.${field}}") key);
          declared = spec.declared or [ ];
          ignore = spec.ignore or [ ];
          ignored =
            record:
            any (
              entry: all (field: (record.${field} or null) == entry.match.${field}) (attrNames entry.match)
            ) ignore;
          byId =
            records:
            listToAttrs (
              map (record: {
                name = idOf record;
                value = record;
              }) records
            );
          seen = byId (filter (r: !(ignored r)) (spec.observed or [ ]));
          said = byId declared;
          level =
            field:
            elem (spec.${field} or "fail") [
              "fail"
              "report"
            ];
        in
        demand "census.${name} (${where raw.census name})"
          (
            known "census" censusFields spec
            ++ [
              {
                cond = match "[a-z][a-z0-9-]*" name != null;
                message = "census names are lower-case words joined by dashes.";
              }
              {
                cond =
                  length (
                    filter (source: spec ? ${source}) [
                      "observe"
                      "observed"
                      "boundary"
                    ]
                  ) == 1;
                message = "a census has exactly one source: `observe` (a command run in the world that prints one JSON record per line), `observed` (a list of records computed while the model is evaluated), or `boundary` (a class of places where the code meets what it does not control, found by the engine in the source).";
              }
              {
                # The engine finds these by syntax; the model says which
                # of them it knows about. Records are keyed by file.
                cond = !(spec ? boundary) || elem spec.boundary boundaryClasses;
                message = "`boundary` is one of: ${concatStringsSep ", " boundaryClasses}.";
              }
              {
                cond = !(spec ? boundary) || !(spec ? world);
                message = "a `boundary` census reads the source tree, not a world; remove `world`.";
              }
              {
                cond = !(spec ? observe) || argv spec.observe;
                message = "`observe` is a command as a list of strings.";
              }
              {
                cond = !(spec ? world) || isWorld spec.world;
                message = "`world` holds something that is not a world.";
              }
              {
                cond = isList key && key != [ ] && all isString key && unique key == key;
                message = "`key` lists the fields that identify a record, for example `key = [ \"host\" \"port\" \"proto\" ]`.";
              }
              {
                cond = isList declared && all keyed declared && all keyed (spec.observed or [ ]);
                message = "every record carries every key field, as an integer or a string without `,` or `=`.";
              }
              {
                cond = length (attrNames said) == length declared;
                message = "two declared records share a key; a census compares sets.";
              }
              {
                # An excuse for something that is no longer there would
                # silently excuse it when it comes back.
                cond =
                  !(spec ? observed)
                  || all (
                    entry:
                    any (
                      record: all (field: (record.${field} or null) == entry.match.${field}) (attrNames entry.match)
                    ) spec.observed
                  ) ignore;
                message = "an `ignore` entry matches no observed record; remove it.";
              }
              {
                cond = level "extra" && level "missing";
                message = "`extra` and `missing` are \"fail\" or \"report\".";
              }
              {
                cond = all (
                  entry:
                  isAttrs entry
                  &&
                    attrNames entry == [
                      "match"
                      "reason"
                    ]
                  && isAttrs entry.match
                  && entry.match != { }
                  && isString entry.reason
                  && entry.reason != ""
                ) ignore;
                message = "each `ignore` entry is `{ match = { field = value; … }; reason = \"…\"; }`. An entry that matches everything, or gives no reason, would switch the census off.";
              }
              {
                # An observation that sees nothing is far more often a
                # broken observation than an empty world.
                cond = !(spec ? observed) || spec.observed != [ ] || declared != [ ];
                message = "nothing is declared and nothing is observed: a census over nothing checks nothing.";
              }
              {
                cond = !(spec ? observed) || spec.observed != [ ] || declared == [ ];
                message = "`observed` is empty while `declared` is not. Either the observation is broken or everything declared is missing; say which by fixing one of them.";
              }
              {
                cond = all (axis: axes ? ${axis} && isString (spec.axes.${axis})) (attrNames (spec.axes or { }));
                message = "`axes` maps a declared axis to the record field that holds its value, for example `axes = { host = \"host\"; }`. Declared: ${concatStringsSep ", " (attrNames axes)}.";
              }
              {
                cond = spec ? inputs && spec.inputs != [ ] && all isSelector spec.inputs;
                message = "a census lists its `inputs`: selectors for what the observation reads or runs. Without them its result could never be reused, or would be reused wrongly.";
              }
            ]
          )
          {
            inherit
              name
              key
              declared
              ignore
              ;
            about = spec.about or null;
            at = where raw.census name;
            world = if spec ? world then spec.world.name else null;
            observe = spec.observe or null;
            boundary = spec.boundary or null;
            extra = spec.extra or "fail";
            missing = spec.missing or "fail";
            axes = spec.axes or { };
            on = unique (map (n: n.id) (spec.on or [ ]));
            inherit (spec) inputs;
            # Known already when the source is a value: the two differences.
            # For a command they are the driver's to compute, by the same rule.
            result =
              if spec ? observed then
                {
                  extra = attrValues (removeAttrs seen (attrNames said));
                  missing = attrValues (removeAttrs said (attrNames seen));
                }
              else
                null;
          };

      policy =
        let
          given = raw.policy or { };
        in
        demand "policy"
          (
            known "policy" policyFields given
            ++ known "policy.idle" [ "mutate" "recheckOneIn" ] (given.idle or { })
            ++ [
              {
                # A set selected by a directory that is not there selects
                # nothing, and a gate of nothing lets everything through.
                cond = all (set: !(isTests set) || missing root (underGlobs set) == [ ]) (
                  (if given ? deployGate then [ given.deployGate ] else [ ])
                  ++ (if (given.idle or { }) ? mutate then [ given.idle.mutate ] else [ ])
                );
                message = "a test set in `policy` selects by a directory that does not exist under the model's root.";
              }
              {
                cond = !(given ? deployGate) || isTests given.deployGate;
                message = "`deployGate` is a test set, for example `tests.minus tests.all (tests.only m.desktop)`.";
              }
              {
                cond =
                  (!((given.idle or { }) ? mutate) || isTests given.idle.mutate)
                  && (!((given.idle or { }) ? recheckOneIn) || positive given.idle.recheckOneIn);
                message = "`idle.mutate` is a test set and `idle.recheckOneIn` a whole number above zero.";
              }
              {
                cond = elem (given.uncovered or "fail") [
                  "fail"
                  "report"
                ];
                message = "`uncovered` is \"fail\" or \"report\".";
              }
            ]
          )
          (
            given
            // {
              # A derived edge A -> B that no test crosses is an untested
              # interaction. Unless the model says otherwise, that fails.
              uncovered = given.uncovered or "fail";
              # Every tracked file has an owner: a node, or the synthetic
              # `unowned`, which everything stands on. `inert` is the one
              # way out, and it is a claim: these files can change no
              # build and no test. It is written here so that it is read
              # from the base commit and reviewed like any other policy.
              inert = demand "policy.inert" [
                {
                  cond = all (s: isSelector s && s.by == "path" && isString (s.reason or null) && s.reason != "") (
                    given.inert or [ ]
                  );
                  message = "`inert` holds entries made with `inert \"<glob>\" \"<reason>\"`, for example `inert \"docs/**\" \"prose; nothing is built from it\"`. A file that changes nothing is a claim, and a claim has a reason.";
                }
                {
                  # `**` would declare the whole repository inert.
                  cond = all (s: literalPrefix (s.glob or "") != "") (given.inert or [ ]);
                  message = "an inert glob must begin with a literal directory or file name; one that begins with a wildcard could excuse anything.";
                }
                {
                  cond = missing root (map (s: s.glob or "") (given.inert or [ ])) == [ ];
                  message = "an inert path does not exist under the model's root: ${
                    concatStringsSep ", " (missing root (map (s: s.glob or "") (given.inert or [ ])))
                  }.";
                }
              ] (given.inert or [ ]);
              # A stands on B: has anything ever taken B away? Unless the
              # model says otherwise, an edge with no fault check on its
              # lower end fails; `unfaulted` excuses one edge with a reason.
              faults = demand "policy.faults" [
                {
                  cond = elem (given.faults or "fail") [
                    "fail"
                    "report"
                  ];
                  message = "`faults` is \"fail\" or \"report\".";
                }
              ] (given.faults or "fail");
              unfaulted = map (
                edge:
                demand "policy.unfaulted"
                  (
                    known "policy.unfaulted entry" [ "from" "to" "reason" ] edge
                    ++ [
                      {
                        cond = isNode (edge.from or null) && isNode (edge.to or null);
                        message = "each entry names an edge by its two nodes: `{ from = m.a; to = m.b; reason = \"…\"; }`.";
                      }
                      {
                        cond = isString (edge.reason or null) && edge.reason != "";
                        message = "an excused edge needs a `reason`.";
                      }
                    ]
                  )
                  {
                    from = edge.from.id;
                    to = edge.to.id;
                    inherit (edge) reason;
                  }
              ) (given.unfaulted or [ ]);
              # Pairs some test or check must exercise together.
              joins = map (
                pair:
                demand "policy.joins"
                  [
                    {
                      cond = length pair >= 2 && length (unique (map (n: n.id or null) pair)) == length pair;
                      message = "a join names at least two different nodes; a node joined to itself is covered by any test at all.";
                    }
                  ]
                  map
                  (
                    n:
                    demand "policy.joins" [
                      {
                        cond = isNode n;
                        message = "each join is a list of nodes, for example `[ m.search m.mcp ]`.";
                      }
                    ] n.id
                  )
                  pair
              ) (given.joins or [ ]);
            }
          );
    in
    demand "model"
      (
        # The set form of an axis is checked first: everything after reads `values` as a list.
        concatMap (
          name:
          let
            axis = declaredAxes.${name};
          in
          if isAttrs axis then
            known "axis `${name}`" [ "values" "default" ] axis
            ++ [
              {
                cond = axis ? values;
                message = "axis `${name}` is written as a set and has no `values`. Write `${name} = { values = [ … ]; default = …; };`, or only the list of values.";
              }
            ]
          else
            [ ]
        ) (attrNames declaredAxes)
        ++ [
          {
            # Axis values are printed in reports and joined into attribute
            # names (`host=ilo`), so they share the cells' reserved characters.
            cond = all (
              axis: isList axes.${axis} && all (v: isString v && match "[^,= \t\n]+" v != null) axes.${axis}
            ) (attrNames axes);
            message = "axis values are non-empty strings without `,`, `=` or white space.";
          }
          {
            cond = all (
              axis: isList axes.${axis} && axes.${axis} != [ ] && unique axes.${axis} == axes.${axis}
            ) (attrNames axes);
            message = "an axis is a non-empty list of distinct values.";
          }
          {
            # `policy = node { … }` would be read as policy and vanish as a node.
            cond = all (
              axis:
              !(elem axis [
                "node"
                "feature"
                "top"
                "package"
                "target"
                "module"
                "file"
                "axis"
                "world"
                "check"
              ])
            ) (attrNames axes);
            message = "an axis may not be named node, feature, top, package, target, module, file, axis, world or check: reports already use those words for what the engine derives.";
          }
          {
            cond = all (name: !(isNode (raw.${name} or null))) reserved;
            message = "a node may not be named ${concatStringsSep ", " reserved}; those names are the model's own sections.";
          }
          {
            cond = all (name: match "[a-z][a-z0-9-]*" name != null && tagged "matrix" (raw.checks.${name})) (
              attrNames (raw.checks or { })
            );
            message = "`checks` maps lower-case dashed names to `matrix { … }` values.";
          }
          {
            cond = raw ? root;
            message = "the model needs `root`, the repository it describes, so that every path it names can be checked to exist.";
          }
          {
            cond = cyclic == [ ];
            message = "`on` and `of` form a cycle through ${
              concatStringsSep ", " (map (n: n.id) cyclic)
            }. Nothing in a cycle is a foundation; decide which stands on which.";
          }
          {
            cond = nodes != [ ];
            message = "the model has no node. A model that describes nothing passes every check.";
          }
          {
            cond =
              (raw.checks or { }) == { } && all (n: n.ship == null) nodes || (raw.policy or { }) ? deployGate;
            message = "the model has checks or shipping nodes and no `policy.deployGate`. Without a gate nothing it describes can stop a deploy; state the set, for example `deployGate = tests.all;`.";
          }
          {
            # A world nothing uses is never looked at otherwise, so a broken
            # one, or something that is no world at all, would sit unseen.
            cond = all (w: w != null) declaredWorlds;
            message = "every entry of `worlds` is a world, a function that returns one, or a set of those.";
          }
          {
            cond = unusedWorlds == [ ];
            message = "a world is declared and no check, placement rule or census uses it: ${
              concatStringsSep ", " (map (w: w.name) unusedWorlds)
            }. Use it or remove it.";
          }
        ]
        ++ map (name: {
          cond = false;
          message = "unknown top-level field `${name}` (${where raw name}). It is not a node, and the reserved fields are: ${concatStringsSep ", " reserved}.";
        }) (filter (name: !(elem name reserved) && !(isNode raw.${name})) (attrNames raw))
        ++ fromCratesRules
        # After the rules that make an axis's values a list of strings.
        ++ map (
          axis:
          let
            default = axisDefaults.${axis};
          in
          {
            cond = isString default && elem default axes.${axis};
            message = "axis `${axis}` has the default ${builtins.toJSON default}, which is not one of its values (${
              concatStringsSep ", " axes.${axis}
            }). Set `default` to one of them, or remove it.";
          }
        ) (attrNames axisDefaults)
      )
      (
        builtins.seq owners {
          schema = 2;
          inherit
            nodes
            axes
            axisDefaults
            worlds
            policy
            ;
          place = map placement (raw.place or [ ]);
          census = attrValues (mapAttrs census (raw.census or { }));
          checks = mapAttrs (
            name: m:
            removeAttrs m [
              "_keel"
              "worlds"
            ]
            // {
              checks = map (located name) m.checks;
            }
          ) (raw.checks or { });
        }
        // (
          if fromCrates == null then
            { }
          else
            {
              nodesFromCrates = {
                strip = fromCrates.strip or "";
                inherit (fromCrates) under;
                at = where raw "nodesFromCrates";
              };
            }
        )
      );
in
{
  inherit
    model
    node
    world
    matrix
    tests
    required
    mayLag
    ;
  inherit (select)
    crate
    path
    module
    pattern
    option
    drv
    within
    state
    inert
    ;
}
