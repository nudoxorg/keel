# Keel fuzzing — what keel-judge, the continuous fuzzing service, found and
# where it spent its time. Every series comes from keel-judge's own
# node-exporter textfile (keel_judge.prom), so the data is on the host that
# runs keel-judge and nowhere else.
#
# For MachineConfigurations: copy to system/services/grafana/dashboards/ and
# list it in dashboards/default.nix keyed on the service being enabled:
#
#   keel-fuzz = {
#     when = services.keel-judge.enable;
#     dashboard = import ./keel-fuzz.nix;
#   };
#
# nix/grafana/check.nu verifies every keel_judge_* name used here against a
# real textfile before this is copied, because Grafana shows a panel on a
# misspelt metric as an empty graph, not as an error.
let
  # A letter per query: tables that join several instant queries need a
  # refId on each, and the joined columns are named after it ("Value #A").
  refId = i: builtins.substring i 1 "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  panel =
    {
      id,
      title,
      x,
      y,
      w ? 12,
      h ? 8,
      type ? "timeseries",
      targets,
      unit ? null,
      description ? null,
      defaults ? { },
      options ? { },
      overrides ? [ ],
      transformations ? [ ],
    }:
    {
      inherit id title type;
      gridPos = {
        inherit
          h
          w
          x
          y
          ;
      };
      targets = builtins.genList (i: { refId = refId i; } // builtins.elemAt targets i) (
        builtins.length targets
      );
      fieldConfig = {
        defaults = (if unit == null then { } else { inherit unit; }) // defaults;
        inherit overrides;
      };
      options =
        (
          if type == "timeseries" then
            {
              # Beside the graph: at the bottom only three legend rows fitted
              # (seen rendered, 2026-11-15), and per-target panels have more.
              legend = {
                showLegend = true;
                displayMode = "list";
                placement = "right";
              };
              tooltip = {
                mode = "multi";
                sort = "desc";
              };
            }
          else
            { }
        )
        // options;
    }
    // (if description == null then { } else { inherit description; })
    // (if transformations == [ ] then { } else { inherit transformations; });

  # A single number with its own colour rule. The judge's health is read at a
  # glance from this row, so each one that can be bad has a threshold.
  stat =
    {
      id,
      title,
      x,
      targets,
      unit ? null,
      description ? null,
      steps ? [
        {
          color = "blue";
          value = null;
        }
      ],
    }:
    panel {
      inherit
        id
        title
        x
        targets
        unit
        description
        ;
      y = 0;
      w = 4;
      h = 4;
      type = "stat";
      defaults.thresholds = {
        mode = "absolute";
        inherit steps;
      };
      options = {
        colorMode = "value";
        graphMode = "none";
        reduceOptions = {
          calcs = [ "lastNotNull" ];
          fields = "";
          values = false;
        };
      };
    };

  # Instant, table-shaped: one row per series at the dashboard's end time.
  # Tables show the state now; the graphs below show how it got there.
  tableQuery = expr: {
    inherit expr;
    instant = true;
    range = false;
    format = "table";
  };

  # Grafana names the value column of a table-format query "Value #<refId>".
  # Naming it in an override keeps the query text free of display concerns.
  column = ref: name: props: {
    matcher = {
      id = "byName";
      options = "Value #${ref}";
    };
    properties = [
      {
        id = "displayName";
        value = name;
      }
    ]
    ++ props;
  };

  unitProp = value: {
    id = "unit";
    inherit value;
  };

  # 0/1 gauges read as words, coloured only when the 1 needs a look.
  yesNo = color: [
    {
      id = "mappings";
      value = [
        {
          type = "value";
          options = {
            "0" = {
              text = "no";
              color = "green";
              index = 0;
            };
            "1" = {
              text = "yes";
              inherit color;
              index = 1;
            };
          };
        }
      ];
    }
    {
      id = "custom.cellOptions";
      value.type = "color-text";
    }
  ];

  # Column order of a merged table: its labels first, then one column per
  # query in the order the queries were written.
  columnOrder =
    labels: n:
    builtins.listToAttrs (
      builtins.genList (i: {
        name = builtins.elemAt labels i;
        value = i;
      }) (builtins.length labels)
      ++ builtins.genList (i: {
        name = "Value #${refId i}";
        value = builtins.length labels + i;
      }) n
    );

  # The textfile carries the scrape's job and instance, and the merge adds
  # the evaluation time; none of them tell a reader anything in a table.
  noise = {
    Time = true;
    job = true;
    instance = true;
  };
in
{
  title = "Keel fuzzing";
  uid = "keel-fuzz";
  tags = [
    "keel"
    "fuzz"
    "ci"
  ];
  timezone = "browser";
  schemaVersion = 39;
  version = 1;
  refresh = "30s";
  panels = [
    # ── Row of numbers ───────────────────────────────────────────────────────
    (stat {
      id = 1;
      title = "Distinct findings";
      x = 0;
      targets = [
        {
          expr = "sum(keel_judge_findings)";
          legendFormat = "findings";
        }
      ];
      description = "Distinct crashes, timeouts, leaks and other findings recorded over the service's whole state log, not only since it last started.";
    })
    (stat {
      id = 2;
      title = "New findings, last 24 h";
      x = 4;
      targets = [
        {
          # vector(0) so a quiet day reads 0 rather than "No data", which
          # looks the same as a dead service. max_over_time bridges a gap in the
          # samples: rendered over a soak that had just ended, the last point
          # found no series and vector(0) turned a real finding into 0.
          expr = "count(max_over_time(keel_judge_finding_first_seen_timestamp_seconds[1h]) > time() - 86400) or vector(0)";
          legendFormat = "new";
        }
      ];
      steps = [
        {
          color = "green";
          value = null;
        }
        {
          color = "yellow";
          value = 1;
        }
      ];
    })
    (stat {
      id = 3;
      title = "Since last write";
      x = 8;
      targets = [
        {
          expr = "time() - max(keel_judge_metrics_written_timestamp_seconds)";
          legendFormat = "age";
        }
      ];
      unit = "s";
      description = "The judge rewrites its metrics file at least every 60 s while it is alive, so three minutes without one means it has stopped, not that it is busy.";
      steps = [
        {
          color = "green";
          value = null;
        }
        {
          color = "red";
          value = 180;
        }
      ];
    })
    (stat {
      id = 4;
      title = "Workers busy / workers";
      x = 12;
      targets = [
        {
          expr = "max(keel_judge_workers_busy)";
          legendFormat = "busy";
        }
        {
          expr = "max(keel_judge_workers)";
          legendFormat = "of";
        }
      ];
    })
    (stat {
      id = 5;
      title = "Targets blocked";
      x = 16;
      targets = [
        {
          expr = "sum(keel_judge_target_blocked)";
          legendFormat = "blocked";
        }
      ];
      description = "A finding is recorded against the target's current binary, so it is not scheduled again until a new build. Not an error, but fuzz time is no longer going there.";
      steps = [
        {
          color = "green";
          value = null;
        }
        {
          color = "yellow";
          value = 1;
        }
      ];
    })
    (stat {
      id = 6;
      title = "Targets faulted";
      x = 20;
      targets = [
        {
          expr = "sum(keel_judge_target_faulted)";
          legendFormat = "faulted";
        }
      ];
      description = "The supervisor could not run the target and is backing off. Unlike a blocked target, this is the service failing, not the target.";
      steps = [
        {
          color = "green";
          value = null;
        }
        {
          color = "red";
          value = 1;
        }
      ];
    })

    # ── Findings ─────────────────────────────────────────────────────────────
    (panel {
      id = 7;
      title = "Findings";
      x = 0;
      y = 4;
      w = 24;
      h = 6;
      type = "table";
      description = "One row per distinct finding, newest first. The sighting count is for the finding's kind on its target (the judge counts sightings per kind, not per key), joined in the query so every row of a kind shows the same number.";
      targets = [
        # Milliseconds, because Grafana's date units want them.
        (tableQuery "keel_judge_finding_first_seen_timestamp_seconds * 1000")
        # The sighting counter has no key label, so it is attached to each
        # finding by (target, kind) in PromQL; "* 0 +" keeps the finding's
        # labels and takes only the counter's value. Done here, not with a
        # Grafana join, because a join on two fields is not available.
        (tableQuery "(keel_judge_finding_first_seen_timestamp_seconds * 0) + on (target, kind) group_left () sum by (target, kind) (keel_judge_finding_sightings_total)")
      ];
      overrides = [
        (column "A" "First seen" [
          (unitProp "dateTimeAsIso")
        ])
        (column "B" "Sightings of this kind" [
          (unitProp "none")
        ])
      ];
      options = {
        sortBy = [
          {
            displayName = "First seen";
            desc = true;
          }
        ];
        footer.show = false;
      };
      transformations = [
        {
          id = "merge";
          options = { };
        }
        {
          id = "organize";
          options = {
            excludeByName = noise;
            indexByName = columnOrder [ "target" "kind" "key" ] 2;
          };
        }
      ];
    })

    # ── Findings over time ───────────────────────────────────────────────────
    (panel {
      id = 8;
      title = "Distinct findings by target";
      x = 0;
      y = 10;
      targets = [
        {
          expr = "sum by (target) (keel_judge_findings)";
          legendFormat = "{{ target }}";
        }
      ];
      unit = "none";
    })
    (panel {
      id = 9;
      title = "Failures found per hour, by kind of outcome";
      x = 12;
      y = 10;
      description = "Every run of a target that did not end ok, by how it ended. Runs, not distinct findings: the same crash found again counts again.";
      targets = [
        {
          expr = ''sum by (outcome) (increase(keel_judge_target_outcomes_total{outcome!="ok"}[1h]))'';
          legendFormat = "{{ outcome }}";
        }
      ];
      unit = "none";
    })

    # ── Targets ──────────────────────────────────────────────────────────────
    (panel {
      id = 10;
      title = "Targets";
      x = 0;
      y = 18;
      w = 24;
      h = 10;
      type = "table";
      description = "The scheduler's view of every target now, highest index first. Index is rank times rate: the static importance of the target times how fast it is still finding new coverage. Blocked: a finding is open against its current build. Faulted: it cannot fuzz and is backed off.";
      # What needs a look first, then what the scheduler weighs, then the rest.
      # Rendered at 1600 px the last three of thirteen columns fell off the
      # right edge (2026-11-15); the narrow minimum width keeps them all in.
      defaults.custom.minWidth = 64;
      targets = [
        (tableQuery "max by (target) (keel_judge_target_blocked)")
        (tableQuery "max by (target) (keel_judge_target_faulted)")
        (tableQuery "max by (target) (keel_judge_target_index)")
        (tableQuery "max by (target) (keel_judge_target_rank)")
        (tableQuery "max by (target) (keel_judge_target_rate)")
        (tableQuery "max by (target) (keel_judge_target_share)")
        (tableQuery "max by (target) (keel_judge_target_features)")
        (tableQuery "max by (target) (keel_judge_target_features_per_hour)")
        (tableQuery "max by (target) (keel_judge_target_exec_per_second)")
        (tableQuery "max by (target) (keel_judge_target_corpus_files)")
        (tableQuery "max by (target) (keel_judge_target_open_findings)")
        (tableQuery "max by (target) (keel_judge_target_last_quantum_timestamp_seconds) * 1000")
      ];
      overrides = [
        (column "A" "Blocked" (yesNo "yellow"))
        (column "B" "Faulted" (yesNo "red"))
        (column "C" "Index" [
          (unitProp "none")
          {
            id = "decimals";
            value = 3;
          }
        ])
        (column "D" "Rank" [ (unitProp "none") ])
        (column "E" "Rate" [
          (unitProp "none")
          {
            id = "decimals";
            value = 3;
          }
        ])
        (column "F" "Fuzz share" [ (unitProp "percentunit") ])
        (column "G" "Features" [ (unitProp "none") ])
        (column "H" "Features/h" [ (unitProp "none") ])
        (column "I" "Exec/s" [ (unitProp "none") ])
        (column "J" "Corpus" [ (unitProp "none") ])
        (column "K" "Findings" [ (unitProp "none") ])
        # "3 minutes ago" fits the column; an ISO date was cut at the left.
        (column "L" "Last ran" [ (unitProp "dateTimeFromNow") ])
      ];
      options = {
        sortBy = [
          {
            displayName = "Index";
            desc = true;
          }
        ];
        footer.show = false;
      };
      transformations = [
        {
          id = "merge";
          options = { };
        }
        {
          id = "organize";
          options = {
            excludeByName = noise;
            indexByName = columnOrder [ "target" ] 12;
          };
        }
      ];
    })

    # ── Time follows the index ───────────────────────────────────────────────
    (panel {
      id = 11;
      title = "Where the fuzz time goes";
      x = 0;
      y = 28;
      description = "Fuzz-seconds spent per wall-clock second on each target, stacked, so the height is how many workers were busy. Read it against Index by target on its right: the point of the service is that fuzz time follows the index, so a target whose index rises should gain a band here within a few quanta.";
      targets = [
        {
          expr = "sum by (target) (rate(keel_judge_target_fuzz_seconds_total[1h]))";
          legendFormat = "{{ target }}";
        }
      ];
      unit = "none";
      defaults.custom = {
        fillOpacity = 40;
        stacking = {
          mode = "normal";
          group = "A";
        };
      };
    })
    (panel {
      id = 12;
      title = "Index by target";
      x = 12;
      y = 28;
      description = "What the scheduler picks by (rank times rate), on a log scale because ranks differ by orders of magnitude. A target at zero has stopped finding new coverage and drops off a log axis. Compare with Where the fuzz time goes on its left.";
      targets = [
        {
          expr = "keel_judge_target_index";
          legendFormat = "{{ target }}";
        }
      ];
      unit = "none";
      defaults.custom.scaleDistribution = {
        type = "log";
        log = 10;
      };
    })

    # ── Is fuzzing productive ────────────────────────────────────────────────
    (panel {
      id = 13;
      title = "Coverage features by target";
      x = 0;
      y = 36;
      w = 8;
      description = "libFuzzer's ft counter. Flat means the target has stopped finding new paths; the scheduler lowers its rate and so its share of time.";
      targets = [
        {
          expr = "keel_judge_target_features";
          legendFormat = "{{ target }}";
        }
      ];
      unit = "none";
    })
    (panel {
      id = 14;
      title = "Executions per second by target";
      x = 8;
      y = 36;
      w = 8;
      targets = [
        {
          expr = "keel_judge_target_exec_per_second";
          legendFormat = "{{ target }}";
        }
      ];
      unit = "none";
    })
    (panel {
      id = 15;
      title = "How targets were chosen (quanta per hour)";
      x = 16;
      y = 36;
      w = 8;
      description = "cold: the target had never run. starved: every n-th quantum goes to the least recently served target, so a rank-0 target still runs. index: the greatest rank times rate. A healthy steady state is almost all index.";
      targets = [
        {
          expr = "sum by (chosen_by) (increase(keel_judge_target_chosen_total[1h]))";
          legendFormat = "{{ chosen_by }}";
        }
      ];
      unit = "none";
      defaults.custom = {
        fillOpacity = 40;
        stacking = {
          mode = "normal";
          group = "A";
        };
      };
    })

    # ── Supervisor ───────────────────────────────────────────────────────────
    (panel {
      id = 16;
      title = "Supervisor health";
      x = 0;
      y = 44;
      w = 24;
      description = "The last three should sit at zero. Workers busy below the worker count means fewer eligible targets than workers (the rest are blocked, faulted or already running). A disk wait is a worker pausing for a minute because the corpus filesystem is below the --min-free-gib threshold.";
      targets = [
        {
          expr = "keel_judge_workers_busy";
          legendFormat = "workers busy";
        }
        {
          expr = "increase(keel_judge_disk_waits_total[1h])";
          legendFormat = "disk waits per hour";
        }
        {
          expr = "keel_judge_state_damaged_lines";
          legendFormat = "damaged state lines at last start";
        }
        {
          expr = "sum(keel_judge_target_faulted)";
          legendFormat = "targets faulted";
        }
      ];
      unit = "none";
    })
  ];
}
