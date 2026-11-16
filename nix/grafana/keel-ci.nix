# Keel CI times — how long Concourse builds take, per job, against the
# framework's budgets. The data is Concourse web's own Prometheus endpoint,
# scraped as job="concourse".
#
# For MachineConfigurations: copy to system/services/grafana/dashboards/ and
# list it in dashboards/default.nix beside the concourse entry, keyed on
# concourse being enabled:
#
#   keel-ci = {
#     when = services.concourse.enable;
#     dashboard = import ./keel-ci.nix;
#   };
#
# NOT VERIFIED: the label set of concourse_builds_duration_seconds. The
# queries assume team, pipeline and job, from Concourse's documentation, and
# nobody has looked at the running host. Check on the CI host:
#
#   curl -s 127.0.0.1:9391/metrics | grep '^concourse_builds_duration_seconds'
#
# The duration panels and the table show nothing until the labels match.
# Concourse's own `job` label collides with the scrape job's (job="concourse"),
# and MachineConfigurations' scrape config (victoriametrics.nix) does not set
# honor_labels, so VictoriaMetrics keeps the target's and stores Concourse's
# as exported_job. That is what jobLabel below says. If the series show a
# plain `job` per pipeline job instead, change jobLabel and nothing else. The four outcome
# panels use counters whose names were already charted by concourse.nix.
let
  # The Concourse job's label, in one place; see the note above.
  jobLabel = "exported_job";

  # The budgets from BRIEF and AMBITION: junk PR < 5 s, leaf < 30 s, core
  # < 2 min, warm complete < 5 min, cold < 10 min. The lines drawn are the
  # last three: 5 s and 30 s would sit on the axis beside a 600 s line.
  budgetSteps = [
    {
      color = "green";
      value = null;
    }
    {
      color = "yellow";
      value = 120;
    }
    {
      color = "orange";
      value = 300;
    }
    {
      color = "red";
      value = 600;
    }
  ];

  # A letter per query: the table joins three instant queries and names its
  # columns after them ("Value #A").
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
              legend = {
                showLegend = true;
                displayMode = "table";
                placement = "bottom";
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

  tableQuery = expr: {
    inherit expr;
    instant = true;
    range = false;
    format = "table";
  };

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

  # The same thresholds drawn as lines on the two time graphs.
  budgetLines = {
    thresholds = {
      mode = "absolute";
      steps = budgetSteps;
    };
    custom.thresholdsStyle.mode = "line";
  };

  byJob = "pipeline, ${jobLabel}";
  selected = ''pipeline=~"$pipeline"'';
  legend = "{{ pipeline }} / {{ ${jobLabel} }}";
in
{
  title = "Keel CI times";
  uid = "keel-ci";
  tags = [
    "keel"
    "ci"
    "concourse"
  ];
  timezone = "browser";
  schemaVersion = 39;
  version = 1;
  refresh = "1m";
  templating.list = [
    {
      name = "pipeline";
      label = "Pipeline";
      type = "query";
      query = "label_values(concourse_builds_duration_seconds_count, pipeline)";
      # Rebuilt when the range changes: a pipeline that last ran last week
      # should not be offered for today.
      refresh = 2;
      sort = 1;
      multi = true;
      includeAll = true;
      # ".*" rather than Grafana's list of every pipeline, so a pipeline that
      # appears after the page was loaded is still in "All".
      allValue = ".*";
      current = {
        selected = true;
        text = [ "All" ];
        value = [ "$__all" ];
      };
    }
  ];
  panels = [
    # ── Over the whole range ─────────────────────────────────────────────────
    (panel {
      id = 1;
      title = "Average build time by job over the dashboard range";
      x = 0;
      y = 0;
      w = 24;
      h = 9;
      type = "table";
      description = "Per job over the selected time range. Average is the duration sum over the build count, so it is exact; the 90th percentile is estimated from histogram buckets and is only as fine as Concourse's bucket boundaries. A job with no build in the range is not listed.";
      targets = [
        # The "> 0" drops the NaN of a job that has a series but no build in
        # the range, which would otherwise be a row of NaN.
        (tableQuery "(sum by (${byJob}) (increase(concourse_builds_duration_seconds_sum{${selected}}[$__range])) / sum by (${byJob}) (increase(concourse_builds_duration_seconds_count{${selected}}[$__range]))) > 0")
        (tableQuery "sum by (${byJob}) (increase(concourse_builds_duration_seconds_count{${selected}}[$__range])) > 0")
        (tableQuery "histogram_quantile(0.9, sum by (le, ${byJob}) (increase(concourse_builds_duration_seconds_bucket{${selected}}[$__range])))")
      ];
      overrides = [
        (column "A" "Average" [ (unitProp "s") ])
        (column "B" "Builds in range" [
          (unitProp "none")
          {
            id = "decimals";
            value = 0;
          }
        ])
        (column "C" "p90" [ (unitProp "s") ])
      ];
      options = {
        sortBy = [
          {
            displayName = "Average";
            desc = true;
          }
        ];
        footer.show = false;
      };
      defaults.thresholds = {
        mode = "absolute";
        steps = [
          {
            color = "text";
            value = null;
          }
        ];
      };
      transformations = [
        {
          id = "merge";
          options = { };
        }
        {
          id = "organize";
          options = {
            excludeByName.Time = true;
            indexByName = {
              pipeline = 0;
              ${jobLabel} = 1;
              "Value #A" = 2;
              "Value #B" = 3;
              "Value #C" = 4;
            };
          };
        }
      ];
    })

    # ── Over time, against the budgets ───────────────────────────────────────
    (panel {
      id = 2;
      title = "Average build time by job (1 h windows)";
      x = 0;
      y = 9;
      description = "Lines at 120 s, 300 s and 600 s are the framework's budgets from BRIEF and AMBITION: junk PR under 5 s, leaf under 30 s, core change under 2 min, warm complete run under 5 min, cold run under 10 min. Only the last three are drawn. Which job is which lane is not encoded yet, so read each job against the lane it stands for.";
      targets = [
        {
          expr = "sum by (${byJob}) (increase(concourse_builds_duration_seconds_sum{${selected}}[1h])) / sum by (${byJob}) (increase(concourse_builds_duration_seconds_count{${selected}}[1h]))";
          legendFormat = legend;
        }
      ];
      unit = "s";
      defaults = budgetLines;
    })
    (panel {
      id = 3;
      title = "p50 / p90 by job (6 h windows)";
      x = 12;
      y = 9;
      description = "Median and 90th percentile estimated from the duration histogram over six hours, long enough that a job which runs a few times a day has builds in every window. Same budget lines as the average on its left: 120 s core change, 300 s warm complete run, 600 s cold run. Which job is which lane is not encoded yet.";
      targets = [
        {
          expr = "histogram_quantile(0.5, sum by (le, ${byJob}) (increase(concourse_builds_duration_seconds_bucket{${selected}}[6h])))";
          legendFormat = "p50 ${legend}";
        }
        {
          expr = "histogram_quantile(0.9, sum by (le, ${byJob}) (increase(concourse_builds_duration_seconds_bucket{${selected}}[6h])))";
          legendFormat = "p90 ${legend}";
        }
      ];
      unit = "s";
      defaults = budgetLines;
    })

    # ── Outcomes, so the board stands alone ──────────────────────────────────
    (panel {
      id = 4;
      title = "Build outcomes (per hour)";
      x = 0;
      y = 17;
      targets = [
        {
          expr = "increase(concourse_builds_succeeded_total[1h])";
          legendFormat = "succeeded";
        }
        {
          expr = "increase(concourse_builds_failed_total[1h])";
          legendFormat = "failed";
        }
        {
          expr = "increase(concourse_builds_errored_total[1h])";
          legendFormat = "errored";
        }
        {
          expr = "increase(concourse_builds_aborted_total[1h])";
          legendFormat = "aborted";
        }
      ];
      unit = "none";
    })
    (panel {
      id = 5;
      title = "Builds started vs finished (rate over 15m — a gap means queueing)";
      x = 12;
      y = 17;
      targets = [
        {
          expr = "rate(concourse_builds_started_total[15m])";
          legendFormat = "started";
        }
        {
          expr = "rate(concourse_builds_finished_total[15m])";
          legendFormat = "finished";
        }
      ];
      unit = "ops";
    })
  ];
}
