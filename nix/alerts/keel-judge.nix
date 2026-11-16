# vmalert rule group for keel-judge, the continuous fuzzing service. Drop it
# into the groups list in system/services/vmalert.nix, on the host that runs
# keel-judge only (see KeelJudgeMetricsAbsent), e.g. behind the service's
# enable flag:
#
#   ++ lib.optional services.keel-judge.enable (import ./alerts/keel-judge.nix)
#
# The series are keel-judge's node-exporter textfile (keel_judge.prom).
# nix/grafana/check.nu verifies every keel_judge_* name used below against a
# real textfile, so a rule cannot sit on a misspelt metric and never fire.
{
  name = "keel_judge";
  rules = [
    {
      alert = "KeelJudgeDown";
      # The judge rewrites its metrics at least every 60 s while it is alive.
      # node-exporter's textfile collector keeps serving the last content of a
      # file whose writer died, so the series stays and `up` stays 1; only the
      # age of the write shows the judge is gone. Five minutes is five missed
      # writes, which a slow quantum or a busy disk does not cause.
      expr = "time() - max(keel_judge_metrics_written_timestamp_seconds) > 300";
      for = "5m";
      labels.severity = "critical";
      annotations.summary = "keel-judge has stopped writing metrics";
      annotations.description = "The last write was {{ $value | humanizeDuration }} ago and it should be under a minute. Fuzzing has stopped: `systemctl status keel-judge` and its journal on the host.";
    }
    {
      alert = "KeelJudgeMetricsAbsent";
      # KeelJudgeDown cannot fire when the series is gone entirely: the file
      # was deleted, or the textfile collector stopped reading it. absent()
      # fires on any host without the series, so this group must only be
      # installed on the host that runs keel-judge.
      expr = "absent(keel_judge_metrics_written_timestamp_seconds)";
      for = "15m";
      labels.severity = "warning";
      annotations.summary = "No keel-judge metrics at all";
      annotations.description = "keel_judge_metrics_written_timestamp_seconds has had no series for 15 minutes: the textfile is missing or node-exporter is not reading it. If keel-judge runs on this host, check the file under node-exporter's textfile directory.";
    }
    {
      alert = "KeelJudgeNewFinding";
      # The reason the service exists. A finding's first-seen timestamp is a
      # gauge that never changes, so comparing it to now makes the alert
      # exist for exactly the half hour after the finding; for = 0m because
      # no finding should wait to be reported.
      expr = "keel_judge_finding_first_seen_timestamp_seconds > time() - 1800";
      for = "0m";
      labels.severity = "warning";
      annotations.summary = "keel-judge found a {{ $labels.kind }} in {{ $labels.target }} ({{ $labels.key }})";
      annotations.description = "New finding of kind {{ $labels.kind }} on target {{ $labels.target }}, key {{ $labels.key }}. This alert resolves by itself after 30 minutes by design; the finding stays in the Findings table of the Keel fuzzing dashboard.";
    }
    {
      alert = "KeelJudgeTargetFaulted";
      # A faulted target is one that cannot fuzz (not one that crashed): the
      # supervisor could not run it, or its quanta end in error (it will not
      # start, leaves on its own, or ignores SIGINT). It backs off and is
      # retried. A single fault clears itself; half an hour of it means
      # something stays broken, such as a missing binary, an unwritable
      # corpus or a target that hangs.
      expr = "keel_judge_target_faulted == 1";
      for = "30m";
      labels.severity = "warning";
      annotations.summary = "keel-judge cannot run target {{ $labels.target }}";
      annotations.description = "{{ $labels.target }} has not fuzzed for 30 minutes (it cannot be run, or every quantum ends in error) and is backed off. It is getting no fuzz time. The judge's journal names the cause.";
    }
    {
      alert = "KeelJudgeIdle";
      # Alive but fuzzing nothing looks healthy on every other panel. With
      # no worker busy, every target is blocked by a finding, faulted, or the
      # workers are waiting for disk. Half an hour clears the gap between
      # quanta and a restart.
      expr = "keel_judge_workers_busy == 0";
      for = "30m";
      labels.severity = "warning";
      annotations.summary = "keel-judge has had no worker busy for 30 minutes";
      annotations.description = "Every target is blocked by a finding, faulted, or the workers are waiting for disk. Look at the Targets table on the Keel fuzzing dashboard: blocked targets need a new build.";
    }
    {
      alert = "KeelJudgeStateDamaged";
      # Damaged lines are dropped when the state log is read at start, so the
      # judge carries on with less history; without an alert that is silent.
      # No `for`: it is a gauge fixed at the last start and a restart clears
      # it, so waiting would only hide it.
      expr = "keel_judge_state_damaged_lines > 0";
      labels.severity = "warning";
      annotations.summary = "keel-judge dropped {{ $value }} damaged lines of its state log at its last start";
      annotations.description = "The damaged log was kept beside the new one under the state directory. Findings and counters recorded only in the lost lines are gone from the dashboards; inspect the kept file.";
    }
    {
      alert = "KeelJudgeDiskWaits";
      # A worker that finds the corpus filesystem below its free-space floor
      # waits a minute and tries again, so a full disk looks like a slow
      # service. More than ten in an hour is a disk that is staying full.
      expr = "increase(keel_judge_disk_waits_total[1h]) > 10";
      labels.severity = "warning";
      annotations.summary = "keel-judge waited for disk space {{ $value | humanize }} times in an hour";
      annotations.description = "The corpus filesystem is below the judge's free-space floor and workers are pausing. Free space there or lower --min-free-gib.";
    }
  ];
}
