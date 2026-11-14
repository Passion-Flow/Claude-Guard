"""Deterministic completion/retry contracts for the production coordinator.

Owned child states and response callbacks are fixture-local. No host processes,
networking, clocks, credentials or installed policy are read or changed.
"""
from pathlib import Path
import argparse
import json
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--worker", type=Path)
parser.add_argument("--expect-counterexample", action="store_true")
options = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
worker = options.worker or repo / "Sources/GuardWorker.sh"
definitions = worker.read_text().split("action=${1-}")[0]


def coordinator(case, provider="primary"):
    with tempfile.TemporaryDirectory(prefix="cg-completion-contract-") as temporary:
        root = Path(temporary)
        for label in ("primary", "backup", "independent"):
            (root / label).mkdir()
            (root / (label + ".stamp")).write_text("unconsumed")
        setup = f"""
health_round='{root}'
phase=OPEN; health_sealed=0; health_now=105; last_verified=100
health_interval_seconds=2; health_refresh_until=108; running_pid=
health_primary_pid=; health_backup_pid=; health_independent_pid=
health_primary_attempt_at=105; health_backup_attempt_at=105; health_independent_attempt_at=105
response=unavailable; callbacks=0
kill() {{ [ -n "$2" ] && [ "$2" = "$running_pid" ]; }}
wait() {{ printf '%s\\n' "$1" >> '{root}/joined'; }}
guard_pending_health() {{
  callbacks=$((callbacks + 1))
  if [ "$response" = rejected ]; then
    [ -f '{root}/primary.stamp' ] || printf missing > '{root}/ordering-error'
    phase=LOCKED; health_sealed=1
  elif [ "$response" = accepted ]; then last_verified=105
  fi
}}
start_health_client() {{
  case "$1" in
    primary) [ -z "$health_primary_pid" ] || printf overlap > '{root}/overlap'; health_primary_pid=201;;
    backup) [ -z "$health_backup_pid" ] || printf overlap > '{root}/overlap'; health_backup_pid=202;;
    independent) [ -z "$health_independent_pid" ] || printf overlap > '{root}/overlap'; health_independent_pid=203;;
  esac
  printf '%s\\n' "$1" >> '{root}/started'
}}
"""
        number = {"primary": 101, "backup": 102, "independent": 103}[provider]
        setup += f"health_{provider}_pid={number}; health_{provider}_attempt_at=100\n"
        if case == "pending-peer":
            setup += "health_backup_pid=102; running_pid=102\n"
        elif case in ("rejecting-response", "accepted-response", "warming"):
            setup += "health_primary_pid=101; health_backup_pid=102; health_independent_pid=103\n"
            if case == "rejecting-response":
                setup += "response=rejected\n"
            elif case == "accepted-response":
                setup += "response=accepted\n"
            else:
                setup += "phase=LOCKED\n"
        elif case == "window-ended":
            setup += "health_now=108\n"
        elif case == "minimum-spacing":
            setup += "health_now=101; last_verified=99\n"
        elif case == "clock-before-attempt":
            setup += "health_now=99\n"
        setup += """
reschedule_completed_health
printf '%s|%s|%s|%s|%s|%s' "$phase" "$callbacks" "$last_verified" "$health_primary_pid" "$health_backup_pid" "$health_independent_pid"
"""
        result = subprocess.run(["/bin/sh", "-c", definitions + setup],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, result.stderr
        joined = (root / "joined").read_text().splitlines() if (root / "joined").exists() else []
        started = (root / "started").read_text().splitlines() if (root / "started").exists() else []
        phase, callbacks, verified, *slots = result.stdout.split("|")
        row = {"case": case, "provider": provider, "joined": joined, "started": started,
               "phase": phase, "callbacks": int(callbacks), "verified": int(verified),
               "ownedSlots": slots}
        assert not (root / "overlap").exists(), row
        assert not (root / "ordering-error").exists(), row
        if options.expect_counterexample and case == "last-completion":
            assert joined == [] and started == [], row
        elif case in ("last-completion", "pending-peer"):
            assert joined == [str(number)] and started == [provider], row
        else:
            expected = ["101", "102", "103"] if case in (
                "rejecting-response", "accepted-response", "warming") else [str(number)]
            assert joined == expected and not started and slots == ["", "", ""], row
            if case == "rejecting-response":
                assert phase == "LOCKED" and verified == "100", row
            if case == "accepted-response":
                assert phase == "OPEN" and verified == "105", row
        return row


def completion_between_polls():
    with tempfile.TemporaryDirectory(prefix="cg-completion-loop-") as temporary:
        setup = f"""
directory='{temporary}'
phase=OPEN; completed=0; handled=0; completion_passes=0
start_health_client() {{
  case "$1" in
    primary) health_primary_pid=101;;
    backup) health_backup_pid=;;
    independent) health_independent_pid=;;
  esac
}}
kill() {{ [ -n "$2" ] && [ "$completed" = 0 ]; }}
wait() {{ return 0; }}
guard_pending_health() {{ return 0; }}
reschedule_completed_health() {{
  completion_passes=$((completion_passes + 1))
  if [ "$completed" = 0 ]; then
    completed=1
  else
    health_primary_pid=; handled=1
  fi
}}
select_health_reply() {{ [ "$handled" = 1 ]; }}
record_health_round() {{ return 0; }}
accepted=false
if sample_exit; then accepted=true; fi
printf '%s|%s|%s' "$accepted" "$handled" "$completion_passes"
"""
        result = subprocess.run(["/bin/sh", "-c", definitions + setup],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, result.stderr
        expected = "false|0|1" if options.expect_counterexample else "true|1|2"
        assert result.stdout == expected, result.stdout
        assert not list(Path(temporary).glob("health.*"))
        return {"case": "last-child-exits-between-polls", "observation": result.stdout}


rows = [coordinator("last-completion", name) for name in ("primary", "backup", "independent")]
rows.append(coordinator("pending-peer"))
rows.append(completion_between_polls())
if not options.expect_counterexample:
    rows.extend(coordinator(case) for case in (
        "rejecting-response", "accepted-response", "warming", "window-ended",
        "minimum-spacing", "clock-before-attempt"))
print(json.dumps({
    "result": "legacy-counterexample" if options.expect_counterexample else "passed",
    "scope": "Actual coordinator and request-loop definitions with deterministic owned-child contracts; no host changes",
    "cases": rows,
}, sort_keys=True))

