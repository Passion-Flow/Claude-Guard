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


def slow_boundary_completion(case):
    """A completed local check must leave time to retry finished transports.

    Only this fixture's clock file advances. The production pending-evidence
    and completion functions execute, with a two-second boundary check and
    immediately completed, initially failed children.
    """
    with tempfile.TemporaryDirectory(prefix="cg-boundary-completion-") as temporary:
        root = Path(temporary)
        for name in ("primary", "backup", "independent"):
            (root / name).mkdir()
        (root / "clock").write_text("105\n")
        (root / "checks").write_text("")
        setup = f"""
directory='{root}'; health_round=$directory
phase=OPEN; health_sealed=0; health_seen_mask=; health_has_reply=0; health_checked_at=0
health_primary_pid=101; health_backup_pid=102; health_independent_pid=103
health_primary_attempt_at=100; health_backup_attempt_at=100; health_independent_attempt_at=100
health_refresh_until=108; last_verified=100
session=s; vpn_service=v; iface=utun1; endpoint_key=e; expected=192.0.2.42; bound_path=p
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_region=US; risk_key=fixture; risk_checked_at=100; risk_context="$evidence_context|US"
fixture_now() {{ /bin/cat "$directory/clock"; }}
rules_intact() {{
  IFS= read -r stamp < "$directory/clock"
  printf '%s\\n' "$((stamp + 2))" > "$directory/clock"
  printf x >> "$directory/checks"
}}
underlay_snapshot() {{ printf p; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
publish() {{ return 0; }}
load_phase() {{ return 0; }}
kill() {{ return 1; }}
wait() {{ return 0; }}
start_health_client() {{
  [ "$1" = primary ] || exit 99
  printf 'ip=192.0.2.42\\nloc=US\\n' > "$directory/primary.trace"
  fixture_now > "$directory/primary.stamp"
  printf x >> "$directory/retried"
}}
guard_pending_health
"""
        if case == "retry-after-slow-check":
            setup += "reschedule_completed_health\n"
        elif case == "unchanged-completed-check":
            setup += "guard_pending_health\nguard_pending_health\n"
        elif case == "conflicting-response":
            setup += """
printf 'ip=192.0.2.99\\nloc=US\\n' > "$directory/primary.trace"
printf '107\\n' > "$directory/primary.stamp"
guard_pending_health
"""
        elif case == "identity-expired":
            setup += "last_verified=94\nguard_pending_health\n"
        elif case == "risk-expired":
            setup += "risk_max_age=7\nguard_pending_health\n"
        elif case == "next-tick-path-change":
            setup += """
printf '108\\n' > "$directory/clock"
underlay_snapshot() { printf changed; }
guard_pending_health
"""
        setup += """
printf '%s|%s|%s' "$phase" "$last_verified" "${health_seal_reason:-none}"
"""
        result = subprocess.run(["/bin/sh", "-c",
                                 definitions.replace("/bin/date +%s", "fixture_now") + setup],
                                capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, result.stderr
        checks = len((root / "checks").read_text())
        row = {"case": case, "result": result.stdout, "boundaryChecks": checks,
               "retried": (root / "retried").exists()}
        if case == "retry-after-slow-check":
            assert result.stdout == "OPEN|107|none" and row["retried"] and checks == 2, row
        elif case == "unchanged-completed-check":
            assert result.stdout == "OPEN|100|none" and checks == 1, row
        else:
            expected = {"conflicting-response": "LOCKED|0|exit-mismatch",
                        "identity-expired": "LOCKED|0|evidence-expired",
                        "risk-expired": "LOCKED|0|evidence-expired",
                        "next-tick-path-change": "SEALED|0|route-changed"}[case]
            assert result.stdout == expected, row
            assert checks == (2 if case == "next-tick-path-change" else 1), row
        return row


rows = [coordinator("last-completion", name) for name in ("primary", "backup", "independent")]
rows.append(coordinator("pending-peer"))
rows.append(completion_between_polls())
if not options.expect_counterexample:
    rows.extend(slow_boundary_completion(case) for case in (
        "retry-after-slow-check", "unchanged-completed-check", "conflicting-response",
        "identity-expired", "risk-expired", "next-tick-path-change"))
    rows.extend(coordinator(case) for case in (
        "rejecting-response", "accepted-response", "warming", "window-ended",
        "minimum-spacing", "clock-before-attempt"))
print(json.dumps({
    "result": "legacy-counterexample" if options.expect_counterexample else "passed",
    "scope": "Actual coordinator and request-loop definitions with deterministic owned-child contracts; no host changes",
    "cases": rows,
}, sort_keys=True))

