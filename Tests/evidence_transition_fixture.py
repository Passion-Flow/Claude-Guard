"""Deterministic evidence ordering controls; no host clock, network or PF writes."""
from pathlib import Path
import subprocess
import tempfile

repo = Path(__file__).resolve().parents[1]
definitions = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]
definitions = definitions.replace('$(/bin/date +%s)', '$(fixture_now)')
worker_source = (repo / 'Sources/GuardWorker.sh').read_text()
decision_start = worker_source.index('      # A delayed probe or a clock jump')
decision_end = worker_source.index('      publish "$phase" "$observed" "$reason"', decision_start)
decision_end += len('      publish "$phase" "$observed" "$reason"')
production_decision = worker_source[decision_start:decision_end].replace('$(/bin/date +%s)', '$(fixture_now)')

with tempfile.TemporaryDirectory(prefix='cg-evidence-order-') as temporary:
    root = Path(temporary)
    cases = [
        ('completed-before-deadline-processed-after', 'fixture_time=113; proof 112', 'OPEN', 112),
        ('observation-gap-expired', 'fixture_time=113; proof 113', 'LOCKED', 0),
        ('new-proof-also-expired', 'fixture_time=125; proof 112', 'LOCKED', 0),
        ('future-response', 'fixture_time=111; proof 112', 'LOCKED', 0),
        ('clock-regression', 'fixture_time=99; proof 99', 'LOCKED', 0),
        ('wrong-exit', 'fixture_time=110; proof 109 192.0.2.99', 'LOCKED', 0),
        ('wrong-region', 'fixture_time=110; proof 109 192.0.2.42 CA', 'LOCKED', 0),
        ('risk-expired', 'fixture_time=113; risk_max_age=100; proof 112', 'LOCKED', 0),
        ('context-changed', 'fixture_time=113; evidence_context=other; proof 112', 'LOCKED', 0),
        ('physical-path-changed', "fixture_time=113; proof 112; underlay_snapshot() { printf other; }", 'SEALED', 0),
        ('filter-changed', 'fixture_time=113; proof 112; rules_intact() { return 1; }', 'SEALED', 0),
        ('already-locked', 'phase=LOCKED; fixture_time=113; proof 112', 'LOCKED', 100),
        ('already-sealed', 'phase=SEALED; health_sealed=1; fixture_time=113; proof 112', 'SEALED', 100),
        ('missing-within-original-lease', 'fixture_time=112', 'OPEN', 100),
        ('missing-after-original-lease', 'fixture_time=113', 'LOCKED', 0),
        ('duplicate-never-renews', 'fixture_time=112; proof 100', 'OPEN', 100),
        ('duplicate-after-expiry', 'fixture_time=113; proof 100', 'LOCKED', 0),
        ('reply-during-boundary-work', 'fixture_time=110; rules_intact() { proof 111; fixture_time=113; }', 'OPEN', 111),
        ('expiry-during-boundary-work', 'fixture_time=110; rules_intact() { fixture_time=113; }', 'LOCKED', 0),
        ('conflict-during-boundary-work', 'fixture_time=110; proof 109; rules_intact() { proof 111 192.0.2.99; fixture_time=113; }', 'LOCKED', 0),
    ]
    setup = f'''
directory='{root}'; health_round="$directory/round"
/bin/mkdir -p "$health_round"
fixture_time=110
fixture_now() {{ printf '%s' "$fixture_time"; }}
iface=utun1; expected=192.0.2.42; risk_region=US
session=fixture; vpn_service=service; endpoint_key=endpoint; bound_path=path
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"; risk_checked_at=10
phase=OPEN; last_verified=100; health_sealed=0; health_changed=1; health_checked_at=0
health_seen_mask=; health_has_reply=0; health_seal_reason=none
last_state=OPEN; last_observed=$expected; last_reason=probe-ok
rules_intact() {{ return 0; }}
underlay_snapshot() {{ printf path; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
load_phase() {{ return 0; }}
enforce_seal() {{ return 0; }}
publish() {{ last_reason=$3; }}
proof() {{
  printf 'ip=%s\\nloc=%s\\n' "${{2:-192.0.2.42}}" "${{3:-US}}" > "$health_round/primary.trace"
  printf '%s\\n' "$1" > "$health_round/primary.stamp"
}}
'''
    for name, scenario, phase, verified in cases:
        for old in (root / 'round').glob('*'):
            old.unlink()
        command = definitions + setup + scenario + '''
if select_health_reply; then health_has_reply=1; fi
guard_pending_health
printf '%s|%s' "$phase" "$last_verified"
'''
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, (name, result.stderr)
        assert result.stdout == f'{phase}|{verified}', (name, result.stdout, f'{phase}|{verified}')
    matrix = definitions + setup + '''
health_has_reply=1; checked=0; gap=0
while [ "$gap" -le 16 ]; do
  lag=0
  while [ "$lag" -le 16 ]; do
    probe_observed_at=$((100 + gap)); current=$((probe_observed_at + lag))
    actual=0; if identity_continuity_fresh "$current"; then actual=1; fi
    expected_result=0
    if [ "$gap" -le 12 ] && [ "$lag" -le 12 ]; then expected_result=1; fi
    [ "$actual" = "$expected_result" ] || exit 1
    checked=$((checked + 1)); lag=$((lag + 1))
  done
  gap=$((gap + 1))
done
printf '%s' "$checked"
'''
    result = subprocess.run(['/bin/sh', '-c', matrix], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and result.stdout == '289', result.stderr

    publication = definitions + setup.replace('publish() { last_reason=$3; }', '') + '''
expires=0; mode=live; trial_verified=0; status_file="$directory/status"
fixture_time=110; publish OPEN "$expected" probe-ok
/bin/cat "$directory/evidence"
fixture_time=111; publish OPEN - probe-retry
/bin/cat "$directory/evidence"
'''
    result = subprocess.run(['/bin/sh', '-c', publication], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    records = [line.split('|') for line in result.stdout.splitlines()]
    assert len(records) == 2 and all(len(row) == 11 for row in records), records
    assert [row[3] for row in records] == ['110', '111'], records
    assert all(row[4] == '100' and row[5] == '10' and row[10] == '1' for row in records), records
    assert (root / 'evidence').stat().st_mode & 0o777 == 0o600
    # The completed round can select an older peer after a newer streamed
    # independent result was already accepted. Exercise the actual outer
    # decision block; it must not overwrite that newer observation.
    command = definitions + setup + '''
fixture_time=113; last_probe=113; last_verified=112; probe_observed_at=100
health_has_reply=1; probe_ok=1; observed=$expected; observed_region=US
probe_used=$probe_primary; mode=live; expires=0; trial_verified=0
while :; do
''' + production_decision + '''
  break
done
printf '%s|%s' "$phase" "$last_verified"
'''
    result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and result.stdout == 'OPEN|112', ('outer-decision-regressed-streamed-proof', result.stdout, result.stderr)
    # Schedule from a completed observation, not from the end of its local
    # processing. These are actual production waits with only time/sleep
    # replaced. A slow peer must not add a second settling interval.
    scheduled_definitions = definitions.replace('/bin/sleep 1', 'fixture_sleep 1')
    for phase, now, observation, expected_sleep in [
        ('LOCKED', 105, 100, 0), ('LOCKED', 101, 100, 2),
        ('LOCKED', 100, 100, 3), ('OPEN', 101, 100, 1),
        ('LOCKED', 100, 0, 3),
    ]:
        command = scheduled_definitions + setup + f'''
phase={phase}; fixture_time={now}; last_verified={observation}; consecutive=1
fixture_slept=0
fixture_sleep() {{ fixture_time=$((fixture_time + $1)); fixture_slept=$((fixture_slept + $1)); }}
guard_sleep 3
printf '%s' "$fixture_slept"
'''
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stdout == str(expected_sleep), (
            'observation-schedule', phase, now, observation, result.stdout, expected_sleep, result.stderr)
    print(f'PASS: {len(cases)} evidence-order transitions, 289 lease combinations and private observation/heartbeat separation')
