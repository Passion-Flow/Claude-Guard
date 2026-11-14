"""Production admission transaction ordering without host/network changes."""
from pathlib import Path
import argparse
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--baseline', type=Path)
options = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
worker = (options.baseline or repo / 'Sources/GuardWorker.sh').read_text()
definitions = worker.split('action=${1-}')[0]
begin = worker.index('      # A delayed probe or a clock jump')
end = worker.index('      publish "$phase" "$observed" "$reason"', begin)
end += len('      publish "$phase" "$observed" "$reason"')
decision = worker[begin:end]
definitions = definitions.replace('$(/bin/date +%s)', '$(fixture_now)').replace('/bin/mv', 'fixture_mv')
decision = decision.replace('$(/bin/date +%s)', '$(fixture_now)').replace('/bin/sleep 2', ':')
with tempfile.TemporaryDirectory(prefix='cg-admission-transaction-') as temporary:
    root = Path(temporary)
    for case in (['success'] if options.baseline else ['success', 'rule-write-failure', 'prepare-write-failure']):
        for path in root.iterdir():
            path.unlink()
        setup = """
directory=FIXTURE_DIRECTORY
status_file="$directory/status"
fixture_now() { printf 110; }
fixture_mv() {
  if [ "${fixture_fail_publish:-0}" = 1 ] && [ "$3" = "$directory/evidence" ] &&
     /usr/bin/grep -q '|ADMITTING|' "$2"; then return 1; fi
  /bin/mv "$@"
}
iface=utun1; expected=192.0.2.42; risk_region=US
session=fixture; vpn_service=service; endpoint_key=endpoint; bound_path=path
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"; risk_checked_at=0
phase=LOCKED; last_verified=106; stable_since=80; consecutive=5
last_probe=110; probe_observed_at=110; probe_ok=1; observed=$expected; observed_region=US
probe_used=$probe_primary; mode=live; expires=0; trial_verified=0
rules_intact() { return 0; }
underlay_snapshot() { printf path; }
vpn_connection() { printf 'Connected utun1'; }
probe_route_reason() { return 0; }
renew_risk_evidence() { risk_checked_at=110; }
load_phase() {
  [ "$1" = OPEN ] || return 1
  /bin/cp "$directory/evidence" "$directory/grant-proof"
  /bin/cp "$status_file" "$directory/grant-status"
  [ "$fixture_case" != rule-write-failure ]
}
publish LOCKED "$expected" settling
fixture_case=FIXTURE_CASE
fixture_fail_publish=0
[ "$fixture_case" != prepare-write-failure ] || fixture_fail_publish=1
for fixture_iteration in once; do
""".replace('FIXTURE_DIRECTORY', "'" + str(root) + "'").replace('FIXTURE_CASE', case)
        result = subprocess.run(['/bin/sh', '-c', definitions + setup + decision + '\ndone\n'],
                                capture_output=True, text=True, timeout=8)
        grant = root / 'grant-proof'
        if case == 'prepare-write-failure':
            assert result.returncode != 0 and not grant.exists(), ('failed-proof-must-precede-any-grant', result.returncode, result.stderr)
            continue
        assert result.returncode == 0, (case, result.stderr)
        proof = grant.read_text().strip().split('|')
        status = (root / 'grant-status').read_text().strip().split('|')
        final_proof = (root / 'evidence').read_text().strip().split('|')
        final_status = (root / 'status').read_text().strip().split('|')
        if options.baseline:
            assert proof[2] == 'LOCKED' and proof[5] == '0' and final_proof[2] == 'OPEN'
            print('COUNTEREXAMPLE: production kernel grant preceded publication of accepted risk evidence')
            continue
        assert proof[2] == 'ADMITTING' and proof[3:6] == ['110', '110', '110'] and proof[10] == '1', (case, proof)
        assert status[1] == 'LOCKED', 'UI must remain restrictive before rule commit'
        expected = 'OPEN' if case == 'success' else 'DRIFT'
        assert final_proof[2] == final_status[1] == expected, (case, final_proof, final_status)
        assert (root / 'evidence').stat().st_mode & 0o777 == 0o600
    if not options.baseline:
        print('PASS: complete proof precedes grant; UI commits afterward; proof/write failures cannot publish OPEN')

