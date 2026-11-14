"""Budget and streaming counterexamples for risk renewal; no host changes."""
from pathlib import Path
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
definitions = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]

with tempfile.TemporaryDirectory(prefix='cg-risk-scheduling-') as temporary:
    root = Path(temporary)
    setup = f'''
directory='{root}'
iface=utun1; peer=192.0.2.7; expected=192.0.2.42; observed=$expected; risk_region=US; observed_region=US
session=fixture; vpn_service=service; endpoint_key=endpoint; bound_path=path
phase=OPEN; desired=OPEN; probe_region_source=observed
now=$(/bin/date +%s); last_probe=$now; last_verified=$now; risk_checked_at=$((now - 2701))
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"
underlay_snapshot() {{ printf path; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
rules_intact() {{ return 0; }}
load_phase() {{ printf '%s\\n' "$1" >> '{root}/loads'; }}
publish() {{ return 0; }}
review_exit_risk() {{
 printf 'attempt\\n' >> '{root}/calls'
 /bin/sleep 2.1
 risk_admission_at=$(/bin/date +%s)
 return 0
}}
'''
    def run(extra):
        (root / 'calls').write_text('')
        result = subprocess.run(['/bin/sh', '-c', definitions + setup + extra + '''
before=$risk_checked_at
renew_risk_evidence
printf '%s|%s|%s|%s' "$phase" "$desired" "$reason" "$((risk_checked_at - before))"
'''], capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, result.stderr
        return result.stdout, (root / 'calls').read_text().splitlines()

    value, calls = run('last_verified=$((now - 11))\n')
    assert value == 'OPEN|OPEN|risk-refresh-pending|0' and not calls, (
        'A slow risk lookup must not begin without enough identity budget', value, len(calls))
    value, calls = run('reason=stable-open\n')
    assert value.startswith('OPEN|OPEN|') and len(calls) == 1 and int(value.split('|')[3]) > 0, value
    value, calls = run('last_verified=$((now - 13))\n')
    assert value.startswith('OPEN|LOCKED|evidence-expired|') and not calls, value
    value, calls = run('evidence_context=foreign\n')
    assert value.startswith('OPEN|LOCKED|evidence-expired|') and not calls, value
    value, calls = run('probe_region_source=accepted-cache\n')
    assert value == 'OPEN|OPEN|risk-refresh-pending|0' and not calls, value

    # Use the real pending-response loop. One fast trace must be able to
    # schedule renewal before its slow peers consume the fresh proof budget.
    curl = root / 'curl'
    curl.write_text('''#!/bin/sh
out=; url=
while [ "$#" -gt 0 ]; do
 case "$1" in --output) out=$2; shift 2;; *) url=$1; shift;; esac
done
case "$url" in
 https://1.1.1.1/*) /bin/sleep .1; printf 'ip=192.0.2.42\\nloc=US\\n' > "$out"; printf 200;;
 *) /bin/sleep 4; exit 28;;
esac
''')
    curl.chmod(0o700)
    stream_definitions = definitions.replace('/usr/bin/curl', str(curl))
    for rejected in (False, True):
        (root / 'calls').write_text('')
        (root / 'independent-address').write_text('9.9.9.9|' + str(int(time.time())) + '|600|checkip.amazonaws.com')
        stream_setup = setup + '''
health_cache_file="$directory/independent-address"
last_verified=$((now - 1))
route_via_tunnel() { return 0; }
'''
        if rejected:
            stream_setup += f'''
review_exit_risk() {{ printf 'attempt\\n' >> '{root}/calls'; /bin/sleep 1; return 1; }}
'''
        command = stream_definitions + stream_setup + '''
before=$risk_checked_at
if sample_exit; then :; fi
printf '%s|%s' "$phase" "$((risk_checked_at - before))"
'''
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert (root / 'calls').read_text().splitlines() == ['attempt'], result.stdout
        phase, advance = result.stdout.split('|')
        assert (phase != 'OPEN' and int(advance) < 0) if rejected else (phase == 'OPEN' and int(advance) > 0), result.stdout

print('PASS: risk operation budget, streaming renewal behind slow peers, rejection, expired and foreign proof')

