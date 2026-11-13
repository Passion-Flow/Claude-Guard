"""Real elapsed-time controls for pending replies; no host clock/network/PF changes."""
from pathlib import Path
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cg-streaming-health-') as temporary:
    root = Path(temporary)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    curl = root / 'curl'
    curl.write_text('''#!/bin/sh
root=$(dirname "$0")
output=; budget=4; url=
while [ "$#" -gt 0 ]; do
 case "$1" in
  --output) output=$2; shift 2;;
  --max-time) budget=$2; shift 2;;
  *) url=$1; shift;;
 esac
done
case "$url" in
 https://1.1.1.1/*) label=primary;;
 https://api.ipify.org) label=independent;;
 *) label=backup;;
esac
IFS='|' read -r delay unavailable < "$root/$label.settings"
wait_for=$(/usr/bin/awk -v a="$delay" -v b="$budget" 'BEGIN {print (a<b ? a:b)}')
/bin/sleep "$wait_for"
[ "$unavailable" = false ] || exit 28
/usr/bin/awk -v a="$delay" -v b="$budget" 'BEGIN {exit(a>b)}' || exit 28
/bin/cat "$root/$label.body" > "$output"
printf 200
''')
    curl.chmod(0o700)
    definitions = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]
    definitions = definitions.replace('/usr/bin/curl', str(curl))
    setup = f'''
directory='{runtime}'; health_cache_file="$directory/independent-address"
iface=utun1; peer=192.0.2.7; expected=192.0.2.42; risk_region=US
session=fixture; vpn_service=service; endpoint_key=endpoint; bound_path=path
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"
phase=OPEN; risk_checked_at=$(( $(/bin/date +%s) - 100 ))
last_verified=$(( $(/bin/date +%s) - LAST_AGE ))
rules_intact() {{ return 0; }}
underlay_snapshot() {{ printf path; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
route_via_tunnel() {{ return 0; }}
load_phase() {{ /bin/date +%s > '{root}/sealed'; }}
enforce_seal() {{ load_phase SEALED; }}
publish() {{ return 0; }}
'''

    def run(scenario, age=7, extra=''):
        for label, case in scenario.items():
            (root / (label + '.settings')).write_text(str(case.get('delay', .1)) + '|' + str(case.get('unavailable', False)).lower() + '\n')
            (root / (label + '.body')).write_text(case.get('body', 'ip=192.0.2.42\nloc=US\n'))
        (runtime / 'independent-address').write_text('9.9.9.9|' + str(int(time.time())))
        (root / 'sealed').unlink(missing_ok=True)
        command = definitions + setup.replace('LAST_AGE', str(age)) + extra + '''
before=$last_verified
if sample_exit; then result=positive; else result=unavailable; fi
now=$(/bin/date +%s)
fresh=false; if identity_fresh "$now"; then fresh=true; fi
printf '%s|%s|%s|%s|%s|%s' "$result" "$phase" "$before" "$last_verified" "$probe_observed_at" "$fresh"
'''
        started = time.time()
        p = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=12)
        assert p.returncode == 0, p.stderr
        assert not list(runtime.glob('health.*'))
        return p.stdout.split('|'), started

    slow_missing = {'delay': 5, 'unavailable': True}
    output, _ = run({'primary': {'delay': .1}, 'backup': slow_missing, 'independent': slow_missing})
    assert 0 <= int(output[4]) - int(output[2]) <= 12, ('early-response-control-invalid', output)
    assert output[1] == 'OPEN' and output[-1] == 'true', output
    assert int(output[3]) > int(output[2]) and output[3] == output[4], output
    assert not (root / 'sealed').exists()

    output, started = run({name: slow_missing for name in ('primary', 'backup', 'independent')}, age=11)
    assert output[1] != 'OPEN' and output[-1] == 'false', output
    assert int((root / 'sealed').read_text()) - started < 3, 'Actual expiry was hidden behind pending transport'

    output, _ = run({'primary': {'delay': 4}, 'backup': slow_missing, 'independent': slow_missing}, age=11)
    assert output[1] != 'OPEN' and output[-1] == 'false', output
    assert output[3] == '0', 'A reply after expiry restored an old OPEN authorization'

    output, _ = run({'primary': {'delay': .1},
                     'backup': {'delay': 2, 'body': 'ip=192.0.2.99\nloc=US\n'},
                     'independent': slow_missing})
    assert output[1] != 'OPEN' and (root / 'sealed').exists(), output
    output, _ = run({name: slow_missing for name in ('primary', 'backup', 'independent')}, age=1)
    assert output[1] == 'OPEN' and output[2] == output[3], 'Missing replies or heartbeats changed the original proof'
    for extra in ('risk_checked_at=1\n', 'underlay_snapshot() { printf changed; }\n',
                  'rules_intact() { return 1; }\n'):
        output, _ = run({'primary': {'delay': .1}, 'backup': slow_missing, 'independent': slow_missing}, extra=extra)
        assert output[1] != 'OPEN' and output[-1] == 'false' and (root / 'sealed').exists(), (extra, output)
    events = (runtime / 'health-events').read_text()
    assert '192.0.2.' not in events and 'ip=' not in events and 'loc=' not in events
    assert 'exit-mismatch' in events and 'evidence-expired' in events
    print('PASS: processed proof continuity while peers are pending, timely actual expiry, late-reply denial and conflicting-proof sealing')
