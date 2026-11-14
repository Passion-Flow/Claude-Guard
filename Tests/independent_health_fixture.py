"""Exercise real worker continuity with substituted transport, never host networking."""
from pathlib import Path
import json
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cg-independent-health-') as temporary:
    root = Path(temporary)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    curl = root / 'curl'
    curl.write_text('''#!/usr/bin/python3
from pathlib import Path
import json,sys,time
root=Path(__file__).parent
a=sys.argv[1:]
assert a[0]=='-q' and a[a.index('--interface')+1]=='if!utun1'
assert a[a.index('--noproxy')+1]=='*' and a[a.index('--proto')+1]=='=https'
assert '--tlsv1.2' in a and '--location' not in a and '-k' not in a
name='independent' if a[-1]=='https://checkip.amazonaws.com' else ('primary' if a[-1].startswith('https://1.1.1.1/') else 'backup')
with (root/'calls').open('a') as f:f.write(name+'\\n')
case=json.loads((root/'scenario.json').read_text())[name]
time.sleep(case.get('delay',.05))
if case.get('unavailable'):raise SystemExit(28)
body=case.get('body','192.0.2.42' if name=='independent' else 'ip=192.0.2.42\\nloc=US\\n')
Path(a[a.index('--output')+1]).write_text(body)
print(case.get('status','200'),end='')
''')
    curl.chmod(0o700)
    route = root / 'route'
    route.write_text('#!/bin/sh\nprintf "interface: %s\\n" "$(cat ' + str(root / 'route-link') + ')"\n')
    route.chmod(0o700)
    (root / 'route-link').write_text('utun1')
    definitions = (repo / 'Sources/GuardWorker.sh').read_text().split('action=${1-}')[0]
    definitions = definitions.replace('/usr/bin/curl', str(curl)).replace('/sbin/route', str(route))
    setup = f'''
directory='{runtime}'; health_cache_file="$directory/independent-address"
iface=utun1; peer=192.0.2.7; expected=192.0.2.42; risk_region=US
session=fixture; vpn_service=service; endpoint_key=endpoint; bound_path=path
risk_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path|$risk_region"
phase=OPEN; risk_checked_at=$(( $(/bin/date +%s) - 100 ))
last_verified=$(/bin/date +%s)
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
rules_intact() {{ return 0; }}
underlay_snapshot() {{ printf path; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
load_phase() {{ printf '%s' "$1" > '{root}/phase'; }}
publish() {{ return 0; }}
'''
    def run(primary=None, backup=None, independent=None, extra=''):
        (root / 'scenario.json').write_text(json.dumps({
            'primary': primary or {}, 'backup': backup or {}, 'independent': independent or {}}))
        (root / 'calls').write_text('')
        (runtime / 'independent-address').write_text('9.9.9.9|' + str(int(time.time())) + '|600|checkip.amazonaws.com')
        command = definitions + setup + extra + '''
if sample_exit; then
 printf '%s|%s|%s|%s' "$observed" "$observed_region" "$probe_used" "$probe_region_source"
else printf unavailable; fi
'''
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, result.stderr
        assert not list(runtime.glob('health.*'))
        return result.stdout, (root / 'calls').read_text().splitlines()

    missing = {'unavailable': True}
    output, calls = run(missing, missing)
    assert output == '192.0.2.42|US|independent|accepted-cache', output
    assert calls.count('independent') == 1
    output, _ = run(missing, missing, {'body': '192.0.2.99'})
    assert output.startswith('192.0.2.99||independent|unavailable'), output
    output, _ = run({'body': 'ip=192.0.2.99\nloc=US\n'}, missing)
    assert output.startswith('192.0.2.99|US|'), output
    output, _ = run({'body': 'ip=192.0.2.42\nloc=CN\n'}, missing)
    assert output.startswith('192.0.2.42|CN|') and output.endswith('|observed'), output
    for extra in ('phase=LOCKED\n', 'risk_checked_at=0\n',
                  'risk_checked_at=$(( $(/bin/date +%s) - 3600 ))\n', 'risk_context=foreign\n'):
        output, calls = run(missing, missing, extra=extra)
        assert output == 'unavailable' and 'independent' not in calls, (extra, output, calls)
    for body in ('192.0.2.42\n192.0.2.99', '192.0.2.42=extra', ' 192.0.2.42', '192.0.2.\0' + '42'):
        output, _ = run(missing, missing, {'body': body})
        assert output == 'unavailable', output
    output, _ = run(missing, missing, {'status': '302'})
    assert output == 'unavailable'
    (root / 'route-link').write_text('en0')
    output, calls = run(missing, missing)
    assert output == 'unavailable' and 'independent' not in calls
    (root / 'route-link').write_text('utun1')

    # Cached region continuity must never extend risk or enter a new admission.
    for expired in (False, True):
        command = definitions + setup + '''
probe_region_source=accepted-cache
review_exit_risk() { exit 99; }
load_phase() { printf '%s|' "$1"; }
''' + ('risk_checked_at=1\n' if expired else '') + '''
before=$risk_checked_at
renew_risk_evidence
printf '%s|%s|%s' "$phase" "$reason" "$((risk_checked_at - before))"
'''
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, check=True)
        if expired:
            assert result.stdout.startswith('LOCKED|LOCKED|evidence-expired|'), result.stdout
        else:
            assert result.stdout == 'OPEN|risk-refresh-pending|0', result.stdout
    print('PASS: independent continuity, conflicting proof rejection, original risk expiry, no new admission, strict bodies and tunnel-only routing')
