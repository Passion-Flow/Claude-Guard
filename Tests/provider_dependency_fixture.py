"""Elapsed-time controls for common health-provider dependencies.

Execute the production worker definitions with fixed local transport responses.
No host networking, installed configuration, clocks or admission data changes.
"""
from pathlib import Path
import argparse
import json
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--worker', type=Path)
parser.add_argument('--expect-counterexample', action='store_true')
options = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
worker = options.worker or repo / 'Sources/GuardWorker.sh'
definitions = worker.read_text().split('action=${1-}')[0]

with tempfile.TemporaryDirectory(prefix='cg-provider-dependency-') as temporary:
    root = Path(temporary)
    runtime = root / 'runtime'
    runtime.mkdir(mode=0o700)
    curl = root / 'curl'
    curl.write_text('''#!/usr/bin/python3
from pathlib import Path
import json,sys,time
root=Path(__file__).parent
a=sys.argv[1:]
url=a[-1]
assert a[0]=='-q' and a[a.index('--interface')+1]=='if!utun1'
assert a[a.index('--proto')+1]=='=https' and a[a.index('--noproxy')+1]=='*'
assert '--tlsv1.2' in a and '-k' not in a and '--location' not in a
if url.startswith('https://1.') or url.startswith('https://cloudflare-dns.com/'):
 label='unavailable-trace-operator'
elif url.startswith('https://dns.google/resolve?'):
 label='independent-resolver'
 assert a[a.index('--resolve')+1]=='dns.google:443:8.8.8.8'
 assert 'edns_client_subnet=0.0.0.0/0' in url
elif url=='https://checkip.amazonaws.com':
 label='independent-address'
 assert a[a.index('--resolve')+1]=='checkip.amazonaws.com:443:9.9.9.9'
else:
 raise AssertionError('unexpected-transport')
with (root/'events').open('a') as f:f.write(json.dumps({'provider':label,'started':time.time()})+'\\n')
if label=='unavailable-trace-operator':
 time.sleep(float(a[a.index('--max-time')+1]));raise SystemExit(28)
time.sleep(.05)
if label=='independent-resolver':
 body=json.dumps({'Status':0,'TC':False,'Question':[{'name':'checkip.amazonaws.com.','type':1}],
   'Answer':[{'name':'checkip.amazonaws.com.','type':1,'data':'9.9.9.9','TTL':1}]})
else:
 body='192.0.2.42'
Path(a[a.index('--output')+1]).write_text(body)
print('200',end='')
''')
    curl.chmod(0o700)
    # Expired cached DNS must require a fresh independent resolution. The very
    # short returned TTL also forces another resolution during the slow round.
    (runtime / 'independent-address').write_text(
        f'9.9.9.9|{int(time.time()) - 61}|60|checkip.amazonaws.com')
    setup = f'''
directory='{runtime}'; health_cache_file="$directory/independent-address"
iface=utun1; peer=192.0.2.7; expected=192.0.2.42; risk_region=US
session=fixture; vpn_service=service; endpoint_key=endpoint; bound_path=path
evidence_context="$session|$vpn_service|$iface|$endpoint_key|$expected|$bound_path"
risk_context="$evidence_context|$risk_region"
phase=OPEN; risk_checked_at=$(( $(/bin/date +%s) - 100 ))
last_verified=$(( $(/bin/date +%s) - 6 ))
before_risk=$risk_checked_at
rules_intact() {{ return 0; }}
underlay_snapshot() {{ printf path; }}
vpn_connection() {{ printf 'Connected utun1'; }}
probe_route_reason() {{ return 0; }}
route_via_tunnel() {{ return 0; }}
load_phase() {{ printf '%s\\n' "$1" >> '{root}/sealed'; }}
enforce_seal() {{ load_phase SEALED; }}
publish() {{ return 0; }}
if sample_exit; then :; fi
fresh=false; if identity_fresh "$(/bin/date +%s)"; then fresh=true; fi
renewed=false; if [ "$risk_checked_at" -gt "$before_risk" ]; then renewed=true; fi
printf '%s|%s|%s' "$phase" "$fresh" "$renewed"
'''
    began = time.monotonic()
    result = subprocess.run(['/bin/sh', '-c', definitions.replace('/usr/bin/curl', str(curl)) + setup],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert not list(runtime.glob('health.*')), 'Health children were not drained'
    events = [json.loads(row) for row in (root / 'events').read_text().splitlines()]
    count = {name: sum(row['provider'] == name for row in events) for name in
             ('unavailable-trace-operator', 'independent-resolver', 'independent-address')}
    report = {'seconds': round(time.monotonic() - began, 3), 'result': result.stdout,
              'sealed': (root / 'sealed').exists(), 'requests': count}
    if options.expect_counterexample:
        assert report['sealed'] and result.stdout == 'LOCKED|false|false', report
        assert count['independent-address'] == 0 and count['independent-resolver'] == 0, report
        print('CONFIRMED: trace-operator loss also prevents the independent provider after DNS cache expiry')
    else:
        assert not report['sealed'] and result.stdout == 'OPEN|true|false', report
        assert count['independent-address'] >= 2 and count['independent-resolver'] >= 2, report
        assert count['independent-resolver'] <= 6, report
        print('PASS: trace-operator loss and repeated DNS expiry retain independent fresh identity without renewing risk')
    print(json.dumps(report, sort_keys=True))
