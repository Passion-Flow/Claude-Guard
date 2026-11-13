"""Check the engineering harness without installation or network access."""
import ast
import copy
from pathlib import Path
import plistlib
import runpy
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
for path in sorted((ROOT / 'Tests').glob('*.py')):
    ast.parse(path.read_text(), filename=path.name)
driver = runpy.run_path(str(ROOT / 'Tests/host_acceptance.py'))
browser_host = runpy.run_path(str(ROOT / 'Tests/browser_host_server.py'))
now = 1000
sample = {'browser_phase': 'protected-open', 'browser_phase_started_at': now, 'checks': {}}
assert browser_host['current_phase'](sample, now) == 'protected-open'
for invalid in [dict(sample, left_state='restored'), dict(sample, browser_phase='ended'),
                dict(sample, browser_phase_started_at=now-606), dict(sample, browser_phase_started_at=now+1),
                dict(sample, checks={'driver_completed': {'result': 'FAIL'}})]:
    assert browser_host['current_phase'](invalid, now) == 'unavailable'
worker = (ROOT / 'Sources/GuardWorker.sh').read_text()
instrumented = driver['instrument_worker'](worker)
subprocess.run(['/bin/sh', '-n'], input=instrumented, text=True, capture_output=True, check=True)
for invariant in ['identity_lease_seconds=12', 'stability_seconds=15', 'stability_samples=6',
                  'block drop log (user) quick all label "CG_BLOCK"', 'user root flags any no state label "CG_PROBE_OUT"',
                  "--noproxy '*'", "--proto '=https'", '--tlsv1.2']:
    assert invariant in instrumented, invariant
assert instrumented.count('>> "$directory/curl-timings"') == 1

# Exercise the transformed transport, including its original failure status.
# Neither branch uses a real network or privileged policy operation.
with tempfile.TemporaryDirectory(prefix='cg-harness-transport-') as temporary:
    root = Path(temporary)
    curl = root / 'curl'
    curl.write_text('''#!/bin/sh
output=
while [ "$#" -gt 0 ]; do
 if [ "$1" = --output ]; then output=$2; shift 2; else shift; fi
done
printf fixture-body > "$output"
if [ -f "${0%/*}/fail" ]; then printf '000|0|0|0|0|0'; exit 28; fi
printf '200|0.01|0.02|0.03|0.04|12345'
''')
    curl.chmod(0o700)
    definitions = instrumented.split('action=${1-}')[0].replace('/usr/bin/curl', str(curl))
    for fail in (False, True):
        if fail:
            (root / 'fail').touch()
        command = definitions + '\ndirectory=' + str(root) + '''
iface=utun1
if tunnel_response 4 https://fixture.invalid > "$directory/body"; then code=0; else code=$?; fi
printf '%s|%s|%s|%s' "$code" "$transport_exit" "$http_status" "$response_received_at"
'''
        result = subprocess.run(['/bin/sh', '-c', command], capture_output=True, text=True, check=True, timeout=10)
        fields = result.stdout.split('|')
        assert fields[:3] == (['1', '28', '000'] if fail else ['0', '0', '200']), fields
        if not fail:
            assert 0 <= time.time() - int(fields[3]) < 3
        assert len((root / 'curl-timings').read_text().splitlines()) == 1 + int(fail)

profile = runpy.run_path(str(ROOT / 'Tests/shadowrocket_numeric_test_profile.py'))
selection = 'fixture-selected-profile'
original_host = 'node.example.invalid'
for wrapped in [False, True]:
    objects = ['$null', selection, original_host]
    host_reference = plistlib.UID(2)
    if wrapped:
        objects.append({'NS.string': host_reference})
        host_reference = plistlib.UID(3)
    record = {'uuid': plistlib.UID(1), 'host': host_reference,
              'opaqueCredentialAlias': host_reference, 'opaquePayload': b'fixture-opaque-payload'}
    objects.append(record)
    graph = {'$archiver': 'NSKeyedArchiver', '$objects': objects, '$top': {'root': plistlib.UID(len(objects)-1)}}
    before = plistlib.dumps(graph, fmt=plistlib.FMT_BINARY, sort_keys=False)
    changed = profile['replace_host'](before, selection, original_host, '198.51.100.42')
    parsed, row, scalar = profile['selected'](changed, selection)
    assert scalar(row['host']) == '198.51.100.42'
    assert scalar(row['opaqueCredentialAlias']) == original_host
    assert row['opaquePayload'] == b'fixture-opaque-payload'
    restored = profile['replace_host'](changed, selection, '198.51.100.42', original_host)
    _, row, scalar = profile['selected'](restored, selection)
    assert scalar(row['host']) == original_host
    assert scalar(row['opaqueCredentialAlias']) == original_host
print('PASS: engineering script syntax, isolated instrumentation and alias-safe profile restoration; no host changes')
