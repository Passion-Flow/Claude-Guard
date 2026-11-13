"""Check the engineering harness without installation or network access."""
import ast
import copy
from pathlib import Path
import plistlib
import runpy
import subprocess

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
