"""Counterexamples for the installed observer, without installed-service access."""
from pathlib import Path
import copy
import runpy
import subprocess

repo=Path(__file__).resolve().parents[1]
module=runpy.run_path(str(repo/'Tests/production_runtime.py'))
decode=module['decode_evidence']
checks=module['open_checks']
session='00000000-0000-4000-8000-000000000001'
service='00000000-0000-4000-8000-000000000002'
evidence=decode(f'1|{session}|OPEN|1000|995|100|utun1|{service}|192.0.2.7:443/tcp|192.0.2.42|1\n')
intent={'armed':True,'approved':True,'persistent':True,'maintenance':False,'session':session,
        'serviceID':service,'route':{'peer':'192.0.2.7','port':'443','transport':'tcp','expected':'192.0.2.42'}}
fence={'session':session,'monitoring':True,'openAllowed':True,'powerBlocked':False,'sleepPending':False}
assert all(checks(evidence,intent,fence,1000).values())
for field,value,category in [
 ('observed',987,'observation-age'),('observed',1001,'observation-age'),
 ('published',987,'heartbeat-age'),('risk',0,'risk-age'),('risk',1001,'risk-age'),
 ('bound',False,'proof-context'),('phase','LOCKED','open'),
 ('session','other','session'),('expected','192.0.2.99','route'),('service','other','service')]:
 changed=dict(evidence,**{field:value})
 assert not checks(changed,intent,fence,1000)[category],(field,category)
# A current heartbeat cannot conceal expired proof.
changed=dict(evidence,published=1000,observed=987)
result=checks(changed,intent,fence,1000)
assert result['heartbeat-age'] and not result['observation-age']
# The same endpoint may use a refreshed utun number after revalidation; the
# observer binds the current session/service and the actual PF readback.
for field,value,category in [('openAllowed',False,'native-permission'),('sleepPending',True,'native-permission')]:
 assert not checks(evidence,intent,dict(fence,**{field:value}),1000)[category]
for text in ['malformed','1|x|OPEN|1|1|1|utun1|x|x|x|yes',
             f'1|{session}|OPEN|1000|nan|100|utun1|{service}|x|x|1',
             f'1|{session}|OPEN|1000|995|100|utun1|{service}|x|x|1\nextra']:
 try:decode(text)
 except module['EvidenceFailure']:pass
 else:raise AssertionError('Malformed evidence accepted')
print('PASS: observation freshness independent of heartbeat; exact session, risk and permission controls')

# Actual macOS pfctl may return zero and partial stdout when a concurrent
# ruleset commit invalidates DIOCGETRULE/DIOCGETADDRS. Reproduce that contract,
# never interpreting a partial list as a complete authorization snapshot.
namespace = module['pf_read'].__globals__
original_command = namespace['command']
original_sleep = namespace['time'].sleep
pending = []
calls = []
warnings = b'No ALTQ support in kernel\nALTQ related functions disabled\n'
def command(arguments, timeout=10):
    calls.append(arguments)
    code, output, diagnostics = pending.pop(0)
    return subprocess.CompletedProcess(arguments, code, output, diagnostics)
try:
    namespace['command'] = command
    namespace['time'].sleep = lambda seconds: None
    for diagnostic in (b'pfctl: DIOCGETRULE: Resource busy\n', b'pfctl: DIOCGETADDRS: Resource busy\n'):
        pending[:] = [(0, b'partial rules\n', warnings + diagnostic),
                      (0, b'block drop quick all label "CG_BLOCK"\n', warnings)]
        result = module['pf_read'](['-a', module['ANCHOR'], '-sr'])
        assert b'CG_BLOCK' in result.stdout and not pending
    for diagnostics in (warnings + b'pfctl: Permission denied\n', warnings + b'unknown diagnostic\n'):
        pending[:] = [(0, b'block drop quick all label "CG_BLOCK"\n', diagnostics)]
        try: module['pf_read'](['-a', module['ANCHOR'], '-sr'])
        except module['EvidenceFailure'] as error: assert str(error) == 'kernel-readback-unavailable'
        else: raise AssertionError('An unrecognized read error must not authorize a complete snapshot')
    calls.clear()
    pending[:] = [(0, b'partial', warnings + b'pfctl: DIOCGETRULE: Resource busy\n')] * 3
    try: module['pf_read'](['-a', module['ANCHOR'], '-sr'])
    except module['EvidenceFailure'] as error: assert str(error) == 'kernel-generation-remained-unstable'
    else: raise AssertionError('Persistent enumeration failure must remain unverified')
    assert len(calls) == 3 and not pending
    calls.clear()
    pending[:] = [(0, b'Status: Enabled\n', warnings), (0, b'', warnings)]
    assert not module['kernel_matches']({'lastRules': 'block drop quick all label "CG_BLOCK"'})
    assert len(calls) == 2 and not pending, 'A complete missing boundary must fail without a success-seeking retry'
finally:
    namespace['command'] = original_command
    namespace['time'].sleep = original_sleep
print('PASS: zero-exit partial PF reads, bounded generation retries and immediate rejection of a complete missing boundary')

