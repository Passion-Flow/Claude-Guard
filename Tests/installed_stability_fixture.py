"""Control safety and observation counterexamples; no host/network changes."""
from pathlib import Path
import ast
import json
import runpy
import signal
import subprocess
import tempfile
from types import SimpleNamespace

repo = Path(__file__).resolve().parents[1]
module = runpy.run_path(str(repo / 'Tests/installed_stability_acceptance.py'))
namespace = module['signal_same_process'].__globals__
deadline = module['deadline_failures']
fresh = dict.fromkeys(('heartbeat-age', 'observation-age', 'risk-age', 'proof-context'), True)
assert deadline(fresh, False) == []
assert deadline(dict(fresh, **{'observation-age': False}), False) == ['observation-age']
assert deadline(dict(fresh, **{'risk-age': False}), False) == ['risk-age']
assert deadline(dict(fresh, **{'observation-age': False}), True) == []
assert deadline({}, False), 'Absent evidence cannot authorize an actual tunnel rule'
original_kill = namespace['os'].kill
sent = []
try:
    namespace['os'].kill = lambda pid, value: sent.append((pid, value))
    namespace['process_identity'] = lambda pid, executable=None: 'new-process'
    assert not module['signal_same_process']({'pid': 42, 'identity': 'old-process'}, signal.SIGCONT)
    assert not sent, 'A reused PID must never receive the recovery signal'
    assert module['signal_same_process']({'pid': 42, 'identity': 'new-process'}, signal.SIGCONT)
    assert sent == [(42, signal.SIGCONT)]
finally:
    namespace['os'].kill = original_kill

stopped = []
namespace['process_identity'] = lambda pid, executable=None: 'identity-' + str(pid)
namespace['signal_same_process'] = lambda record, value: stopped.append(record['pid']) or True
provider_commands = {
    51: '/usr/bin/curl https://1.1.1.1/cdn-cgi/trace',
    52: '/usr/bin/curl https://cloudflare-dns.com/dns-query?name=checkip.amazonaws.com&type=A',
    53: '/usr/bin/curl https://dns.google/resolve?name=checkip.amazonaws.com&type=A&edns_client_subnet=0.0.0.0/0',
    54: '/usr/bin/curl https://checkip.amazonaws.com',
    55: '/usr/bin/curl https://cloudflare-dns.com/dns-query?name=unrelated.invalid&type=A',
    56: '/usr/bin/curl https://1.0.0.1/cdn-cgi/trace',
}
def provider_processes(arguments, **options):
    if '-axo' in arguments:
        output = '\n'.join(f'{pid} {42 if pid != 56 else 1} 0 /usr/bin/curl'
                           for pid in provider_commands)
    else:
        output = provider_commands[int(arguments[arguments.index('-p') + 1])]
    return subprocess.CompletedProcess(arguments, 0, output.encode(), b'')
namespace['run'] = provider_processes
assert module['terminate_health_requests']({'pid': 42, 'identity': 'identity-42'},
    healthy_provider='independent', trace_operator=True) == 2
assert stopped == [51, 52], 'Operator control must affect only exact owned trace and DNS requests'
stopped.clear()
assert module['terminate_health_requests']({'pid': 42, 'identity': 'identity-42'},
    healthy_provider='independent') == 1
assert stopped == [51], 'Ordinary provider loss must not include resolver loss'

calls = []
def run(arguments, timeout=15, **options):
    calls.append(list(arguments))
    if '-getairportpower' in arguments:
        output = b'Wi-Fi Power (en0): On\n'
    elif arguments[0] == '/usr/bin/curl':
        output = b'403'
    else:
        output = b''
    return subprocess.CompletedProcess(arguments, 0, output, b'')

namespace['run'] = run
namespace['pwd'].getpwuid = lambda uid: type('User', (), {'pw_gid': 20})()
result = module['anonymous_request'](501)
assert result['httpResponse'] and result['httpCategory'] == '4xx', 'An HTTP rejection still proves reachability'
assert '--noproxy' in calls[-1] and '-L' not in calls[-1]

with tempfile.TemporaryDirectory(prefix='cg-installed-controls-') as temporary:
    root = Path(temporary)
    namespace['ROOT'] = root
    namespace['private_json'] = lambda path: json.loads(path.read_text())
    namespace['current_service'] = lambda service: 'Connected'
    namespace['time'].monotonic = lambda: 10
    module['write_json'](root / 'restore.json', {
        'wifi': {'interface': 'en0', 'at': 11},
        'vpn': {'service': '00000000-0000-4000-8000-000000000001', 'at': 11},
    })
    calls.clear()
    assert module['safety_step']() == {} and not calls
    assert module['safety_step'](force=True) == {'wifi-restored': True}
    assert calls == [
        ['/usr/sbin/networksetup', '-setairportpower', 'en0', 'on'],
        ['/usr/sbin/networksetup', '-getairportpower', 'en0'],
    ], 'Restoration must not disable the product, alter approval or clear PF'
    assert json.loads((root / 'restore.json').read_text()) == {}
    assert (root / 'restore.json').stat().st_mode & 0o777 == 0o600
    module['write_json'](root / 'restore.json', {'wifi': {'interface': 'en0; unsafe', 'at': 1}})
    calls.clear()
    try:
        module['safety_step']()
    except module['AcceptanceFailure']:
        pass
    else:
        raise AssertionError('Unsafe interface accepted')
    assert not calls

    namespace['console_agent_running'] = lambda uid: False
    namespace['verified_config'] = lambda: {'uid': 501}
    module['write_json'](root / 'restore.json', {'loginAgent': {'uid': 501, 'at': 11}})
    assert module['safety_step']() == {} and not calls
    assert module['safety_step'](force=True) == {'fallback-login-agent-started': True}
    assert calls[-1] == ['/bin/launchctl', 'kickstart', 'gui/501/org.claudeguard.mac']
    calls.clear()
    module['write_json'](root / 'restore.json', {'loginAgent': {'uid': 502, 'at': 1}})
    try:
        module['safety_step']()
    except module['AcceptanceFailure']:
        pass
    else:
        raise AssertionError('Unapproved console identity accepted')
    assert not calls

# Replay the production acceptance tail itself. A delayed seal followed by a
# healthy recovery previously passed because wait_open discarded the gap.
# These controls never load the installed controller or change the host clock.
provider_tree = ast.parse((repo / 'Tests/installed_provider_loss.py').read_text())
provider_observe = next(node for node in provider_tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'observe')
provider_try = next(node for node in provider_observe.body if isinstance(node, ast.Try))
def assigns_name(node, name):
    return isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == name for target in node.targets)
def assigns_report(node, key):
    return isinstance(node, ast.Assign) and any(
        isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
        and target.value.id == 'report' and isinstance(target.slice, ast.Constant)
        and target.slice.value == key for target in node.targets)
tail_start = next(i for i, node in enumerate(provider_try.body)
                  if assigns_name(node, 'tail_started'))
tail_end = next(i for i, node in enumerate(provider_try.body)
                if i > tail_start and assigns_report(node, 'afterRequest'))
tail_code = compile(ast.Module(body=provider_try.body[tail_start:tail_end], type_ignores=[]),
                    'installed-provider-post-fault-tail', 'exec')
class TailFailure(Exception):
    pass
class TailClock:
    def __init__(self):
        self.now = 0.0
    def monotonic(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds
class TailController:
    def __init__(self, clock, change):
        self.clock = clock
        self.change = change
        self.runtime = {'kernel_matches': lambda fence: fence['matches']}
    def snapshot(self, entry):
        # The fault clears later; success after it must not erase its existence.
        changed = 0.8 <= self.clock.now < 1.6
        current = {'session': 'foreign' if changed and self.change == 'session' else 'original'}
        checks = {'native-permission': not (changed and self.change == 'permission')}
        fence = {'matches': not (changed and self.change == 'rules')}
        return current, None, fence, checks, changed and self.change == 'seal'
for change in ('healthy', 'seal', 'session', 'permission', 'rules'):
    clock = TailClock()
    report = {'postFaultContinuous': False}
    scope = {'time': clock, 'controller': TailController(clock, change), 'entry': {},
             'session': 'original', 'report': report, 'failure': TailFailure,
             'retain_transport_rows': lambda: None}
    try:
        exec(tail_code, scope)
    except TailFailure as error:
        assert change != 'healthy'
        assert str(error) == ('post-fault-kernel-readback' if change == 'rules'
                              else 'post-fault-continuity-not-established')
        assert not report['postFaultContinuous'] and clock.now < 1.6
    else:
        assert change == 'healthy', 'A recovered gap cannot pass continuous acceptance'
        assert report['postFaultContinuous'] and report['postFaultSeconds'] >= 15

print('PASS: process identity/PID reuse, bounded restoration, HTTP reachability and uninterrupted post-fault acceptance')
