"""Opt-in fault acceptance for the exact installed, approved production payload.

Never bundled in the product. A root-owned copy and an independent safety job
are required. No approval, risk evidence, clock, profile or packet exception is
injected. Reports retain categories/timings only. A network timeout alone is
not described as packet-capture evidence.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import pwd
import re
import runpy
import select
import signal
import stat
import subprocess
import tempfile
import threading
import time

ROOT = Path('/Library/PrivilegedHelperTools/org.claudeguard.stability-acceptance')
PRODUCT = Path('/Library/PrivilegedHelperTools/org.claudeguard')
RUNTIME = Path('/var/run/org.claudeguard.runtime')
LABEL = 'system/org.claudeguard.daemon'
ANCHOR = 'com.apple/00000.org.claudeguard.runtime'
RESULT = Path('/var/tmp/org.claudeguard-stability-faults.json')
CASES = ('worker-terminate', 'worker-kill', 'worker-stall', 'supervisor-kill',
         'restrictive-rule-drift', 'vpn-disconnect', 'wifi-disconnect', 'all-proofs-unavailable',
         'browser-vpn-disconnect', 'browser-open', 'development-vpn-disconnect', 'packet-vpn-disconnect')


class AcceptanceFailure(Exception):
    pass


def deadline_failures(checks, sealed):
    # Eventual recovery alone cannot pass a fault whose actual tunnel rule
    # outlived the identity or risk evidence. UI publication lag while sealed
    # is recorded separately and never mistaken for live kernel permission.
    if sealed:
        return []
    return [name for name in ('heartbeat-age', 'observation-age', 'risk-age', 'proof-context')
            if not checks.get(name, False)]


def run(arguments, timeout=15, **options):
    return subprocess.run(list(map(str, arguments)), capture_output=True, timeout=timeout,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'HOME': '/var/empty'},
                          **options)


def private_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077 or metadata.st_size > 65536:
            raise AcceptanceFailure('private-controller-state')
        return json.loads(os.read(fd, 65537))
    finally:
        os.close(fd)


def write_json(path, value, public=False):
    descriptor, temporary = tempfile.mkstemp(prefix='.acceptance-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644 if public else 0o600)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def verified_config():
    if os.geteuid() != 0 or ROOT.lstat().st_uid != 0 or ROOT.stat().st_mode & 0o077:
        raise AcceptanceFailure('controller-authorization')
    config = private_json(ROOT / 'config.json')
    if type(config.get('uid')) is not int or config['uid'] < 501:
        raise AcceptanceFailure('console-identity')
    if set(config.get('pins', {})) != {
        'Applications/Claude Guard.app/Contents/MacOS/ClaudeGuard',
        'Library/PrivilegedHelperTools/org.claudeguard/GuardDaemon',
        'Library/PrivilegedHelperTools/org.claudeguard/GuardOfflineRecovery',
    }:
        raise AcceptanceFailure('component-pin-set')
    if not all(hashlib.sha256((Path('/') / path).read_bytes()).hexdigest() == digest
               for path, digest in config['pins'].items()):
        raise AcceptanceFailure('installed-component-changed')
    return config


def process_identity(pid, executable=None):
    if type(pid) is not int or pid <= 1:
        return None
    result = run(['/bin/ps', '-ww', '-p', pid, '-o', 'uid=,lstart=,comm='])
    text = result.stdout.decode().strip()
    if result.returncode or not text or text.split()[0] != '0':
        return None
    if executable and not text.endswith(' ' + executable):
        return None
    return text


def signal_same_process(record, value):
    if process_identity(record.get('pid')) == record.get('identity') and record.get('identity'):
        try:
            os.kill(record['pid'], value)
            return True
        except ProcessLookupError:
            pass
    return False


def selected_process(kind, intent):
    if kind == 'worker':
        pid = int((RUNTIME / 'active/pid').read_text().strip())
        if (RUNTIME / 'active/session').read_text().strip() != intent['session']:
            raise AcceptanceFailure('worker-session')
        identity = process_identity(pid, '/bin/sh')
        command = run(['/bin/ps', '-ww', '-p', pid, '-o', 'args=']).stdout.decode().strip()
        if not command.endswith('claude-guard-worker worker-input ' + intent['session']):
            raise AcceptanceFailure('worker-process')
    else:
        values = re.findall(rb'^\s*pid = ([0-9]+)\s*$', run(['/bin/launchctl', 'print', LABEL]).stdout, re.M)
        if len(values) != 1:
            raise AcceptanceFailure('supervisor-process')
        pid = int(values[0])
        identity = process_identity(pid, str(PRODUCT / 'GuardDaemon'))
    if not identity:
        raise AcceptanceFailure('target-process-identity')
    return {'pid': pid, 'identity': identity}


def current_service(service):
    if re.fullmatch(r'[0-9A-Fa-f-]{36}', service) is None:
        raise AcceptanceFailure('service-format')
    result = run(['/usr/sbin/scutil', '--nc', 'status', service])
    first = result.stdout.decode().splitlines()
    return first[0] if result.returncode == 0 and first else 'Unavailable'


def console_agent_running(uid):
    label = 'gui/' + str(uid) + '/org.claudeguard.mac'
    result = run(['/bin/launchctl', 'print', label])
    return result.returncode == 0 and re.search(rb'^\s*pid = [0-9]+\s*$', result.stdout, re.M) is not None


def restore_console_agent(uid):
    if type(uid) is not int or uid != verified_config()['uid']:
        raise AcceptanceFailure('console-recovery-identity')
    label = 'gui/' + str(uid) + '/org.claudeguard.mac'
    loaded = run(['/bin/launchctl', 'print', label]).returncode == 0
    arguments = ['/bin/launchctl', 'kickstart', label] if loaded else [
        '/bin/launchctl', 'bootstrap', 'gui/' + str(uid), '/Library/LaunchAgents/org.claudeguard.mac.plist']
    return run(arguments).returncode == 0


def safety_step(force=False):
    plan_path = ROOT / 'restore.json'
    if not plan_path.exists():
        return {}
    plan = private_json(plan_path)
    now = time.monotonic()
    actions = {}
    if plan.get('loginAgent') and (force or now >= plan['loginAgent']['at']):
        uid = plan['loginAgent']['uid']
        if not console_agent_running(uid):
            actions['fallback-login-agent-started'] = restore_console_agent(uid)
        del plan['loginAgent']
    if plan.get('wifi') and (force or now >= plan['wifi']['at']):
        interface = plan['wifi']['interface']
        if re.fullmatch(r'en[0-9]+', interface) is None:
            raise AcceptanceFailure('wifi-interface')
        result = run(['/usr/sbin/networksetup', '-setairportpower', interface, 'on'])
        check = run(['/usr/sbin/networksetup', '-getairportpower', interface])
        actions['wifi-restored'] = result.returncode == check.returncode == 0 and check.stdout.strip().endswith(b': On')
        if actions['wifi-restored']:
            del plan['wifi']
    if plan.get('stopped') and (force or now >= plan['stopped']['at']):
        actions['stopped-process-resumed'] = signal_same_process(plan['stopped'], signal.SIGCONT)
        del plan['stopped']
    if plan.get('vpn') and (force or now >= plan['vpn']['at']):
        service = plan['vpn']['service']
        if current_service(service) != 'Connected':
            actions['fallback-vpn-started'] = run(['/usr/sbin/scutil', '--nc', 'start', service]).returncode == 0
        del plan['vpn']
    if actions:
        history_path = ROOT / 'safety-actions.json'
        history = private_json(history_path) if history_path.exists() else []
        history.append({'at': now, 'actions': actions})
        write_json(history_path, history)
        write_json(plan_path, plan)
    return actions


def safety():
    verified_config()
    (ROOT / 'safety-ready').touch(mode=0o600)
    deadline = time.monotonic() + 7200
    while time.monotonic() < deadline:
        done = (ROOT / 'done').exists()
        safety_step(force=done)
        if done:
            (ROOT / 'safety-done').touch(mode=0o600)
            return
        time.sleep(.2)
    safety_step(force=True)
    (ROOT / 'safety-done').touch(mode=0o600)


def anonymous_request(uid):
    # Always a fresh anonymous request. An HTTP error is still reachability;
    # cached page content is never an interception result.
    result = run(['/usr/bin/curl', '-q', '--noproxy', '*', '--proto', '=https',
                  '--connect-timeout', '12', '--max-time', '12', '--max-filesize', '1048576',
                  '-H', 'Cache-Control: no-cache', '-H', 'Pragma: no-cache', '-o', '/dev/null',
                  '-w', '%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}',
                  '-sS', 'https://claude.ai/?_=' + os.urandom(12).hex()],
                 timeout=15, user=uid, group=pwd.getpwuid(uid).pw_gid, extra_groups=[])
    fields = result.stdout.decode().strip().split('|')
    code = fields[0]
    timing = {}
    if len(fields) == 6 and all(re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', value) for value in fields[1:]):
        timing = dict(zip(('dns', 'tcp', 'tls', 'firstByte', 'total'), map(float, fields[1:])))
    stage = 'complete' if result.returncode == 0 else next(
        (name for name in ('dns', 'tcp', 'tls', 'firstByte') if timing.get(name) == 0), 'unclassified')
    return {'transportExit': result.returncode, 'httpResponse': bool(re.fullmatch('[1-5][0-9]{2}', code)),
            'httpCategory': code[0] + 'xx' if re.fullmatch('[1-5][0-9]{2}', code) else 'none',
            'timingSeconds': timing, 'networkStage': stage, 'requestBudgetSeconds': 12}


def browser_request(config, expected, phase):
    browser = config.get('browser') or {}
    paths = browser.get('sourcePins') or {}
    if len(paths) != 2 or not all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
                                  for path, digest in paths.items()):
        raise AcceptanceFailure('browser-source-pin')
    request = {'phase': phase, 'expected': expected, 'scratch': browser['scratch']}
    # A system launchd job enters the existing console bootstrap domain before
    # starting this isolated browser as that user. Its source lives in reviewed
    # temporary storage, not a privacy-protected user documents directory.
    # Browser work can outlast an identity lease. Observe its entire execution;
    # a state sampled before launch cannot describe a later network failure.
    window = {'samples': 0, 'transitions': [], 'maximumProofAge': 0, 'readFailures': 0}
    stopped = threading.Event()
    began = time.monotonic()
    def observe():
        previous = None
        while not stopped.is_set():
            try:
                fields = (RUNTIME / 'evidence').read_text().strip().split('|')
                if len(fields) != 11:
                    raise ValueError('evidence-shape')
                state = fields[2]
                window['samples'] += 1
                if state != previous:
                    window['transitions'].append({'seconds': round(time.monotonic() - began, 3), 'state': state})
                    previous = state
                if state == 'OPEN':
                    window['maximumProofAge'] = max(window['maximumProofAge'], int(time.time()) - int(fields[4]))
            except (OSError, ValueError):
                window['readFailures'] += 1
            stopped.wait(.25)
    monitor = threading.Thread(target=observe, daemon=True)
    monitor.start()
    try:
        process = subprocess.run(['/bin/launchctl', 'asuser', str(config['uid']), '/usr/bin/sudo',
            '-n', '-u', '#' + str(config['uid']), '--', browser['node'], browser['script']],
            input=json.dumps(request).encode(), capture_output=True, timeout=50,
            env={'PATH': '/usr/bin:/bin', 'HOME': pwd.getpwuid(config['uid']).pw_dir,
                                 'TMPDIR': browser['scratch'] + '/'})
    finally:
        stopped.set()
        monitor.join(timeout=2)
    if len(process.stdout) > 4096:
        raise AcceptanceFailure('browser-result-size')
    try:
        result = json.loads(process.stdout)
    except ValueError:
        raise AcceptanceFailure('browser-result-format')
    if process.returncode or result.get('completed') is not True:
        raise AcceptanceFailure('browser-engine-control')
    result['runtimeWindow'] = window
    write_json(ROOT / 'browser-observation.json', result)
    document, ice = result.get('document', {}), result.get('ice', {})
    if not document.get('requestObserved') or ice.get('publicHost') != 0 or ice.get('otherReflexive') != 0:
        raise AcceptanceFailure('browser-observation-missing-or-different')
    if phase == 'OPEN':
        if (window['readFailures'] or not window['samples'] or
                any(row['state'] != 'OPEN' for row in window['transitions'])):
            raise AcceptanceFailure('browser-control-phase-changed')
        if (not document.get('httpResponse') or document.get('fromCache') or document.get('fromServiceWorker') or
                not ice.get('complete') or ice.get('approvedReflexive', 0) <= 0):
            raise AcceptanceFailure('browser-positive-control-unavailable')
    elif document.get('httpResponse') or ice.get('approvedReflexive') != 0 or ice.get('relay') != 0:
        raise AcceptanceFailure('browser-network-reached-while-sealed')
    return result


def terminate_health_requests(worker, trace_only=False, healthy_provider=None, trace_operator=False):
    if (healthy_provider not in (None, "primary", "backup", "independent") or
        (trace_only and healthy_provider is not None) or
        (trace_operator and healthy_provider != "independent")):
        raise AcceptanceFailure("provider-selection")
    if process_identity(worker['pid']) != worker['identity']:
        return 0
    rows = run(['/bin/ps', '-axo', 'pid=,ppid=,uid=,comm=']).stdout.decode().splitlines()
    processes = []
    for line in rows:
        fields = line.strip().split(None, 3)
        if len(fields) == 4 and all(value.isdigit() for value in fields[:3]):
            processes.append((int(fields[0]), int(fields[1]), int(fields[2]), fields[3]))
    descendants = {worker['pid']}
    while True:
        extended = descendants | {pid for pid, parent, uid, _ in processes if parent in descendants and uid == 0}
        if extended == descendants:
            break
        descendants = extended
    stopped = 0
    for pid, _, uid, executable in processes:
        if pid not in descendants or uid != 0 or executable != '/usr/bin/curl':
            continue
        record = {'pid': pid, 'identity': process_identity(pid, executable)}
        args = run(['/bin/ps', '-ww', '-p', pid, '-o', 'args=']).stdout.decode().strip()
        providers = {'primary': 'https://1.1.1.1/cdn-cgi/trace', 'backup': 'https://1.0.0.1/cdn-cgi/trace', 'independent': 'https://checkip.amazonaws.com'}
        targets = tuple(url for name,url in providers.items() if name != healthy_provider and (not trace_only or name != 'independent'))
        if trace_operator:
            targets += tuple('https://cloudflare-dns.com/dns-query?name=' + host + '&type=A'
                             for host in ('checkip.amazonaws.com', 'proxycheck.io'))
        if args.endswith(targets):
            stopped += bool(signal_same_process(record, signal.SIGTERM))
    return stopped


class DevelopmentProbe:
    def __init__(self, config):
        client = config.get('development') or {}
        pins = client.get('sourcePins') or {}
        if len(pins) != 2 or not all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest
                                     for p, digest in pins.items()):
            raise AcceptanceFailure('development-source-pin')
        uid = config['uid']
        environment = {'PATH': '/usr/bin:/bin', 'HOME': pwd.getpwuid(uid).pw_dir}
        agent = client.get('agent')
        if agent:
            metadata = Path(agent).stat()
            if metadata.st_uid != uid or not stat.S_ISSOCK(metadata.st_mode):
                raise AcceptanceFailure('development-agent-identity')
            environment['SSH_AUTH_SOCK'] = agent
        self.process = subprocess.Popen(['/bin/launchctl', 'asuser', str(uid), '/usr/bin/sudo',
            '-n', '-u', '#' + str(uid), '--', '/usr/bin/python3', '-I', client['script'], '--session'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=environment, text=True)

    def request(self, action):
        self.process.stdin.write(json.dumps({'action': action}) + '\n')
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], 30)
        if not ready:
            raise AcceptanceFailure('development-control-timeout')
        line = self.process.stdout.readline(4097)
        if len(line) > 4096:
            raise AcceptanceFailure('development-result-size')
        try:
            return json.loads(line)
        except ValueError:
            raise AcceptanceFailure('development-result-format')

    def close(self):
        if self.process.poll() is None:
            try:
                self.request('stop')
                self.process.wait(timeout=6)
            except (OSError, AcceptanceFailure, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)


class Controller:
    def __init__(self):
        self.config = verified_config()
        self.runtime = runpy.run_path(str(ROOT / 'production_runtime.py'))
        self.report = {'phase': 'running', 'scope': 'Exact installed production helpers and real provider evidence; no risk override or packet exceptions', 'cases': []}
        self.began = time.monotonic()
        self.baseline = None
        self.development = None

    def save(self):
        self.report['seconds'] = round(time.monotonic() - self.began, 3)
        self.report['kernelGenerationRetries'] = self.runtime['PF_READBACK']['generationRetries']
        write_json(RESULT, self.report, public=True)

    def snapshot(self, entry):
        try:
            evidence, intent, fence, checks = self.runtime['sample']()
        except (FileNotFoundError, self.runtime['EvidenceFailure']):
            # Publication may briefly disappear when a verified worker is
            # replaced. This can never count as OPEN, and the actual kernel
            # boundary is still required below on every sample.
            intent = private_json(PRODUCT / 'state/intent.json')
            fence = private_json(PRODUCT / 'state/filter.json')
            evidence = {'phase': 'UNPUBLISHED', 'observed': 0, 'risk': 0, 'session': None}
            checks = {'published': False}
        binding = self.runtime['binding_digest'](intent)
        if self.baseline is None:
            self.baseline = binding
        if binding != self.baseline or not all(intent.get(k) is True for k in ('armed', 'approved', 'persistent')):
            raise AcceptanceFailure('approval-or-configuration-changed')
        rows = self.runtime['pf_read'](['-a', ANCHOR, '-sr']).stdout.decode()
        enabled = b'Status: Enabled' in self.runtime['pf_read'](['-s', 'info']).stdout
        if not enabled:
            raise AcceptanceFailure('packet-filter-disabled')
        if ('block drop quick all label "CG_BLOCK"' not in rows and
                'block drop quick all label "CG_TEST_DRIFT"' not in rows):
            raise AcceptanceFailure('restrictive-boundary-missing')
        sealed = 'CG_TUNNEL' not in rows
        item = {'seconds': round(time.monotonic() - self.began, 3), 'state': evidence['phase'],
                'sealed': sealed, 'proofAge': int(time.time()) - evidence['observed'] if evidence['observed'] else None,
                'riskAge': int(time.time()) - evidence['risk'] if evidence['risk'] else None}
        entry.setdefault('samples', []).append(item)
        failures = deadline_failures(checks, sealed)
        if failures:
            # Exclude an observation captured immediately before an atomic
            # publication changed. Recheck the proof and actual rule together;
            # no old timestamp is rewritten or treated as a new observation.
            newer, _, _, current_checks = self.runtime['sample']()
            current_rules = self.runtime['pf_read'](['-a', ANCHOR, '-sr'])
            still_sealed = 'CG_TUNNEL' not in current_rules.stdout.decode()
            current_failures = deadline_failures(current_checks, still_sealed)
            item['deadlineRecheck'] = {'sealed': still_sealed, 'failures': current_failures,
                'proofAge': int(time.time()) - newer['observed'] if newer['observed'] else None}
            if current_failures:
                raise AcceptanceFailure('live-permission-after-deadline:' + ','.join(current_failures))
        if len(entry['samples']) > 1200:
            raise AcceptanceFailure('bounded-observation-exceeded')
        return evidence, intent, fence, checks, sealed

    def wait_open(self, entry, timeout=240, stable_seconds=8, previous_session=None):
        until = time.monotonic() + timeout
        stable_at = None
        while time.monotonic() < until:
            evidence, intent, fence, checks, _ = self.snapshot(entry)
            ready = all(checks.values()) and self.runtime['kernel_matches'](fence)
            if previous_session is not None:
                ready = ready and evidence['session'] != previous_session
            if ready:
                stable_at = stable_at or time.monotonic()
                if time.monotonic() - stable_at >= stable_seconds:
                    return evidence, intent
            else:
                stable_at = None
            time.sleep(.4)
        raise AcceptanceFailure('fresh-automatic-readmission-timeout')

    def one(self, name):
        verified_config()
        entry = {'case': name, 'phase': 'preparing'}
        self.report['cases'].append(entry)
        evidence, intent = self.wait_open(entry, stable_seconds=5)
        entry['beforeRequest'] = anonymous_request(self.config['uid'])
        if not entry['beforeRequest']['httpResponse']:
            raise AcceptanceFailure('service-positive-control-unavailable')
        if name in ('browser-vpn-disconnect', 'browser-open'):
            entry['beforeBrowser'] = browser_request(self.config, evidence['expected'], 'OPEN')
        if name == 'browser-open':
            entry['phase'] = 'passed'
            self.save()
            return
        if name == 'development-vpn-disconnect':
            self.development = DevelopmentProbe(self.config)
            entry['beforeDevelopment'] = self.development.request('fresh')
            entry['existingDevelopment'] = self.development.request('start')
            if not entry['beforeDevelopment'].get('reachable') or not entry['existingDevelopment'].get('ready'):
                raise AcceptanceFailure('development-positive-control-unavailable')
        evidence, intent = self.wait_open(entry, stable_seconds=1)
        entry['phase'] = 'fault-active'
        started = time.monotonic()
        service = intent['serviceID']
        plan = {'vpn': {'service': service, 'at': started + 180}}
        worker = None
        require_new_session = name.startswith('worker-') or name == 'supervisor-kill'
        if name.startswith('worker-') or name == 'all-proofs-unavailable':
            worker = selected_process('worker', intent)
        if name == 'worker-stall':
            plan['stopped'] = dict(worker, at=started + 40)
        if name == 'wifi-disconnect':
            output = run(['/usr/sbin/networksetup', '-listallhardwareports']).stdout.decode()
            interfaces = re.findall(r'Hardware Port: (?:Wi-Fi|AirPort)\nDevice: (en[0-9]+)', output)
            if len(interfaces) != 1:
                raise AcceptanceFailure('wifi-interface-unavailable')
            interface = interfaces[0]
            if not run(['/usr/sbin/networksetup', '-getairportpower', interface]).stdout.strip().endswith(b': On'):
                raise AcceptanceFailure('wifi-initially-off')
            plan['wifi'] = {'interface': interface, 'at': started + 15}
        write_json(ROOT / 'restore.json', plan)
        entry['faultStarted'] = round(started - self.began, 3)
        self.save()
        if name.startswith('worker-'):
            sig = {'worker-terminate': signal.SIGTERM, 'worker-kill': signal.SIGKILL, 'worker-stall': signal.SIGSTOP}[name]
            if not signal_same_process(worker, sig):
                raise AcceptanceFailure('worker-signal-failed')
        elif name == 'supervisor-kill':
            if not signal_same_process(selected_process('supervisor', intent), signal.SIGKILL):
                raise AcceptanceFailure('supervisor-signal-failed')
        elif name == 'restrictive-rule-drift':
            command = run(['/sbin/pfctl', '-a', ANCHOR, '-f', '-'],
                          input=b'block drop quick all label "CG_TEST_DRIFT"\n')
            if command.returncode:
                raise AcceptanceFailure('restrictive-fault-injection-failed')
        elif name == 'wifi-disconnect':
            if run(['/usr/sbin/networksetup', '-setairportpower', interface, 'off']).returncode:
                raise AcceptanceFailure('wifi-fault-injection-failed')
        first_sealed = None
        request_checked = False
        fault_control = {'terminated': 0, 'failure': None}
        held_vpn = name in ('browser-vpn-disconnect', 'development-vpn-disconnect', 'packet-vpn-disconnect')
        hold = 45 if held_vpn else (
            20 if name in ('vpn-disconnect', 'all-proofs-unavailable') else 0)
        fault_stop = threading.Event()
        def maintain_fault():
            try:
                while not fault_stop.is_set() and time.monotonic() < started + hold:
                    if name == 'vpn-disconnect' or held_vpn:
                        run(['/usr/sbin/scutil', '--nc', 'stop', service])
                    else:
                        fault_control['terminated'] += terminate_health_requests(worker)
                    fault_stop.wait(.1)
            except Exception as error:
                fault_control['failure'] = type(error).__name__
        fault_thread = threading.Thread(target=maintain_fault, daemon=True)
        if hold:
            fault_thread.start()
        until = started + max(hold, 30)
        try:
            while time.monotonic() < until:
                current, _, _, _, sealed = self.snapshot(entry)
                if sealed and first_sealed is None:
                    first_sealed = time.monotonic()
                    entry['sealSeconds'] = round(first_sealed - started, 3)
                if sealed and not request_checked:
                    entry['blockedRequest'] = anonymous_request(self.config['uid'])
                    request_checked = True
                    if entry['blockedRequest']['httpResponse']:
                        after_request, _, _, _, still_sealed = self.snapshot(entry)
                        raise AcceptanceFailure('service-request-reached-while-sealed' if still_sealed
                                                else 'blocked-request-overlapped-readmission')
                    if name == 'browser-vpn-disconnect':
                        entry['blockedBrowser'] = browser_request(self.config, evidence['expected'], 'LOCKED')
                        if not self.snapshot(entry)[4]:
                            raise AcceptanceFailure('browser-check-overlapped-readmission')
                    if name == 'development-vpn-disconnect':
                        entry['blockedDevelopment'] = self.development.request('fresh')
                        entry['interruptedDevelopment'] = self.development.request('interrupted')
                        if (entry['blockedDevelopment'].get('reachable') or
                                not entry['interruptedDevelopment'].get('interrupted')):
                            raise AcceptanceFailure('development-not-interrupted')
                        if not self.snapshot(entry)[4]:
                            raise AcceptanceFailure('development-check-overlapped-readmission')
                    if name == 'packet-vpn-disconnect':
                        packet_source = self.config.get('packet') or {}
                        data = Path(packet_source['script']).read_bytes()
                        if hashlib.sha256(data).hexdigest() != packet_source['sha256']:
                            raise AcceptanceFailure('packet-source-pin')
                        packet_module = {'__name__': 'packet_control'}
                        exec(compile(data, packet_source['script'], 'exec'), packet_module)
                        entry['physicalPackets'] = packet_module['probe']('LOCKED')
                        observed = entry['physicalPackets']
                        if (not observed['positiveControlVerified'] or not observed['sameSessionAndPhase'] or
                                any(row['physicalTapHeaders'] or row['responseReceived'] or row['captureDroppedPackets'] != 0
                                    for row in observed['negativeControls'])):
                            raise AcceptanceFailure('physical-negative-control')
                if first_sealed and request_checked and time.monotonic() >= started + hold:
                    break
                time.sleep(.3)
        finally:
            fault_stop.set()
            if hold:
                fault_thread.join(timeout=20)
                if fault_thread.is_alive() or fault_control['failure']:
                    raise AcceptanceFailure('bounded-fault-controller-failed')
        if first_sealed is None:
            raise AcceptanceFailure('seal-not-observed')
        if name == 'all-proofs-unavailable':
            entry['terminatedHealthRequests'] = fault_control['terminated']
            if not fault_control['terminated']:
                raise AcceptanceFailure('health-loss-not-injected')
        entry['phase'] = 'awaiting-fresh-readmission'
        self.save()
        self.wait_open(entry, previous_session=evidence['session'] if require_new_session else None)
        entry['afterRequest'] = anonymous_request(self.config['uid'])
        if not entry['afterRequest']['httpResponse']:
            # A service can reject one anonymous TLS client while its actual
            # browser path works. Retain that failed transport and require a
            # fresh browser response under continuously OPEN protection. Never
            # reinterpret a timeout or cached document as restored access.
            current, _, _, _, _ = self.snapshot(entry)
            entry['afterBrowser'] = browser_request(self.config, current['expected'], 'OPEN')
            entry['serviceControl'] = 'fresh-browser-confirmed-after-curl-transport-failure'
        if name == 'browser-vpn-disconnect':
            current, _, _, _, _ = self.snapshot(entry)
            entry['afterBrowser'] = browser_request(self.config, current['expected'], 'OPEN')
        if name == 'development-vpn-disconnect':
            entry['afterDevelopment'] = self.development.request('fresh')
            if not entry['afterDevelopment'].get('reachable'):
                raise AcceptanceFailure('development-not-restored')
            self.development.close()
            self.development = None
        safety_history = private_json(ROOT / 'safety-actions.json') if (ROOT / 'safety-actions.json').exists() else []
        interventions = [row for row in safety_history if row['at'] >= started and any(
            row['actions'].get(key) for key in ('stopped-process-resumed', 'fallback-vpn-started'))]
        if interventions:
            raise AcceptanceFailure('automatic-recovery-required-test-intervention')
        entry.update(phase='passed', recoverySeconds=round(time.monotonic() - started, 3))
        if name == 'packet-vpn-disconnect':
            unavailable = [row for row in entry['physicalPackets']['negativeControls']
                           if row['classified'] != 'no-physical-egress-observed']
            entry['unverifiedPacketControls'] = len(unavailable)
            entry['coverage'] = 'partial' if unavailable else 'complete'
        write_json(ROOT / 'restore.json', {})
        self.save()

    def execute(self, cases):
        if not (ROOT / 'safety-ready').exists():
            raise AcceptanceFailure('independent-safety-not-ready')
        try:
            for name in cases:
                self.one(name)
            self.report['phase'] = 'passed'
        except Exception as error:
            self.report['phase'] = 'failed'
            self.report['failure'] = str(error) if isinstance(error, (AcceptanceFailure, self.runtime['EvidenceFailure'])) else type(error).__name__
            self.report['failureBoundary'] = self.runtime['failure_boundary']()
            if (ROOT / 'browser-observation.json').exists():
                self.report['lastBrowserObservation'] = private_json(ROOT / 'browser-observation.json')
            try:
                self.report['healthRounds'] = (RUNTIME / 'health-events').read_text().splitlines()[-60:]
            except OSError:
                pass
        finally:
            if self.development is not None:
                self.development.close()
            self.save()
            (ROOT / 'done').touch(mode=0o600)
        return 0 if self.report['phase'] == 'passed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--safety', action='store_true')
    parser.add_argument('--case', action='append', choices=CASES)
    arguments = parser.parse_args()
    if arguments.safety:
        safety()
    else:
        raise SystemExit(Controller().execute(arguments.case or CASES))
