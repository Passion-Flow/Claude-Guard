"""Administrator-only, bounded development-host PF acceptance driver.

Never bundled in the application. The first phase overrides ONLY risk admission
in a disposable worker copy, to test real enforcement/recovery without claiming
that the current exit passed reputation checks. Production installation follows
with the unchanged real risk gate. A separate launchd safety job must be ready.
"""
from pathlib import Path
from collections import Counter
import hashlib
import json
import os
import re
import runpy
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import threading
import uuid

ROOT = Path('/Library/PrivilegedHelperTools/org.claudeguard.acceptance')
RESULT = Path('/var/tmp/org.claudeguard-acceptance-result.json')
RUNTIME = Path('/var/run/org.claudeguard.acceptance')
ANCHOR = 'com.apple/00000.org.claudeguard.acceptance'
SAFETY_ANCHOR = ANCHOR + '.safety'
FILTER = ROOT / 'FilterFixture'
TARGET = '223.5.5.5'  # fixed public test destination; no account requests
TARGET6 = '2606:4700:4700::1111'
REPORT = {'mode': 'development-host', 'controlled_risk_fixture': True, 'checks': {}}
WORKER = None
CAPTURE = None
ROUTE_ADDED = False
SERVICE = ''
LOG_READY = False
LOG_CREATED = False
PROBE_LOGGER = None
PROBE_THREADS = []
PROBE_DROPS = []
PROBE_CAPTURE = {'ready': False, 'kernel_dropped': None}
SUPERVISED = False


def environment():
    return runpy.run_path(str(Path(__file__).with_name('environment.py')))


def process_stamp(pid):
    result = run(['/bin/ps', '-p', str(pid), '-o', 'uid=,lstart=,comm='])
    return result.stdout.decode().strip() if result.returncode == 0 else ''


def register_process(name, pid):
    stamp = process_stamp(pid)
    if not stamp or stamp.split()[0] != '0':
        raise RuntimeError('test-child-identity-unconfirmed')
    (ROOT / (name + '.process')).write_text(json.dumps({'pid': pid, 'stamp': stamp}))


def signal_registered(name, value):
    path = ROOT / (name + '.process')
    if path.exists():
        identity = json.loads(path.read_text())
        if isinstance(identity['pid'], int) and identity['pid'] > 1 and process_stamp(identity['pid']) == identity['stamp']:
            try:
                os.kill(identity['pid'], value)
            except ProcessLookupError:
                pass


def start_probe_capture():
    global PROBE_LOGGER
    ready = threading.Event()
    PROBE_LOGGER = subprocess.Popen(['/usr/sbin/tcpdump', '-n', '-e', '-tt', '-l', '-i', 'pflog0',
        'tcp and port 443 and (host 1.1.1.1 or host 1.0.0.1)'], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    register_process('probe-logger', PROBE_LOGGER.pid)
    def headers():
        for line in PROBE_LOGGER.stdout:
            stamp = re.match(r'^([0-9]+[.][0-9]+) ', line)
            direction = re.search(r'\b(in|out) on (\w+):', line)
            flow = re.search(r'([0-9]+(?:[.][0-9]+){3})[.]([0-9]+) > ([0-9]+(?:[.][0-9]+){3})[.]([0-9]+)', line)
            flags = re.search(r'Flags \[([^]]*)\]', line)
            if not (stamp and direction and flow and flags):
                continue
            source, source_port, destination, destination_port = flow.groups()
            port = source_port if destination in ['1.1.1.1', '1.0.0.1'] and destination_port == '443' else (
                destination_port if source in ['1.1.1.1', '1.0.0.1'] and source_port == '443' else None)
            if port is None:
                continue
            uid = re.search(r'\buid\s*[=:]?\s*([0-9]+)', line)
            identity = 'root' if uid and uid[1] == '0' else ('unknown' if uid and uid[1] in ['4294967295', '2147483647'] else ('other' if uid else 'unavailable'))
            tcp_flags = flags[1]
            category = 'reset' if 'R' in tcp_flags else ('finish' if 'F' in tcp_flags else ('syn' if 'S' in tcp_flags else 'data_or_ack'))
            PROBE_DROPS.append((float(stamp[1]), int(port), direction[1], direction[2], identity, category))
            if len(PROBE_DROPS) > 2048:
                del PROBE_DROPS[:1024]
    def statistics():
        for line in PROBE_LOGGER.stderr:
            if 'listening on pflog0' in line:
                PROBE_CAPTURE['ready'] = True
                ready.set()
            dropped = re.match(r'^([0-9]+) packets dropped by kernel', line)
            if dropped:
                PROBE_CAPTURE['kernel_dropped'] = int(dropped[1])
    for target in [headers, statistics]:
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        PROBE_THREADS.append(thread)
    if not ready.wait(timeout=3):
        raise RuntimeError('health-drop-capture-not-ready')


def stop_probe_capture():
    global PROBE_LOGGER
    if PROBE_LOGGER is None:
        return
    if PROBE_LOGGER.poll() is None:
        PROBE_LOGGER.terminate()
        try:
            PROBE_LOGGER.wait(timeout=3)
        except subprocess.TimeoutExpired:
            PROBE_LOGGER.kill()
            PROBE_LOGGER.wait(timeout=2)
    for thread in PROBE_THREADS:
        thread.join(timeout=2)
    PROBE_LOGGER = None


def drop_summary(port, start, end, interface):
    counts = Counter()
    for stamp, local_port, direction, link, identity, flags in PROBE_DROPS:
        if local_port == port and start <= stamp <= end:
            counts['/'.join([direction, 'tunnel' if link == interface else 'other-interface', identity, flags])] += 1
    return dict(counts)


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, timeout=kwargs.pop('timeout', 10), **kwargs)


def record(name, passed, detail=''):
    REPORT['checks'][name] = {'result': 'NOT_TESTED' if passed is None else ('PASS' if passed else 'FAIL'), 'detail': detail}
    write_report()


def write_report():
    fd, temporary = tempfile.mkstemp(prefix='.claude-guard-acceptance-', dir=RESULT.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(json.dumps(REPORT, indent=2) + '\n')
        os.chmod(temporary, 0o644)  # only sanitized categories and timing evidence
        os.replace(temporary, RESULT)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def browser_window(config, phase, acknowledge=True):
    """Bounded engineering-only coordination; never installed in the product."""
    bridge = config.get('browserBridge')
    if not bridge:
        return
    REPORT['browser_phase'] = phase
    REPORT['browser_phase_started_at'] = time.time()
    REPORT.setdefault('browser_phase_history', []).append({'phase': phase, 'started_at': REPORT['browser_phase_started_at']})
    write_report()
    deadline = time.monotonic() + (600 if acknowledge else 90)
    while time.monotonic() < deadline:
        try:
            failed = os.open(str(Path(bridge) / 'observer-failed'), os.O_RDONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(failed)
                if stat.S_ISREG(info.st_mode) and info.st_uid == config['browserOwner'] and info.st_size <= 64 and os.read(failed, 65) == b'stop':
                    raise RuntimeError('local-observer-reported-failure')
            finally:
                os.close(failed)
        except FileNotFoundError:
            pass
        if acknowledge:
            try:
                descriptor = os.open(str(Path(bridge) / (phase + '.ack')), os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    info = os.fstat(descriptor)
                    if stat.S_ISREG(info.st_mode) and info.st_uid == config['browserOwner'] and info.st_size <= 64:
                        if os.read(descriptor, 65) == b'advance':
                            return
                finally:
                    os.close(descriptor)
            except FileNotFoundError:
                pass
        else:
            # Keep the real service down long enough for a fresh main-document
            # request to fail. Recovery runs locally without a cloud callback.
            run(['/usr/sbin/scutil', '--nc', 'stop', SERVICE])
        time.sleep(1)
    if acknowledge:
        raise RuntimeError('browser-phase-acknowledgment-timeout')


def status():
    try:
        fields = (RUNTIME / 'status').read_text().strip().split('|')
        return fields if len(fields) == 14 else []
    except FileNotFoundError:
        return []


def wait_phase(phase, seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = status()
        if value and value[1] == phase:
            return value
        if WORKER is not None and WORKER.poll() is not None:
            break
        time.sleep(0.2)
    raise RuntimeError('worker-phase-' + phase + '-unconfirmed')


def wait_native_seal(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        rules = run(['/sbin/pfctl', '-a', ANCHOR, '-sr'], timeout=5).stdout
        if b'CG_BLOCK' in rules and b'CG_TUNNEL' not in rules:
            return
        time.sleep(0.1)
    raise RuntimeError('native-seal-not-observed')


def wait_native_open(seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if b'CG_TUNNEL' in run(['/sbin/pfctl', '-a', ANCHOR, '-sr'], timeout=5).stdout:
            return
        time.sleep(0.1)
    raise RuntimeError('native-release-not-observed')


def wait_fresh_open(previous, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = status()
        if value and value[0] != previous and value[1] == 'OPEN':
            return
        if WORKER.poll() is not None:
            break
        time.sleep(0.2)
    raise RuntimeError('fresh-session-admission-not-observed')


def lifecycle_faults():
    global WORKER
    for name, fault in [('worker_term', signal.SIGTERM), ('worker_kill', signal.SIGKILL),
                        ('worker_heartbeat_frozen', signal.SIGSTOP)]:
        previous = status()[0]
        pid = int((RUNTIME / 'active/pid').read_text().strip())
        command = run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=', '-o', 'command=']).stdout.decode().lstrip().rstrip()
        if pid <= 1 or not command.startswith('0 ') or not command.endswith(' claude-guard-worker worker-input ' + previous):
            raise RuntimeError('test-worker-identity-unconfirmed')
        began = time.monotonic()
        os.kill(pid, fault)
        wait_native_seal(25)
        REPORT['durations_seconds'][name + '_to_seal'] = round(time.monotonic() - began, 3)
        record(name + '_seals_native_rules', True)
        wait_fresh_open(previous)
        REPORT['durations_seconds'][name + '_to_fresh_admission'] = round(time.monotonic() - began, 3)
        record(name + '_fresh_session_recovers', time.monotonic() - began >= 14)

    previous = status()[0]
    began = time.monotonic()
    WORKER.kill()
    WORKER.wait(timeout=5)
    WORKER = subprocess.Popen([str(FILTER), '--supervise'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    register_process('worker', WORKER.pid)
    wait_native_seal(15)
    record('replacement_core_seals_native_rules', True,
           'Actual native startup; bounded driver restarts fixture parent, not a production launchd claim')
    wait_fresh_open(previous)
    REPORT['durations_seconds']['replacement_core_to_fresh_admission'] = round(time.monotonic() - began, 3)
    record('replacement_core_fresh_session_recovers', time.monotonic() - began >= 14)

    # A later, independent restrictive anchor covers this deliberate empty-rule
    # interval. This validates repair, not zero exposure from a sole PF anchor.
    installed = run(['/sbin/pfctl', '-a', SAFETY_ANCHOR, '-f', '-'],
                    input=b'block drop quick all label "CG_TEST_SAFETY"\n')
    if installed.returncode != 0 or b'CG_TEST_SAFETY' not in run(['/sbin/pfctl', '-a', SAFETY_ANCHOR, '-sr']).stdout:
        raise RuntimeError('test-tamper-safety-rule-unavailable')
    try:
        run(['/sbin/pfctl', '-a', ANCHOR, '-F', 'rules'], check=True)
        began = time.monotonic()
        wait_native_seal(15)
        REPORT['durations_seconds']['empty_anchor_to_restrictive_repair'] = round(time.monotonic() - began, 3)
        record('empty_anchor_repaired_under_independent_block', True,
               'Temporary test safety anchor present; no zero-exposure or global-PF-disable claim')
    finally:
        run(['/sbin/pfctl', '-a', SAFETY_ANCHOR, '-F', 'rules'])
    began = time.monotonic()
    # Status can still contain the previous OPEN until the worker publishes its
    # post-repair heartbeat. Measure the actual native rule transition first.
    wait_native_open(180)
    REPORT['durations_seconds']['rule_repair_to_fresh_admission'] = round(time.monotonic() - began, 3)
    record('rule_repair_recovers_after_stability', time.monotonic() - began >= 14)
    wait_phase('OPEN', 5)


def supervised_soak():
    began = time.monotonic()
    counts, reasons = Counter(), Counter()
    last_report = 0
    while time.monotonic() - began < 600:
        fields = status()
        if WORKER.poll() is not None or len(fields) != 14:
            raise RuntimeError('soak-supervision-lost')
        rules = run(['/sbin/pfctl', '-a', ANCHOR, '-sr'], timeout=5)
        info = run(['/sbin/pfctl', '-s', 'info'], timeout=5)
        if rules.returncode != 0 or b'CG_BLOCK' not in rules.stdout or b'Status: Enabled' not in info.stdout:
            raise RuntimeError('soak-enforcement-unconfirmed')
        counts[fields[1]] += 1
        reasons[fields[6]] += 1
        elapsed = time.monotonic() - began
        if elapsed - last_report >= 30:
            REPORT['soak'] = {'elapsed_seconds': round(elapsed, 1),
                              'phase_samples': dict(counts), 'reason_samples': dict(reasons)}
            write_report()
            last_report = elapsed
        time.sleep(2)
    REPORT['soak'] = {'elapsed_seconds': round(time.monotonic() - began, 1),
                      'phase_samples': dict(counts), 'reason_samples': dict(reasons)}
    record('ten_minute_supervision_and_filter_continuity', True,
           'Actual Core/worker and PF; synthetic risk. Samples are bounded observations, not a long-term availability guarantee')


def stop_worker():
    global WORKER
    if WORKER is None:
        return
    if WORKER.poll() is None:
        WORKER.send_signal(signal.SIGCONT)
    sid = (RUNTIME / 'active/session')
    if sid.exists() and not SUPERVISED:
        (RUNTIME / ('restore-' + sid.read_text().strip())).touch()
    WORKER.send_signal(signal.SIGTERM) if WORKER.poll() is None else None
    try:
        WORKER.wait(timeout=12)
    except subprocess.TimeoutExpired:
        WORKER.kill()
        WORKER.wait(timeout=2)
    began = time.monotonic()
    restored = run([str(FILTER), '--restore'], timeout=55)
    active = RUNTIME / 'active'
    REPORT['native_restoration'] = {'exit_code': restored.returncode,
        'seconds': round(time.monotonic() - began, 3),
        'active_entry_count': len(list(active.iterdir())) if active.is_dir() else 0}
    record('native_test_fence_restores', restored.returncode == 0,
           'root-control-exit-' + str(restored.returncode))
    run(['/sbin/pfctl', '-a', ANCHOR, '-F', 'rules'])
    WORKER = None


def cleanup():
    global CAPTURE
    stop_probe_capture()
    if CAPTURE is not None and CAPTURE.poll() is None:
        CAPTURE.terminate()
        try:
            CAPTURE.wait(timeout=2)
        except subprocess.TimeoutExpired:
            CAPTURE.kill()
    stop_worker()
    run(['/sbin/pfctl', '-a', SAFETY_ANCHOR, '-F', 'rules'])
    restored_environment = environment()['restore_due'](ROOT, force=True)
    if restored_environment:
        REPORT['environment_restoration'] = restored_environment
    recovery = Path('/Library/PrivilegedHelperTools/org.claudeguard/GuardOfflineRecovery')
    if recovery.is_file():
        run([str(recovery), '--restore-local'], timeout=55)
    if SERVICE:
        run(['/usr/sbin/scutil', '--nc', 'start', SERVICE])
    if ROUTE_ADDED:
        run(['/sbin/route', '-n', 'delete', '-host', TARGET])


def probe(physical, protocol='tcp', ipv6=False):
    global CAPTURE
    logger = None
    target = TARGET6 if ipv6 else TARGET
    channel = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    channel.settimeout(1.5)
    # IP_BOUND_IF=25 and IPV6_BOUND_IF=125 are from the installed Darwin SDK.
    channel.setsockopt(socket.IPPROTO_IPV6 if ipv6 else socket.IPPROTO_IP, 125 if ipv6 else 25, socket.if_nametoindex(physical))
    channel.bind(('::' if ipv6 else '', 0))
    source_port = channel.getsockname()[1]
    exact_flow = 'dst host ' + target + ' and ' + protocol + ' and dst port 53 and src port ' + str(source_port)
    if LOG_READY:
        logger = subprocess.Popen(['/usr/sbin/tcpdump', '-n', '-l', '-i', 'pflog0',
            exact_flow],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    CAPTURE = subprocess.Popen(['/usr/sbin/tcpdump', '-n', '-l', '-i', physical, '-tt',
        exact_flow],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    received = False
    # Darwin IP_BOUND_IF from the installed SDK: force this control to the
    # physical interface rather than accepting transparent tunnel routing.
    identifier = os.urandom(2)
    query = identifier + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + b'\x07example\x07invalid\x00\x00\x01\x00\x01'
    try:
        if protocol == 'tcp':
            channel.connect((target, 53))
            channel.sendall(struct.pack('!H', len(query)) + query)
            def receive(count):
                result = b''
                while len(result) < count:
                    chunk = channel.recv(count - len(result))
                    if not chunk: raise OSError('closed')
                    result += chunk
                return result
            length = struct.unpack('!H', receive(2))[0]
            if 12 <= length <= 4096:
                response = receive(length)
                received = response[:2] == identifier and bool(response[2] & 0x80)
        else:
            channel.sendto(query, (target, 53))
            response, sender = channel.recvfrom(4096)
            received = len(response) >= 12 and response[:2] == identifier and sender[0] == target and bool(response[2] & 0x80)
    except (OSError, TimeoutError):
        pass
    finally:
        channel.close()
    time.sleep(0.25)
    CAPTURE.terminate()
    output, _ = CAPTURE.communicate(timeout=2)
    CAPTURE = None
    dropped = 0
    if logger is not None:
        logger.terminate()
        logged, _ = logger.communicate(timeout=2)
        dropped = len(logged.splitlines())
    return {'response_received': received, 'physical_tap_headers': len(output.splitlines()),
            'pf_drop_headers': dropped, 'drop_observation_available': LOG_READY}


def positive_control(physical, ipv6=False):
    # An intermittent response timeout is inconclusive, not a failed block or
    # a positive path. Permit three fresh bounded controls before fault setup;
    # only an actual matching DNS response establishes the underlay path.
    for attempt in range(1, 4):
        observed = probe(physical, ipv6=ipv6)
        observed['attempts'] = attempt
        if observed['response_received']:
            return observed
    return observed


def safety():
    # A separate process/job survives driver/installer failure and cloud loss.
    recovery = environment()
    register_process('safety', os.getpid())
    (ROOT / 'safety-ready').write_text(str(os.getpid()))
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline and not (ROOT / 'done').exists():
        recovery['restore_due'](ROOT)
        time.sleep(2)
    recovery['restore_due'](ROOT, force=True)
    if not (ROOT / 'done').exists():
        try:
            config = json.loads((ROOT / 'route.private.json').read_text())
            signal_registered('driver', signal.SIGKILL)
        except (OSError, ValueError):
            config = {}
        try:
            sid = (RUNTIME / 'active/session').read_text().strip()
            (RUNTIME / ('restore-' + sid)).touch()
            signal_registered('worker', signal.SIGTERM)
            time.sleep(3)
            try:
                signal_registered('worker', signal.SIGKILL)
            except ProcessLookupError:
                pass
        except (OSError, ValueError):
            pass
        signal_registered('probe-logger', signal.SIGTERM)
        if FILTER.is_file():
            run([str(FILTER), '--restore'], timeout=20)
        run(['/sbin/pfctl', '-a', ANCHOR, '-F', 'rules'])
        run(['/sbin/pfctl', '-a', SAFETY_ANCHOR, '-F', 'rules'])
        helper = Path('/Library/PrivilegedHelperTools/org.claudeguard/GuardOfflineRecovery')
        if helper.exists():
            run([str(helper), '--restore-local'], timeout=55)
        services = run(['/usr/sbin/scutil', '--nc', 'list']).stdout.decode()
        for line in services.splitlines():
            if '(com.liguangming.Shadowrocket)' in line:
                identifiers = re.findall(r'\b[0-9A-Fa-f-]{36}\b', line)
                if len(identifiers) == 1:
                    run(['/usr/sbin/scutil', '--nc', 'start', identifiers[0]])
        run(['/sbin/route', '-n', 'delete', '-host', TARGET])
        if not RESULT.exists():
            RESULT.write_text(json.dumps({'safety_timeout': True, 'checks': {}}))
            RESULT.chmod(0o644)
    # Remove test-owned components only after restoration or confirmed completion.
    for label in ['org.claudeguard.acceptance.driver', 'org.claudeguard.acceptance.safety']:
        Path('/Library/LaunchDaemons/' + label + '.plist').unlink(missing_ok=True)
    run(['/bin/launchctl', 'bootout', 'system/org.claudeguard.acceptance.driver'])
    import shutil
    shutil.rmtree(ROOT, ignore_errors=True)
    shutil.rmtree(RUNTIME, ignore_errors=True)
    run(['/bin/launchctl', 'bootout', 'system/org.claudeguard.acceptance.safety'])


def instrument_worker(original):
    script = original.replace('directory=/var/run/org.claudeguard.runtime', 'directory=' + str(RUNTIME)).replace('anchor=com.apple/00000.org.claudeguard.runtime', 'anchor=' + ANCHOR)
    script = script.replace('filter_helper=$boot_dir/GuardDaemon', 'filter_helper=' + str(FILTER))
    # Controlled positive gate is isolated to this disposable test process.
    script = script.replace('action=${1-}', 'review_exit_risk() { risk_admission_at=$(/bin/date +%s); return 0; }\naction=${1-}', 1)
    script = script.replace('block drop quick all label', 'block drop log (user) quick all label')
    # Instrument only the disposable curl call. No response body, endpoint,
    # account identifier or credential is included in timing evidence.
    pattern = r"if http_status=\$\((/usr/bin/env -i .*?)\); then"
    def timed_request(match):
        command = match.group(1).replace("'%{http_code}'", "'%{http_code}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}|%{local_port}'")
        return ("request_started=$(/usr/bin/python3 -I -c 'import time; print(time.time())')\n"
            "    if http_status=$(" + command + "); then request_result=0; else request_result=$?; fi\n"
            "    request_completed_at=$(/bin/date +%s)\n"
            "    request_ended=$(/usr/bin/python3 -I -c 'import time; print(time.time())')\n"
            "    printf '%s|%s|%s|%s|%s\\n' \"$request_timeout\" \"$request_started\" \"$request_ended\" \"$request_result\" \"$http_status\" >> \"$directory/curl-timings\"\n"
            "    http_status=${http_status%%|*}\n"
            "    if (exit \"$request_result\"); then")
    script, instrumented = re.subn(pattern, timed_request, script, count=1, flags=re.S)
    if instrumented != 1:
        raise RuntimeError('timing-instrumentation-mismatch')
    stamp = 'response_received_at=$(/bin/date +%s)'
    if script.count(stamp) != 1:
        raise RuntimeError('response-timestamp-instrumentation-mismatch')
    script = script.replace(stamp, 'response_received_at=$request_completed_at', 1)
    # Keep enough non-secret progress to distinguish identity changes,
    # scheduling gaps and rule repair from a stalled stability counter.
    script = script.replace('publish() {', '''publish() {
      printf '%s|%s|%s|%s|%s|%s\\n' "$1" "$3" "${consecutive:-0}" "${stable_since:-0}" "${last_verified:-0}" "$(/bin/date +%s)" >> "$directory/progress"
    ''', 1)
    return script


def install_production(seconds):
    previous = Path('/Library/PrivilegedHelperTools/org.claudeguard/GuardOfflineRecovery')
    if previous.exists():
        removed = run([str(previous), '--uninstall'], timeout=60)
        record('previous_installation_removed', removed.returncode == 0)
        if removed.returncode != 0:
            return
    began = time.time()
    installed = run(['/usr/sbin/installer', '-pkg', str(ROOT / 'Guard.pkg'), '-target', '/'], timeout=60)
    record('production_package_installs', installed.returncode == 0)
    if installed.returncode != 0:
        return
    observations = []
    deadline = time.monotonic() + seconds
    active, decision = False, 'not-reached'
    blocked = False
    while time.monotonic() < deadline:
        try:
            fields = Path('/var/run/org.claudeguard.runtime/status').read_text().strip().split('|')
        except FileNotFoundError:
            fields = []
        if len(fields) == 14 and float(fields[2]) >= began - 2:
            phase, reason = fields[1], fields[6]
            active |= phase in ['LOCKED', 'OPEN']
            observation = {'phase': phase, 'reason': reason}
            if not observations or observations[-1] != observation:
                observations.append(observation)
            if phase == 'OPEN' and fields[13].isdigit() and int(fields[13]) > 0:
                decision = 'accepted'
                break
            if phase == 'LOCKED' and reason.startswith('risk-') and reason != 'risk-review':
                decision = 'denied' if reason == 'risk-rejected' else 'unavailable'
                loaded = run(['/sbin/pfctl', '-a', 'com.apple/00000.org.claudeguard.runtime', '-sr'])
                blocked = loaded.returncode == 0 and b'CG_BLOCK' in loaded.stdout and b'CG_TUNNEL' not in loaded.stdout
                # DNS transport failures do not spend the provider quota. Let
                # the production backoff retry instead of ending at the first
                # transient observation. Other outcomes retain query spacing.
                if reason != 'risk-dns-unavailable':
                    break
        time.sleep(0.5)
    REPORT['installed_admission'] = {'decision': decision, 'observations': observations[-80:]}
    attempt = Path('/var/run/org.claudeguard.runtime/risk-last-attempt')
    if attempt.exists():
        stamp = attempt.read_text().strip()
        if stamp.isdigit() and len(stamp) <= 12:
            REPORT['installed_admission']['last_provider_attempt_age_seconds'] = max(0, int(time.time()) - int(stamp))
            REPORT['installed_admission']['provider_retry_seconds'] = max(0, int(stamp) + 3600 - int(time.time()))
    record('installed_automatic_activation', active)
    record('installed_real_risk_denies_release', True if decision == 'denied' else None,
        'Provider rejection observed' if decision == 'denied' else 'A denied provider verdict was not observed; see the distinct admission outcome')
    record('installed_missing_or_denied_risk_blocks_apps', blocked if decision in ['denied', 'unavailable'] else None)
    record('installed_real_risk_accepts_release', True if decision == 'accepted' else None)
    available = run(['/bin/launchctl', 'print', 'system/org.claudeguard.daemon'])
    record('installed_system_guardian_running', available.returncode == 0 and b'state = running' in available.stdout)
    recovery = Path('/Library/PrivilegedHelperTools/org.claudeguard/GuardOfflineRecovery')
    restored = run([str(recovery), '--restore-local'], timeout=55)
    record('installed_independent_restore', restored.returncode == 0)


def main():
    global WORKER, SERVICE, ROUTE_ADDED, LOG_READY, LOG_CREATED, SUPERVISED
    time.sleep(4)  # allow the outer installer transaction to finish
    (ROOT / 'driver.pid').write_text(str(os.getpid()))
    register_process('driver', os.getpid())
    config = json.loads((ROOT / 'route.private.json').read_text())
    if config.get('browserBridge'):
        REPORT['bridge_id'] = hashlib.sha256(config['browserBridge'].encode()).hexdigest()
    SUPERVISED = bool(config.get('faultMode'))
    if config.get('faultMode') not in [None, 'supervisor', 'wifi', 'sleep', 'lifecycle', 'soak']:
        raise RuntimeError('unsupported-fault-mode')
    if time.time() > config.get('testExpires', 0):
        record('driver_completed', False, 'Prepared test package expired; no network fault injected')
        (ROOT / 'done').touch()
        return
    if config.get('acceptanceMode') == 'admission-only':
        try:
            install_production(180)
        finally:
            cleanup()
            REPORT['left_state'] = 'Production installed if installation passed; protection disarmed through local recovery'
            write_report()
            (ROOT / 'done').touch()
        return
    try:
        routes = run(['/usr/sbin/netstat', '-rn', '-f', 'inet']).stdout.decode()
        candidates = [line.split() for line in routes.splitlines() if line.startswith('default ')]
        underlays = [(row[1], row[-1]) for row in candidates if re.fullmatch(r'en[0-9]+', row[-1]) and re.fullmatch(r'[0-9.]+', row[1])]
        if len(set(underlays)) != 1:
            raise RuntimeError('physical-default-route-ambiguous')
        gateway, physical = underlays[0]
        if not (ROOT / 'safety-ready').exists():
            raise RuntimeError('independent-safety-job-unavailable')
        safety_identity = json.loads((ROOT / 'safety.process').read_text())
        if process_stamp(safety_identity['pid']) != safety_identity['stamp']:
            raise RuntimeError('independent-safety-job-not-running')
        services = run(['/usr/sbin/scutil', '--nc', 'list']).stdout.decode()
        selected = [line for line in services.splitlines() if '(Connected)' in line and '(com.liguangming.Shadowrocket)' in line]
        if len(selected) != 1:
            raise RuntimeError('connected-service-ambiguous')
        SERVICE = re.findall(r'\b[0-9A-Fa-f-]{36}\b', selected[0])[0]
        added = run(['/sbin/route', '-n', 'add', '-host', TARGET, gateway])
        if added.returncode != 0:
            raise RuntimeError('test-host-route-unavailable')
        ROUTE_ADDED = True
        baseline = positive_control(physical)
        record('physical_capture_positive_control', baseline['response_received'])
        REPORT['physical_baseline'] = baseline
        if not baseline['response_received']:
            raise RuntimeError('physical-capture-inconclusive')
        ipv6_available = False
        if not config.get('browserOnly'):
            ipv6_baseline = positive_control(physical, ipv6=True)
            REPORT['physical_ipv6_baseline'] = ipv6_baseline
            ipv6_available = ipv6_baseline['response_received']
            optional_ipv6 = config.get('faultMode') in ['wifi', 'sleep']
            record('physical_ipv6_tcp_positive_control', ipv6_available if ipv6_available or not optional_ipv6 else None,
                   '' if ipv6_available else 'No validated physical IPv6 path; this run cannot claim IPv6 enforcement')
            if not ipv6_available and not optional_ipv6:
                raise RuntimeError('physical-ipv6-control-inconclusive')
        else:
            REPORT['scope'] = 'Actual browser faults; physical IPv4/IPv6 controls have separate matched-build evidence'
        baseline_trace = run(['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/var/empty',
            '/usr/bin/curl', '-q', '-4', '--noproxy', '*', '--interface', 'if!' + config['interface'],
            '--proto', '=https', '--tlsv1.2', '--connect-timeout', '2', '--max-time', '4',
            '-fsS', '--write-out', '\n%{http_code}', 'https://1.1.1.1/cdn-cgi/trace'])
        trace_text = baseline_trace.stdout.decode(errors='replace')
        trace_addresses = re.findall(r'^ip=(.*)$', trace_text, re.M)
        record('root_tunnel_probe_before_filter', baseline_trace.returncode == 0 and trace_text.endswith('\n200') and trace_addresses == [config['expected']])
        main_rules = run(['/sbin/pfctl', '-sr']).stdout.decode()
        siblings = run(['/sbin/pfctl', '-a', 'com.apple', '-s', 'Anchors']).stdout.decode()
        skipped = run(['/sbin/pfctl', '-v', '-s', 'Interfaces']).stdout.decode()
        REPORT['pf_diagnostics'] = {
            'main_rules': re.sub(r'(?<![A-Za-z])[0-9]+(?:[.][0-9]+){3}', '<address>', main_rules),
            'anchors': re.sub(r'(?<![A-Za-z])[0-9]+(?:[.][0-9]+){3}', '<address>', siblings),
            'skipped': [line.strip() for line in skipped.splitlines() if 'skip' in line]
        }
        LOG_CREATED = run(['/sbin/ifconfig', 'pflog0']).returncode != 0
        if LOG_CREATED: run(['/sbin/ifconfig', 'pflog0', 'create'])
        LOG_READY = run(['/sbin/ifconfig', 'pflog0']).returncode == 0
        if LOG_READY:
            start_probe_capture()
        original = (ROOT / 'GuardWorker.sh').read_text()
        script = instrument_worker(original)
        browser_window(config, 'waiting-for-browser')
        session = str(uuid.uuid4())
        fields = ['live', config['interface'], config['peer'], config['transport'], config['port'], config['expected'], 'US', SERVICE, 'run', '0', '', '']
        if SUPERVISED:
            REPORT['native_supervision_fixture'] = True
            REPORT['fixture_scope'] = 'Actual Core, IOKit power observer, packet fence and worker; fixed test paths and synthetic risk/trust only'
            WORKER = subprocess.Popen([str(FILTER), '--supervise'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            initialized = run([str(FILTER), '--initialize', session], timeout=20)
            record('native_test_fence_initializes', initialized.returncode == 0,
                   'Actual native packet fence; isolated anchor and synthetic readiness/risk only')
            if initialized.returncode != 0:
                raise RuntimeError('native-test-fence-unavailable')
            WORKER = subprocess.Popen(['/bin/sh', '-c', script, 'claude-guard-worker', 'worker-input', session], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        register_process('worker', WORKER.pid)
        if not SUPERVISED:
            WORKER.stdin.write(('\n' + '|'.join(fields) + '\n/Library/PrivilegedHelperTools/org.claudeguard/GuardDaemon\n').encode())
            WORKER.stdin.close()
        began = time.monotonic()
        wait_phase('OPEN', 180 if config.get('browserOnly') or SUPERVISED else 70)
        REPORT.setdefault('durations_seconds', {})['initial_admission'] = round(time.monotonic() - began, 3)
        record('real_pf_stable_open_controlled_risk', time.monotonic() - began >= 15, 'Synthetic risk acceptance; not a reputation pass')
        if SUPERVISED:
            events = json.loads((ROOT / 'power-events.json').read_text())
            record('native_iokit_registration', any(row['event'] == 'registered-and-awake' for row in events))
        for protocol in ([] if config.get('browserOnly') else ['tcp', 'udp']):
            observation = probe(physical, protocol)
            REPORT['physical_' + protocol + '_observation'] = observation
            record('physical_' + protocol + '_blocked_while_open',
                   not observation['response_received'] and observation['pf_drop_headers'] > 0,
                   'Requires failed application control and matching PF drop log; tap headers alone do not decide')
            if ipv6_available:
                observation6 = probe(physical, protocol, ipv6=True)
                REPORT['physical_ipv6_' + protocol + '_observation'] = observation6
                record('physical_ipv6_' + protocol + '_hits_drop_while_open',
                       not observation6['response_received'] and observation6['pf_drop_headers'] > 0,
                       'Exact fresh IPv6 flow observed at the kernel drop rule; TCP positive control established the physical IPv6 path')
        browser_window(config, 'protected-open')
        if config.get('faultMode') == 'lifecycle':
            lifecycle_faults()
        if config.get('faultMode') == 'soak':
            supervised_soak()
        if config.get('faultMode') == 'wifi':
            recovery = environment()
            recovery['prepare_wifi'](ROOT, physical)
            off = run(['/usr/sbin/networksetup', '-setairportpower', physical, 'off'])
            if off.returncode != 0:
                raise RuntimeError('wireless-power-change-failed')
            revoked_at = time.monotonic()
            until = time.monotonic() + 10
            while time.monotonic() < until and status()[6] != 'underlay-offline':
                time.sleep(0.2)
            REPORT['durations_seconds']['wireless_off_observation'] = round(time.monotonic() - revoked_at, 3)
            record('wireless_loss_revokes_release', status()[1] != 'OPEN' and status()[6] == 'underlay-offline')
            until = time.monotonic() + 35
            while (ROOT / 'wifi-restore.json').exists() and time.monotonic() < until:
                time.sleep(0.2)
            record('independent_wireless_restore', not (ROOT / 'wifi-restore.json').exists())
            began = time.monotonic()
            wait_phase('OPEN', 240)
            REPORT['durations_seconds']['wireless_restoration_to_admission'] = round(time.monotonic() - began, 3)
            record('wireless_recovers_after_fresh_stability', time.monotonic() - began >= 14)
        elif config.get('faultMode') == 'sleep':
            before_session = status()[0]
            before_events = len(json.loads((ROOT / 'power-events.json').read_text()))
            recovery = environment()
            recovery['prepare_sleep'](ROOT, os.stat('/dev/console').st_uid, 8 if config.get('shortSleep') else 20)
            slept = run(['/usr/bin/pmset', 'sleepnow'], timeout=45)
            if slept.returncode != 0:
                raise RuntimeError('system-sleep-request-failed')
            until = time.monotonic() + 45
            events = []
            while time.monotonic() < until:
                events = json.loads((ROOT / 'power-events.json').read_text())[before_events:]
                if any(row['event'] == 'completed-wake' for row in events):
                    break
                time.sleep(0.2)
            names = [row['event'] for row in events]
            record('actual_sleep_seals_before_acknowledgment', 'sealed-before-sleep-acknowledgment' in names and 'power-failure' not in names)
            record('actual_completed_wake_observed', 'completed-wake' in names)
            REPORT['power_events'] = events
            sealed = [row['at'] for row in events if row['event'] == 'sealed-before-sleep-acknowledgment']
            powered = [row['at'] for row in events if row['event'] == 'completed-wake']
            if sealed and powered:
                REPORT['durations_seconds']['sleep_notification_to_completed_wake'] = round(powered[-1] - sealed[0], 3)
                if config.get('shortSleep'):
                    record('actual_sleep_shorter_than_identity_lease', 0 < powered[-1] - sealed[0] < 12)
            REPORT['environment_restoration'] = recovery['restore_due'](ROOT, force=True)
            wait_phase('OPEN', 240)
            record('wake_uses_fresh_worker_session', status()[0] != before_session)
            completed = [row['at'] for row in events if row['event'] == 'completed-wake']
            if completed:
                REPORT['durations_seconds']['completed_wake_to_admission'] = round(float(status()[2]) - completed[-1], 3)
            record('wake_recovers_after_fresh_stability', bool(completed) and float(status()[2]) - completed[-1] >= 14)
        if config.get('browserBridge'):
            REPORT['browser_phase'] = 'disconnect-scheduled'
            write_report()
            time.sleep(5)
        if config.get('faultMode') not in ['wifi', 'sleep', 'soak']:
            run(['/usr/sbin/scutil', '--nc', 'stop', SERVICE])
            wait_phase('LOCKED', 10)
            record('vpn_disconnect_revokes_release', True)
            observation = probe(physical)
            REPORT['disconnected_physical_observation'] = observation
            record('physical_tcp_blocked_after_disconnect', not observation['response_received'] and observation['pf_drop_headers'] > 0)
            browser_window(config, 'vpn-disconnected', acknowledge=False)
            began = time.monotonic()
            run(['/usr/sbin/scutil', '--nc', 'start', SERVICE])
            wait_phase('OPEN', 180 if config.get('browserOnly') or SUPERVISED else 120)
            REPORT['durations_seconds']['vpn_start_to_admission'] = round(time.monotonic() - began, 3)
            record('vpn_recovers_after_fresh_stability', time.monotonic() - began >= 14)
            browser_window(config, 'recovered-open')
        stop_worker()
        record('test_anchor_removed_after_restore', not run(['/sbin/pfctl', '-a', ANCHOR, '-sr']).stdout.strip())
        run(['/sbin/route', '-n', 'delete', '-host', TARGET])
        ROUTE_ADDED = False
    except Exception as error:
        # Exception type/message are local fixed failure codes; no command output.
        REPORT['worker_diagnostics'] = {'exit_code': WORKER.poll() if WORKER is not None else None, 'phase': status()[1] if status() else None, 'reason': status()[6] if status() else None}
        if WORKER is not None:
            curl = run(['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/var/empty', '/usr/bin/curl', '-q', '-4', '--noproxy', '*', '--interface', 'if!' + config['interface'], '--proto', '=https', '--tlsv1.2', '--connect-timeout', '2', '--max-time', '4', '-fsS', '--output', '/dev/null', '--write-out', '%{http_code}', 'https://1.1.1.1/cdn-cgi/trace'])
            REPORT['worker_diagnostics']['curl_code'] = curl.returncode
            REPORT['worker_diagnostics']['http_status'] = curl.stdout.decode()[:3]
            rules = run(['/sbin/pfctl', '-a', ANCHOR, '-vvsr']).stdout.decode()
            REPORT['worker_diagnostics']['rules'] = re.sub(r'(?<![A-Za-z])[0-9]+(?:[.][0-9]+){3}', '<address>', rules)
            if status() and status()[1] == 'LOCKED' and 'CG_TUNNEL' not in rules and 'CG_PROBE_OUT' in rules and WORKER.poll() is None:
                # Freeze only this disposable worker while its restrictive
                # rules hold. Longer controls cannot authorize app release.
                WORKER.send_signal(signal.SIGSTOP)
                controls = []
                for connect_budget, total_budget in [(1.5, 2), (2.5, 3), (3, 4)] * 2:
                    started = time.time()
                    result = run(['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/var/empty', '/usr/bin/curl', '-q', '-4', '--noproxy', '*', '--interface', 'if!' + config['interface'], '--proto', '=https', '--tlsv1.2', '--connect-timeout', str(connect_budget), '--max-time', str(total_budget), '-fsS', '--output', '/dev/null', '--write-out', '%{http_code}|%{time_appconnect}|%{time_total}|%{local_port}', 'https://1.1.1.1/cdn-cgi/trace'])
                    ended = time.time()
                    fields = result.stdout.decode().split('|')
                    if len(fields) == 4 and all(re.fullmatch(r'[0-9.]+', value) for value in fields):
                        controls.append(({'connect_budget_seconds': connect_budget, 'total_budget_seconds': total_budget,
                            'exit_code': result.returncode, 'http_status': fields[0], 'tls_seconds': fields[1],
                            'total_seconds': fields[2]}, int(fields[3]), started, ended))
                stop_probe_capture()
                REPORT['locked_timing_controls'] = [dict(value, request_drop_categories=drop_summary(port, start, end, config['interface']))
                    for value, port, start, end in controls]

        record('driver_completed', False, type(error).__name__ + ': ' + str(error)[:160])
    finally:
        if config.get('browserBridge'):
            REPORT['browser_phase'] = 'ended'
            write_report()
        stop_probe_capture()
        REPORT['health_drop_capture'] = PROBE_CAPTURE
        timing_file = RUNTIME / 'curl-timings'
        if timing_file.exists():
            timings = []
            for line in timing_file.read_text().splitlines()[-240:]:
                values = line.split('|')
                if len(values) == 10 and all(re.fullmatch(r'[0-9.]+', value) for value in values):
                    timings.append({'budget_seconds': values[0], 'exit_code': values[3], 'http_status': values[4],
                        'connect_seconds': values[5], 'tls_seconds': values[6],
                        'first_byte_seconds': values[7], 'total_seconds': values[8],
                        'request_drop_categories': drop_summary(int(values[9]), float(values[1]), float(values[2]), config['interface'])})
            REPORT['curl_timings'] = timings
        progress = RUNTIME / 'progress'
        if progress.exists():
            records = []
            for line in progress.read_text().splitlines()[-240:]:
                fields = line.split('|')
                if len(fields) != 6 or not all(value.isdigit() for value in fields[2:]):
                    continue
                records.append({'phase': fields[0], 'reason': fields[1],
                    'samples': int(fields[2]),
                    'dwell_seconds': max(0, int(fields[5]) - int(fields[3])) if int(fields[3]) else 0,
                    'observation_age_seconds': max(0, int(fields[5]) - int(fields[4])) if int(fields[4]) else None})
            REPORT['worker_progress'] = records
        cleanup()
        if LOG_CREATED: run(['/sbin/ifconfig', 'pflog0', 'destroy'])
        if not config.get('browserOnly') and not SUPERVISED:
            install_production(180)
        REPORT['left_state'] = ('Existing production installation retained; disposable filter restored; VPN reconnect requested'
            if config.get('browserOnly') or SUPERVISED else 'Production installed if installation passed; protection disarmed locally; VPN reconnect requested')
        write_report()
        (ROOT / 'done').touch()


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit(77)
    safety() if sys.argv[1:] == ['--safety'] else main()
