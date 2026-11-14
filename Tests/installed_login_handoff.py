"""Bounded installed login-agent handoff, without rebooting or logging out.

The approved vendor UI and Guard login agent are stopped, while root protection
remains active. Restart only Guard's installed login agent. Observe its signed
vendor startup and automatic service recovery. This is not cold-boot evidence.
"""
from pathlib import Path
import os
import runpy
import signal
import threading
import time

ROOT = Path('/Library/PrivilegedHelperTools/org.claudeguard.stability-acceptance')
RESULT = Path('/var/tmp/org.claudeguard-diverse-login-handoff.json')
VENDOR = '/Applications/Shadowrocket.app/Contents/MacOS/Shadowrocket'
APP = '/Applications/Claude Guard.app/Contents/MacOS/ClaudeGuard'
REQUIREMENT = '''anchor apple generic and identifier "com.liguangming.Shadowrocket" and (
certificate leaf[field.1.2.840.113635.100.6.1.9] exists or (
certificate 1[field.1.2.840.113635.100.6.2.6] exists and
certificate leaf[field.1.2.840.113635.100.6.1.13] exists and
certificate leaf[subject.OU] = "JBJ55K5C9X"))'''


def observe():
    control = runpy.run_path(str(ROOT / 'controller.py'))
    controller = control['Controller']()
    config = controller.config
    uid = config['uid']
    run = control['run']
    failure = control['AcceptanceFailure']
    entry = {'case': 'login-agent-handoff', 'phase': 'preparing'}
    report = {'phase': 'preparing', 'scope': 'Fresh existing login-agent handoff with signed vendor application absent; no logout, reboot, FileVault unlock or early-boot claim'}
    began = time.monotonic()
    stop = threading.Event()
    thread = None
    fault = {'error': None}
    def identity(pid, executable):
        result = run(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=,lstart=,comm='])
        text = result.stdout.decode().strip()
        return text if result.returncode == 0 and text and text.split()[0] == str(uid) and text.endswith(' ' + executable) else None
    def instances(executable):
        result = run(['/usr/bin/pgrep', '-x', Path(executable).name])
        return [(int(pid), identity(int(pid), executable)) for pid in result.stdout.split()
                if pid.isdigit() and identity(int(pid), executable)]
    def stop_verified(executable):
        for pid, value in instances(executable):
            if value is not None and identity(pid, executable) == value:
                os.kill(pid, signal.SIGTERM)
        until = time.monotonic() + 10
        while instances(executable) and time.monotonic() < until:
            time.sleep(.2)
        if instances(executable):
            raise failure('application-did-not-exit')
    try:
        evidence, intent = controller.wait_open(entry, stable_seconds=5)
        report['vendorSignatureValid'] = run(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures',
            '-R=' + REQUIREMENT, '/Applications/Shadowrocket.app']).returncode == 0
        if not report['vendorSignatureValid'] or not instances(VENDOR):
            raise failure('signed-vendor-prerequisite')
        report['beforeRequest'] = control['anonymous_request'](uid)
        if not report['beforeRequest']['httpResponse']:
            raise failure('service-positive-control-unavailable')
        service = intent['serviceID']
        started = time.monotonic()
        control['write_json'](ROOT / 'restore.json', {
            'loginAgent': {'uid': uid, 'at': started + 120},
            'vpn': {'service': service, 'at': started + 180}})
        label = 'gui/' + str(uid) + '/org.claudeguard.mac'
        report['loginAgentInitiallyLoaded'] = run(['/bin/launchctl', 'print', label]).returncode == 0
        if report['loginAgentInitiallyLoaded'] and run(['/bin/launchctl', 'bootout', label]).returncode:
            raise failure('login-agent-stop')
        stop_verified(APP)
        stop_verified(VENDOR)
        report['vendorAbsentBeforeHandoff'] = not instances(VENDOR)
        def disconnect():
            try:
                while not stop.is_set() and time.monotonic() - started < 90:
                    run(['/usr/sbin/scutil', '--nc', 'stop', service])
                    stop.wait(.2)
            except Exception as error:
                fault['error'] = type(error).__name__
        thread = threading.Thread(target=disconnect, daemon=True)
        thread.start()
        until = time.monotonic() + 20
        while time.monotonic() < until:
            if controller.snapshot(entry)[4]:
                break
            time.sleep(.2)
        else:
            raise failure('seal-not-observed')
        report['sealedBeforeHandoff'] = True
        report['phase'] = 'awaiting-vendor-start'
        control['write_json'](RESULT, report, public=True)
        handoff = time.monotonic()
        if not control['restore_console_agent'](uid):
            raise failure('login-agent-start')
        # Initial UI state can briefly retain a pre-seal publication. Allow
        # the documented thirty-second automatic check cadence plus startup
        # and signature-validation work, while keeping the VPN fault bounded.
        until = time.monotonic() + 60
        while time.monotonic() < until:
            controller.snapshot(entry)
            if instances(VENDOR):
                report['vendorStartedByHandoff'] = True
                report['vendorStartSeconds'] = round(time.monotonic() - handoff, 3)
                break
            time.sleep(.3)
        if not report.get('vendorStartedByHandoff'):
            raise failure('vendor-not-started-by-login-agent')
        stop.set()
        thread.join(timeout=20)
        if thread.is_alive() or fault['error']:
            raise failure('fault-control')
        controller.wait_open(entry)
        report['afterRequest'] = control['anonymous_request'](uid)
        if not report['afterRequest']['httpResponse']:
            raise failure('service-not-restored')
        history = control['private_json'](ROOT / 'safety-actions.json') if (ROOT / 'safety-actions.json').exists() else []
        if any(row['at'] >= started and any(row['actions'].get(key) for key in (
            'fallback-login-agent-started', 'fallback-vpn-started')) for row in history):
            raise failure('automatic-recovery-required-intervention')
        control['write_json'](ROOT / 'restore.json', {})
        report['recoverySeconds'] = round(time.monotonic() - started, 3)
        report['phase'] = 'passed'
    except Exception as error:
        report['phase'] = 'failed'
        report['failure'] = str(error) if isinstance(error, failure) else type(error).__name__
    finally:
        stop.set()
        if thread is not None:
            thread.join(timeout=20)
        report['seconds'] = round(time.monotonic() - began, 3)
        report['observations'] = entry
        control['write_json'](RESULT, report, public=True)
    return 0 if report['phase'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(observe())
