"""Opt-in installed control-plane acceptance; requires disarmed production intent.

Signals only the fixed launchd primary after verifying its root process identity.
An independent timer resumes that same process if the recovery attempt fails.
No VPN profile, packet rule, key or unrelated process is configured here.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

ROOT = Path('/Library/PrivilegedHelperTools/org.claudeguard')
PRIMARY = ROOT / 'GuardDaemon'
RECOVERY = ROOT / 'GuardOfflineRecovery'
LABEL = 'system/org.claudeguard.daemon'
PLIST = '/Library/LaunchDaemons/org.claudeguard.daemon.plist'


def command(arguments, seconds=10):
    return subprocess.run(arguments, capture_output=True, timeout=seconds,
                          env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})


def primary_pid():
    result = command(['/bin/launchctl', 'print', LABEL])
    values = re.findall(rb'^\s*pid = ([0-9]+)\s*$', result.stdout, re.M)
    return int(values[0]) if result.returncode == 0 and len(values) == 1 else None


def identity(pid):
    if not isinstance(pid, int) or pid <= 1:
        return None
    result = command(['/bin/ps', '-ww', '-p', str(pid), '-o', 'uid=,lstart=,comm='])
    text = result.stdout.decode().strip()
    return text if result.returncode == 0 and text.split()[0] == '0' and text.endswith(str(PRIMARY)) else None


def wait_primary(previous=None):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        pid = primary_pid()
        if pid != previous and identity(pid):
            return pid
        time.sleep(0.1)
    raise RuntimeError('installed-primary-not-running')


def run():
    assert os.geteuid() == 0 and sys.argv[1:] == ['--run']
    intent = json.loads((ROOT / 'state/intent.json').read_text())
    assert not any(intent.get(name) for name in ['armed', 'approved', 'maintenance'])
    assert intent.get('automaticEnabled') is False, 'Production protection must be explicitly disarmed'
    assert command([str(PRIMARY), '--validate-payload', '/']).returncode == 0
    report = {'scope': 'Actual installed launchd/control/recovery with disarmed production intent; no active-enforcement or reboot claim', 'checks': {}, 'durations_seconds': {}}
    old = wait_primary()
    began = time.monotonic()
    os.kill(old, signal.SIGKILL)
    current = wait_primary(old)
    report['checks']['launchd_restarts_killed_primary'] = True
    report['durations_seconds']['launchd_restart'] = round(time.monotonic() - began, 3)
    token = identity(current)
    stopped = False

    def thaw():
        if identity(current) == token:
            try:
                os.kill(current, signal.SIGCONT)
            except ProcessLookupError:
                pass

    timer = threading.Timer(20, thaw)
    timer.daemon = True
    timer.start()
    descriptor = os.open(ROOT / 'state/control.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except BlockingIOError:
                os.kill(current, signal.SIGSTOP)
                stopped = True
                assert identity(current) == token
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    thaw()
                    stopped = False
                except BlockingIOError:
                    break
            time.sleep(0.0005)
        if not stopped:
            raise RuntimeError('stopped-primary-lock-ownership-not-observed')
        report['checks']['actual_primary_stopped_while_holding_control_lock'] = True
        began = time.monotonic()
        result = command([str(RECOVERY), '--restore-local'], seconds=55)
        report['durations_seconds']['independent_recovery'] = round(time.monotonic() - began, 3)
        report['checks']['independent_recovery_succeeds'] = result.returncode == 0
        assert result.returncode == 0, 'Installed independent recovery failed'
        wait_primary(current)
        intent = json.loads((ROOT / 'state/intent.json').read_text())
        report['checks']['disarmed_intent_remains_durable'] = not any(intent.get(name) for name in ['armed', 'approved', 'maintenance', 'automaticEnabled'])
        assert report['checks']['disarmed_intent_remains_durable']
        print(json.dumps(report, indent=2))
    finally:
        os.close(descriptor)
        thaw()
        timer.cancel()
        if primary_pid() is None:
            command(['/bin/launchctl', 'bootstrap', 'system', PLIST])


if __name__ == '__main__':
    run()
