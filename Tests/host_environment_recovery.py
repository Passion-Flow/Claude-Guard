"""Bounded engineering-only link/display recovery for the independent safety job.

Never installed by the product. Only the separately authorized host acceptance
package copies this module into its private, root-owned test directory.
"""
import datetime
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import tempfile
import time

AWAKE_LABEL = 'org.claudeguard.workspace-awake'
WAKE_OWNER = 'org.claudeguard.acceptance'


def command(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, timeout=10,
                              env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        # A temporarily unavailable system utility must leave the plan for
        # the independent safety loop's next retry, rather than kill that loop.
        return subprocess.CompletedProcess(arguments, 74, b'', b'')


def write_plan(root, name, value):
    assert os.geteuid() == 0
    descriptor, temporary = tempfile.mkstemp(prefix='.environment-', dir=root)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, root / name)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_plan(root, name):
    assert os.geteuid() == 0
    try:
        descriptor = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
        assert stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 1024
        return json.loads(os.read(descriptor, 1025))
    finally:
        os.close(descriptor)


def awake_agent(uid):
    assert type(uid) is int and uid >= 501
    path = Path(pwd.getpwuid(uid).pw_dir) / 'Library/LaunchAgents' / (AWAKE_LABEL + '.plist')
    metadata = path.lstat()
    assert stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid
    assert stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 8192
    value = plistlib.loads(path.read_bytes())
    assert value['Label'] == AWAKE_LABEL and value['ProgramArguments'] == ['/usr/bin/caffeinate', '-disu']
    return path


def prepare_wifi(root, interface):
    assert re.fullmatch(r'en[0-9]+', interface)
    result = command(['/usr/sbin/networksetup', '-getairportpower', interface])
    assert result.returncode == 0 and result.stdout.decode().strip().endswith(': On')
    write_plan(root, 'wifi-restore.json', {'interface': interface, 'at': time.monotonic() + 15})


def prepare_sleep(root, uid, seconds=20):
    assert seconds in [8, 20]
    awake_agent(uid)
    power = command(['/usr/bin/pmset', '-g', 'batt'])
    assert power.returncode == 0 and b"'AC Power'" in power.stdout, 'Keep this host on AC power'
    wake_at = time.time() + seconds
    dates = [datetime.datetime.fromtimestamp(stamp).strftime('%m/%d/%y %H:%M:%S')
             for stamp in [wake_at, wake_at + 40]]
    write_plan(root, 'sleep-restore.json', {'uid': uid, 'dates': dates, 'at': wake_at + 5})
    for date in dates:
        scheduled = command(['/usr/bin/pmset', 'schedule', 'wakeorpoweron', date, WAKE_OWNER])
        assert scheduled.returncode == 0, 'Hardware wake could not be scheduled'
    listed = command(['/usr/bin/pmset', '-g', 'sched'])
    assert listed.returncode == 0 and WAKE_OWNER.encode() in listed.stdout, 'Scheduled wake was not confirmed'
    stopped = command(['/bin/launchctl', 'bootout', 'gui/' + str(uid) + '/' + AWAKE_LABEL])
    assert stopped.returncode == 0, 'Task-owned awake service could not be suspended'


def restore_due(root, force=False):
    """Idempotent and restricted to recorded test-owned recovery actions."""
    results = {}
    wifi = read_plan(root, 'wifi-restore.json')
    if wifi is not None and (force or time.monotonic() >= wifi['at']):
        interface = wifi['interface']
        assert re.fullmatch(r'en[0-9]+', interface)
        result = command(['/usr/sbin/networksetup', '-setairportpower', interface, 'on'])
        verified = command(['/usr/sbin/networksetup', '-getairportpower', interface])
        results['wifi_restored'] = result.returncode == verified.returncode == 0 and verified.stdout.decode().strip().endswith(': On')
        if results['wifi_restored']:
            (root / 'wifi-restore.json').unlink(missing_ok=True)
    sleep = read_plan(root, 'sleep-restore.json')
    if sleep is not None and (force or time.time() >= sleep['at']):
        uid = sleep['uid']
        path = awake_agent(uid)
        domain = 'gui/' + str(uid)
        label = domain + '/' + AWAKE_LABEL
        verified = command(['/bin/launchctl', 'print', label])
        if verified.returncode != 0 or b'state = running' not in verified.stdout:
            command(['/bin/launchctl', 'bootstrap', domain, str(path)])
            command(['/bin/launchctl', 'kickstart', label])
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                verified = command(['/bin/launchctl', 'print', label])
                if verified.returncode == 0 and b'state = running' in verified.stdout:
                    break
                time.sleep(0.1)
        results['awake_service_restored'] = verified.returncode == 0 and b'state = running' in verified.stdout
        if results['awake_service_restored']:
            # Cancel only this test's exact scheduled event; never other alarms.
            for date in sleep['dates']:
                command(['/usr/bin/pmset', 'schedule', 'cancel', 'wakeorpoweron', date, WAKE_OWNER])
            (root / 'sleep-restore.json').unlink(missing_ok=True)
    return results
