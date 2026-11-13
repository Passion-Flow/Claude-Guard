"""Console-user SSH observer for the opt-in, isolated host acceptance run.

Uses one existing SSH alias matching the only online Linux peer. No credential,
host-key exception or remote file is created. Never bundled in the product.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import signal
import stat
import subprocess
import sys
import time

RESULT = Path('/var/tmp/org.claudeguard-acceptance-result.json')


def selected_alias():
    pids = subprocess.run(['/usr/bin/pgrep', '-x', 'tailscaled'], capture_output=True,
                          text=True, timeout=5, check=True).stdout.split()
    assert len(pids) == 1, 'Exactly one existing Tailscale daemon is required'
    text = subprocess.run(['/bin/ps', '-ww', '-p', pids[0], '-o', 'command='],
                          capture_output=True, text=True, timeout=5, check=True).stdout
    args = shlex.split(text)
    socket = None
    for index, arg in enumerate(args):
        for flag in ['-socket', '--socket']:
            if arg.startswith(flag + '='):
                socket = arg.split('=', 1)[1]
            elif arg == flag and index + 1 < len(args):
                socket = args[index + 1]
    cli = Path.home() / '.local/bin/tailscale'
    command = [str(cli)] + (['--socket=' + socket] if socket else []) + ['status', '--json']
    result = subprocess.run(command, capture_output=True, timeout=10, check=True)
    peers = [peer for peer in json.loads(result.stdout).get('Peer', {}).values()
             if peer.get('Online') and peer.get('OS') == 'linux']
    assert len(peers) == 1, 'The existing online Linux peer must be unambiguous'
    peer = peers[0]
    names = set(peer.get('TailscaleIPs', []) + [peer.get('HostName', ''), peer.get('DNSName', '').rstrip('.')])
    blocks, current = [], None
    for line in (Path.home() / '.ssh/config').read_text().splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2:
            continue
        key, value = fields
        if key.lower() == 'host':
            current = {'host': value}
            blocks.append(current)
        elif current is not None:
            current[key.lower()] = value
    matches = [block for block in blocks if block.get('hostname', '').rstrip('.') in names
               and len(block['host'].split()) == 1 and '*' not in block['host']
               and '?' not in block['host']]
    assert len(matches) == 1, 'Use an exact, already configured alias for that peer'
    return matches[0]['host']


def observe(bridge):
    assert os.geteuid() != 0
    metadata = bridge.lstat()
    assert stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid()
    assert stat.S_IMODE(metadata.st_mode) == 0o700
    alias = selected_alias()
    command = ['/usr/bin/ssh', '-F', str(Path.home() / '.ssh/config'), '-T',
        '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'ConnectionAttempts=1',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
        '-o', 'ServerAliveInterval=1', '-o', 'ServerAliveCountMax=2', alias]
    token = hashlib.sha256(str(bridge).encode()).hexdigest()
    began = time.time()
    deadline = time.monotonic() + 600
    observations, completed = [], set()
    long_connection = None
    failure_category = None

    def save():
        temporary = bridge / 'ssh-result.tmp'
        temporary.write_text(json.dumps({'scope': 'Actual console-user SSH; existing exact alias; no remote file changes',
                                        'checks': observations}, indent=2))
        temporary.chmod(0o600)
        os.replace(temporary, bridge / 'ssh-result.json')

    def fresh():
        nonlocal failure_category
        diagnostics = bridge / 'ssh-diagnostics.tmp'
        try:
            with diagnostics.open('w+b') as output:
                diagnostics.chmod(0o600)
                result = subprocess.run(command + ['true'], stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=output, timeout=15)
                output.seek(0)
                error = output.read(4096).decode(errors='replace').lower()
            if result.returncode == 0:
                failure_category = None
            elif 'host key' in error or 'identification has changed' in error:
                failure_category = 'host-key'
            elif 'permission denied' in error or 'authentication failed' in error:
                failure_category = 'authentication'
            elif 'timed out' in error or 'timeout' in error:
                failure_category = 'timeout'
            elif any(text in error for text in ['connect', 'network', 'no route', 'closed', 'reset']):
                failure_category = 'network'
            else:
                failure_category = 'other'
            return result.returncode
        except subprocess.TimeoutExpired:
            failure_category = 'timeout'
            return 124
        finally:
            diagnostics.unlink(missing_ok=True)

    try:
        while time.monotonic() < deadline:
            try:
                report = json.loads(RESULT.read_text())
            except (OSError, ValueError):
                time.sleep(0.1)
                continue
            phase = report.get('browser_phase')
            if report.get('bridge_id') != token or report.get('browser_phase_started_at', 0) < began or phase in completed:
                time.sleep(0.1)
                continue
            started = time.monotonic()
            attempts = 1
            retries = []
            if phase == 'waiting-for-browser':
                code = fresh()
                passed = code == 0
            elif phase == 'protected-open':
                code = fresh()
                long_connection = subprocess.Popen(command + ['printf "READY\\n"; exec sleep 180'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    start_new_session=True)
                readable, _, _ = select.select([long_connection.stdout], [], [], 10)
                passed = code == 0 and bool(readable) and long_connection.stdout.readline(7) == b'READY\n'
            elif phase == 'vpn-disconnected':
                code = fresh()
                try:
                    long_connection.wait(timeout=10)
                    interrupted = long_connection.returncode != 0
                except subprocess.TimeoutExpired:
                    interrupted = False
                passed = code != 0 and interrupted
            elif phase == 'recovered-open':
                code = fresh()
                recovery_deadline = time.monotonic() + 90
                while code != 0 and failure_category in ['network', 'timeout'] and time.monotonic() < recovery_deadline:
                    retries.append(failure_category)
                    time.sleep(1)
                    attempts += 1
                    code = fresh()
                passed = code == 0
            else:
                time.sleep(0.1)
                continue
            entry = {'phase': phase, 'passed': passed, 'exit_code': code,
                     'seconds': round(time.monotonic() - started, 3),
                     'attempts': attempts, 'failure_category': failure_category}
            if retries:
                entry['recovery_retry_categories'] = retries
            if phase == 'vpn-disconnected':
                entry['existing_ssh_interrupted'] = interrupted
            observations.append(entry)
            completed.add(phase)
            save()
            if not passed:
                return 1
            (bridge / (phase + '.ack')).write_bytes(b'advance')
            if phase == 'recovered-open':
                return 0
        observations.append({'phase': 'observer-timeout', 'passed': False})
        save()
        return 1
    finally:
        if long_connection is not None and long_connection.poll() is None:
            os.killpg(long_connection.pid, signal.SIGTERM)
            try:
                long_connection.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(long_connection.pid, signal.SIGKILL)
                long_connection.wait(timeout=2)


if __name__ == '__main__':
    assert len(sys.argv) == 2
    destination = Path(sys.argv[1]).resolve()
    try:
        code = observe(destination)
    except Exception:
        code = 1
    if code != 0:
        metadata = destination.lstat()
        if stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o700:
            (destination / 'observer-failed').write_bytes(b'stop')
    raise SystemExit(code)
