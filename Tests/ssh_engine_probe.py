"""Fresh existing-peer SSH control with strict host keys and no remote writes."""
from pathlib import Path
import json
import os
import runpy
import select
import signal
import subprocess
import sys
import time


def probe():
    if os.geteuid() == 0:
        return {'reachable': False, 'failureCategory': 'console-user-required'}
    selected = runpy.run_path(str(Path(__file__).with_name('tailscale_host_client.py')))
    try:
        alias = selected['selected_alias']()
    except Exception:
        return {'reachable': False, 'failureCategory': 'existing-peer-unavailable'}
    command = ['/usr/bin/ssh', '-F', str(Path.home() / '.ssh/config'), '-T',
               '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
               '-o', 'ConnectTimeout=8', '-o', 'ConnectionAttempts=1',
               '-o', 'ServerAliveInterval=1', '-o', 'ServerAliveCountMax=2', alias, 'true']
    started = time.monotonic()
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.PIPE, start_new_session=True)
    try:
        _, error = child.communicate(timeout=12)
        code = child.returncode
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        _, error = child.communicate(timeout=3)
        code = 124
    text = error[:4096].decode(errors='replace').lower()
    if code == 0:
        category = 'none'
    elif code == 124 or 'timed out' in text or 'timeout' in text:
        category = 'timeout'
    elif 'host key' in text or 'identification has changed' in text:
        category = 'host-key'
    elif 'permission denied' in text or 'authentication failed' in text:
        category = 'authentication'
    elif any(word in text for word in ('connect', 'network', 'no route', 'closed', 'reset')):
        category = 'network'
    else:
        category = 'other'
    return {'reachable': code == 0, 'exitCode': code, 'failureCategory': category,
            'seconds': round(time.monotonic() - started, 3),
            'scope': 'Fresh SSH to the single existing Linux peer; strict host keys; no remote file writes'}


def session():
    """Pipe-controlled user process; no loopback bridge or remote state files."""
    selected = runpy.run_path(str(Path(__file__).with_name('tailscale_host_client.py')))
    alias = selected['selected_alias']()
    connection = None
    try:
        for line in sys.stdin:
            if len(line) > 256:
                raise ValueError('request-size')
            action = json.loads(line).get('action')
            if action == 'fresh':
                result = probe()
            elif action == 'start' and connection is None:
                command = ['/usr/bin/ssh', '-F', str(Path.home() / '.ssh/config'), '-T',
                           '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                           '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                           '-o', 'ConnectTimeout=8', '-o', 'ConnectionAttempts=1',
                           '-o', 'ServerAliveInterval=1', '-o', 'ServerAliveCountMax=2',
                           alias, 'printf "READY\\n"; exec sleep 180']
                connection = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                              stderr=subprocess.DEVNULL, start_new_session=True)
                ready, _, _ = select.select([connection.stdout], [], [], 12)
                result = {'ready': bool(ready) and connection.stdout.readline(6) == b'READY\n'}
            elif action == 'interrupted' and connection is not None:
                try:
                    connection.wait(timeout=10)
                    result = {'interrupted': connection.returncode != 0, 'exitCode': connection.returncode}
                except subprocess.TimeoutExpired:
                    result = {'interrupted': False}
            elif action == 'stop':
                print(json.dumps({'stopped': True}), flush=True)
                break
            else:
                raise ValueError('request-action')
            print(json.dumps(result), flush=True)
    finally:
        if connection is not None and connection.poll() is None:
            os.killpg(connection.pid, signal.SIGTERM)
            try:
                connection.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(connection.pid, signal.SIGKILL)
                connection.wait(timeout=2)


if __name__ == '__main__':
    if sys.argv[1:] == ['--session']:
        session()
    elif not sys.argv[1:]:
        print(json.dumps(probe()))
    else:
        raise SystemExit('Unsupported argument')
