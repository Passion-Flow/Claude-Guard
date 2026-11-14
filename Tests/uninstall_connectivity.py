"""Explicit root-only network round trip with the installed components absent."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def run(args, timeout=20, input=None):
    return subprocess.run(args, input=input, capture_output=True, timeout=timeout)


def request(seconds):
    result = run(['/usr/bin/curl', '--noproxy', '*', '--silent', '--max-time', str(seconds),
                  '--output', '/dev/null', '--write-out', '%{http_code}', 'https://www.apple.com/'], seconds + 3)
    return result.returncode == 0 and result.stdout.strip().isdigit() and result.stdout.strip() != b'000'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if not args.execute or os.geteuid() != 0:
        raise RuntimeError('explicit-root-execution-required')
    directory = args.directory.resolve()
    if directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
        raise RuntimeError('private-root-stage-required')
    native, package = directory / 'GuardUninstall', directory / 'Uninstall.pkg'
    for path in (native, package):
        if not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise RuntimeError('trusted-package-required')
    anchor = 'com.apple/00000.org.claudeguard.runtime'
    assert not Path('/Applications/Claude Guard.app').exists()
    assert not Path('/Library/PrivilegedHelperTools/org.claudeguard').exists()
    assert not run(['/sbin/pfctl', '-a', anchor, '-sr']).stdout.strip()
    report = {'phase': 'running', 'uninstallerSHA256': hashlib.sha256(package.read_bytes()).hexdigest(),
              'scope': 'Fresh anonymous HTTPS with app and helpers absent; controlled product anchor only'}
    token = None
    watchdog = subprocess.Popen(['/bin/sh', '-c', 'sleep 45; exec "$1" --remove-only', 'guard-uninstall-watchdog', str(native)],
                                start_new_session=True, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        report['reachableBeforeBlock'] = request(10)
        assert report['reachableBeforeBlock']
        enabled = run(['/sbin/pfctl', '-E'])
        found = re.search(rb'Token\s*:\s*([0-9]+)', enabled.stdout + enabled.stderr)
        assert enabled.returncode == 0 and found is not None
        token = found.group(1).decode()
        assert run(['/sbin/pfctl', '-a', anchor, '-f', '-'], input=b'block drop quick all label "CG_UNINSTALL_ROUNDTRIP"\n').returncode == 0
        report['freshHTTPSBlocked'] = not request(3)
        assert report['freshHTTPSBlocked']
        removed = run(['/usr/sbin/installer', '-pkg', str(package), '-target', '/'], timeout=90)
        report['independentUninstallSucceeded'] = removed.returncode == 0
        assert report['independentUninstallSucceeded']
        rules = run(['/sbin/pfctl', '-a', anchor, '-sr'])
        report['ownRulesEmpty'] = rules.returncode == 0 and not rules.stdout.strip()
        assert report['ownRulesEmpty']
        report['freshHTTPSRestored'] = request(10)
        assert report['freshHTTPSRestored']
        report['phase'] = 'passed'
    finally:
        recovery = run([str(native), '--remove-only'], timeout=45)
        if token:
            run(['/sbin/pfctl', '-X', token])
        if recovery.returncode == 0:
            try:
                os.killpg(watchdog.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            watchdog.wait(timeout=5)
        if report['phase'] != 'passed':
            report['phase'] = 'failed'
        (directory / 'connectivity-roundtrip.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))


if __name__ == '__main__':
    main()
