"""Explicit administrator-only uninstall acceptance on a disposable installation.

Not shipped in the app. The caller must stage this script and both packages in
a root-owned directory and authorize removal of the installed Claude Guard.
Only Guard's own jobs, files and PF anchor are changed. A separate local process
always runs the independent native uninstaller if this controller stalls.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import subprocess
import time
import uuid

ANCHOR = 'com.apple/00000.org.claudeguard.runtime'
HELPERS = Path('/Library/PrivilegedHelperTools/org.claudeguard')
APP = Path('/Applications/Claude Guard.app')
KIT = Path('/Users/Shared/Claude Guard Recovery')
LABELS = ('org.claudeguard.daemon', 'org.claudeguard.offline-recovery')
RECEIPTS = ('org.claudeguard.private', 'org.claudeguard.private.Uninstall', 'org.claudeguard.private.OfflineRecovery')


def run(args, timeout=20, input=None):
    return subprocess.run(args, input=input, capture_output=True, timeout=timeout)


def require(condition, label):
    if not condition:
        raise RuntimeError(label)


def empty_anchor():
    result = run(['/sbin/pfctl', '-a', ANCHOR, '-sr'])
    if result.returncode == 0:
        return not result.stdout.strip()
    parent = run(['/sbin/pfctl', '-a', 'com.apple', '-s', 'Anchors'])
    return parent.returncode == 0 and ANCHOR.split('/')[-1].encode() not in parent.stdout


def verify_removed(directory):
    checks = {}
    labels = LABELS + ('org.claudeguard.guardian',)
    checks['systemJobsAbsent'] = all(run(['/bin/launchctl', 'print', 'system/' + x]).returncode == 113 for x in labels)
    uid = os.stat('/dev/console').st_uid
    checks['loginJobAbsent'] = run(['/bin/launchctl', 'print', 'gui/' + str(uid) + '/org.claudeguard.mac']).returncode == 113
    jobs = run(['/bin/launchctl', 'list'])
    checks['finisherJobsAbsent'] = jobs.returncode == 0 and b'org.claudeguard.uninstall-finish.' not in jobs.stdout
    paths = [APP, HELPERS, KIT, Path('/Applications/Claude Guard Recovery.app'),
             Path('/Library/LaunchAgents/org.claudeguard.mac.plist'), Path('/private/var/run/org.claudeguard.runtime'),
             Path('/private/var/run/org.claudeguard.uninstall.lock')]
    paths += [Path('/Library/LaunchDaemons', x + '.plist') for x in labels]
    checks['installedPathsAbsent'] = all(not p.exists() for p in paths)
    receipts = run(['/usr/sbin/pkgutil', '--pkgs'])
    checks['productAndTestReceiptsAbsent'] = receipts.returncode == 0 and not any(x.startswith(b'org.claudeguard.') for x in receipts.stdout.splitlines())
    checks['finisherFilesAbsent'] = not list(Path('/private/var/tmp').glob('org.claudeguard.uninstall.*'))
    checks['guardRulesAbsent'] = empty_anchor()
    response = run(['/usr/bin/curl', '--noproxy', '*', '--silent', '--max-time', '10', '--output', '/dev/null',
                    '--write-out', '%{http_code}', 'https://www.apple.com/'])
    checks['freshHTTPSResponse'] = response.returncode == 0 and response.stdout.strip().isdigit() and response.stdout.strip() != b'000'
    result = {'phase': 'passed' if all(checks.values()) else 'failed', 'checks': checks}
    (directory / 'final-readback.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    require(all(checks.values()), 'final-readback-failed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--verify-removed', action='store_true')
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    require(args.execute and os.geteuid() == 0, 'explicit-root-execution-required')
    directory = args.directory.resolve()
    require(directory.stat().st_uid == 0 and directory.stat().st_mode & 0o077 == 0, 'private-root-stage-required')
    if args.verify_removed:
        verify_removed(directory)
        return
    installer, uninstaller, native = [directory / name for name in ('Install.pkg', 'Uninstall.pkg', 'GuardUninstall')]
    for path in (installer, uninstaller, native):
        require(path.is_file() and path.stat().st_uid == 0 and path.stat().st_mode & 0o022 == 0, 'trusted-stage-required')
    require(not APP.exists() and not HELPERS.exists() and empty_anchor(), 'existing-installation-must-be-removed-first')
    report = {'version': '1.0.1', 'build': 43, 'phase': 'running', 'cases': [],
              'scope': 'Actual local installation and removal; no reboot, GUI cleaner interaction or account-availability claim',
              'sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (installer, uninstaller)}}
    output = directory / 'result.json'

    def save():
        temporary = output.with_suffix('.next')
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(output)

    def clean():
        require(empty_anchor(), 'guard-rules-remain')
        for label in LABELS:
            require(run(['/bin/launchctl', 'print', 'system/' + label]).returncode == 113, 'guard-job-remains')
            require(not Path('/Library/LaunchDaemons', label + '.plist').exists(), 'boot-registration-remains')
        require(not Path('/Library/LaunchAgents/org.claudeguard.mac.plist').exists(), 'login-registration-remains')
        for path in (APP, HELPERS, KIT, Path('/private/var/run/org.claudeguard.runtime')):
            require(not path.exists(), 'installed-file-remains')
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            receipts_absent = all(run(['/usr/sbin/pkgutil', '--pkg-info', name]).returncode == 1 for name in RECEIPTS)
            finishes_absent = not list(Path('/private/var/tmp').glob('org.claudeguard.uninstall.*'))
            jobs = run(['/bin/launchctl', 'list'])
            finish_jobs_absent = jobs.returncode == 0 and b'org.claudeguard.uninstall-finish.' not in jobs.stdout
            if receipts_absent and finishes_absent and finish_jobs_absent:
                return
            time.sleep(.5)
        raise RuntimeError('receipt-cleanup-did-not-complete')

    save()
    try:
        for name in ('intact-installation', 'app-removed-first', 'app-and-helpers-removed-first', 'live-jobs-and-exiting-writer'):
            entry = {'case': name, 'passed': False}
            report['cases'].append(entry)
            save()
            # The watchdog survives a disconnected desktop/tool connection.
            watchdog = subprocess.Popen(['/bin/sh', '-c', 'sleep 180; exec "$1" --remove-only', 'guard-uninstall-watchdog', str(native)],
                                        start_new_session=True, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            controlled_token = None
            writer = None
            try:
                installed = run(['/usr/sbin/installer', '-pkg', str(installer), '-target', '/'], timeout=100)
                require(installed.returncode == 0, 'installation-failed')
                require(APP.exists() and HELPERS.exists() and (KIT / 'Uninstall.pkg').exists(), 'recovery-kit-missing')
                # A real restrictive filter is installed after stopping the
                # app's login job. It is a controlled uninstall fault, not a
                # claim that this test admitted a live production route.
                uid = os.stat('/dev/console').st_uid
                if name != 'live-jobs-and-exiting-writer':
                    run(['/bin/launchctl', 'bootout', 'gui/' + str(uid) + '/org.claudeguard.mac'])
                    for label in LABELS:
                        run(['/bin/launchctl', 'bootout', 'system/' + label])
                else:
                    require(all(run(['/bin/launchctl', 'print', 'system/' + label]).returncode == 0 for label in LABELS),
                            'live-guardian-jobs-not-observed')
                    entry['liveGuardianJobsObserved'] = True
                    # Model the real worker's shutdown trap writing a final
                    # seal. Removal must join this writer before clearing PF.
                    marker = directory / 'exiting-writer-sealed'
                    marker.unlink(missing_ok=True)
                    finish = 'printf \'block drop quick all label "CG_EXITING_WORKER"\\n\' | /sbin/pfctl -a ' + ANCHOR + ' -f - >/dev/null 2>&1 && /usr/bin/touch ' + shlex.quote(str(marker)) + '; exit 0'
                    script = 'trap ' + shlex.quote(finish) + ' TERM; while :; do /bin/sleep 0.1; done'
                    writer = subprocess.Popen(['/bin/sh', '-c', script, 'claude-guard-worker', 'worker-input', str(uuid.uuid4())],
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Drain exact installed processes using the independent engine
                # only during final removal; stopped launchd groups have no
                # permission to be re-registered by this controller.
                enabled = run(['/sbin/pfctl', '-E'])
                match = re.search(rb'Token\s*:\s*([0-9]+)', enabled.stdout + enabled.stderr)
                require(enabled.returncode == 0 and match is not None, 'test-reference-unavailable')
                controlled_token = match.group(1).decode()
                entry['controlledFilter'] = True
                require(run(['/sbin/pfctl', '-a', ANCHOR, '-f', '-'], input=b'block drop quick all label "CG_UNINSTALL_ACCEPTANCE"\n').returncode == 0,
                        'controlled-filter-load-failed')
                require(not empty_anchor(), 'controlled-filter-not-observed')
                if name in ('app-removed-first', 'app-and-helpers-removed-first'):
                    shutil.rmtree(APP)
                if name == 'app-and-helpers-removed-first':
                    shutil.rmtree(HELPERS)
                # Run the copy outside the deleted app/helper directories.
                removed = run(['/usr/sbin/installer', '-pkg', str(KIT / 'Uninstall.pkg'), '-target', '/'], timeout=100)
                require(removed.returncode == 0, 'independent-uninstall-failed')
                if writer is not None:
                    writer.wait(timeout=5)
                    require((directory / 'exiting-writer-sealed').is_file(), 'shutdown-writer-not-exercised')
                    entry['exitingWriterStopped'] = True
                clean()
                entry['rulesAndFilesAbsent'] = True
                # This reference belongs to the test, never to the product.
                require(run(['/sbin/pfctl', '-X', controlled_token]).returncode == 0, 'test-reference-release-failed')
                controlled_token = None
                response = run(['/usr/bin/curl', '--noproxy', '*', '--max-time', '15', '--silent', '--output', '/dev/null',
                                '--write-out', '%{http_code}', 'https://www.apple.com/'], timeout=18)
                entry['freshHTTPSResponse'] = response.returncode == 0 and response.stdout.strip().isdigit() and response.stdout.strip() != b'000'
                require(entry['freshHTTPSResponse'], 'post-uninstall-network-check-failed')
                repeated = run(['/usr/sbin/installer', '-pkg', str(uninstaller), '-target', '/'], timeout=100)
                require(repeated.returncode == 0, 'repeated-uninstall-failed')
                clean()
                entry['repeatUninstallPassed'] = True
                entry['passed'] = True
            finally:
                # Always remove the temporary policy before ending this case,
                # including failures. Only the exact product anchor is touched.
                emergency = run([str(native), '--remove-only'], timeout=100)
                if writer is not None and writer.poll() is None:
                    writer.terminate()
                    writer.wait(timeout=5)
                    run([str(native), '--remove-only'], timeout=100)
                if controlled_token:
                    run(['/sbin/pfctl', '-X', controlled_token])
                if emergency.returncode == 0:
                    try:
                        os.killpg(watchdog.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    watchdog.wait(timeout=5)
                save()
        report['phase'] = 'passed'
    except Exception as error:
        report['phase'] = 'failed'
        report['failure'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
