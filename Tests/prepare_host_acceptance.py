"""Build an opt-in, bounded local acceptance package from reviewed artifacts.

The console operator authorizes installation through macOS Installer. No sudo
configuration or reusable administrator credential is created. Private route
data stays in mode-0600 staging and root-only installed test storage. The
independent safety job restores networking and removes test-owned components.
"""
from pathlib import Path
import hashlib
import base64
import ipaddress
import json
import os
import plistlib
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import time

REPOSITORY = Path(__file__).resolve().parents[1]
PROVIDER_SUFFIX = '/Shadowrocket.app/Contents/PlugIns/MacPacketTunnel.appex/Contents/MacOS/MacPacketTunnel'
PROVIDER_REQUIREMENT = '''anchor apple generic and identifier "com.liguangming.Shadowrocket.PacketTunnel" and (
certificate leaf[field.1.2.840.113635.100.6.1.9] exists or (
certificate 1[field.1.2.840.113635.100.6.2.6] exists and
certificate leaf[field.1.2.840.113635.100.6.1.13] exists and
certificate leaf[subject.OU] = "JBJ55K5C9X"))'''


def call(arguments, **options):
    return subprocess.run(arguments, capture_output=True, timeout=15, **options)


def configuration():
    helper = runpy.run_path(str(REPOSITORY / 'Tests/shadowrocket_numeric_test_profile.py'))
    prefs = plistlib.loads(helper['read'](helper['PREFERENCES'], 65536))
    assert prefs['group.com.liguangming.GlobalRoutingMethod'] == 'Proxy', 'Proxy mode is required'
    selection = prefs['group.com.liguangming.SelectedServerUUID']
    _, row, scalar = helper['selected'](helper['read'](helper['ARCHIVE']), selection)
    port = str(scalar(row['port']))
    assert str(int(port)) == port and 1 <= int(port) <= 65535
    selected_host = str(scalar(row['host']))
    host_hash = hashlib.sha256(selected_host.encode()).hexdigest()
    try:
        numeric_host = str(ipaddress.IPv4Address(selected_host))
    except ipaddress.AddressValueError:
        numeric_host = None
    services = call(['/usr/sbin/scutil', '--nc', 'list']).stdout.decode()
    services = [line for line in services.splitlines() if '(Connected)' in line and '(com.liguangming.Shadowrocket)' in line]
    assert len(services) == 1, 'Exactly one connected Shadowrocket service is required'
    identifiers = re.findall(r'\b[0-9A-Fa-f-]{36}\b', services[0])
    assert len(identifiers) == 1
    status = call(['/usr/sbin/scutil', '--nc', 'status', identifiers[0]]).stdout.decode()
    interfaces = set(re.findall(r'^\s*InterfaceName\s*:\s*(utun[0-9]+)\s*$', status, re.M))
    assert status.startswith('Connected\n') and len(interfaces) == 1
    interface = next(iter(interfaces))
    processes = call(['/bin/ps', '-axo', 'pid=,uid=,comm=']).stdout.decode()
    providers = []
    for line in processes.splitlines():
        columns = line.strip().split(None, 2)
        if len(columns) == 3 and columns[1] == str(os.getuid()) and columns[2].endswith(PROVIDER_SUFFIX):
            verified = call(['/usr/bin/codesign', '--verify', '--strict', '-R=' + PROVIDER_REQUIREMENT, columns[2]])
            if verified.returncode == 0:
                providers.append(columns[0])
    assert providers, 'A signed running provider is required'
    endpoints = set()
    for _ in range(3):
        for pid in providers:
            result = call(['/usr/sbin/lsof', '-n', '-P', '-a', '-p', pid, '-i4', '-F', 'fPnT'])
            if result.returncode != 0:
                continue
            protocol, remote, established = '', None, False
            def finish():
                if protocol == 'TCP' and remote and established:
                    address, remote_port = remote
                    if remote_port == port and ipaddress.ip_address(address).is_global and (numeric_host is None or address == numeric_host):
                        endpoints.add(address)
            for line in result.stdout.decode().splitlines() + ['f']:
                if line.startswith(('f', 'p')):
                    finish()
                    protocol, remote, established = '', None, False
                elif line.startswith('P'):
                    protocol = line[1:]
                elif line.startswith('n') and '->' in line:
                    match = re.fullmatch(r'([0-9.]+):([0-9]+)', line.split('->', 1)[1])
                    if match:
                        remote = match.groups()
                elif line == 'TST=ESTABLISHED':
                    established = True
        time.sleep(0.25)
    assert len(endpoints) == 1, 'The selected live endpoint must be unique'
    trace_arguments = ['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/var/empty', '/usr/bin/curl',
        '-q', '-4', '--noproxy', '*', '--interface', 'if!' + interface, '--proto', '=https', '--tlsv1.2',
        '--connect-timeout', '2', '--max-time', '4', '--max-filesize', '16384', '-fsS',
        '--write-out', '\n%{http_code}', 'https://1.1.1.1/cdn-cgi/trace']
    for _ in range(3):
        trace = call(trace_arguments)
        body = trace.stdout.decode()
        exits = re.findall(r'^ip=([^\r\n]+)$', body, re.M)
        if trace.returncode == 0 and body.endswith('\n200') and len(exits) == 1:
            break
    else:
        raise RuntimeError('Fresh tunnel trace unavailable after three bounded preparation attempts')
    assert ipaddress.ip_address(exits[0]).version == 4 and ipaddress.ip_address(exits[0]).is_global
    return {'interface': interface, 'peer': next(iter(endpoints)), 'port': port, 'transport': 'tcp',
        'expected': exits[0], 'region': 'US', 'profileSelection': selection, 'profileHostHash': host_hash}


def prepare(package, staging, pin_profile, admission_only=False, browser_phases=False, browser_only=False, fault_mode=None, tailscale=False, short_sleep=False):
    assert os.geteuid() != 0 and package.is_file(), 'Prepare as the console user with a reviewed installer'
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix='local-acceptance-', dir=staging))
    payload = root / 'payload'
    installed = payload / 'Library/PrivilegedHelperTools/org.claudeguard.acceptance'
    installed.mkdir(parents=True)
    (installed / 'core').mkdir(mode=0o700)
    for source, name in [('Tests/host_acceptance.py', 'driver.py'),
                         ('Tests/host_environment_recovery.py', 'environment.py'),
                         ('Sources/GuardWorker.sh', 'GuardWorker.sh')]:
        shutil.copy2(REPOSITORY / source, installed / name)
    # Translate only fixed fixture-owned paths; keep actual Core/Power/Fence
    # implementations. Risk and installation trust are explicitly synthetic.
    driver = runpy.run_path(str(REPOSITORY / 'Tests/host_acceptance.py'))
    worker = driver['instrument_worker']((REPOSITORY / 'Sources/GuardWorker.sh').read_text())
    fixture_base = '/Library/PrivilegedHelperTools/org.claudeguard.acceptance'
    worker = worker.replace('boot_dir=/Library/PrivilegedHelperTools/org.claudeguard',
                            'boot_dir=' + fixture_base + '/legacy')
    worker = worker.replace('boot_plist=/Library/LaunchDaemons/org.claudeguard.guardian.plist',
                            'boot_plist=' + fixture_base + '/legacy.guardian.plist')
    worker = worker.replace('boot_label=org.claudeguard.guardian', 'boot_label=org.claudeguard.acceptance.legacy')
    worker = worker.replace('/Library/PrivilegedHelperTools/org.claudeguard/GuardDaemon', fixture_base + '/core/GuardDaemon')
    embedded = root / 'PrivilegedFixture.swift'
    embedded.write_text('import Foundation\nlet privilegedWorker = String(decoding: Data(base64Encoded: "' +
                        base64.b64encode(worker.encode()).decode() + '")!, as: UTF8.self)\n')
    core = root / 'GuardianCore.swift'
    core.write_text((REPOSITORY / 'Daemon/GuardianCore.swift').read_text().replace(
        '"/var/run/org.claudeguard.runtime"', '"/var/run/org.claudeguard.acceptance"'))
    shared = ['Sources/NodeAdmission.swift', 'Sources/GuardRiskPolicy.swift', 'Sources/GuardService.swift',
              'Sources/GuardianStore.swift', 'Tests/guardian_host_trust.swift', 'Daemon/GuardianRecovery.swift',
              'Daemon/GuardianPacketFence.swift', 'Daemon/GuardianPowerObserver.swift', 'Tests/packet_fence_host.swift']
    subprocess.run(['/usr/bin/xcrun', '--sdk', 'macosx', 'swiftc', '-swift-version', '5', '-O',
                    '-D', 'GUARD_DIAGNOSTICS', '-parse-as-library',
                    *[str(REPOSITORY / name) for name in shared], str(core), str(embedded), '-o', str(installed / 'FilterFixture')],
                   check=True, capture_output=True, timeout=60)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(installed / 'FilterFixture')],
                   check=True, capture_output=True, timeout=10)
    shutil.copy2(installed / 'FilterFixture', installed / 'core/GuardDaemon')
    shutil.copy2(package, installed / 'Guard.pkg')
    config = configuration()
    config['acceptanceMode'] = 'admission-only' if admission_only else 'full'
    config['browserOnly'] = browser_only
    if fault_mode:
        assert fault_mode in ['supervisor', 'wifi', 'sleep', 'lifecycle', 'soak']
        config['faultMode'] = fault_mode
    if short_sleep:
        assert fault_mode == 'sleep'
        config['shortSleep'] = True
    if browser_phases:
        bridge = root / 'browser-bridge'
        bridge.mkdir(mode=0o700)
        config['browserBridge'] = str(bridge)
        config['browserOwner'] = os.getuid()
    assert pin_profile, 'Explicit --pin-selected-profile approval is required for this development fixture'
    helper_path = REPOSITORY / 'Tests/shadowrocket_numeric_test_profile.py'
    helper = runpy.run_path(str(helper_path))
    manifest = helper['stage_configuration'](config)
    helper['apply'](manifest)
    subprocess.Popen(['/usr/bin/python3', '-I', str(helper_path), 'auto-restore', str(manifest)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    config['testExpires'] = time.time() + 300
    (installed / 'route.private.json').write_text(json.dumps(config))
    daemons = payload / 'Library/LaunchDaemons'
    daemons.mkdir(parents=True)
    for directory in [payload, payload / 'Library', payload / 'Library/PrivilegedHelperTools', daemons]:
        directory.chmod(0o755)
    for mode in ['safety', 'driver']:
        arguments = ['/usr/bin/python3', '-I', '/Library/PrivilegedHelperTools/org.claudeguard.acceptance/driver.py']
        if mode == 'safety':
            arguments.append('--safety')
        label = 'org.claudeguard.acceptance.' + mode
        (daemons / (label + '.plist')).write_bytes(plistlib.dumps({'Label': label, 'ProgramArguments': arguments,
            'RunAtLoad': True, 'ProcessType': 'Background'}))
    scripts = root / 'scripts'
    scripts.mkdir()
    postinstall = scripts / 'postinstall'
    postinstall.write_text('''#!/bin/sh
set -eu
[ "$(/usr/bin/id -u)" = 0 ] || exit 77
directory=/Library/PrivilegedHelperTools/org.claudeguard.acceptance
/usr/sbin/chown -R root:wheel "$directory"
/bin/chmod -R go-rwx "$directory"
for mode in safety driver; do
  /usr/sbin/chown root:wheel /Library/LaunchDaemons/org.claudeguard.acceptance.$mode.plist
  /bin/chmod 0644 /Library/LaunchDaemons/org.claudeguard.acceptance.$mode.plist
  /bin/launchctl bootstrap system /Library/LaunchDaemons/org.claudeguard.acceptance.$mode.plist
done
''')
    postinstall.chmod(0o755)
    output = root / 'Claude-Guard-Local-Acceptance.pkg'
    result = call(['/usr/bin/pkgbuild', '--root', str(payload), '--scripts', str(scripts),
        '--identifier', 'org.claudeguard.local-acceptance', '--version', '0.4.0',
        '--install-location', '/', '--ownership', 'recommended', str(output)])
    if result.returncode != 0:
        helper['restore'](manifest)
        raise RuntimeError('Acceptance package construction failed; original profile restored')
    if tailscale:
        subprocess.Popen(['/usr/bin/python3', '-I', str(REPOSITORY / 'Tests/tailscale_host_client.py'), str(bridge)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    print(json.dumps({'package': str(output), 'profileManifest': str(manifest), 'expiresInSeconds': 300,
                      'browserBridge': config.get('browserBridge')}))


if __name__ == '__main__':
    assert len(sys.argv) in [4, 5] and sys.argv[3] == '--pin-selected-profile', 'Supply the matched package, disposable staging and explicit profile approval'
    mode = sys.argv[4] if len(sys.argv) == 5 else None
    assert mode in [None, '--admission-only', '--browser-phases', '--browser-only', '--supervisor', '--wifi', '--sleep', '--sleep-short', '--tailscale', '--lifecycle', '--soak'], 'Unknown acceptance mode'
    faults = {'--supervisor': 'supervisor', '--wifi': 'wifi', '--sleep': 'sleep',
              '--sleep-short': 'sleep', '--tailscale': 'supervisor', '--lifecycle': 'lifecycle', '--soak': 'soak'}
    prepare(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), True,
            admission_only=mode == '--admission-only',
            browser_phases=mode in ['--browser-phases', '--browser-only', '--tailscale'],
            browser_only=mode == '--browser-only', fault_mode=faults.get(mode),
            tailscale=mode == '--tailscale', short_sleep=mode == '--sleep-short')
